from __future__ import annotations

import json
from typing import Dict, List, Optional

from sqlalchemy import text

from db import SessionLocal
from ollama_client import embed_one, chat as ollama_chat


def _vector_literal(vec: List[float]) -> str:
    # pgvector expects [v1,v2,...]
    return "[" + ",".join(f"{x:.8f}" for x in vec) + "]"


def _parse_query(query: str) -> Dict:
    system = {
        "role": "system",
        "content": (
            "You convert natural-language Gmail forensics queries into strict JSON filters. "
            "Return ONLY JSON with keys: senders (list), recipients (list), names (list), keywords (list), "
            "after (YYYY-MM-DD or null), before (YYYY-MM-DD or null), has_attachment (true/false/null)."
        ),
    }
    user = {"role": "user", "content": query}
    try:
        response = ollama_chat([system, user])
        data = json.loads(response)
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}


def search_emails(
    query: str,
    *,
    from_contains: Optional[str] = None,
    after: Optional[str] = None,
    before: Optional[str] = None,
    k: int = 20,
) -> List[Dict]:
    """Hybrid retrieval mixing structured filters with pgvector similarity."""

    k = max(1, min(k, 200))
    parsed = _parse_query(query)
    qvec = embed_one(query)

    where_clauses: List[str] = ["1=1"]
    params: Dict[str, object] = {"k": k * 3}

    sender_clause_sql = ""
    sender_param_names: List[str] = []
    recipient_clause_sql = ""
    recipient_param_names: List[str] = []
    name_clause_sql = ""
    name_param_names: List[str] = []

    if from_contains:
        where_clauses.append("(m.from_addr ILIKE :fromq)")
        params["fromq"] = f"%{from_contains}%"

    senders = parsed.get("senders") or []
    recipients = parsed.get("recipients") or []
    names = parsed.get("names") or []
    keywords = parsed.get("keywords") or []
    parsed_after = parsed.get("after")
    parsed_before = parsed.get("before")
    has_attachment = parsed.get("has_attachment")

    if parsed_after and not after:
        after = parsed_after
    if parsed_before and not before:
        before = parsed_before

    if after:
        where_clauses.append("(m.date_utc >= :after)")
        params["after"] = after
    if before:
        where_clauses.append("(m.date_utc <= :before)")
        params["before"] = before

    if has_attachment is True:
        where_clauses.append(
            "EXISTS (SELECT 1 FROM attachments att WHERE att.message_id = m.id)"
        )
    elif has_attachment is False:
        where_clauses.append(
            "NOT EXISTS (SELECT 1 FROM attachments att WHERE att.message_id = m.id)"
        )

    if senders:
        clause_parts = []
        for idx, value in enumerate(senders):
            if not value:
                continue
            key = f"sender_filter_{idx}"
            params[key] = f"%{value}%"
            sender_param_names.append(key)
            clause_parts.append(
                f"(a_sender.email ILIKE :{key} OR a_sender.display_name ILIKE :{key})"
            )
        if clause_parts:
            sender_clause_sql = " OR ".join(clause_parts)
            where_clauses.append(
                "EXISTS (SELECT 1 FROM message_addresses ma_sender "
                "JOIN addresses a_sender ON a_sender.id = ma_sender.address_id "
                "WHERE ma_sender.message_id = m.id AND ma_sender.role = 'from' AND ("
                + sender_clause_sql
                + "))"
            )

    if recipients:
        clause_parts = []
        for idx, value in enumerate(recipients):
            if not value:
                continue
            key = f"recipient_filter_{idx}"
            params[key] = f"%{value}%"
            recipient_param_names.append(key)
            clause_parts.append(
                f"(a_rec.email ILIKE :{key} OR a_rec.display_name ILIKE :{key})"
            )
        if clause_parts:
            recipient_clause_sql = " OR ".join(clause_parts)
            where_clauses.append(
                "EXISTS (SELECT 1 FROM message_addresses ma_rec "
                "JOIN addresses a_rec ON a_rec.id = ma_rec.address_id "
                "WHERE ma_rec.message_id = m.id AND ma_rec.role IN ('to','cc','bcc') AND ("
                + recipient_clause_sql
                + "))"
            )

    if names:
        clause_parts = []
        for idx, value in enumerate(names):
            if not value:
                continue
            key = f"name_filter_{idx}"
            params[key] = f"%{value}%"
            name_param_names.append(key)
            clause_parts.append(
                f"(a_any.email ILIKE :{key} OR a_any.display_name ILIKE :{key})"
            )
        if clause_parts:
            name_clause_sql = " OR ".join(clause_parts)
            where_clauses.append(
                "EXISTS (SELECT 1 FROM message_addresses ma_any "
                "JOIN addresses a_any ON a_any.id = ma_any.address_id "
                "WHERE ma_any.message_id = m.id AND ("
                + name_clause_sql
                + "))"
            )

    if keywords:
        keyword_clauses = []
        for idx, kw in enumerate(keywords):
            if not kw:
                continue
            key = f"kw_{idx}"
            params[key] = f"%{kw}%"
            keyword_clauses.append(
                f"(m.subject ILIKE :{key} OR m.snippet ILIKE :{key})"
            )
        if keyword_clauses:
            where_clauses.append("(" + " OR ".join(keyword_clauses) + ")")

    where_sql = " AND ".join(where_clauses)

    sql = f"""
    WITH candidates AS (
        SELECT m.id AS message_id
        FROM messages m
        WHERE {where_sql}
        ORDER BY m.date_utc DESC NULLS LAST
        LIMIT 5000
    )
    SELECT mi.message_id, mi.chunk_id, mi.chunk_text,
           m.gmail_id, m.subject, m.from_addr, m.date_utc, m.snippet,
           (mi.chunk_vector <=> CAST(:qvec AS vector)) AS distance
    FROM message_index mi
    JOIN candidates c ON c.message_id = mi.message_id
    JOIN messages m ON m.id = mi.message_id
    ORDER BY distance ASC
    LIMIT :k
    """

    rows: List[Dict] = []
    with SessionLocal() as db:
        res = db.execute(text(sql), {**params, "qvec": _vector_literal(qvec)})
        for r in res.mappings():
            rows.append(dict(r))

        sender_match_ids = set()
        recipient_match_ids = set()
        name_match_ids = set()

        if sender_clause_sql:
            sender_query = text(
                "SELECT DISTINCT ma_sender.message_id FROM message_addresses ma_sender "
                "JOIN addresses a_sender ON a_sender.id = ma_sender.address_id "
                "WHERE ma_sender.role = 'from' AND (" + sender_clause_sql + ")"
            )
            sender_params = {k: params[k] for k in sender_param_names}
            sender_match_ids = set(db.execute(sender_query, sender_params).scalars().all())

        if recipient_clause_sql:
            rec_query = text(
                "SELECT DISTINCT ma_rec.message_id FROM message_addresses ma_rec "
                "JOIN addresses a_rec ON a_rec.id = ma_rec.address_id "
                "WHERE ma_rec.role IN ('to','cc','bcc') AND (" + recipient_clause_sql + ")"
            )
            rec_params = {k: params[k] for k in recipient_param_names}
            recipient_match_ids = set(db.execute(rec_query, rec_params).scalars().all())

        if name_clause_sql:
            name_query = text(
                "SELECT DISTINCT ma_any.message_id FROM message_addresses ma_any "
                "JOIN addresses a_any ON a_any.id = ma_any.address_id "
                "WHERE (" + name_clause_sql + ")"
            )
            name_params = {k: params[k] for k in name_param_names}
            name_match_ids = set(db.execute(name_query, name_params).scalars().all())

    scored: Dict[int, Dict] = {}
    for r in rows:
        mid = r["message_id"]
        distance = r.get("distance") or 0.0
        score = 1.0 - float(distance)
        if mid in sender_match_ids:
            score += 0.3
        if mid in recipient_match_ids:
            score += 0.15
        if mid in name_match_ids:
            score += 0.1
        if mid not in scored or score > scored[mid]["score"]:
            scored[mid] = {"record": r, "score": score}

    sorted_records = sorted(scored.values(), key=lambda x: x["score"], reverse=True)
    return [entry["record"] for entry in sorted_records[:k]]
