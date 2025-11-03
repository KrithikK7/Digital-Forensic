from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, List, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db import SessionLocal
from models import Address, Message, MessageAddress, SenderProfile
from ollama_client import chat as ollama_chat


def _iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)


def _compute_basic_profile(db: Session, email: str) -> Tuple[Dict, datetime | None, datetime | None, int]:
    # Aggregate counts and date range
    q = (
        select(
            func.count(Message.id),
            func.min(Message.date_utc),
            func.max(Message.date_utc),
        )
        .join(MessageAddress, MessageAddress.message_id == Message.id)
        .join(Address, Address.id == MessageAddress.address_id)
        .where(MessageAddress.role == "from", Address.email == email)
    )
    count, first_seen, last_seen = (0, None, None)
    row = db.execute(q).first()
    if row:
        count, first_seen, last_seen = row
    prof_json = {
        "email": email,
        "message_stats": {"count": int(count or 0)},
        "time_range": {"first": _iso(first_seen), "last": _iso(last_seen)},
        "summary": "Profile pending full NLP enrichment.",
    }
    return prof_json, first_seen, last_seen, int(count or 0)


def _fetch_sample_messages(db: Session, email: str, limit: int = 5) -> List[Dict]:
    rows = (
        db.execute(
            select(Message.subject, Message.snippet, Message.date_utc)
            .join(MessageAddress, MessageAddress.message_id == Message.id)
            .join(Address, Address.id == MessageAddress.address_id)
            .where(MessageAddress.role == "from", Address.email == email)
            .order_by(Message.date_utc.desc())
            .limit(limit)
        )
        .mappings()
        .all()
    )
    samples = []
    for r in rows:
        samples.append(
            {
                "subject": r.get("subject"),
                "snippet": r.get("snippet"),
                "date": _iso(r.get("date_utc")),
            }
        )
    return samples


def _summarize_with_llm(email: str, samples: List[Dict]) -> Dict:
    if not samples:
        return {}
    sample_text = "\n".join(
        [
            f"- Date: {s.get('date')}, Subject: {s.get('subject')}, Snippet: {s.get('snippet')}"
            for s in samples
        ]
    )
    system_msg = {
        "role": "system",
        "content": (
            "You are an email forensics analyst. Given a set of emails from one sender, "
            "produce a concise JSON summary capturing overall communication tone, relationship, "
            "threat assessment, and key topics. Respond with valid JSON only, using the schema: "
            "{\"summary\": str, \"tone\": str, \"relationship\": {\"label\": str, \"confidence\": float}, "
            "\"threat_assessment\": {\"level\": str, \"notes\": str}, \"key_topics\": [str]}."
        ),
    }
    user_msg = {
        "role": "user",
        "content": f"Sender: {email}\nEmails:\n{sample_text}\nReturn JSON only.",
    }
    try:
        response = ollama_chat([system_msg, user_msg])
    except Exception as exc:
        return {"summary": f"LLM error: {exc}"}
    try:
        return json.loads(response)
    except Exception:
        return {"summary": response}


def upsert_sender_profile(email: str) -> None:
    with SessionLocal() as db:
        prof_json, first_seen, last_seen, msg_count = _compute_basic_profile(db, email)
        samples = _fetch_sample_messages(db, email)
        llm_data = _summarize_with_llm(email, samples)
        if llm_data:
            if llm_data.get("summary"):
                prof_json["summary"] = llm_data.get("summary")
            if llm_data.get("tone"):
                prof_json["tone_analysis"] = llm_data.get("tone")
            if llm_data.get("key_topics"):
                prof_json["key_topics"] = llm_data.get("key_topics")
            if llm_data.get("threat_assessment"):
                prof_json["threat_assessment"] = llm_data.get("threat_assessment")
        relationship_label = None
        risk_level = None
        if isinstance(llm_data.get("relationship"), dict):
            relationship_label = llm_data["relationship"].get("label")
        if isinstance(llm_data.get("threat_assessment"), dict):
            risk_level = llm_data["threat_assessment"].get("level")
        row = db.execute(select(SenderProfile).where(SenderProfile.email == email)).scalar_one_or_none()
        if row is None:
            row = SenderProfile(
                email=email,
                profile_json=prof_json,
                msg_count=msg_count,
                first_seen=first_seen,
                last_seen=last_seen,
                relationship_label=relationship_label,
                risk_level=risk_level,
            )
            db.add(row)
        else:
            row.profile_json = prof_json
            row.msg_count = msg_count
            row.first_seen = first_seen
            row.last_seen = last_seen
            row.relationship_label = relationship_label
            row.risk_level = risk_level
        db.commit()


def recompute_sender_profiles(limit: int = 50, progress_callback=None) -> int:
    with SessionLocal() as db:
        emails = db.execute(
            select(Address.email)
            .join(MessageAddress, MessageAddress.address_id == Address.id)
            .where(MessageAddress.role == "from")
            .group_by(Address.email)
            .order_by(func.count().desc())
            .limit(limit)
        ).scalars().all()
        total = len(emails)
        for idx, e in enumerate(emails, start=1):
            upsert_sender_profile(e)
            if progress_callback:
                try:
                    progress_callback(idx, total, e)
                except Exception:
                    pass
        return len(emails)


def list_sender_profiles(limit: int = 200) -> List[Dict]:
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(SenderProfile)
                .order_by(SenderProfile.msg_count.desc().nullslast())
                .limit(limit)
            )
            .scalars()
            .all()
        )

    profiles: List[Dict] = []
    for row in rows:
        pj = row.profile_json or {}
        time_range = pj.get("time_range", {}) if isinstance(pj, dict) else {}
        profiles.append(
            {
                "email": row.email,
                "message_count": row.msg_count,
                "first_seen": _iso(row.first_seen),
                "last_seen": _iso(row.last_seen),
                "relationship": row.relationship_label,
                "risk_level": row.risk_level,
                "summary": pj.get("summary") if isinstance(pj, dict) else None,
                "time_range_first": time_range.get("first"),
                "time_range_last": time_range.get("last"),
                "profile_json": pj,
            }
        )
    return profiles
