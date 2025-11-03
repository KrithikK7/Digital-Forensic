"""Streamlit UI for exploring the Gmail forensic database."""

import datetime
import json
import os
import re
import socket
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd
import streamlit as st
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session
from urllib.parse import quote
from dotenv import load_dotenv

load_dotenv()

from sqlalchemy import text  # noqa: E402
from db import SessionLocal, engine, Base  # noqa: E402
from models import (  # noqa: E402
    Address,
    Attachment,
    Header,
    Label,
    Message,
    MessageAddress,
    MessageLabel,
    Part,
    PartHeader,
    UserToken,
)
from gmail_sync import sync_all_mail  # noqa: E402
from indexer import get_missing_message_ids, index_message, reindex_all_messages  # noqa: E402
from retriever import search_emails  # noqa: E402
from profiles import recompute_sender_profiles, list_sender_profiles  # noqa: E402
from ollama_client import chat as ollama_chat  # noqa: E402

# Ensure tables/extension exist (important for newly added user_tokens and pgvector tables)
with engine.connect() as conn:
    conn = conn.execution_options(isolation_level="AUTOCOMMIT")
    try:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    except Exception as exc:
        raise RuntimeError(
            "Failed to create pgvector extension. Ensure the extension is installed and you have sufficient privileges."
        ) from exc
    ext = conn.execute(text("SELECT extname FROM pg_extension WHERE extname = 'vector'"))
    if ext.scalar_one_or_none() is None:
        raise RuntimeError("pgvector extension is not installed on this database instance.")
Base.metadata.create_all(bind=engine)

# If redirected back from OAuth, drop the flag from query params to avoid reruns
if "oauth" in st.query_params:
    del st.query_params["oauth"]

# Try importing uvicorn lazily; only needed for legacy Web OAuth
try:
    import uvicorn  # type: ignore
except Exception:
    uvicorn = None

RISK_FLAG_OPTIONS = {
    "SPF fail": "auth_spf_fail",
    "DKIM fail": "auth_dkim_fail",
    "DMARC fail": "auth_dmarc_fail",
    "Unusual mailer": "xmailer_unusual",
    "Bulk precedence": "precedence_bulk",
}


# --------- Helpers ---------


@st.cache_resource(show_spinner=False)
def get_sessionmaker():
    """Return the configured SQLAlchemy session factory."""

    return SessionLocal


def get_session() -> Session:
    return get_sessionmaker()()


def _format_bytes(size: Optional[int]) -> str:
    if size is None:
        return "-"
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while size >= step and idx < len(units) - 1:
        size /= step
        idx += 1
    return f"{size:.1f} {units[idx]}"


def _utc_from_ms(ms: Optional[int]) -> Optional[datetime.datetime]:
    if ms is None:
        return None
    return datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)


def _parse_list_input(raw: str) -> Tuple[str, ...]:
    if not raw:
        return tuple()
    tokens = re.split(r"[\s,;]+", raw.strip())
    cleaned = sorted({t.lower() for t in tokens if t})
    return tuple(cleaned)


def render_dataframe(data, *, width: str | int | None = "stretch", **kwargs):
    """Render a dataframe using the new width API while staying compatible with older Streamlit releases."""
    try:
        return st.dataframe(data, width=width, **kwargs)
    except TypeError:
        # Older Streamlit required use_container_width; fall back to that behavior
        kwargs.setdefault("use_container_width", True)
        return st.dataframe(data, **kwargs)


# --------- Auth & Sync helpers ---------


def _get_streamlit_base_url() -> str:
    env_url = os.getenv("STREAMLIT_URL")
    if env_url:
        return env_url.rstrip("/")
    server_addr = st.get_option("browser.serverAddress") or "127.0.0.1"
    server_port = st.get_option("browser.serverPort") or 8501
    try:
        port_int = int(server_port)
    except (TypeError, ValueError):
        port_int = 8501
    protocol = "https" if port_int == 443 else "http"
    return f"{protocol}://{server_addr}:{port_int}"


def _get_stored_token() -> Tuple[Optional[str], Optional[dict]]:
    """Return (email, token_dict) from the most recently stored OAuth token."""
    with get_session() as db:
        row = db.execute(
            select(UserToken).order_by(UserToken.updated_at.desc()).limit(1)
        ).scalar_one_or_none()
    if row is None:
        return None, None
    try:
        token = json.loads(row.token_json or "{}")
    except json.JSONDecodeError:
        token = None
    return row.email, token


def _perform_sync(token: dict) -> Tuple[int, int]:
    page_limit_env = os.getenv("PAGE_LIMIT", "0") or "0"
    page_limit = int(page_limit_env)
    with get_session() as db:
        processed, atts = sync_all_mail(db, token, page_limit=page_limit)
    st.cache_data.clear()
    return processed, atts


def _clear_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # Clear cached queries so UI reflects freshly emptied tables
    st.cache_data.clear()
    st.cache_resource.clear()


@st.cache_data(show_spinner=False)
def fetch_sender_suggestions(limit: int = 50) -> List[str]:
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(Address.display_name, Address.email, func.count(MessageAddress.id))
                .join(MessageAddress, MessageAddress.address_id == Address.id)
                .where(MessageAddress.role == "from")
                .group_by(Address.display_name, Address.email)
                .order_by(func.count(MessageAddress.id).desc())
                .limit(limit)
            )
            .all()
        )
    suggestions: List[str] = []
    for display, email, _count in rows:
        label = ""
        if display and email:
            label = f"{display} <{email}>"
        else:
            label = display or email or ""
        label = label.strip()
        if label and label not in suggestions:
            suggestions.append(label)
    return suggestions


@st.cache_data(show_spinner=False)
def fetch_message_date_range() -> Tuple[Optional[str], Optional[str]]:
    with SessionLocal() as db:
        row = db.execute(select(func.min(Message.date_utc), func.max(Message.date_utc))).first()
    if not row:
        return None, None
    min_dt, max_dt = row

    def _fmt(dt: Optional[datetime.datetime]) -> Optional[str]:
        if not dt:
            return None
        if isinstance(dt, datetime.datetime):
            return dt.date().isoformat()
        return str(dt)

    return _fmt(min_dt), _fmt(max_dt)


def fetch_sender_matches(term: str, limit: int = 20) -> List[str]:
    term = term.strip()
    if not term:
        return []
    like = f"%{term}%"
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(Address.display_name, Address.email)
                .join(MessageAddress, MessageAddress.address_id == Address.id)
                .where(MessageAddress.role == "from")
                .where(
                    (Address.display_name.ilike(like))
                    | (Address.email.ilike(like))
                )
                .group_by(Address.display_name, Address.email)
                .order_by(func.count(MessageAddress.id).desc())
                .limit(limit)
            )
            .all()
        )
    results: List[str] = []
    for display, email in rows:
        label = ""
        if display and email:
            label = f"{display} <{email}>"
        else:
            label = display or email or ""
        label = label.strip()
        if label and label not in results:
            results.append(label)
    return results


# --------- Legacy Web OAuth (FastAPI) helpers ---------


def _is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _start_fastapi_once():
    if st.session_state.get("api_started"):
        return
    api_port = int(os.getenv("API_PORT", "8000"))
    if uvicorn is None:
        st.warning("uvicorn is not installed; cannot start FastAPI server from Streamlit.")
        return
    if _is_port_open("127.0.0.1", api_port):
        st.session_state["api_started"] = True
        return

    def _runner():
        import app as api_app  # local import to avoid circulars
        uvicorn.run(api_app.app, host="127.0.0.1", port=api_port, log_level="warning")

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    st.session_state["api_started"] = True


# --------- Cached data fetchers ---------

@st.cache_data(show_spinner=False)
def fetch_overview() -> Dict[str, object]:
    with get_session() as db:
        total_messages = db.scalar(select(func.count(Message.id))) or 0
        total_attachments = db.scalar(select(func.count(Attachment.id))) or 0
        total_labels = db.scalar(select(func.count(Label.id))) or 0
        total_addresses = db.scalar(select(func.count(Address.id))) or 0

        latest_message: Optional[datetime.datetime] = db.scalar(
            select(Message.date_utc)
            .where(Message.date_utc.is_not(None))
            .order_by(Message.date_utc.desc())
            .limit(1)
        )

        top_labels = db.execute(
            select(Label.name, func.count(MessageLabel.message_id).label("count"))
            .join(MessageLabel, MessageLabel.label_id == Label.id)
            .group_by(Label.id)
            .order_by(func.count(MessageLabel.message_id).desc())
            .limit(10)
        ).all()

        return {
            "messages": total_messages,
            "attachments": total_attachments,
            "labels": total_labels,
            "addresses": total_addresses,
            "latest_message": latest_message,
            "top_labels": top_labels,
        }


@st.cache_data(show_spinner=False)
def fetch_labels() -> List[Tuple[int, str]]:
    with get_session() as db:
        rows = db.execute(select(Label.id, Label.name).order_by(Label.name)).all()
    return [(row.id, row.name) for row in rows]


def fetch_attachment_extensions() -> List[str]:
    with get_session() as db:
        rows = db.execute(
            select(func.lower(func.split_part(Attachment.filename, '.', -1)).label("ext"))
            .where(Attachment.filename.is_not(None))
            .group_by("ext")
            .order_by("ext")
        ).scalars().all()
    return [ext for ext in rows if ext]


@st.cache_data(show_spinner=False)
def fetch_header_names() -> List[str]:
    with get_session() as db:
        rows = db.execute(
            select(func.distinct(Header.name)).order_by(Header.name)
        ).scalars().all()
    return rows


@st.cache_data(show_spinner=False)
def fetch_top_senders(limit: int = 20) -> pd.DataFrame:
    with get_session() as db:
        rows = db.execute(
            select(Message.from_addr, func.count(Message.id).label("count"))
            .group_by(Message.from_addr)
            .order_by(func.count(Message.id).desc())
            .limit(limit)
        ).all()
    df = pd.DataFrame(rows, columns=["from_addr", "messages"])
    df = df[df["from_addr"].notna()]
    return df


@st.cache_data(show_spinner=False)
def fetch_auth_results() -> pd.DataFrame:
    with get_session() as db:
        rows = db.execute(
            select(Header.message_id, Header.value)
            .where(func.lower(Header.name) == "authentication-results")
        ).all()

    data = []
    for mid, value in rows:
        if not value:
            continue
        lv = value.lower()
        data.append(
            {
                "message_id": mid,
                "spf": _extract_auth_result(lv, "spf"),
                "dkim": _extract_auth_result(lv, "dkim"),
                "dmarc": _extract_auth_result(lv, "dmarc"),
            }
        )
    return pd.DataFrame(data)


def _extract_auth_result(val: str, mech: str) -> Optional[str]:
    match = re.search(rf"{mech}\s*=\s*([a-z0-9_-]+)", val)
    if match:
        return match.group(1)
    return None


@st.cache_data(show_spinner=False)
def fetch_attachment_summary() -> pd.DataFrame:
    with get_session() as db:
        rows = db.execute(
            select(
                func.lower(func.split_part(Attachment.filename, '.', -1)).label("ext"),
                func.count(Attachment.id),
                func.sum(Attachment.size)
            )
            .group_by("ext")
            .order_by(func.count(Attachment.id).desc())
        ).all()
    df = pd.DataFrame(rows, columns=["extension", "count", "total_size"])
    df = df[df["extension"].notna()]
    df["total_size_fmt"] = df["total_size"].apply(_format_bytes)
    return df


@st.cache_data(show_spinner=False)
def fetch_messages(
    label_ids: Tuple[int, ...],
    search_term: str,
    only_with_attachments: bool,
    limit: int,
    from_addrs: Tuple[str, ...],
    to_addrs: Tuple[str, ...],
    cc_addrs: Tuple[str, ...],
    bcc_addrs: Tuple[str, ...],
    reply_to_addrs: Tuple[str, ...],
    header_filters: Tuple[Tuple[str, str], ...],
    date_start: Optional[datetime.datetime],
    date_end: Optional[datetime.datetime],
    regex_filter: Optional[str],
    min_size: Optional[int],
    max_size: Optional[int],
    attachment_exts: Tuple[str, ...],
    attachment_hash: Optional[str],
    risk_filters: Tuple[str, ...],
) -> pd.DataFrame:
    stmt = (
        select(
            Message.id,
            Message.gmail_id,
            Message.subject,
            Message.from_addr,
            Message.date_utc,
            Message.internal_date_ms,
            Message.snippet,
            Message.size_estimate,
            func.count(func.distinct(Attachment.id)).label("attachment_count"),
            func.count(func.distinct(MessageLabel.id)).label("label_count"),
            func.bool_or(Attachment.data.is_not(None)).label("has_attachment_data"),
        )
        .outerjoin(Attachment, Attachment.message_id == Message.id)
        .outerjoin(MessageLabel, MessageLabel.message_id == Message.id)
    )

    if label_ids:
        sub = (
            select(MessageLabel.message_id)
            .where(MessageLabel.label_id.in_(label_ids))
            .group_by(MessageLabel.message_id)
        )
        stmt = stmt.where(Message.id.in_(sub))

    if search_term:
        pattern = f"%{search_term.lower()}%"
        stmt = stmt.where(
            func.lower(Message.subject).like(pattern)
            | func.lower(Message.snippet).like(pattern)
            | func.lower(Message.from_addr).like(pattern)
        )

    if only_with_attachments:
        stmt = stmt.where(
            Message.id.in_(
                select(Attachment.message_id).group_by(Attachment.message_id)
            )
        )

    addr_filters: List[Tuple[Tuple[str, ...], str]] = [
        (from_addrs, "from"),
        (to_addrs, "to"),
        (cc_addrs, "cc"),
        (bcc_addrs, "bcc"),
        (reply_to_addrs, "reply-to"),
    ]
    for emails, role in addr_filters:
        if emails:
            stmt = stmt.where(
                Message.id.in_(
                    select(MessageAddress.message_id)
                    .join(Address, Address.id == MessageAddress.address_id)
                    .where(
                        and_(
                            MessageAddress.role == role,
                            func.lower(Address.email).in_([e.lower() for e in emails])
                        )
                    )
                )
            )

    for header_name, header_value in header_filters:
        if header_name and header_value:
            pattern = f"%{header_value.lower()}%"
            stmt = stmt.where(
                Message.id.in_(
                    select(Header.message_id)
                    .where(
                        and_(
                            func.lower(Header.name) == header_name.lower(),
                            func.lower(Header.value).like(pattern),
                        )
                    )
                )
            )

    if date_start:
        stmt = stmt.where(
            or_(
                Message.date_utc >= date_start,
                Message.internal_date_ms >= int(date_start.timestamp() * 1000),
            )
        )

    if date_end:
        stmt = stmt.where(
            or_(
                Message.date_utc <= date_end,
                Message.internal_date_ms <= int(date_end.timestamp() * 1000),
            )
        )

    if min_size is not None:
        stmt = stmt.where(Message.size_estimate >= min_size)
    if max_size is not None:
        stmt = stmt.where(Message.size_estimate <= max_size)

    if attachment_exts:
        stmt = stmt.where(
            Message.id.in_(
                select(Attachment.message_id)
                .where(
                    func.lower(func.split_part(Attachment.filename, '.', -1)).in_(
                        [ext.lower() for ext in attachment_exts]
                    )
                )
            )
        )

    if attachment_hash:
        hash_pattern = attachment_hash.lower()
        stmt = stmt.where(
            Message.id.in_(
                select(Attachment.message_id)
                .where(func.lower(Attachment.sha256).like(f"%{hash_pattern}%"))
            )
        )

    stmt = (
        stmt.group_by(Message.id)
        .order_by(Message.internal_date_ms.desc().nullslast())
        .limit(limit)
    )

    with get_session() as db:
        rows = db.execute(stmt).all()

    data = []
    for row in rows:
        internal_dt = _utc_from_ms(row.internal_date_ms)
        data.append(
            {
                "id": row.id,
                "gmail_id": row.gmail_id,
                "subject": row.subject,
                "from": row.from_addr,
                "date_utc": row.date_utc,
                "internal_ts": internal_dt,
                "snippet": row.snippet,
                "size": row.size_estimate,
                "attachment_count": row.attachment_count,
                "label_count": row.label_count,
                "has_attachment_data": row.has_attachment_data,
            }
        )

    df = pd.DataFrame(data)
    if not df.empty:
        df["date_display"] = df["date_utc"].fillna(df["internal_ts"])
        df["size_display"] = df["size"].apply(_format_bytes)

        if regex_filter:
            try:
                pattern = re.compile(regex_filter, flags=re.IGNORECASE)
                df = df[df.apply(
                    lambda r: bool(
                        pattern.search(r.get("subject") or "")
                        or pattern.search(r.get("snippet") or "")
                        or pattern.search(r.get("from") or "")
                    ),
                    axis=1,
                )]
            except re.error:
                st.warning("Invalid regex filter; ignoring.")

        if risk_filters:
            risk_lookup = compute_risk_lookup(df["id"].tolist(), risk_filters)
            df = df[df["id"].isin(risk_lookup.keys())]
            df["risk_flags"] = df["id"].map(lambda mid: ", ".join(risk_lookup.get(mid, [])))
        else:
            df["risk_flags"] = ""

    return df


def fetch_message_details(message_id: int) -> Optional[Dict[str, object]]:
    with get_session() as db:
        msg = db.get(Message, message_id)
        if msg is None:
            return None

        labels = db.execute(
            select(Label.name)
            .join(MessageLabel, MessageLabel.label_id == Label.id)
            .where(MessageLabel.message_id == message_id)
            .order_by(Label.name)
        ).scalars().all()

        headers = db.execute(
            select(Header.name, Header.value)
            .where(Header.message_id == message_id)
            .order_by(Header.name)
        ).all()

        addresses = db.execute(
            select(
                MessageAddress.role,
                Address.email,
                Address.display_name,
            )
            .join(Address, Address.id == MessageAddress.address_id)
            .where(MessageAddress.message_id == message_id)
            .order_by(MessageAddress.role)
        ).all()

        parts = db.execute(
            select(Part)
            .where(Part.message_id == message_id)
            .order_by(Part.part_id.nullsfirst())
        ).scalars().all()

        parts_data: List[Dict[str, object]] = []
        part_ids = [p.id for p in parts]

        headers_map: Dict[int, List[Tuple[str, Optional[str]]]] = {}
        if part_ids:
            part_headers = db.execute(
                select(PartHeader.part_id, PartHeader.name, PartHeader.value)
                .where(PartHeader.part_id.in_(part_ids))
                .order_by(PartHeader.part_id)
            ).all()
            for pid, name, value in part_headers:
                headers_map.setdefault(pid, []).append((name, value))

        for part in parts:
            text_preview = None
            if part.data and part.mime_type and part.mime_type.startswith("text/"):
                try:
                    text_preview = part.data.decode("utf-8", errors="replace")[:500]
                except Exception:
                    text_preview = None

            parts_data.append(
                {
                    "id": part.id,
                    "part_id": part.part_id,
                    "mime_type": part.mime_type,
                    "filename": part.filename,
                    "size": part.size,
                    "is_attachment": part.is_attachment,
                    "content_id": part.content_id,
                    "content_disposition": part.content_disposition,
                    "content_transfer_encoding": part.content_transfer_encoding,
                    "content_language": part.content_language,
                    "content_location": part.content_location,
                    "sha256": part.sha256,
                    "has_data": part.data is not None,
                    "text_preview": text_preview,
                    "headers": headers_map.get(part.id, []),
                }
            )

        attachments = db.execute(
            select(Attachment)
            .where(Attachment.message_id == message_id)
            .order_by(Attachment.filename)
        ).scalars().all()

        attachment_data: List[Dict[str, object]] = []
        for att in attachments:
            attachment_data.append(
                {
                    "id": att.id,
                    "part_id": att.part_id,
                    "filename": att.filename,
                    "mime_type": att.mime_type,
                    "size": att.size,
                    "sha256": att.sha256,
                    "content_id": att.content_id,
                    "content_disposition": att.content_disposition,
                    "content_transfer_encoding": att.content_transfer_encoding,
                    "content_language": att.content_language,
                    "content_location": att.content_location,
                    "has_data": att.data is not None,
                    "data": att.data,
                }
            )

        raw_text = None
        if msg.raw_rfc822:
            raw_text = msg.raw_rfc822.decode("utf-8", errors="replace")

        return {
            "message": msg,
            "labels": labels,
            "headers": headers,
            "addresses": addresses,
            "parts": parts_data,
            "attachments": attachment_data,
            "raw_text": raw_text,
        }


@st.cache_data(show_spinner=False)
def compute_risk_lookup(message_ids: List[int], requested_flags: Tuple[str, ...]) -> Dict[int, Set[str]]:
    if not message_ids:
        return {}

    flags_needed: Set[str] = set(requested_flags)
    with get_session() as db:
        header_rows = db.execute(
            select(Header.message_id, Header.name, Header.value)
            .where(Header.message_id.in_(message_ids))
        ).all()

    results: Dict[int, Set[str]] = {mid: set() for mid in message_ids}

    for mid, name, value in header_rows:
        lname = (name or "").lower()
        lvalue = (value or "").lower()
        if "auth_spf_fail" in flags_needed and lname == "authentication-results" and "spf=fail" in lvalue:
            results[mid].add("SPF fail")
        if "auth_dkim_fail" in flags_needed and lname == "authentication-results" and "dkim=fail" in lvalue:
            results[mid].add("DKIM fail")
        if "auth_dmarc_fail" in flags_needed and lname == "authentication-results" and "dmarc=fail" in lvalue:
            results[mid].add("DMARC fail")
        if "xmailer_unusual" in flags_needed and lname in {"x-mailer", "user-agent"}:
            if value and not re.search(r"outlook|gmail|apple mail|thunderbird", lvalue):
                results[mid].add("Unusual mailer")
        if "precedence_bulk" in flags_needed and lname == "precedence" and "bulk" in lvalue:
            results[mid].add("Bulk precedence")

    # Remove empty entries
    return {mid: flags for mid, flags in results.items() if flags}


# --------- UI ---------


st.set_page_config(page_title="Gmail Forensics Explorer", layout="wide")
st.title("Gmail Forensics Explorer")
st.caption("Inspect synchronized Gmail metadata, MIME structure, and attachments")

overview = fetch_overview()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Messages", overview["messages"])
col2.metric("Attachments", overview["attachments"])
col3.metric("Labels", overview["labels"])
col4.metric("Addresses", overview["addresses"])

if overview["latest_message"]:
    st.info(
        f"Latest message captured: {overview['latest_message'].astimezone(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}"
    )

if "last_sync_message" not in st.session_state:
    st.session_state["last_sync_message"] = None
if "last_clear_message" not in st.session_state:
    st.session_state["last_clear_message"] = None


with st.sidebar:
    st.header("Controls")

    api_port = int(os.getenv("API_PORT", "8000"))
    if st.button("Start FastAPI server", key="start_api"):
        _start_fastapi_once()

    api_running = _is_port_open("127.0.0.1", api_port)
    if api_running:
        st.success(f"OAuth server running on http://127.0.0.1:{api_port}")
        return_url = f"{_get_streamlit_base_url()}/?oauth=1"
        login_url = f"http://127.0.0.1:{api_port}/login?next={quote(return_url, safe='')}"
        st.link_button("Sign in with Google", login_url)
    else:
        st.info("Start the server to launch the Google sign-in flow.")

    email, token = _get_stored_token()
    if email:
        st.success(f"Stored credentials for: {email}")
    else:
        st.warning("No stored Google token. Complete sign-in to enable sync.")

    if st.button("Sync All Mail", key="sync_mail", disabled=token is None):
        if token is None:
            st.session_state["last_sync_message"] = "No token available. Sign in first."
        else:
            try:
                processed, atts = _perform_sync(token)
                st.session_state["last_sync_message"] = (
                    f"Sync complete: {processed} messages, {atts} attachments."
                )
            except Exception as exc:  # noqa: BLE001
                st.session_state["last_sync_message"] = f"Sync failed: {exc}"

    if st.session_state["last_sync_message"]:
        st.caption(st.session_state["last_sync_message"])

    if st.button("Clear database", key="clear_db"):
        try:
            _clear_database()
            st.session_state["last_clear_message"] = "Database cleared. Re-run sign-in before syncing."
            st.session_state["last_sync_message"] = None
        except Exception as exc:  # noqa: BLE001
            st.session_state["last_clear_message"] = f"Failed to clear database: {exc}"

    if st.session_state["last_clear_message"]:
        st.caption(st.session_state["last_clear_message"])

with st.expander("Top labels", expanded=False):
    top_label_df = pd.DataFrame(overview["top_labels"], columns=["Label", "Messages"])
    render_dataframe(top_label_df)

label_options = fetch_labels()

label_lookup = {name: lid for lid, name in label_options}

with st.sidebar:
    st.header("Filters")
    selected_labels = st.multiselect(
        "Labels",
        options=[name for _, name in label_options],
    )
    label_ids = tuple(label_lookup[name] for name in selected_labels)

    search_term = st.text_input("Keyword search", help="Matches subject, snippet, from")
    regex_filter = st.text_input("Regex filter", help="Applied to subject/snippet/from")

    st.subheader("Identity filters")
    from_input = st.text_input("From", placeholder="alice@example.com, bob@threat.com")
    to_input = st.text_input("To", placeholder="recipient@example.com")
    cc_input = st.text_input("Cc")
    bcc_input = st.text_input("Bcc")
    reply_to_input = st.text_input("Reply-To")
    message_id_input = st.text_input("Message-ID contains")

    st.subheader("Time window")
    enable_date_filter = st.checkbox("Filter by date range")
    date_start: Optional[datetime.datetime] = None
    date_end: Optional[datetime.datetime] = None
    if enable_date_filter:
        default_start = datetime.date.today() - datetime.timedelta(days=30)
        default_end = datetime.date.today()
        date_range = st.date_input(
            "Between (UTC)",
            value=(default_start, default_end),
            help="Inclusive range; left blank to clear",
        )
        if isinstance(date_range, (list, tuple)) and len(date_range) == 2:
            start_date, end_date = date_range
            if start_date:
                date_start = datetime.datetime.combine(start_date, datetime.time.min, tzinfo=datetime.timezone.utc)
            if end_date:
                date_end = datetime.datetime.combine(end_date, datetime.time.max, tzinfo=datetime.timezone.utc)

    limit = st.slider("Max messages", min_value=25, max_value=500, step=25, value=200)

    st.markdown("---")
    st.caption("Run via `streamlit run streamlit_app.py`")

from_addrs = _parse_list_input(from_input)
to_addrs = _parse_list_input(to_input)
cc_addrs = _parse_list_input(cc_input)
bcc_addrs = _parse_list_input(bcc_input)
reply_to_addrs = _parse_list_input(reply_to_input)

header_filters: Tuple[Tuple[str, str], ...] = tuple()
only_with_attachments = False
min_size = None
max_size = None
attachment_hash = None
selected_exts: Tuple[str, ...] = tuple()

header_filter_list: List[Tuple[str, str]] = []
if message_id_input:
    header_filter_list.append(("Message-ID", message_id_input))
header_filters = tuple(header_filter_list)

messages_df = fetch_messages(
    label_ids=label_ids,
    search_term=search_term.strip().lower(),
    only_with_attachments=only_with_attachments,
    limit=limit,
    from_addrs=from_addrs,
    to_addrs=to_addrs,
    cc_addrs=cc_addrs,
    bcc_addrs=bcc_addrs,
    reply_to_addrs=reply_to_addrs,
    header_filters=tuple(header_filters),
    date_start=date_start,
    date_end=date_end,
    regex_filter=regex_filter or None,
    min_size=min_size,
    max_size=max_size,
    attachment_exts=tuple(selected_exts),
    attachment_hash=attachment_hash,
    risk_filters=tuple(),
)

if not messages_df.empty:
    risk_lookup_all = compute_risk_lookup(messages_df["id"].tolist(), tuple(RISK_FLAG_OPTIONS.values()))
    messages_df["risk_flags"] = messages_df["id"].map(lambda mid: ", ".join(sorted(risk_lookup_all.get(mid, []))))
else:
    risk_lookup_all = {}

catalog_tab, analytics_tab, chatbot_tab, summary_tab = st.tabs([
    "Catalog",
    "Analytics",
    "AI Chatbot",
    "Sender Summary",
])

with catalog_tab:
    st.subheader("Message catalog")
    if messages_df.empty:
        st.warning("No messages match the current filters.")
    else:
        display_df = messages_df[[
            "subject",
            "from",
            "date_display",
            "attachment_count",
            "label_count",
            "risk_flags",
            "size_display",
            "snippet",
        ]].rename(columns={"from": "from_addr", "date_display": "date"})

        # Render interactive table with a Select column for robust selection
        selected_idx = st.session_state.get("selected_index", 0)
        if selected_idx >= len(display_df):
            selected_idx = 0
        editable_df = display_df.copy()
        editable_df.insert(0, "Select", False)
        if len(editable_df) > 0 and 0 <= selected_idx < len(editable_df):
            editable_df.iloc[selected_idx, editable_df.columns.get_loc("Select")] = True

        try:
            edited_df = st.data_editor(
                editable_df,
                height=400,
                num_rows="fixed",
                column_config={
                    "Select": st.column_config.CheckboxColumn("Select")
                },
                key="message_table_editor",
            )
            sel_rows = [i for i, v in enumerate(edited_df["Select"].tolist()) if bool(v)]
            prev_idx = st.session_state.get("selected_index", selected_idx)
            # Determine the newly intended selection
            if sel_rows:
                new_idx = sel_rows[-1] if len(sel_rows) > 1 else sel_rows[0]
            else:
                new_idx = prev_idx  # keep previous to enforce single selection

            # If selection changed or multiple were checked, enforce single select and rerun
            if new_idx != prev_idx or len(sel_rows) > 1:
                st.session_state["selected_index"] = new_idx
                st.rerun()

            selected_idx = st.session_state.get("selected_index", new_idx)
        except Exception:
            render_dataframe(display_df, height=400)
            selected_record = st.selectbox(
                "Select a message to inspect",
                options=messages_df.to_dict("records"),
                format_func=lambda m: f"{m.get('subject') or '(no subject)'} — {m.get('from') or 'unknown'}",
            )
            selected_idx = messages_df.index[messages_df["id"] == selected_record["id"]].tolist()[0]

        st.session_state["selected_index"] = selected_idx

        csv_data = display_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download visible results (CSV)",
            data=csv_data,
            file_name="gmail_forensics_results.csv",
            mime="text/csv",
        )
        selected_message = messages_df.iloc[selected_idx].to_dict()

        details = fetch_message_details(selected_message["id"])
        if not details:
            st.error("Unable to load message details.")
        else:
            msg = details["message"]
            risk_for_msg = compute_risk_lookup([msg.id], tuple(RISK_FLAG_OPTIONS.values()))
            risk_tags = ", ".join(sorted(risk_for_msg.get(msg.id, []))) or "None"

            st.markdown(
                f"### Message metadata\n"
                f"- **Subject:** {msg.subject or '(no subject)'}\n"
                f"- **From:** {msg.from_addr or 'unknown'}\n"
                f"- **Date (UTC):** {msg.date_utc}\n"
                f"- **Internal timestamp:** {_utc_from_ms(msg.internal_date_ms)}\n"
                f"- **Size estimate:** {_format_bytes(msg.size_estimate)}\n"
                f"- **Gmail ID:** `{msg.gmail_id}`\n"
                f"- **Thread ID:** `{msg.thread_id}`\n"
                f"- **History ID:** `{msg.history_id}`\n"
                f"- **Risk flags:** {risk_tags}"
            )

            if details["labels"]:
                st.write("**Labels:**", ", ".join(details["labels"]))

            raw_text = details.get("raw_text")
            if raw_text:
                st.subheader("Full message (RFC 5322)")
                st.code(raw_text, language="message")
            else:
                st.info("Raw message content not stored for this email.")

with analytics_tab:
    st.subheader("Analytics & trends")
    top_senders_df = fetch_top_senders()
    if not top_senders_df.empty:
        st.write("**Top senders by message count**")
        st.bar_chart(top_senders_df.set_index("from_addr"))
    else:
        st.info("No sender data yet.")

    attachment_summary = fetch_attachment_summary()
    if not attachment_summary.empty:
        st.write("**Attachment summary by extension**")
        render_dataframe(attachment_summary)
    else:
        st.info("No attachment metadata available.")

    auth_df = fetch_auth_results()
    if not auth_df.empty:
        st.write("**Authentication verdicts**")
        auth_counts = auth_df.melt(id_vars="message_id", value_vars=["spf", "dkim", "dmarc"], var_name="mechanism", value_name="result")
        auth_counts = auth_counts.dropna()
        pivot = auth_counts.groupby(["mechanism", "result"]).size().reset_index(name="count")
        render_dataframe(pivot)
    else:
        st.info("No Authentication-Results headers captured yet.")

with chatbot_tab:
    st.subheader("AI Chatbot – Local Ollama")
    st.caption("Build the index, then chat with the forensics assistant. Responses cite gmail_id.")

    if status := st.session_state.get("index_status"):
        st.caption(f"📦 Embeddings: {status}")
    if status := st.session_state.get("profile_status"):
        st.caption(f"👤 Profiles: {status}")

    colc, cold, colre, colclear = st.columns(4)
    with colc:
        if st.button("Build/Refresh Index", key="chat_index_btn", help="Chunk + embed messages missing from the index"):
            ids = get_missing_message_ids(limit=1000)
            if not ids:
                msg = f"All messages embedded as of {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                st.session_state["index_status"] = msg
                st.info(msg)
            else:
                progress = st.progress(0)
                status_box = st.empty()
                start = time.time()
                chunk_total = 0
                total = len(ids)
                with SessionLocal() as db:
                    for idx, mid in enumerate(ids, start=1):
                        try:
                            chunk_total += index_message(db, mid)
                        except Exception as e:
                            status_box.error(f"Failed indexing message {mid}: {e}")
                            continue
                        progress.progress(idx / total)
                        elapsed = time.time() - start
                        rate = idx / elapsed if elapsed > 0 else 0
                        eta = (total - idx) / rate if rate > 0 else None
                        eta_text = f" ETA ~{eta:.1f}s" if eta else ""
                        status_box.write(f"Indexed {idx}/{total} messages ({chunk_total} chunks).{eta_text}")
                st.cache_data.clear()
                msg = f"Indexed {total} messages, {chunk_total} chunks at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                st.session_state["index_status"] = msg
                st.success(msg)
    with cold:
        if st.button("Recompute Sender Profiles", key="chat_profiles_btn"):
            progress = st.progress(0)
            status_box = st.empty()
            start = time.time()

            def _progress_cb(done: int, total: int, email: str):
                progress.progress(done / total if total else 1.0)
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else None
                eta_text = f" ETA ~{eta:.1f}s" if eta else ""
                status_box.write(f"Profiling {email} — {done}/{total}{eta_text}")

            try:
                n = recompute_sender_profiles(limit=50, progress_callback=_progress_cb)
                msg = f"Updated {n} profiles at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                st.session_state["profile_status"] = msg
                st.success(msg)
                st.session_state.pop("summary_profiles_cache", None)
            except Exception as e:
                st.error(f"Profile recompute failed: {e}")
    with colre:
        if st.button("Reindex ALL", key="chat_reindex_btn", help="Re-embed every message (slow)"):
            progress = st.progress(0)
            status_box = st.empty()
            start = time.time()
            total_msgs = 0
            total_chunks = 0

            def _reindex_cb(done: int, total: int, mid: int):
                progress.progress(done / total if total else 1.0)
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else None
                eta_text = f" ETA ~{eta:.1f}s" if eta else ""
                status_box.write(f"Reindexed message {mid} — {done}/{total}{eta_text}")

            total_msgs, total_chunks = reindex_all_messages(progress_callback=_reindex_cb)
            st.cache_data.clear()
            msg = (
                f"Reindexed {total_msgs} messages, {total_chunks} chunks at "
                f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            st.session_state["index_status"] = msg
            st.success(msg)
    with colclear:
        if st.button("Clear Chat History", key="chat_clear_btn"):
            st.session_state.pop("chat_history", None)
            st.session_state.pop("chat_context_log", None)
            st.success("Chat history cleared.")

    with st.expander("Optional filters"):
        sender_suggestions = fetch_sender_suggestions()
        if "chat_filter_from_input" not in st.session_state:
            st.session_state["chat_filter_from_input"] = st.session_state.get("chat_filter_from", "")

        custom_sender = st.text_input(
            "From contains",
            value=st.session_state.get("chat_filter_from_input", ""),
            key="chat_filter_from_input",
            help="Start typing a name or email; click a suggestion to autofill",
        )
        f_from = custom_sender.strip()
        st.session_state["chat_filter_from"] = f_from

        filtered_suggestions: List[str]
        if f_from:
            filtered_suggestions = [s for s in sender_suggestions if f_from.lower() in s.lower()]
            if not filtered_suggestions:
                filtered_suggestions = fetch_sender_matches(f_from, limit=20)
        else:
            filtered_suggestions = sender_suggestions[:10]

        if filtered_suggestions:
            st.caption("Suggestions")
            sugg_cols = st.columns(min(3, len(filtered_suggestions)))
            for idx, suggestion in enumerate(filtered_suggestions[:15]):
                col = sugg_cols[idx % len(sugg_cols)]
                if col.button(suggestion, key=f"chat_sender_suggest_{idx}"):
                    st.session_state["chat_filter_from_input"] = suggestion
                    st.session_state["chat_filter_from"] = suggestion
                    if hasattr(st, "rerun"):
                        st.rerun()
                    elif hasattr(st, "experimental_rerun"):
                        st.experimental_rerun()

        min_date, max_date = fetch_message_date_range()
        if min_date and max_date:
            st.caption(f"Available date range: {min_date} → {max_date}")
        placeholder_after = min_date or "YYYY-MM-DD"
        placeholder_before = max_date or "YYYY-MM-DD"
        f_after = st.text_input(
            "After (YYYY-MM-DD)",
            value=st.session_state.get("chat_filter_after", ""),
            key="chat_filter_after",
            placeholder=placeholder_after,
        ).strip()
        f_before = st.text_input(
            "Before (YYYY-MM-DD)",
            value=st.session_state.get("chat_filter_before", ""),
            key="chat_filter_before",
            placeholder=placeholder_before,
        ).strip()
        topk = st.slider(
            "Top results",
            min_value=5,
            max_value=50,
            value=st.session_state.get("chat_filter_topk", 20),
            step=5,
            key="chat_filter_topk",
        )

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []
    if "chat_context_log" not in st.session_state:
        st.session_state["chat_context_log"] = []

    for msg in st.session_state["chat_history"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    prompt = st.chat_input("Ask about your Gmail data")
    if prompt:
        st.session_state["chat_history"].append({"role": "user", "content": prompt})
        try:
            results = search_emails(
                prompt.strip(),
                from_contains=(f_from or None),
                after=(f_after or None),
                before=(f_before or None),
                k=topk,
            )
        except Exception as e:
            assistant_msg = f"Search failed: {e}"
            results = []
        else:
            if not results:
                assistant_msg = "I could not find any relevant messages for that request."
            else:
                lines = [
                    f"gmail_id: {r['gmail_id']}, date: {r.get('date_utc')}, from: {r.get('from_addr')}, subject: {r.get('subject')}\nExcerpt: {r.get('chunk_text')[:600]}"
                    for r in results
                ]
                context = "\n\n".join(lines)
                system_msg = {
                    "role": "system",
                    "content": (
                        "You are a digital-forensics assistant. Follow the user's question STRICTLY. "
                        "Answer ONLY what was asked, using ONLY the provided email excerpts and metadata. "
                        "Do NOT add extra commentary, background, or speculation. If the question requests a list, return only that list. "
                        "If the context is insufficient, reply: 'Not enough context to answer.' "
                        "Cite gmail_id for each factual claim in square brackets. Keep the response concise and directly relevant."
                    ),
                }
                user_msg = {
                    "role": "user",
                    "content": f"Question: {prompt}\n\nContext:\n{context}",
                }
                try:
                    assistant_msg = ollama_chat([system_msg, user_msg])
                except Exception as e:
                    assistant_msg = f"LLM call failed: {e}"
                else:
                    st.session_state["chat_context_log"].append({"question": prompt, "results": results})
        st.session_state["chat_history"].append({"role": "assistant", "content": assistant_msg})
        if hasattr(st, "rerun"):
            st.rerun()
        elif hasattr(st, "experimental_rerun"):
            st.experimental_rerun()

    if st.session_state.get("chat_context_log"):
        last = st.session_state["chat_context_log"][-1]
        with st.expander("Latest retrieved context", expanded=False):
            ctx_df = pd.DataFrame(
                [
                    {
                        "gmail_id": r["gmail_id"],
                        "date": r.get("date_utc"),
                        "from": r.get("from_addr"),
                        "subject": r.get("subject"),
                        "distance": r.get("distance"),
                    }
                    for r in last.get("results", [])
                ]
            )
            if not ctx_df.empty:
                render_dataframe(ctx_df)
            else:
                st.info("No context available.")

with summary_tab:
    st.subheader("Sender Summary")
    st.caption("Overview of generated sender profiles.")

    if status := st.session_state.get("profile_status"):
        st.caption(f"👤 Profiles: {status}")

    colp1, colp2 = st.columns(2)
    with colp1:
        if st.button("Recompute Profiles", key="summary_profiles_btn"):
            progress = st.progress(0)
            status_box = st.empty()
            start = time.time()

            def _progress_cb(done: int, total: int, email: str):
                progress.progress(done / total if total else 1.0)
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else None
                eta_text = f" ETA ~{eta:.1f}s" if eta else ""
                status_box.write(f"Profiling {email} — {done}/{total}{eta_text}")

            try:
                n = recompute_sender_profiles(limit=200, progress_callback=_progress_cb)
                msg = f"Updated {n} profiles at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                st.session_state["profile_status"] = msg
                st.success(msg)
                st.session_state.pop("summary_profiles_cache", None)
            except Exception as e:
                st.error(f"Profile recompute failed: {e}")
    with colp2:
        if st.button("Refresh Table", key="summary_refresh_btn"):
            st.session_state.pop("summary_profiles_cache", None)

    profiles = st.session_state.get("summary_profiles_cache")
    if profiles is None:
        profiles = list_sender_profiles(limit=500)
        st.session_state["summary_profiles_cache"] = profiles

    if not profiles:
        st.info("No sender profiles yet. Build the index and recompute profiles to populate this table.")
    else:
        table_rows = [
            {
                "Email": p["email"],
                "Messages": p["message_count"],
                "First Seen": p.get("first_seen") or p.get("time_range_first"),
                "Last Seen": p.get("last_seen") or p.get("time_range_last"),
                "Relationship": p.get("relationship"),
                "Risk": p.get("risk_level"),
                "Summary": p.get("summary"),
                "Topics": ", ".join(p.get("profile_json", {}).get("key_topics", []) if isinstance(p.get("profile_json"), dict) else []),
            }
            for p in profiles
        ]
        render_dataframe(pd.DataFrame(table_rows))

        choices = [p["email"] for p in profiles]
        selected_email = st.selectbox("Inspect sender profile", choices)
        selected_profile = next((p for p in profiles if p["email"] == selected_email), None)
        if selected_profile:
            st.markdown(f"**Profile for {selected_email}**")
            st.json(selected_profile.get("profile_json") or {})

st.success("Ready. Use the sidebar filters to refine the catalog and tabs to explore analytics.")
