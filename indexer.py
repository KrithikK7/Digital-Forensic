from __future__ import annotations

import re
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from db import SessionLocal
from models import (
    Message,
    Part,
    MessageAddress,
    Address,
    MessageLabel,
    Label,
    Attachment,
    MessageIndex,
)
from ollama_client import embed_one


def _extract_text_for_message(db: Session, message_id: int) -> tuple[Message | None, str]:
    msg = db.get(Message, message_id)
    if msg is None:
        return None, ""
    texts: list[str] = []
    if msg.subject:
        texts.append(f"Subject: {msg.subject}\n")

    parts = db.execute(
        select(Part).where(Part.message_id == message_id).order_by(Part.part_id.nullsfirst())
    ).scalars().all()
    for p in parts:
        if p.data and p.mime_type and p.mime_type.startswith("text/"):
            try:
                texts.append(p.data.decode("utf-8", errors="replace"))
            except Exception:
                continue
    if not texts and msg.snippet:
        texts.append(msg.snippet)
    raw = "\n\n".join(t.strip() for t in texts if t)
    return msg, re.sub(r"\s+", " ", raw).strip()


def _chunk_text(s: str, max_chars: int = 3000, overlap: int = 300) -> list[str]:
    if not s:
        return []
    chunks: list[str] = []
    start = 0
    n = len(s)
    while start < n:
        end = min(start + max_chars, n)
        chunk = s[start:end]
        chunks.append(chunk)
        if end >= n:
            break
        start = end - overlap
        if start < 0:
            start = 0
    return chunks


def _format_address(display: str | None, email: str | None) -> str:
    if display and email:
        return f"{display} <{email}>"
    return display or email or ""


def _metadata_header(db: Session, msg: Message) -> str:
    lines: list[str] = []
    if msg.from_addr:
        lines.append(f"From: {msg.from_addr}")

    addr_rows = db.execute(
        select(MessageAddress.role, Address.display_name, Address.email)
        .join(Address, Address.id == MessageAddress.address_id)
        .where(MessageAddress.message_id == msg.id)
    ).all()
    role_map: dict[str, list[str]] = {"to": [], "cc": [], "bcc": [], "reply-to": []}
    for role, display, email in addr_rows:
        formatted = _format_address(display, email)
        if not formatted:
            continue
        key = (role or "").lower()
        if key in role_map:
            role_map[key].append(formatted)
        else:
            role_map.setdefault(key, []).append(formatted)

    for role, values in role_map.items():
        if values:
            role_label = role.replace("reply-to", "Reply-To").title()
            lines.append(f"{role_label}: {', '.join(values)}")

    label_rows = db.execute(
        select(Label.name)
        .join(MessageLabel, MessageLabel.label_id == Label.id)
        .where(MessageLabel.message_id == msg.id)
    ).scalars().all()
    if label_rows:
        lines.append(f"Labels: {', '.join(sorted(label_rows))}")

    attachment_rows = db.execute(
        select(Attachment.filename, Attachment.mime_type)
        .where(Attachment.message_id == msg.id)
    ).all()
    if attachment_rows:
        names = []
        for filename, mime in attachment_rows:
            if filename:
                names.append(filename)
            elif mime:
                names.append(f"({mime})")
        if names:
            lines.append(f"Attachments: {', '.join(names)}")

    metadata = "\n".join(lines).strip()
    return metadata


def index_message(db: Session, message_id: int) -> int:
    msg, text_blob = _extract_text_for_message(db, message_id)
    if msg is None and not text_blob:
        return 0
    metadata = _metadata_header(db, msg) if msg else ""
    combined = metadata
    if text_blob:
        combined = f"{metadata}\n\n{text_blob}" if metadata else text_blob
    combined = combined.strip()
    if not combined:
        return 0
    chunks = _chunk_text(combined)
    # Remove existing chunks
    db.execute(delete(MessageIndex).where(MessageIndex.message_id == message_id))
    count = 0
    for idx, chunk in enumerate(chunks):
        vec = embed_one(chunk)
        rec = MessageIndex(message_id=message_id, chunk_id=idx, chunk_text=chunk, chunk_vector=vec)
        db.add(rec)
        count += 1
    db.commit()
    return count


def _missing_message_ids(db: Session, limit: int = 500) -> list[int]:
    return (
        db.execute(
            text(
                """
                SELECT m.id
                FROM messages m
                LEFT JOIN message_index mi ON mi.message_id = m.id
                WHERE mi.id IS NULL
                ORDER BY m.id DESC
                LIMIT :lim
                """
            ),
            {"lim": limit},
        )
        .scalars()
        .all()
    )


def get_missing_message_ids(limit: int = 500) -> list[int]:
    with SessionLocal() as db:
        return _missing_message_ids(db, limit)


def index_missing_messages(limit: int = 500) -> tuple[int, int]:
    """Return (messages_processed, chunks_created)."""
    with SessionLocal() as db:
        ids = _missing_message_ids(db, limit)
        msgs = 0
        chunks = 0
        for mid in ids:
            msgs += 1
            chunks += index_message(db, mid)
        return msgs, chunks


def reindex_all_messages(batch_size: int = 200, progress_callback=None) -> tuple[int, int]:
    """Re-embed every message regardless of existing chunks."""
    total_msgs = 0
    total_chunks = 0
    with SessionLocal() as db:
        total_count = db.scalar(text("SELECT COUNT(*) FROM messages")) or 0
        offset = 0
        while True:
            ids = (
                db.execute(
                    text(
                        """
                        SELECT id
                        FROM messages
                        ORDER BY id
                        OFFSET :off
                        LIMIT :lim
                        """
                    ),
                    {"off": offset, "lim": batch_size},
                )
                .scalars()
                .all()
            )
            if not ids:
                break
            for mid in ids:
                total_msgs += 1
                total_chunks += index_message(db, mid)
                if progress_callback:
                    try:
                        progress_callback(total_msgs, total_count, mid)
                    except Exception:
                        pass
            offset += batch_size
    return total_msgs, total_chunks
