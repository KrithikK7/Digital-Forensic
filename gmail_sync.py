import base64
import hashlib
import os
from typing import Dict, List, Optional, Tuple
from email.utils import parsedate_to_datetime

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from sqlalchemy import select
from sqlalchemy.orm import Session

from models import (
    Message, Label, MessageLabel, Header, Address, MessageAddress, Part, Attachment, PartHeader
)

def _b64url_to_bytes(data: str | None) -> Optional[bytes]:
    if not data:
        return None
    return base64.urlsafe_b64decode(data.encode("utf-8"))

def _sha256_hex(data: Optional[bytes]) -> Optional[str]:
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()

def _upsert_label_map(svc, db: Session) -> Dict[str, int]:
    # fetch all labels
    labels = svc.users().labels().list(userId="me").execute().get("labels", [])
    id_map: Dict[str, int] = {}
    for lab in labels:
        glid = lab.get("id")
        name = lab.get("name")
        # upsert
        row = db.execute(select(Label).where(Label.gmail_label_id == glid)).scalar_one_or_none()
        if row is None:
            row = Label(gmail_label_id=glid, name=name)
            db.add(row)
            db.flush()
        else:
            if row.name != name:
                row.name = name
        id_map[glid] = row.id
    db.commit()
    return id_map

def _store_addresses(db: Session, message_id: int, role: str, addr_list: List[str]):
    # very light parser: keep exact string; de-dup by email token if found
    from email.utils import getaddresses
    pairs = getaddresses(addr_list)
    for display, email in pairs:
        email = (email or display or "").strip()
        if not email:
            continue
        addr = db.execute(select(Address).where(Address.email == email)).scalar_one_or_none()
        if addr is None:
            addr = Address(email=email, display_name=display or None)
            db.add(addr)
            db.flush()
        # link
        link = MessageAddress(message_id=message_id, address_id=addr.id, role=role)
        db.add(link)

def _flatten_parts(
    message_id: int,
    part: dict,
    out_parts: List[Tuple[Part, List[dict]]],
    out_attachments: List[Attachment]
):
    headers = part.get("headers", []) or []
    mime = part.get("mimeType")
    filename = part.get("filename") or None
    body = part.get("body", {}) or {}
    size = body.get("size")
    part_id = part.get("partId")

    is_attachment = bool(filename) and not (mime or "").startswith("multipart/")
    data_bytes = _b64url_to_bytes(body.get("data")) if body.get("data") else None
    content_id = (_extract_header(headers, "Content-ID") or [None])[0]
    content_disposition = (_extract_header(headers, "Content-Disposition") or [None])[0]
    content_transfer_encoding = (_extract_header(headers, "Content-Transfer-Encoding") or [None])[0]
    content_language = (_extract_header(headers, "Content-Language") or [None])[0]
    content_location = (_extract_header(headers, "Content-Location") or [None])[0]

    part_record = Part(
        message_id=message_id,
        part_id=part_id,
        mime_type=mime,
        filename=filename,
        size=size,
        is_attachment=is_attachment or bool(body.get("attachmentId")),
        data=data_bytes,
        content_id=content_id,
        content_disposition=content_disposition,
        content_transfer_encoding=content_transfer_encoding,
        content_language=content_language,
        content_location=content_location,
        sha256=_sha256_hex(data_bytes),
    )
    out_parts.append((part_record, headers))

    if body.get("attachmentId"):
        out_attachments.append(
            Attachment(
                message_id=message_id,
                part_id=part_id,
                attachment_id=body["attachmentId"],
                mime_type=mime,
                filename=filename,
                size=size,
                content_id=content_id,
                content_disposition=content_disposition,
                content_transfer_encoding=content_transfer_encoding,
                content_language=content_language,
                content_location=content_location,
            )
        )

    # Recurse if multipart
    for child in part.get("parts", []) or []:
        _flatten_parts(message_id, child, out_parts, out_attachments)

def _extract_header(headers: List[dict], name: str) -> List[str]:
    return [h.get("value", "") for h in headers if h.get("name", "").lower() == name.lower()]

def build_gmail_service(token_or_creds):
    """Create a Gmail API client from either a token dict or Credentials.

    Accepts:
    - A dict containing at least access_token (and optionally refresh_token), as produced by web OAuth flows.
    - A google.oauth2.credentials.Credentials object (e.g., from InstalledAppFlow).
    """
    if isinstance(token_or_creds, Credentials):
        creds = token_or_creds
    else:
        token = token_or_creds or {}
        creds = Credentials(
            token=token.get("access_token"),
            refresh_token=token.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=os.getenv("GOOGLE_CLIENT_ID"),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
    return build("gmail", "v1", credentials=creds, cache_discovery=False)

def sync_all_mail(db: Session, token: dict, page_limit: int = 0) -> Tuple[int, int]:
    """
    Returns: (messages_processed, attachments_downloaded)
    """
    svc = build_gmail_service(token)
    label_id_map = _upsert_label_map(svc, db)

    processed = 0
    att_downloaded = 0

    page_token = None
    pages_seen = 0

    while True:
        try:
            list_req = svc.users().messages().list(
                userId="me",
                includeSpamTrash=True,
                pageToken=page_token,
                maxResults=500,  # tune as needed
            )
            resp = list_req.execute()
        except HttpError as e:
            raise RuntimeError(f"Gmail list error: {e}")

        ids = [m["id"] for m in resp.get("messages", [])]
        if not ids:
            break

        for mid in ids:
            # skip if exists
            existing = db.execute(select(Message).where(Message.gmail_id == mid)).scalar_one_or_none()
            if existing:
                continue

            # get full + raw
            full = svc.users().messages().get(userId="me", id=mid, format="full", metadataHeaders=[]).execute()
            raw = svc.users().messages().get(userId="me", id=mid, format="raw").execute()

            payload = full.get("payload", {}) or {}
            headers = payload.get("headers", []) or []
            labelIds = full.get("labelIds", []) or []

            subject = (_extract_header(headers, "Subject") or [None])[0]
            date_hdr = (_extract_header(headers, "Date") or [None])[0]
            from_hdr = (_extract_header(headers, "From") or [None])[0]

            date_utc = None
            if date_hdr:
                try:
                    date_utc = parsedate_to_datetime(date_hdr)
                except Exception:
                    date_utc = None

            msg = Message(
                gmail_id=mid,
                thread_id=full.get("threadId"),
                history_id=full.get("historyId"),
                internal_date_ms=int(full.get("internalDate")) if full.get("internalDate") else None,
                size_estimate=full.get("sizeEstimate"),
                snippet=full.get("snippet"),
                subject=subject,
                date_utc=date_utc,
                from_addr=from_hdr,
                raw_rfc822=_b64url_to_bytes(raw.get("raw")),
            )
            db.add(msg)
            db.flush()  # to get msg.id

            # headers table
            for h in headers:
                db.add(Header(message_id=msg.id, name=h.get("name", ""), value=h.get("value", "")))

            # addresses by role
            for role, key in [
                ("from", "From"), ("to", "To"), ("cc", "Cc"), ("bcc", "Bcc"), ("reply-to", "Reply-To")
            ]:
                vals = _extract_header(headers, key)
                if vals:
                    _store_addresses(db, msg.id, role, vals)

            # parts & attachments (flatten)
            parts: List[Tuple[Part, List[dict]]] = []
            atts: List[Attachment] = []
            if payload:
                _flatten_parts(msg.id, payload, parts, atts)

            for p, _headers in parts:
                db.add(p)
            db.flush()

            for p, hdrs in parts:
                for h in hdrs:
                    db.add(
                        PartHeader(
                            part_id=p.id,
                            name=h.get("name", ""),
                            value=h.get("value", "")
                        )
                    )

            # fetch actual attachment bytes
            for a in atts:
                try:
                    att = svc.users().messages().attachments().get(
                        userId="me", messageId=mid, id=a.attachment_id
                    ).execute()
                    a.data = _b64url_to_bytes(att.get("data"))
                    a.sha256 = _sha256_hex(a.data)
                    db.add(a)
                    att_downloaded += 1
                except HttpError:
                    # store record without data if retrieval fails
                    db.add(a)

            # labels link
            for glid in labelIds:
                if glid in label_id_map:
                    db.add(MessageLabel(message_id=msg.id, label_id=label_id_map[glid]))

            db.commit()
            processed += 1

        page_token = resp.get("nextPageToken")
        pages_seen += 1
        if not page_token:
            break
        if page_limit and pages_seen >= page_limit:
            break

    return processed, att_downloaded
