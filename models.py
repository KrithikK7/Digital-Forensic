from sqlalchemy import (
    Column, Integer, String, BigInteger, LargeBinary, ForeignKey, Boolean, DateTime, Text, UniqueConstraint, func
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from pgvector.sqlalchemy import Vector
from db import Base

class Label(Base):
    __tablename__ = "labels"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    gmail_label_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)

class Message(Base):
    __tablename__ = "messages"
    # Gmail message id is globally unique; store it and enforce uniqueness
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    gmail_id: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    thread_id: Mapped[str | None] = mapped_column(String(256), index=True, default=None)
    history_id: Mapped[str | None] = mapped_column(String(256), default=None)
    internal_date_ms: Mapped[int | None] = mapped_column(BigInteger, index=True, default=None)
    size_estimate: Mapped[int | None] = mapped_column(Integer, default=None)
    snippet: Mapped[str | None] = mapped_column(Text, default=None)
    raw_rfc822: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)  # full raw mail for forensics

    # quick decoded top-level metadata (also available from headers)
    subject: Mapped[str | None] = mapped_column(Text, default=None)
    date_utc: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), index=True, default=None)
    from_addr: Mapped[str | None] = mapped_column(Text, default=None)

    labels = relationship("MessageLabel", back_populates="message", cascade="all, delete-orphan")
    headers = relationship("Header", back_populates="message", cascade="all, delete-orphan")
    addresses = relationship("MessageAddress", back_populates="message", cascade="all, delete-orphan")
    parts = relationship("Part", back_populates="message", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="message", cascade="all, delete-orphan")

class MessageLabel(Base):
    __tablename__ = "message_labels"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    label_id: Mapped[int] = mapped_column(ForeignKey("labels.id", ondelete="CASCADE"), index=True)
    message = relationship("Message", back_populates="labels")
    label = relationship("Label")

    __table_args__ = (UniqueConstraint("message_id", "label_id", name="uq_message_label"),)

class Header(Base):
    __tablename__ = "headers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[str | None] = mapped_column(Text, default=None)
    message = relationship("Message", back_populates="headers")

class Address(Base):
    __tablename__ = "addresses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(512), default=None)

class MessageAddress(Base):
    __tablename__ = "message_addresses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    address_id: Mapped[int] = mapped_column(ForeignKey("addresses.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))  # 'from', 'to', 'cc', 'bcc', 'reply-to'
    message = relationship("Message", back_populates="addresses")
    address = relationship("Address")

    __table_args__ = (UniqueConstraint("message_id", "address_id", "role", name="uq_msg_addr_role"),)

class Part(Base):
    __tablename__ = "parts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    part_id: Mapped[str | None] = mapped_column(String(256), default=None)  # Gmail payload partId
    mime_type: Mapped[str | None] = mapped_column(String(255), default=None)
    filename: Mapped[str | None] = mapped_column(Text, default=None)
    size: Mapped[int | None] = mapped_column(Integer, default=None)
    is_attachment: Mapped[bool] = mapped_column(Boolean, default=False)
    data: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)  # inline content when present (e.g., text/plain)
    content_id: Mapped[str | None] = mapped_column(String(512), default=None)
    content_disposition: Mapped[str | None] = mapped_column(Text, default=None)
    content_transfer_encoding: Mapped[str | None] = mapped_column(String(128), default=None)
    content_language: Mapped[str | None] = mapped_column(String(128), default=None)
    content_location: Mapped[str | None] = mapped_column(Text, default=None)
    sha256: Mapped[str | None] = mapped_column(String(128), index=True, default=None)
    message = relationship("Message", back_populates="parts")
    headers = relationship("PartHeader", back_populates="part", cascade="all, delete-orphan")

class Attachment(Base):
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    part_id: Mapped[str | None] = mapped_column(String(256), default=None)
    attachment_id: Mapped[str] = mapped_column(String(1024), index=True)
    mime_type: Mapped[str | None] = mapped_column(String(255), default=None)
    filename: Mapped[str | None] = mapped_column(Text, default=None)
    size: Mapped[int | None] = mapped_column(Integer, default=None)
    data: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)  # full bytes for forensics
    content_id: Mapped[str | None] = mapped_column(String(512), default=None)
    content_disposition: Mapped[str | None] = mapped_column(Text, default=None)
    content_transfer_encoding: Mapped[str | None] = mapped_column(String(128), default=None)
    content_language: Mapped[str | None] = mapped_column(String(128), default=None)
    content_location: Mapped[str | None] = mapped_column(Text, default=None)
    sha256: Mapped[str | None] = mapped_column(String(128), index=True, default=None)
    message = relationship("Message", back_populates="attachments")


class PartHeader(Base):
    __tablename__ = "part_headers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    part_id: Mapped[int] = mapped_column(ForeignKey("parts.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[str | None] = mapped_column(Text, default=None)
    part = relationship("Part", back_populates="headers")


class UserToken(Base):
    __tablename__ = "user_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    token_json: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ---------- RAG / AI Tables ----------

class MessageIndex(Base):
    __tablename__ = "message_index"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    chunk_id: Mapped[int] = mapped_column(Integer)
    chunk_text: Mapped[str] = mapped_column(Text)
    chunk_vector = mapped_column(Vector(1024), nullable=False)
    start_offset: Mapped[int | None] = mapped_column(Integer, default=None)
    end_offset: Mapped[int | None] = mapped_column(Integer, default=None)


class MessageNLP(Base):
    __tablename__ = "message_nlp"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    language: Mapped[str | None] = mapped_column(String(16), default=None)
    sentiment: Mapped[float | None] = mapped_column(Integer, default=None)
    toxicity: Mapped[float | None] = mapped_column(Integer, default=None)
    tone: Mapped[dict | None] = mapped_column(JSONB, default=None)
    entities: Mapped[dict | None] = mapped_column(JSONB, default=None)
    topics: Mapped[dict | None] = mapped_column(JSONB, default=None)


class SenderProfile(Base):
    __tablename__ = "sender_profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    address_id: Mapped[int | None] = mapped_column(ForeignKey("addresses.id", ondelete="SET NULL"), index=True)
    email: Mapped[str] = mapped_column(String(512), index=True)
    profile_json: Mapped[dict | None] = mapped_column(JSONB, default=None)
    msg_count: Mapped[int | None] = mapped_column(Integer, default=None)
    first_seen: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_seen: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), default=None)
    avg_sentiment: Mapped[float | None] = mapped_column(Integer, default=None)
    toxicity_max: Mapped[float | None] = mapped_column(Integer, default=None)
    relationship_label: Mapped[str | None] = mapped_column(String(64), default=None)
    risk_level: Mapped[str | None] = mapped_column(String(32), default=None)
    last_updated: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), server_default=func.now())
    user_id: Mapped[str | None] = mapped_column(String(256), default=None)
    query: Mapped[str | None] = mapped_column(Text, default=None)
    filters: Mapped[dict | None] = mapped_column(JSONB, default=None)
    retrieved_ids: Mapped[dict | None] = mapped_column(JSONB, default=None)
    model: Mapped[str | None] = mapped_column(String(128), default=None)
    embedding_model: Mapped[str | None] = mapped_column(String(128), default=None)
    prompt_hash: Mapped[str | None] = mapped_column(String(128), default=None)
    response_hash: Mapped[str | None] = mapped_column(String(128), default=None)

