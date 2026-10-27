from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    files = relationship("StoredFile", back_populates="owner", cascade="all, delete-orphan")


class LoginSession(Base):
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class StoredFile(Base):
    __tablename__ = "stored_files"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    tier: Mapped[str] = mapped_column(String(8))
    format_version: Mapped[int] = mapped_column(Integer, default=1)
    cid: Mapped[str] = mapped_column(Text)
    storage_provider: Mapped[str] = mapped_column(String(16), default="ipfs")
    object_key: Mapped[str] = mapped_column(Text)
    integrity_sha256: Mapped[str] = mapped_column(String(64))
    ciphertext_size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    blockchain_chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    blockchain_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    blockchain_record_id: Mapped[str | None] = mapped_column(String(66), nullable=True)
    blockchain_contract_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    blockchain_status: Mapped[str] = mapped_column(String(24), default="not_requested")
    blockchain_registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    owner = relationship("User", back_populates="files")


class UploadIntent(Base):
    __tablename__ = "upload_intents"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    file_id: Mapped[str] = mapped_column(String(36), index=True)
    tier: Mapped[str] = mapped_column(String(8))
    format_version: Mapped[int] = mapped_column(Integer)
    publish_onchain: Mapped[bool] = mapped_column(default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
