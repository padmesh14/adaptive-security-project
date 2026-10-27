"""Initial user, session, upload intent and encrypted file metadata tables."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("users", sa.Column("id", sa.String(36), primary_key=True), sa.Column("email", sa.String(320), nullable=False), sa.Column("password_hash", sa.String(512), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table("login_sessions", sa.Column("token_hash", sa.String(64), primary_key=True), sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_login_sessions_user_id", "login_sessions", ["user_id"])
    op.create_index("ix_login_sessions_expires_at", "login_sessions", ["expires_at"])
    op.create_table("stored_files", sa.Column("id", sa.String(36), primary_key=True), sa.Column("owner_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("tier", sa.String(8), nullable=False), sa.Column("format_version", sa.Integer(), nullable=False), sa.Column("cid", sa.Text(), nullable=False), sa.Column("storage_provider", sa.String(16), nullable=False), sa.Column("object_key", sa.Text(), nullable=False), sa.Column("integrity_sha256", sa.String(64), nullable=False), sa.Column("ciphertext_size", sa.Integer(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("blockchain_chain_id", sa.Integer(), nullable=True), sa.Column("blockchain_tx_hash", sa.String(66), nullable=True), sa.Column("blockchain_record_id", sa.String(66), nullable=True), sa.Column("blockchain_contract_address", sa.String(42), nullable=True), sa.Column("blockchain_status", sa.String(24), nullable=False, server_default="not_requested"), sa.Column("blockchain_registered_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_stored_files_owner_id", "stored_files", ["owner_id"])
    op.create_index("ix_stored_files_blockchain_registered_at", "stored_files", ["blockchain_registered_at"])
    op.create_table("upload_intents", sa.Column("token_hash", sa.String(64), primary_key=True), sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False), sa.Column("file_id", sa.String(36), nullable=False), sa.Column("tier", sa.String(8), nullable=False), sa.Column("format_version", sa.Integer(), nullable=False), sa.Column("publish_onchain", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False))
    for column in ("user_id", "file_id", "expires_at"):
        op.create_index(f"ix_upload_intents_{column}", "upload_intents", [column])
    op.create_table("audit_events", sa.Column("id", sa.String(36), primary_key=True), sa.Column("actor_user_id", sa.String(36), nullable=True), sa.Column("action", sa.String(48), nullable=False), sa.Column("target_id", sa.String(36), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    for column in ("actor_user_id", "action", "created_at"):
        op.create_index(f"ix_audit_events_{column}", "audit_events", [column])

def downgrade():
    op.drop_table("audit_events")
    op.drop_table("upload_intents")
    op.drop_table("stored_files")
    op.drop_table("login_sessions")
    op.drop_table("users")
