from uuid import uuid4
from sqlalchemy.orm import Session
from .models import AuditEvent


def record_event(db: Session, action: str, actor_user_id: str | None = None, target_id: str | None = None) -> None:
    """Persist fixed security events without credentials, content, or network data."""
    db.add(AuditEvent(id=str(uuid4()), actor_user_id=actor_user_id, action=action, target_id=target_id))
    db.commit()
