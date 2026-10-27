from fastapi import HTTPException
from sqlalchemy.orm import Session
from .models import StoredFile, User
from .audit import record_event


def owned_file(db: Session, file_id: str, user: User) -> StoredFile:
    row = db.query(StoredFile).filter(StoredFile.id == file_id, StoredFile.owner_id == user.id).first()
    if row is None:
        # Identical response for absent and another user's file.
        record_event(db, "file_access_denied", user.id)
        raise HTTPException(status_code=404, detail="File not found")
    return row
