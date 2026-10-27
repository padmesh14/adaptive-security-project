from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import base64
import re
import secrets
import uuid
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from .auth import current_user, require_csrf
from .authorization import owned_file
from .config import settings
from .database import get_db
from .models import StoredFile, UploadIntent, User
from .schemas import FileOut, InitiateFile, VerifyOut
from .storage import StorageUnavailable, retrieve_encrypted_bytes, upload_encrypted_bytes
from .audit import record_event

router = APIRouter(prefix="/api/files", tags=["files"])
def _out(row: StoredFile) -> dict:
    created = row.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return {"id": row.id, "tier": row.tier, "format_version": row.format_version,
            "cid": row.cid, "integrity_sha256": row.integrity_sha256,
            "storage_provider": row.storage_provider,
            "ciphertext_size": row.ciphertext_size, "created_at": created.isoformat(),
            "blockchain_chain_id": row.blockchain_chain_id, "blockchain_tx_hash": row.blockchain_tx_hash,
            "blockchain_record_id": row.blockchain_record_id,
            "blockchain_contract_address": row.blockchain_contract_address,
            "blockchain_status": row.blockchain_status,
            "blockchain_registered_at": row.blockchain_registered_at.isoformat() if row.blockchain_registered_at else None}


@router.post("/initiate", status_code=201)
def initiate(payload: InitiateFile, user: User = Depends(current_user), db: Session = Depends(get_db), _csrf=Depends(require_csrf)):
    now = datetime.now(timezone.utc)
    expired = db.query(UploadIntent).filter(UploadIntent.expires_at < now).all()
    for intent in expired:
        db.delete(intent)
    file_id = str(uuid.uuid4())
    while db.query(StoredFile).filter(StoredFile.id == file_id).first() or db.query(UploadIntent).filter(UploadIntent.file_id == file_id).first():
        file_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db.add(UploadIntent(token_hash=token_hash, user_id=user.id, file_id=file_id,
                        tier=payload.tier, format_version=payload.format_version,
                        publish_onchain=payload.publish_onchain,
                        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)))
    db.commit()
    return {"file_id": file_id, "upload_token": token, "max_ciphertext_bytes": settings.max_upload_bytes + 16 * 1024 + 24}


@router.post("/{file_id}/complete", response_model=FileOut, status_code=201)
async def complete(file_id: str, request: Request, request_digest: str = Header(alias="X-Content-SHA256"),
                   user: User = Depends(current_user), db: Session = Depends(get_db), _csrf=Depends(require_csrf)):
    token = request.headers.get("x-upload-token", "")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    pending = db.get(UploadIntent, token_hash) if token else None
    if not pending or pending.user_id != user.id or pending.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=404, detail="Upload not found")
    if pending.file_id != file_id:
        raise HTTPException(status_code=404, detail="Upload not found")
    limit = settings.max_upload_bytes + 16 * 1024 + 24
    try:
        if request.headers.get("content-length") and int(request.headers["content-length"]) > limit:
            raise HTTPException(status_code=413, detail="Encrypted upload exceeds the size limit")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid content length") from exc
    buffer = bytearray()
    async for chunk in request.stream():
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise HTTPException(status_code=413, detail="Encrypted upload exceeds the size limit")
    payload = bytes(buffer)
    if not payload:
        raise HTTPException(status_code=413, detail="Encrypted upload is empty or exceeds the size limit")
    actual_hash = hashlib.sha256(payload).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", request_digest) or actual_hash != request_digest:
        raise HTTPException(status_code=400, detail="Ciphertext integrity digest mismatch")
    try:
        header = _inspect_encrypted_file(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Encrypted file format is invalid") from exc
    if header.get("fileId") != file_id or header.get("tier") != pending.tier or header.get("version") != pending.format_version:
        raise HTTPException(status_code=400, detail="Encrypted envelope does not match initiated metadata")
    object_key = f"encrypted/{uuid.uuid4().hex}.amls"
    try:
        provider, cid = await run_in_threadpool(upload_encrypted_bytes, payload, object_key, settings.storage_provider)
    except (StorageUnavailable, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    row = StoredFile(id=file_id, owner_id=user.id, tier=header["tier"], format_version=header["version"], cid=cid,
                     storage_provider=provider, object_key=object_key,
                     integrity_sha256=actual_hash, ciphertext_size=len(payload),
                     blockchain_status="pending" if pending.publish_onchain else "not_requested")
    db.delete(pending)
    db.add(row)
    db.commit()
    db.refresh(row)
    record_event(db, "encrypted_file_uploaded", user.id, file_id)
    if pending.publish_onchain:
        await _try_register_onchain(row, db)
        db.refresh(row)
    return _out(row)


async def _try_register_onchain(row: StoredFile, db: Session) -> None:
    try:
        from blockchain.integration.sepolia_registry import register_local_or_sepolia_cid, verify_registered_cid
        preexisting = await run_in_threadpool(verify_registered_cid, row.id, row.cid)
        if preexisting["cid"]:
            if not preexisting["valid"]:
                raise RuntimeError("The record ID is already associated with another CID")
            row.blockchain_status = "already_registered"
            row.blockchain_chain_id = preexisting["chain_id"]
            row.blockchain_record_id = preexisting["record_id"]
            row.blockchain_contract_address = preexisting["contract_address"]
            row.blockchain_registered_at = datetime.now(timezone.utc)
            record_event(db, "cid_registration_skipped", row.owner_id, row.id)
            return
        cutoff = datetime.now(timezone.utc) - timedelta(days=1)
        global_count = db.query(StoredFile).filter(StoredFile.blockchain_registered_at >= cutoff).count()
        user_count = db.query(StoredFile).filter(StoredFile.owner_id == row.owner_id,
                                                 StoredFile.blockchain_registered_at >= cutoff).count()
        if global_count >= settings.blockchain_daily_limit or user_count >= settings.blockchain_per_user_daily_limit:
            row.blockchain_status = "failed"
            record_event(db, "cid_registration_rate_limited", row.owner_id, row.id)
            return
        outcome = await run_in_threadpool(register_local_or_sepolia_cid, row.id, row.cid)
        verified = await run_in_threadpool(verify_registered_cid, row.id, row.cid)
        if not verified["valid"]:
            raise RuntimeError("Registry read-back verification failed")
        row.blockchain_status = outcome["status"]
        row.blockchain_chain_id = outcome["chain_id"]
        row.blockchain_record_id = outcome["record_id"]
        row.blockchain_tx_hash = outcome["transaction_hash"]
        row.blockchain_contract_address = verified["contract_address"]
        row.blockchain_registered_at = datetime.now(timezone.utc)
        record_event(db, "cid_registered", row.owner_id, row.id)
    except Exception:
        # Storage remains committed. Do not persist provider or credential errors.
        row.blockchain_status = "failed"
        record_event(db, "cid_registration_failed", row.owner_id, row.id)
    db.commit()


def _inspect_encrypted_file(payload: bytes) -> dict:
    if len(payload) < 24 or payload[:4] != b"AMLS":
        raise ValueError("Invalid encrypted file format")
    header_size = int.from_bytes(payload[4:8], "big")
    if header_size < 2 or header_size > 16384 or 8 + header_size + 16 > len(payload):
        raise ValueError("Invalid encrypted file header size")
    try:
        value = json.loads(payload[8:8 + header_size])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid encrypted file header") from exc
    if (not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1 or value.get("algorithm") != "AES-256-GCM"
            or value.get("tier") not in {"Low", "Medium", "High"}
            or not isinstance(value.get("fileId"), str) or len(value["fileId"]) != 36):
        raise ValueError("Unsupported encrypted file metadata")
    try:
        uuid.UUID(value["fileId"])
    except ValueError as exc:
        raise ValueError("Invalid encrypted file ID") from exc
    for key in ("contentNonce", "wrapSalt", "wrapNonce", "wrappedKey"):
        if not isinstance(value.get(key), str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value[key]):
            raise ValueError("Invalid encrypted key envelope")
    lengths = {"contentNonce": 12, "wrapSalt": 16, "wrapNonce": 12, "wrappedKey": 48}
    for key, expected_length in lengths.items():
        encoded = value[key].replace("-", "+").replace("_", "/")
        try:
            decoded = base64.b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4), validate=True)
        except ValueError as exc:
            raise ValueError("Invalid encrypted key envelope encoding") from exc
        if len(decoded) != expected_length:
            raise ValueError("Invalid encrypted key envelope length")
    if type(value.get("plaintextSize")) is not int or not 0 <= value["plaintextSize"] <= settings.max_upload_bytes:
        raise ValueError("Invalid encrypted plaintext size")
    if len(payload) - 8 - header_size != value["plaintextSize"] + 16:
        raise ValueError("Ciphertext length does not match file metadata")
    return value


@router.get("")
def list_files(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(StoredFile).filter(StoredFile.owner_id == user.id).order_by(StoredFile.created_at.desc()).all()
    return [_out(row) for row in rows]


def _payload(row: StoredFile) -> bytes:
    try:
        return retrieve_encrypted_bytes(row.cid, row.storage_provider, row.object_key)
    except StorageUnavailable as exc:
        raise HTTPException(status_code=503, detail="Encrypted file storage is unavailable") from exc


@router.get("/{file_id}", response_model=FileOut)
def get_file(file_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _out(owned_file(db, file_id, user))


@router.get("/{file_id}/ciphertext")
def download_ciphertext(file_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    row = owned_file(db, file_id, user)
    payload = _payload(row)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != row.integrity_sha256:
        raise HTTPException(status_code=502, detail="Stored ciphertext integrity check failed")
    return Response(payload, media_type="application/octet-stream", headers={"X-Content-SHA256": digest, "Cache-Control": "no-store"})


@router.post("/{file_id}/verify", response_model=VerifyOut)
def verify_file(file_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    row = owned_file(db, file_id, user)
    payload = _payload(row)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != row.integrity_sha256:
        raise HTTPException(status_code=409, detail="Stored ciphertext integrity check failed")
    return {"valid": True, "computed_sha256": digest}


@router.delete("/{file_id}", status_code=204)
def delete_file(file_id: str, user: User = Depends(current_user), db: Session = Depends(get_db), _csrf=Depends(require_csrf)):
    row = owned_file(db, file_id, user)
    record_event(db, "encrypted_file_removed", user.id, row.id)
    db.delete(row)
    db.commit()


@router.post("/{file_id}/register-blockchain", response_model=FileOut)
async def register_blockchain(file_id: str, user: User = Depends(current_user), db: Session = Depends(get_db), _csrf=Depends(require_csrf)):
    row = owned_file(db, file_id, user)
    if row.blockchain_status not in {"registered", "already_registered", "verified"}:
        row.blockchain_status = "pending"
        db.commit()
    await _try_register_onchain(row, db)
    db.refresh(row)
    return _out(row)


@router.post("/{file_id}/verify-blockchain")
async def verify_blockchain(file_id: str, user: User = Depends(current_user), db: Session = Depends(get_db), _csrf=Depends(require_csrf)):
    row = owned_file(db, file_id, user)
    try:
        from blockchain.integration.sepolia_registry import verify_registered_cid
        result = await run_in_threadpool(verify_registered_cid, row.id, row.cid)
        row.blockchain_chain_id = result["chain_id"]
        row.blockchain_record_id = result["record_id"]
        row.blockchain_contract_address = result["contract_address"]
        row.blockchain_status = "verified" if result["valid"] else "failed"
        row.blockchain_registered_at = datetime.now(timezone.utc) if result["valid"] else row.blockchain_registered_at
        record_event(db, "cid_verification_succeeded" if result["valid"] else "cid_verification_failed", user.id, row.id)
        db.commit()
        return {"valid": result["valid"], "chain_id": result["chain_id"], "contract_address": result["contract_address"]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Blockchain verification is unavailable") from exc
