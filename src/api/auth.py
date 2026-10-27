from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from .config import settings
from .database import get_db
from .models import LoginSession, User
from .schemas import Credentials, UserOut
from .audit import record_event

router = APIRouter(prefix="/api/auth", tags=["authentication"])
password_hasher = PasswordHasher()
# Equalize unknown-account login work without retaining or printing a password.
DUMMY_PASSWORD_HASH = password_hasher.hash(secrets.token_urlsafe(32))
SESSION_COOKIE = "adaptive_session"
CSRF_COOKIE = "adaptive_csrf"


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _set_session(response: Response, db: Session, user: User):
    session_token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=settings.session_ttl_hours)
    db.add(LoginSession(token_hash=_token_hash(session_token), user_id=user.id, expires_at=expires))
    db.commit()
    response.set_cookie(SESSION_COOKIE, session_token, httponly=True, secure=settings.cookie_secure, samesite="strict", max_age=settings.session_ttl_hours * 3600, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=settings.cookie_secure, samesite="strict", max_age=settings.session_ttl_hours * 3600, path="/")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    session = db.get(LoginSession, _token_hash(token))
    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")
    expires = session.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_csrf(request: Request):
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get("x-csrf-token")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: Credentials, response: Response, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="Account cannot be created with these details")
    user = User(id=str(uuid.uuid4()), email=email, password_hash=password_hasher.hash(payload.password))
    db.add(user)
    db.flush()
    _set_session(response, db, user)
    record_event(db, "account_created", user.id)
    return user


@router.post("/login", response_model=UserOut)
def login(payload: Credentials, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.strip().lower()).first()
    try:
        valid = password_hasher.verify(user.password_hash if user else DUMMY_PASSWORD_HASH, payload.password)
        valid = valid and user is not None
    except (VerifyMismatchError, VerificationError):
        valid = False
    if not valid:
        record_event(db, "login_failed", user.id if user else None)
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    _set_session(response, db, user)
    record_event(db, "login_succeeded", user.id)
    return user


@router.post("/logout", status_code=204)
def logout(response: Response, request: Request, db: Session = Depends(get_db), _csrf=Depends(require_csrf)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        session = db.get(LoginSession, _token_hash(token))
        if session:
            actor = session.user_id
            db.delete(session)
            db.commit()
            record_event(db, "session_revoked", actor)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
