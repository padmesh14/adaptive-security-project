import hashlib
import json
import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.database import Base, get_db
from src.api.models import AuditEvent, LoginSession, User
from src.api.main import app
from src.api.main import _requests
from src.api.config import settings


@pytest.fixture
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()
    app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr("src.api.files.upload_encrypted_bytes", lambda payload, key, provider: ("filebase", "bafy-synthetic-cid"))
    monkeypatch.setattr("src.api.files.retrieve_encrypted_bytes", lambda cid, provider, key: client_state["payload"])
    client_state = {"payload": b""}
    with TestClient(app) as test_client:
        test_client.app.state.test_payload = client_state
        test_client.app.state.test_factory = factory
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)


def _csrf(client):
    return {"X-CSRF-Token": client.cookies["adaptive_csrf"]}


def _register(client, email):
    return client.post("/api/auth/register", json={"email": email, "password": "Synthetic-password-42!"})


def _envelope(file_id, tier="Low"):
    header = {"version": 1, "algorithm": "AES-256-GCM", "tier": tier, "fileId": file_id,
              "contentNonce": "AAAAAAAAAAAAAAAA", "wrapSalt": "AAAAAAAAAAAAAAAAAAAAAA",
              "wrapNonce": "AAAAAAAAAAAAAAAA", "wrappedKey": "A" * 64,
              "plaintextSize": 4}
    encoded = json.dumps(header, separators=(",", ":")).encode()
    return b"AMLS" + len(encoded).to_bytes(4, "big") + encoded + b"x" * 20


def test_registration_sessions_upload_ownership_and_integrity(client):
    assert _register(client, "alice@example.com").status_code == 201
    assert client.get("/api/auth/me").status_code == 200
    initiated = client.post("/api/files/initiate", json={"tier": "Low", "format_version": 1}, headers=_csrf(client))
    assert initiated.status_code == 201
    file_id = initiated.json()["file_id"]
    payload = _envelope(file_id)
    client.app.state.test_payload["payload"] = payload
    digest = hashlib.sha256(payload).hexdigest()
    completed = client.post(f"/api/files/{file_id}/complete", content=payload, headers={**_csrf(client), "X-Upload-Token": initiated.json()["upload_token"], "X-Content-SHA256": digest})
    assert completed.status_code == 201
    assert completed.json()["cid"] == "bafy-synthetic-cid"
    assert client.post(f"/api/files/{file_id}/verify").json()["valid"] is True
    assert client.get(f"/api/files/{file_id}/ciphertext").content == payload

    client.cookies.clear()
    assert _register(client, "bob@example.com").status_code == 201
    assert client.get(f"/api/files/{file_id}").status_code == 404
    assert client.get("/api/files").json() == []
    assert client.post(f"/api/files/{file_id}/verify").status_code == 404
    assert client.get(f"/api/files/{file_id}/ciphertext").status_code == 404
    assert client.delete(f"/api/files/{file_id}", headers=_csrf(client)).status_code == 404


def test_rejects_digest_mismatch_and_requires_csrf(client):
    assert _register(client, "charlie@example.com").status_code == 201
    assert client.post("/api/files/initiate", json={"tier": "High", "format_version": 1}).status_code == 403
    initiated = client.post("/api/files/initiate", json={"tier": "High", "format_version": 1}, headers=_csrf(client))
    file_id = initiated.json()["file_id"]
    payload = _envelope(file_id, "High")
    response = client.post(f"/api/files/{file_id}/complete", content=payload, headers={**_csrf(client), "X-Upload-Token": initiated.json()["upload_token"], "X-Content-SHA256": "0" * 64})
    assert response.status_code == 400
    assert client.get("/api/files").json() == []


def test_optional_blockchain_success_repeat_and_failure_preserve_storage(client, monkeypatch):
    assert _register(client, "dana@example.com").status_code == 201
    initiated = client.post("/api/files/initiate", json={"tier": "Low", "format_version": 1,
                            "publish_onchain": True}, headers=_csrf(client))
    first_id = initiated.json()["file_id"]
    payload = _envelope(first_id)
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr("blockchain.integration.sepolia_registry.register_local_or_sepolia_cid",
        lambda file_id, cid: {"status": "registered", "chain_id": 31337, "record_id": "0x" + "12" * 32,
                              "cid": cid, "transaction_hash": "0x" + "34" * 32})
    verify_count = {"value": 0}
    def fake_verify(file_id, cid):
        verify_count["value"] += 1
        valid = verify_count["value"] > 1
        return {"valid": valid, "chain_id": 31337, "record_id": "0x" + "12" * 32,
                "cid": cid if valid else "", "timestamp": 1 if valid else 0,
                "contract_address": "0x" + "56" * 20}
    monkeypatch.setattr("blockchain.integration.sepolia_registry.verify_registered_cid", fake_verify)
    result = client.post(f"/api/files/{first_id}/complete", content=payload,
        headers={**_csrf(client), "X-Upload-Token": initiated.json()["upload_token"], "X-Content-SHA256": digest})
    assert result.status_code == 201
    assert result.json()["blockchain_status"] == "registered"
    repeat = client.post(f"/api/files/{first_id}/register-blockchain", headers=_csrf(client))
    assert repeat.json()["blockchain_status"] == "already_registered"

    second = client.post("/api/files/initiate", json={"tier": "High", "format_version": 1,
                           "publish_onchain": True}, headers=_csrf(client))
    second_id = second.json()["file_id"]
    monkeypatch.setattr("blockchain.integration.sepolia_registry.register_local_or_sepolia_cid",
                        lambda _file_id, _cid: (_ for _ in ()).throw(RuntimeError("simulated chain unavailable")))
    monkeypatch.setattr("blockchain.integration.sepolia_registry.verify_registered_cid",
                        lambda file_id, cid: {"valid": False, "chain_id": 31337,
                                              "record_id": "0x" + "12" * 32, "cid": "", "timestamp": 0,
                                              "contract_address": "0x" + "56" * 20})
    payload2 = _envelope(second_id, "High")
    failed_chain = client.post(f"/api/files/{second_id}/complete", content=payload2,
        headers={**_csrf(client), "X-Upload-Token": second.json()["upload_token"],
                 "X-Content-SHA256": hashlib.sha256(payload2).hexdigest()})
    assert failed_chain.status_code == 201
    assert failed_chain.json()["blockchain_status"] == "failed"
    assert any(row["id"] == second_id for row in client.get("/api/files").json())

    db = client.app.state.test_factory()
    actions = [event.action for event in db.query(AuditEvent).all()]
    assert "cid_registered" in actions and "cid_registration_failed" in actions
    logged = " ".join(str(value) for event in db.query(AuditEvent).all() for value in (event.action, event.actor_user_id, event.target_id))
    assert "Synthetic-password-42!" not in logged and "dana@example.com" not in logged
    db.close()


def test_password_hash_login_expiry_and_logout(client):
    created = _register(client, "erin@example.com")
    assert created.status_code == 201
    assert "password_hash" not in created.json()
    db = client.app.state.test_factory()
    account = db.get(User, created.json()["id"])
    assert account.password_hash.startswith("$argon2id$")
    assert account.password_hash != "Synthetic-password-42!"
    db.close()
    client.cookies.clear()
    assert client.post("/api/auth/login", json={"email": "erin@example.com", "password": "wrong-password-123"}).status_code == 401
    logged_in = client.post("/api/auth/login", json={"email": "erin@example.com", "password": "Synthetic-password-42!"})
    assert logged_in.status_code == 200
    token_hash = hashlib.sha256(client.cookies["adaptive_session"].encode()).hexdigest()
    db = client.app.state.test_factory()
    session = db.get(LoginSession, token_hash)
    session.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    db.commit()
    db.close()
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/logout", headers=_csrf(client)).status_code == 204


def test_cors_is_allowlisted_and_rate_limit_is_enforced(client, monkeypatch):
    allowed = client.options("/health", headers={"Origin": settings.frontend_origin,
        "Access-Control-Request-Method": "GET"})
    assert allowed.headers.get("access-control-allow-origin") == settings.frontend_origin
    denied = client.options("/health", headers={"Origin": "https://untrusted.example",
        "Access-Control-Request-Method": "GET"})
    assert denied.headers.get("access-control-allow-origin") is None
    _requests.clear()
    monkeypatch.setattr(settings, "rate_limit_requests", 1)
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 429
    _requests.clear()


def test_upload_limit_is_enforced_before_storage(client, monkeypatch):
    assert _register(client, "frank@example.com").status_code == 201
    initiated = client.post("/api/files/initiate", json={"tier": "Low", "format_version": 1}, headers=_csrf(client))
    monkeypatch.setattr(settings, "max_upload_bytes", 1)
    response = client.post(f"/api/files/{initiated.json()['file_id']}/complete", content=b"x" * 17000,
        headers={**_csrf(client), "X-Upload-Token": initiated.json()["upload_token"], "X-Content-SHA256": "0" * 64})
    assert response.status_code == 413
    assert client.get("/api/files").json() == []
