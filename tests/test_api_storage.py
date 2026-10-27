import io
import pytest
from src.api import storage


class FakeFilebase:
    def __init__(self, payload):
        self.payload = payload
        self.saved = {}
    def put_object(self, **kwargs):
        self.saved[kwargs["Key"]] = kwargs["Body"].read()
        return {"ResponseMetadata": {"HTTPHeaders": {"x-amz-meta-cid": "bafy-synthetic"}}}
    def get_object(self, **kwargs):
        return {"Body": io.BytesIO(self.saved[kwargs["Key"]])}


def test_filebase_byte_adapter_stores_and_retrieves_exact_ciphertext(monkeypatch):
    body = b"AMLS\x00already-encrypted-synthetic-bytes"
    client = FakeFilebase(body)
    monkeypatch.setattr(storage, "FILEBASE_ACCESS_KEY", "configured")
    monkeypatch.setattr(storage, "FILEBASE_SECRET_KEY", "configured")
    monkeypatch.setattr(storage, "FILEBASE_BUCKET", "synthetic-bucket")
    monkeypatch.setattr(storage, "_get_filebase_client", lambda: client)
    provider, cid = storage.upload_encrypted_bytes(body, "encrypted/unique.amls", "filebase")
    assert (provider, cid) == ("filebase", "bafy-synthetic")
    assert client.saved["encrypted/unique.amls"] == body
    assert storage.retrieve_encrypted_bytes(cid, provider, "encrypted/unique.amls") == body


def test_filebase_selection_fails_closed_when_explicit_but_unconfigured(monkeypatch):
    monkeypatch.setattr(storage, "FILEBASE_ACCESS_KEY", "")
    monkeypatch.setattr(storage, "FILEBASE_SECRET_KEY", "")
    monkeypatch.setattr(storage, "FILEBASE_BUCKET", "")
    with pytest.raises(storage.StorageUnavailable, match="not configured"):
        storage.selected_provider("filebase")
