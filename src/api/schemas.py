from pydantic import BaseModel, ConfigDict, EmailStr, Field


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)


class UserOut(BaseModel):
    id: str
    email: EmailStr
    model_config = ConfigDict(from_attributes=True)


class InitiateFile(BaseModel):
    tier: str = Field(pattern=r"^(Low|Medium|High)$")
    format_version: int = Field(ge=1, le=1)
    publish_onchain: bool = False


class FileOut(BaseModel):
    id: str
    tier: str
    format_version: int
    cid: str
    storage_provider: str
    integrity_sha256: str
    ciphertext_size: int
    created_at: str
    blockchain_chain_id: int | None = None
    blockchain_tx_hash: str | None = None
    blockchain_record_id: str | None = None
    blockchain_contract_address: str | None = None
    blockchain_status: str
    blockchain_registered_at: str | None = None


class VerifyOut(BaseModel):
    valid: bool
    computed_sha256: str
