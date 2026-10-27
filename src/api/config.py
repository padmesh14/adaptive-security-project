from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ADAPTIVE_", env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./adaptive_api_dev.db"
    frontend_origin: str = "http://localhost:5173"
    cookie_secure: bool = False  # Set true behind HTTPS in deployment.
    session_ttl_hours: int = 12
    max_upload_bytes: int = 50 * 1024 * 1024
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    storage_provider: str = "auto"
    blockchain_daily_limit: int = 10
    blockchain_per_user_daily_limit: int = 2


settings = Settings()
