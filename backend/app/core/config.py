from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    APP_NAME: str = "QRSafe API"
    APP_ENV: str = "development"
    DATABASE_URL: str = "sqlite:///./qrsafe.db"
    VIRUSTOTAL_API_KEY: str = ""
    CACHE_HASH_SECRET: str = ""
    USE_MOCK_MODEL: bool = True

    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
