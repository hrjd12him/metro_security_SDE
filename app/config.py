from typing import List
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    OKTA_BASE_URL: AnyHttpUrl  
    OKTA_API_TOKEN: str

    # detection config
    BUSINESS_HOURS_START: int = 9   # 09:00
    BUSINESS_HOURS_END: int = 18    # 18:00
    BUSINESS_TZ: str = "Asia/Kolkata"
    ALLOWED_COUNTRIES: List[str] = ["India"]
    BRUTE_FORCE_FAIL_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_MINUTES: int = 10

    # scheduler
    POLL_INTERVAL_MINUTES: int = 5

    # database
    DATABASE_URL: str = "sqlite:///./oktaguard.db"

    # Pydantic v2 way to configure .env
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",   # ignore unknown env vars
    )


settings = Settings()
