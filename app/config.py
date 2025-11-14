from pydantic import BaseSettings, AnyHttpUrl
from typing import List


class Settings(BaseSettings):
    OKTA_BASE_URL: AnyHttpUrl  # e.g. https://dev-123456.okta.com
    OKTA_API_TOKEN: str

    # detection config
    BUSINESS_HOURS_START: int = 9   # 09:00
    BUSINESS_HOURS_END: int = 18    # 18:00
    BUSINESS_TZ: str = "Asia/Kolkata"
    ALLOWED_COUNTRIES: List[str] = ["India"]  # customize
    BRUTE_FORCE_FAIL_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_MINUTES: int = 10

    # scheduler
    POLL_INTERVAL_MINUTES: int = 5

    # database
    DATABASE_URL: str = "sqlite:///./oktaguard.db"

    class Config:
        env_file = ".env"


settings = Settings()
