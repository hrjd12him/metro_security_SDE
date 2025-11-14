import os
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from zoneinfo import ZoneInfo

load_dotenv()

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "").strip()
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN", "").strip()

ORG_TZ = os.getenv("ORG_TZ", "UTC")
TZINFO = ZoneInfo(ORG_TZ)

BUSINESS_HOURS_START = int(os.getenv("BUSINESS_HOURS_START", "9"))
BUSINESS_HOURS_END   = int(os.getenv("BUSINESS_HOURS_END", "18"))

BRUTE_FAIL_THRESHOLD = int(os.getenv("BRUTE_FAIL_THRESHOLD", "5"))
BRUTE_WINDOW_MIN     = int(os.getenv("BRUTE_WINDOW_MIN", "15"))

AUTO_SUSPEND_KINDS = {k.strip() for k in os.getenv(
    "AUTO_SUSPEND_KINDS", "bruteforce_success,impossible_travel"
).split(",") if k.strip()}

SCAN_SCHEDULE_SECS  = int(os.getenv("SCAN_SCHEDULE_SECS", "60"))
INITIAL_SCAN_MINUTES = int(os.getenv("INITIAL_SCAN_MINUTES", "60"))

ALERTS_JSONL_PATH = os.getenv("ALERTS_JSONL_PATH", "data/alerts.jsonl")
STATE_PATH        = os.getenv("STATE_PATH", "data/state.json")

LOG_FILE  = os.getenv("LOG_FILE", "logs/okta_guard.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

def setup_logging():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logger = logging.getLogger()
    logger.setLevel(LOG_LEVEL)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(sh)