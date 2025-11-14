# ─────────────────────────────────────────────────────────────────────────────
# file: README.md
# ─────────────────────────────────────────────────────────────────────────────
# OktaGuard — Detect, Respond, and Remediate Identity Risks

## Features
- Okta API (token) integration: system logs, users, factors, suspend users.
- Detections: brute-force→success, unusual geo, off-hours (extendable).
- MFA audit: no MFA, weak-only (SMS/call/email).
- Normalized alerts JSON (`user_id`, `username`, `risk_type`, `timestamp`, `severity`, `action_taken`).
- REST: `GET /alerts`, `POST /remediate/{userId}`, `POST /rescan`, `POST /scan/mfa`, `GET /health`.
- Auto-suspend high-risk kinds (configurable).
- Scheduled scanning with bookmark persistence.
- Logging to rotating file (`logs/okta_guard.log`).
- Dockerfile + Compose. Optional HTML dashboard at `/public`.

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
cp .env.example .env   # set OKTA_DOMAIN, OKTA_API_TOKEN, etc.
python -m okta_guard    # runs FastAPI on :8080
# curl endpoints:
curl localhost:8080/health
curl localhost:8080/rescan -X POST
curl localhost:8080/alerts
