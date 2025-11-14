import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
import requests
from .config import settings

logger = logging.getLogger(__name__)


class OktaClient:
    def __init__(self):
        self.base_url = str(settings.OKTA_BASE_URL).rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {settings.OKTA_API_TOKEN}",
            "Accept": "application/json"
        })

    def get_system_logs(self, minutes_back: int = 5) -> List[Dict[str, Any]]:
        """
        Fetch recent system log events.
        For simplicity we fetch last N minutes each time.
        """
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes_back)).isoformat()
        url = f"{self.base_url}/api/v1/logs"
        params = {"since": since, "limit": 100}
        events: List[Dict[str, Any]] = []

        while True:
            resp = self.session.get(url, params=params)
            if resp.status_code != 200:
                logger.error("Error fetching system logs: %s %s", resp.status_code, resp.text)
                break

            batch = resp.json()
            if not batch:
                break

            events.extend(batch)

            # Handle pagination by Link header if present
            link = resp.headers.get("Link")
            if link and 'rel="next"' in link:
                # very simple parsing
                next_url = link.split(";")[0].strip("<> ")
                url = next_url
                params = {}
            else:
                break

        logger.info("Fetched %d log events from Okta", len(events))
        return events

    def get_user_factors(self, user_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/users/{user_id}/factors"
        resp = self.session.get(url)
        if resp.status_code != 200:
            logger.error("Error fetching factors for %s: %s %s",
                         user_id, resp.status_code, resp.text)
            return []
        return resp.json()

    def suspend_user(self, user_id: str) -> bool:
        url = f"{self.base_url}/api/v1/users/{user_id}/lifecycle/suspend"
        resp = self.session.post(url)
        if resp.status_code in (200, 202):
            logger.warning("Suspended user %s via Okta", user_id)
            return True
        logger.error("Failed to suspend user %s: %s %s",
                     user_id, resp.status_code, resp.text)
        return False
