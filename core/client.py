import httpx, logging
from fastapi import HTTPException
from typing import Any, Dict, Iterable, List
log = logging.getLogger("client")

class OktaClient:
    def __init__(self, domain: str, token: str):
        self.base = f"https://{domain}"
        self.h = {
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.http = httpx.Client(timeout=30)

    def _get(self, path: str, params: Dict[str, Any] | None = None):
        r = self.http.get(self.base + path, headers=self.h, params=params)
        if r.status_code >= 400:
            raise HTTPException(502, f"GET {path} failed: {r.status_code} {r.text[:200]}")
        return r

    def _post(self, path: str, data: Any | None = None):
        r = self.http.post(self.base + path, headers=self.h, json=data)
        if r.status_code >= 400:
            raise HTTPException(502, f"POST {path} failed: {r.status_code} {r.text[:200]}")
        return r

    def iter_system_log(self, since_iso: str) -> Iterable[Dict[str, Any]]:
        url = "/api/v1/logs"
        params = {"since": since_iso, "limit": 1000}
        while True:
            resp = self._get(url, params=params)
            arr = resp.json()
            for e in arr: yield e
            link = resp.headers.get("Link","")
            nxt = None
            for part in link.split(","):
                if 'rel="next"' in part:
                    seg = part.split(";")[0].strip()
                    if seg.startswith("<") and seg.endswith(">"): nxt = seg[1:-1]
            if not nxt or not arr: break
            resp = self.http.get(nxt, headers=self.h, timeout=30)
            if resp.status_code >= 400: break
            arr = resp.json()
            for e in arr: yield e
            link = resp.headers.get("Link","")
            if 'rel="next"' not in link: break

    def list_users(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        url="/api/v1/users"; params={"limit":200}
        while True:
            r = self._get(url, params=params)
            arr = r.json(); out.extend(arr)
            link = r.headers.get("Link",""); nxt=None
            for part in link.split(","):
                if 'rel="next"' in part:
                    seg = part.split(";")[0].strip()
                    if seg.startswith("<") and seg.endswith(">"): nxt=seg[1:-1]
            if not nxt or not arr: break
            r = self.http.get(nxt, headers=self.h, timeout=30)
            if r.status_code >= 400: break
            arr = r.json(); out.extend(arr)
            link = r.headers.get("Link","")
            if 'rel="next"' not in link: break
        return out

    def list_user_factors(self, user_id: str) -> List[Dict[str, Any]]:
        return self._get(f"/api/v1/users/{user_id}/factors").json()

    def suspend_user(self, user_id: str) -> None:
        self._post(f"/api/v1/users/{user_id}/lifecycle/suspend", data=None)
        log.info("Suspended user %s", user_id)