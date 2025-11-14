from typing import List
from okta_guard.core.client import OktaClient
from okta_guard.core.models import Alert
from okta_guard.core.config import TZINFO

STRONG = {"token:software:totp","token:hardware","u2f","webauthn","okta_verify","push","fido","fido2"}
WEAK = {"sms","call","email"}

def audit_mfa(okta: OktaClient) -> List[Alert]:
    out: List[Alert] = []
    users = okta.list_users()
    for u in users:
        uid = u.get("id"); prof = u.get("profile") or {}
        email = prof.get("email") or prof.get("login")
        types = set()
        for f in okta.list_user_factors(uid):
            ft = (f.get("factorType") or "").lower()
            p = (f.get("provider") or "").lower()
            if ft in WEAK: types.add(ft)
            elif ft in ("token:software:totp","token:hardware"): types.add("token:software:totp")
            elif ft in ("u2f","webauthn"): types.add("webauthn")
            elif "okta" in p or "push" in ft: types.add("okta_verify")
        if not types:
            out.append(Alert(kind="no_mfa", severity="high", user_id=uid, user_email=email,
                             ts=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                             evidence={"factors":[]},
                             recommended_action="Require MFA enrollment; block until set."))
        else:
            strong = any(t in STRONG for t in types)
            weak_only = all(t in WEAK for t in types)
            if weak_only or not strong:
                out.append(Alert(kind="weak_mfa_only", severity="medium", user_id=uid, user_email=email,
                                 ts=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                                 evidence={"factors": sorted(list(types))},
                                 recommended_action="Enroll strong factor (WebAuthn/Okta Verify/TOTP)."))
    return out
