"""Token mint/extract helpers for tests and bootstrap paths.

``create_auth_token`` mints a COOKIE-type JWE token (the same shape the
``/auth`` callback endpoint issues) using only the EncryptionService — no DB
session is required, so it is safe to call from setup paths that have no
request-scoped session. ``extract_user_id`` decrypts and returns the ``sub``
claim without DB or user-enabled checks — it is a *transport* decode, not
authentication; use :meth:`TokenService.authenticate` for real auth.
"""

from __future__ import annotations

import uuid

from openhands.ev2.config import get_config
from openhands.ev2.encryption.encryption_service import get_encryption_service

_SUB_CLAIM = "sub"
_TYP_CLAIM = "ttyp"


def create_auth_token(
    user_id: uuid.UUID,
) -> str:
    """Mint a COOKIE-type JWE token for *user_id* (no DB writes)."""
    from datetime import timedelta

    cfg = get_config()
    enc = get_encryption_service()
    return enc.create_jwe_token(
        {
            _SUB_CLAIM: str(user_id),
            _TYP_CLAIM: "cookie",
            "jti": str(uuid.uuid4()),
        },
        expires_in=timedelta(seconds=cfg.auth_cookie_timeout_seconds),
    )


def extract_user_id(token: str) -> uuid.UUID | None:
    """Decrypt *token* and return its user id, or None if invalid/expired.

    This is a transport-level decode (no DB/user checks); for real
    authentication use :meth:`TokenService.authenticate`.
    """
    enc = get_encryption_service()
    try:
        payload = enc.decrypt_jwe_token(token)
    except Exception:
        return None
    sub = payload.get(_SUB_CLAIM)
    if not isinstance(sub, str):
        return None
    try:
        return uuid.UUID(sub)
    except ValueError:
        return None
