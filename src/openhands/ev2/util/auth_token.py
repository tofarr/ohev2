"""Token mint/extract helpers for tests and bootstrap paths.

``create_auth_token`` mints a COOKIE-type JWE token (the same shape the
``/auth`` callback endpoint issues) using only the EncryptionService — no DB
session is required, so it is safe to call from setup paths that have no
request-scoped session. ``extract_user_id`` decrypts and returns the ``sub``
claim without DB or user-enabled checks — it is a *transport* decode, not
authentication; use :meth:`TokenService.authenticate` for real auth.

This helper is for tests / bootstrap only. In production, cookies are always
minted by :class:`TokenService` / :class:`AuthService` with their ``exp``
synced to the backing IdP access-token row. Because this helper has no DB
session, it cannot read that row; callers that need an IdP-synced expiry
should use :class:`TokenService` instead, or pass an explicit ``expires_in``.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from openhands.ev2.encryption.encryption_service import get_encryption_service

_SUB_CLAIM = "sub"
_TYP_CLAIM = "ttyp"

# Default lifetime for bootstrap/test tokens minted without a DB session. Real
# sessions always derive the cookie expiry from the IdP access-token row via
# TokenService; this constant only covers the no-DB test/bootstrap path.
_DEFAULT_TOKEN_TTL = timedelta(hours=1)


def create_auth_token(
    user_id: uuid.UUID,
    *,
    expires_in: timedelta = _DEFAULT_TOKEN_TTL,
) -> str:
    """Mint a COOKIE-type JWE token for *user_id* (no DB writes).

    The expiry defaults to one hour; pass ``expires_in`` to override. For
    production cookies whose expiry must mirror the IdP access token, use
    :meth:`TokenService.create_cookie_token` instead.
    """
    enc = get_encryption_service()
    return enc.create_jwe_token(
        {
            _SUB_CLAIM: str(user_id),
            _TYP_CLAIM: "cookie",
            "jti": str(uuid.uuid4()),
        },
        expires_in=expires_in,
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
