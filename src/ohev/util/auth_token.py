"""Auth-token issuance and verification.

Auth tokens are JWE-encrypted (via EncryptionService) JSON payloads carrying the
authenticated user id under the `sub` claim and an `exp` matching the cookie
max-age. The token is opaque to clients (encrypted, not merely signed) so the
principal id cannot be read without the server's key.

`create_auth_token` / `extract_user_id` are the only entry points the router
and dependency layer use.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from ohev.config import AppConfig, get_config
from ohev.encryption.encryption_service import EncryptionService, get_encryption_service

_SUB_CLAIM = "sub"


def _ttl(config: AppConfig) -> timedelta:
    return timedelta(seconds=config.auth_token_ttl_seconds)


def create_auth_token(
    user_id: uuid.UUID,
    *,
    encryption_service: EncryptionService | None = None,
    config: AppConfig | None = None,
) -> str:
    """Encrypt a JWE auth token for *user_id* with the configured TTL as `exp`."""
    enc = encryption_service or get_encryption_service()
    cfg = config or get_config()
    return enc.create_jwe_token(
        {_SUB_CLAIM: str(user_id)},
        expires_in=_ttl(cfg),
    )


def extract_user_id(
    token: str,
    *,
    encryption_service: EncryptionService | None = None,
) -> uuid.UUID | None:
    """Decrypt *token* and return its user id, or None if invalid/expired.

    None (rather than raising) lets the dependency layer treat every bad token
    as "no principal" and apply the same 401/anonymous logic uniformly.
    """
    enc = encryption_service or get_encryption_service()
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
