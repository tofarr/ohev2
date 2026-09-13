"""SecretStr / sensitive-column serialization standard (AGENTS.md §13).

Sensitive columns are serialized through a uniform pydantic-context convention
applied to every :class:`SecretStr` (and secret-bearing) field across the
codebase:

* An optional **context object** is passed when serializing/deserializing.
* If the context carries an ``encryption_service`` (an
  :class:`EncryptionService`), :class:`SecretStr` values are encrypted on dump
  via :func:`EncryptionService.encrypt_value` and decrypted on load via
  :func:`EncryptionService.decrypt_value` (the column stores JWE ciphertext).
* Otherwise, if the context carries ``expose_secrets: true``, secrets are
  dumped in plaintext.
* Otherwise (no context / neither flag), secrets are **redacted** (Pydantic's
  default ``str(SecretStr)`` → ``**********``).

The helpers here are used from ``field_serializer`` / ``field_validator``
decorators on the owning models; they take the pydantic ``ValidationInfo`` /
``SerializationInfo`` when available so the context flows through
``model_dump(..., context=...)`` and ``model_validate(..., context=...)``.
"""

from __future__ import annotations

from typing import Any

from pydantic import SecretStr

from openhands.ev2.encryption.encryption_service import EncryptionService

# Sentinel used to detect a missing/empty context regardless of how the field
# serializer is invoked (``None`` is possible in FastAPI / pydantic configs).
_EMPTY: dict[str, Any] = {}


def _ctx_dict(info: Any | None) -> dict[str, Any]:
    """Extract the dict view of a pydantic context (info.context or headers)."""
    if info is None:
        return _EMPTY
    ctx = getattr(info, "context", None)
    if ctx is None:
        return _EMPTY
    if isinstance(ctx, dict):
        return ctx
    # Some pydantic paths thread a Mapping rather than a dict.
    return dict(ctx)


def encryption_service_from_context(info: Any | None) -> EncryptionService | None:
    """The ``encryption_service`` from the serialization context, or ``None``."""
    enc = _ctx_dict(info).get("encryption_service")
    return enc if isinstance(enc, EncryptionService) else None


def expose_secrets_from_context(info: Any | None) -> bool:
    """Whether the context requests plaintext secrets (``expose_secrets``)."""
    return bool(_ctx_dict(info).get("expose_secrets"))


def dump_secret_str(secret: SecretStr, info: Any | None = None) -> str:
    """Serialize a :class:`SecretStr` per the §13 convention.

    Encryption (context ``encryption_service``) wins over plaintext exposure
    (context ``expose_secrets``), which wins over redaction — an explicit
    encryption request must never leak plaintext through a stray flag.
    """
    enc = encryption_service_from_context(info)
    if enc is not None:
        return enc.encrypt_value(secret.get_secret_value())
    if expose_secrets_from_context(info):
        return secret.get_secret_value()
    return str(secret)


def load_secret_str(secret: SecretStr, info: Any | None = None) -> str:
    """Deserialize a :class:`SecretStr` per the §13 convention.

    When the context carries an ``encryption_service`` the stored value is JWE
    ciphertext and is decrypted to plaintext.
    """
    enc = encryption_service_from_context(info)
    if enc is not None:
        return enc.decrypt_value(secret.get_secret_value())
    return secret.get_secret_value()


def dump_secret_map(
    values: dict[str, SecretStr] | None,
    info: Any | None = None,
) -> dict[str, str] | None:
    """Serialize a map of :class:`SecretStr` values per the §13 convention."""
    if values is None:
        return None
    return {key: dump_secret_str(item, info) for key, item in values.items()}


def encrypt_secret_map(
    enc: EncryptionService | None,
    values: dict[str, SecretStr] | None,
) -> dict[str, str]:
    """Encrypt a map of secrets to JWE ciphertext for storage (service layer).

    With ``enc`` ``None`` (no encryption configured) the plaintext is stored
    as-is — the caller must already have accepted that trade-off.
    """
    if values is None:
        return {}
    out: dict[str, str] = {}
    for key, item in values.items():
        out[key] = (
            enc.encrypt_value(item.get_secret_value())
            if enc is not None
            else item.get_secret_value()
        )
    return out


def decrypt_secret_map(
    enc: EncryptionService | None,
    values: dict[str, str] | None,
) -> dict[str, SecretStr]:
    """Decrypt a stored (ciphertext) map back to in-memory :class:`SecretStr` values."""
    if values is None:
        return {}
    out: dict[str, SecretStr] = {}
    for key, item in values.items():
        out[key] = SecretStr(enc.decrypt_value(str(item)) if enc is not None else str(item))
    return out
