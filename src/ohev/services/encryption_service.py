"""Encryption service for signing/verifying JWS and encrypting/decrypting JWE tokens."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt
from joserfc import jwe
from joserfc.jwk import OctKey

from ohev.config import AppConfig, EncryptionKeyConfig, get_config

# Only allow dir + A256GCM to prevent cryptographic agility attacks
_JWE_REGISTRY = jwe.JWERegistry(algorithms=["dir", "A256GCM"])
_JWE_REGISTRY.max_ciphertext_length = 100 * 1024 * 1024  # 100MB


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _derive_symmetric_key(secret: str) -> OctKey:
    """Derive a 256-bit symmetric key from a secret string."""
    key_bytes = secret.encode()
    key_256 = hashlib.sha256(key_bytes).digest()
    return OctKey.import_key(key_256)


class EncryptionService:
    """Service for signing/verifying JWS tokens and encrypting/decrypting JWE tokens."""

    def __init__(self, config: AppConfig) -> None:
        self._encryption_key = config.encryption_key
        self._decryption_keys: dict[str, EncryptionKeyConfig] = {
            k.id: k for k in config.decryption_keys
        }

    @property
    def encryption_key_id(self) -> str:
        """Get the encryption key ID."""
        return self._encryption_key.id

    @property
    def decryption_key_ids(self) -> list[str]:
        """Get all available decryption key IDs."""
        return list(self._decryption_keys.keys())

    def _get_decryption_key(self, key_id: str) -> EncryptionKeyConfig:
        """Get a decryption key by ID."""
        if key_id not in self._decryption_keys:
            raise ValueError(f"Key ID '{key_id}' not found")
        return self._decryption_keys[key_id]

    def create_jws_token(
        self,
        payload: dict[str, Any],
        expires_in: timedelta | None = None,
    ) -> str:
        """Create a JWS (JSON Web Signature) token.

        Args:
            payload: The JWT payload
            expires_in: Token expiration time. If None, defaults to 1 hour.

        Returns:
            The signed JWS token
        """
        now = _utc_now()
        if expires_in is None:
            expires_in = timedelta(hours=1)

        jwt_payload = {
            **payload,
            "iat": int(now.timestamp()),
            "exp": int((now + expires_in).timestamp()),
        }

        secret_key = self._encryption_key.value.get_secret_value()
        return jwt.encode(
            jwt_payload,
            secret_key,
            algorithm="HS256",
            headers={"kid": self._encryption_key.id},
        )

    def verify_jws_token(self, token: str) -> dict[str, Any]:
        """Verify and decode a JWS token.

        Args:
            token: The JWS token to verify

        Returns:
            The decoded JWT payload

        Raises:
            ValueError: If token is invalid or key_id is not found
            jwt.InvalidTokenError: If token verification fails
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
            key_id = unverified_header.get("kid")
            if not key_id:
                key_id = self._encryption_key.id
        except jwt.DecodeError as e:
            raise ValueError("Invalid JWT token format") from e

        key = self._get_decryption_key(key_id)
        secret_key = key.value.get_secret_value()

        try:
            return jwt.decode(token, secret_key, algorithms=["HS256"])
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError("Token verification failed") from e

    def create_jwe_token(
        self,
        payload: dict[str, Any],
        expires_in: timedelta | None = None,
    ) -> str:
        """Create a JWE (JSON Web Encryption) token.

        Args:
            payload: The JWT payload to encrypt
            expires_in: Token expiration time. If None, no expiration is set.

        Returns:
            The encrypted JWE token
        """
        now = _utc_now()
        jwt_payload: dict[str, Any] = {
            **payload,
            "iat": int(now.timestamp()),
        }

        if expires_in is not None:
            jwt_payload["exp"] = int((now + expires_in).timestamp())

        secret_key = self._encryption_key.value.get_secret_value()
        symmetric_key = _derive_symmetric_key(secret_key)

        protected_header = {
            "alg": "dir",
            "enc": "A256GCM",
            "kid": self._encryption_key.id,
        }
        return jwe.encrypt_compact(
            protected_header,
            json.dumps(jwt_payload).encode("utf-8"),
            symmetric_key,
            registry=_JWE_REGISTRY,
        )

    def decrypt_jwe_token(self, token: str) -> dict[str, Any]:
        """Decrypt and decode a JWE token.

        Args:
            token: The JWE token to decrypt

        Returns:
            The decrypted JWT payload

        Raises:
            ValueError: If token is invalid or key_id is not found
            Exception: If token decryption fails
        """
        try:
            obj = jwe.extract_compact(token.encode("utf-8"), _JWE_REGISTRY)  # type: ignore[attr-defined]
        except Exception as e:
            raise ValueError("Invalid JWE token format") from e

        protected_header = obj.protected
        key_id = protected_header.get("kid")
        if not key_id:
            raise ValueError("Token does not contain 'kid' header with key ID")

        key = self._get_decryption_key(key_id)
        secret_key = key.value.get_secret_value()
        symmetric_key = _derive_symmetric_key(secret_key)

        try:
            result = jwe.decrypt_compact(token, symmetric_key, registry=_JWE_REGISTRY)
            if result.plaintext is None:
                raise ValueError("Decryption produced no plaintext")
            parsed: dict[str, Any] = json.loads(result.plaintext)
            return parsed
        except Exception as e:
            raise ValueError("Token decryption failed") from e

    def encrypt_value(self, plaintext: str) -> str:
        """Encrypt a plaintext string using JWE.

        Args:
            plaintext: The string to encrypt

        Returns:
            The encrypted ciphertext
        """
        return self.create_jwe_token({"v": plaintext})

    def decrypt_value(self, ciphertext: str) -> str:
        """Decrypt a ciphertext string.

        Args:
            ciphertext: The encrypted string

        Returns:
            The decrypted plaintext

        Raises:
            ValueError: If decryption fails
        """
        payload = self.decrypt_jwe_token(ciphertext)
        return str(payload["v"])


@lru_cache(maxsize=1)
def get_encryption_service() -> EncryptionService:
    """Get the singleton encryption service instance."""
    return EncryptionService(get_config())
