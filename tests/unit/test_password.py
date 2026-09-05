"""Unit tests for the password utility (bcrypt + sha256 pre-hash for >72 bytes)."""

from __future__ import annotations

from openhands.ev2.util.password import _normalize, hash_password, verify_password


class TestNormalize:
    def test_short_password_unchanged(self) -> None:
        assert _normalize("short") == b"short"

    def test_exactly_72_bytes_not_pre_hashed(self) -> None:
        raw = "a" * 72
        assert _normalize(raw) == raw.encode("utf-8")

    def test_over_72_bytes_pre_hashed_with_sha256(self) -> None:
        import hashlib

        raw = "x" * 73
        assert _normalize(raw) == hashlib.sha256(raw.encode("utf-8")).digest()


class TestHashPassword:
    def test_returns_bcrypt_hash(self) -> None:
        h = hash_password("mypassword")
        assert h.startswith("$2b$")

    def test_different_salts_each_call(self) -> None:
        assert hash_password("same") != hash_password("same")


class TestVerifyPassword:
    def test_correct_password(self) -> None:
        h = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", h) is True

    def test_wrong_password(self) -> None:
        h = hash_password("right")
        assert verify_password("wrong", h) is False

    def test_long_password_roundtrip(self) -> None:
        long_pw = "a" * 200
        h = hash_password(long_pw)
        assert verify_password(long_pw, h) is True

    def test_malformed_hash_returns_false(self) -> None:
        assert verify_password("anything", "not-a-valid-hash") is False

    def test_none_hash_returns_false(self) -> None:
        assert verify_password("anything", "") is False
