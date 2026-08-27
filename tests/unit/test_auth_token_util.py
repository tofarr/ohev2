"""Tests for the auth-token backwards-compat shim in openhands.ev2.util.auth_token."""

from __future__ import annotations

import uuid

import pytest

from openhands.ev2.util.auth_token import create_auth_token, extract_user_id

pytestmark = pytest.mark.asyncio


async def test_create_and_extract_round_trip(engine) -> None:
    uid = uuid.uuid4()
    token = create_auth_token(uid)
    assert extract_user_id(token) == uid


async def test_extract_garbage_returns_none(engine) -> None:
    assert extract_user_id("not-a-jwe") is None


async def test_extract_missing_sub_returns_none(engine) -> None:
    from openhands.ev2.encryption.encryption_service import get_encryption_service

    enc = get_encryption_service()
    bad = enc.create_jwe_token({"jti": str(uuid.uuid4())})
    assert extract_user_id(bad) is None


async def test_extract_invalid_sub_returns_none(engine) -> None:
    from openhands.ev2.encryption.encryption_service import get_encryption_service

    enc = get_encryption_service()
    bad = enc.create_jwe_token({"sub": "not-a-uuid", "jti": str(uuid.uuid4())})
    assert extract_user_id(bad) is None
