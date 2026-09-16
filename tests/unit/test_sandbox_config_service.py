"""Unit tests for the ``SandboxConfigService`` secret-key flow.

Verifies that ``create`` mints and encrypts a per-sandbox ``secret_key`` (JWE
ciphertext at rest), that it is never present in the API read model, and that
``get_secret_key`` round-trips the decrypted value.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.sandbox.sandbox_config_schemas import SandboxConfigCreate
from openhands.ev2.sandbox.sandbox_config_service import SandboxConfigService
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL


async def _seed_user(session: AsyncSession) -> uuid.UUID:
    user = User(email=f"u-{uuid.uuid4()}@example.com", username="u", enabled=True)
    session.add(user)
    await session.flush()
    return user.id


async def _seed_template(session: AsyncSession, creator_id: uuid.UUID) -> uuid.UUID:
    template = SandboxTemplate(creator_id=creator_id, docker_image_tag=f"img-{uuid.uuid4()}")
    session.add(template)
    await session.flush()
    return template.id


@pytest.mark.asyncio
async def test_create_mints_and_encrypts_secret_key(session: AsyncSession) -> None:
    creator_id = await _seed_user(session)
    template_id = await _seed_template(session, creator_id)
    service = SandboxConfigService(session, ALL)
    config = await service.create(
        SandboxConfigCreate(sandbox_template_id=template_id, enabled=True),
        creator_id=creator_id,
    )
    # The stored value is JWE ciphertext, not a raw key.
    assert config.secret_key
    assert config.secret_key != ""
    enc = get_encryption_service()
    decrypted = enc.decrypt_value(config.secret_key)
    # The decrypted key is an opaque random id (urlsafe, ~22 chars).
    assert decrypted and decrypted != config.secret_key
    assert len(decrypted) >= 22


@pytest.mark.asyncio
async def test_get_secret_key_round_trips(session: AsyncSession) -> None:
    creator_id = await _seed_user(session)
    template_id = await _seed_template(session, creator_id)
    service = SandboxConfigService(session, ALL)
    config = await service.create(
        SandboxConfigCreate(sandbox_template_id=template_id, enabled=True),
        creator_id=creator_id,
    )
    decrypted = await service.get_secret_key(config.id)
    assert decrypted == get_encryption_service().decrypt_value(config.secret_key)


@pytest.mark.asyncio
async def test_secret_key_omitted_from_read_model(session: AsyncSession) -> None:
    creator_id = await _seed_user(session)
    template_id = await _seed_template(session, creator_id)
    service = SandboxConfigService(session, ALL)
    config = await service.create(
        SandboxConfigCreate(sandbox_template_id=template_id, enabled=True),
        creator_id=creator_id,
    )
    read = service.to_read(config)
    assert "secret_key" not in read.model_dump()
    assert "session_api_key" not in read.model_dump()


@pytest.mark.asyncio
async def test_each_config_has_unique_secret_key(session: AsyncSession) -> None:
    creator_id = await _seed_user(session)
    template_id = await _seed_template(session, creator_id)
    service = SandboxConfigService(session, ALL)
    c1 = await service.create(
        SandboxConfigCreate(sandbox_template_id=template_id, enabled=True),
        creator_id=creator_id,
    )
    c2 = await service.create(
        SandboxConfigCreate(sandbox_template_id=template_id, enabled=True),
        creator_id=creator_id,
    )
    assert c1.secret_key != c2.secret_key
    assert await service.get_secret_key(c1.id) != await service.get_secret_key(c2.id)


@pytest.mark.asyncio
async def test_get_secret_key_missing_raises(session: AsyncSession) -> None:
    from openhands.ev2.sandbox.sandbox_config_service import SandboxConfigNotFoundError

    service = SandboxConfigService(session, ALL)
    with pytest.raises(SandboxConfigNotFoundError):
        await service.get_secret_key(uuid.uuid4())
