"""Shared helpers for role-based authorization in route tests."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.auth.auth_tokens import hash_api_key_value
from openhands.ev2.role.role_models import Role, UserRole
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
from openhands.ev2.security.security_models import Permission
from openhands.ev2.user.user_models import User
from openhands.ev2.user.user_schemas import UserCreate
from openhands.ev2.user.user_service import UserService
from openhands.ev2.util.search_filter import AllSearchFilter


async def make_principal(
    session: AsyncSession,
    *,
    email: str,
    username: str,
    password: str | None = None,
) -> User:
    """Create a user directly in the DB (bypassing the permission-guarded API)."""
    return await UserService(session, AllSearchFilter[User]()).create(
        UserCreate(email=email, username=username, password=password)
    )


async def assign_role(
    session: AsyncSession,
    user_id: uuid.UUID,
    permissions: dict[str, Permission | None],
    *,
    role_name: str | None = None,
) -> Role:
    """Create (or reuse) a role with *permissions* and assign it to *user_id*.

    *permissions* maps a Role per-entity ``Permission`` column name (e.g.
    ``"user_permission"``) to its policy. Each call creates a fresh role so
    per-test policy isolation is preserved.
    """
    name = role_name or f"role-{user_id}-{len(permissions)}"
    role = Role(name=name, **dict(permissions))
    session.add(role)
    await session.flush()
    session.add(UserRole(role_id=role.id, user_id=user_id))
    await session.flush()
    return role


async def roles_for(session: AsyncSession, user_id: uuid.UUID) -> list[Role]:
    """Return the roles assigned to *user_id*."""
    stmt = (
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )
    return list((await session.execute(stmt)).scalars().all())


async def make_sandbox_config(
    session: AsyncSession,
    *,
    creator_id: uuid.UUID,
    docker_image_tag: str = "example/agent-server:latest",
    session_key: str | None = None,
) -> SandboxConfig:
    """Create a minimal template + sandbox config owned by *creator_id*.

    Writes ORM rows directly so tests for resources that reference
    ``sandbox_configs`` (e.g. conversations) do not depend on the
    permission-guarded sandbox APIs or a live provider. The plaintext
    ``session_key`` is what an ``X-Session-API-Key`` header must carry to
    resolve to this config: a linked system :class:`ApiKey` row is minted
    exactly like :class:`SandboxConfigService` does at create time. Defaults
    to a unique value per call (the key hash is unique-indexed).
    """
    if session_key is None:
        session_key = f"session-key-{uuid.uuid4()}"
    template = SandboxTemplate(creator_id=creator_id, docker_image_tag=docker_image_tag)
    session.add(template)
    await session.flush()
    config = SandboxConfig(
        creator_id=creator_id,
        sandbox_template_id=template.id,
        session_api_key="encrypted-session-key",
    )
    session.add(config)
    await session.flush()
    session.add(
        ApiKey(
            key_hash=hash_api_key_value(session_key),
            prefix=session_key[:7],
            creator_id=creator_id,
            name=f"Sandbox {config.id} API Key",
            system=True,
            sandbox_config_id=config.id,
        )
    )
    await session.flush()
    return config
