"""Seed an admin user with unrestricted access to every resource type.

Idempotent: re-running with the same username upserts the user (password, email,
enabled) and skips permission grants that already exist. Safe to call on a fresh
database, on one that already has the admin, or after adding new ResourceType
values (it will backfill the grants the admin is missing).

Run via ``uv run python -m openhands.ev2.scripts.seed_admin``; credentials default from the
``OHEV_SEED_ADMIN_*`` environment variables, or dev defaults if those are unset.

This script intentionally writes ORM rows directly, bypassing the service layer.
There is no authenticated principal to scope against at seed/bootstrap time, and
the service layer's ``perm_filter`` machinery would block the very bootstrap the
script performs (AGENTS.md §4 — layering enforced by import direction; a script is
an edge that may touch repositories/models directly).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import uuid
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.config import get_config
from openhands.ev2.db import create_engine, create_session_factory
from openhands.ev2.permission.permission_models import Action, Permission, ResourceType
from openhands.ev2.user.user_models import User
from openhands.ev2.util.password import hash_password

# Matches the RFC 5322-ish shape enforced by EmailStr loosely; the canonical
# validation lives in the pydantic schema, but this script does not route through
# it, so a cheap structural check guards the most common typos here.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_DEFAULT_USERNAME = "admin"
_DEFAULT_EMAIL = "admin@example.com"
_DEFAULT_PASSWORD = "changeme"


def _is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))


async def seed_admin(
    session: AsyncSession,
    *,
    username: str,
    email: str,
    password: str,
) -> User:
    """Create or update the admin user and grant it ALL on every resource type.

    Returns the persisted ``User`` (with server-generated id on first create).
    Raises ``ValueError`` on invalid email or empty username/password.
    """
    username = username.strip()
    if not username:
        raise ValueError("username must be a non-empty string")
    if not _is_valid_email(email):
        raise ValueError(f"invalid email: {email!r}")
    if not password:
        raise ValueError("password must be a non-empty string")

    user = await _upsert_user(session, username=username, email=email, password=password)
    await _backfill_admin_permissions(session, user)
    await session.commit()
    return user


async def _upsert_user(
    session: AsyncSession,
    *,
    username: str,
    email: str,
    password: str,
) -> User:
    """Insert the admin user or update its credentials if it already exists."""
    existing = await session.scalar(select(User).where(User.username == username))
    if existing is None:
        user = User(
            email=email,
            username=username,
            enabled=True,
            password=hash_password(password),
        )
        session.add(user)
        await session.flush()
        await session.refresh(user)
        return user

    existing.email = email
    existing.enabled = True
    existing.password = hash_password(password)
    await session.flush()
    await session.refresh(existing)
    return existing


async def _backfill_admin_permissions(
    session: AsyncSession,
    user: User,
) -> None:
    """Grant ALL on every resource type, skipping grants that already exist.

    Iterating the ResourceType enum keeps the script correct as new resource
    types land without editing this file.
    """
    existing_types = await _existing_admin_resource_types(session, user.id)
    for resource_type in ResourceType:
        if resource_type in existing_types:
            continue
        session.add(
            Permission(
                user_id=user.id,
                action=Action.ALL,
                resource_type=resource_type,
                attributes=None,  # all attributes
                search_filter=None,  # unrestricted (whole table in scope)
            )
        )
    await session.flush()


async def _existing_admin_resource_types(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> set[ResourceType]:
    """Resource types the user already has an ALL grant on."""
    stmt = select(Permission.resource_type).where(
        Permission.user_id == user_id,
        Permission.action == Action.ALL,
    )
    result = await session.execute(stmt)
    return set(result.scalars().all())


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed an admin user with unrestricted access to every resource.",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("OHEV_SEED_ADMIN_USERNAME", _DEFAULT_USERNAME),
        help="Admin username (default: env OHEV_SEED_ADMIN_USERNAME or 'admin').",
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("OHEV_SEED_ADMIN_EMAIL", _DEFAULT_EMAIL),
        help="Admin email (default: env OHEV_SEED_ADMIN_EMAIL or 'admin@example.com').",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("OHEV_SEED_ADMIN_PASSWORD", _DEFAULT_PASSWORD),
        help="Admin password (default: env OHEV_SEED_ADMIN_PASSWORD or 'changeme').",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


async def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    using_defaults = (
        args.username == _DEFAULT_USERNAME
        and args.email == _DEFAULT_EMAIL
        and args.password == _DEFAULT_PASSWORD
    )
    if using_defaults:
        print(
            "WARNING: using default admin credentials (admin/admin@example.com/changeme). "
            "Set OHEV_SEED_ADMIN_* env vars or --username/--email/--password to override.",
            file=sys.stderr,
        )

    engine = create_engine(get_config().database_url)
    factory = create_session_factory(engine)
    try:
        async with factory() as session:
            user = await seed_admin(
                session,
                username=args.username,
                email=args.email,
                password=args.password,
            )
            print(
                f"Seeded admin user: id={user.id} username={user.username} "
                f"email={user.email} enabled={user.enabled}",
                file=sys.stderr,
            )
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
