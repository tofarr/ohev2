"""Seed the database with bootstrap roles and users.

Seeds two roles:

* ``admin`` — grants :class:`Permitted` (unrestricted access) on every shipped
  resource type. Assigned to the seeded admin user.
* ``user`` — a regular-user role granting :class:`ApiKeyAccess` on
  ``api_key_permission`` so a non-admin user can manage their own API keys
  (create/read/update/delete keys scoped to their own ``user_id``). All other
  entity columns are ``NULL`` (deny). Assigned to the optional seeded regular
  user.

Idempotent: re-running upserts the users (password, email, enabled) and
ensures both roles exist with the correct per-entity ``Permission`` columns,
then ensures each user is a member of its role. Safe to call on a fresh
database, on one already seeded, or after adding new resource types
(re-running backfills the missing admin per-entity columns).

Run via ``uv run python -m openhands.ev2.scripts.seed_db``; credentials default
from the ``OHE_SEED_ADMIN_*`` / ``OHE_SEED_USER_*`` environment variables, or
dev defaults if those are unset.

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

from openhands.ev2.api_key.api_key_security import ApiKeyAccess
from openhands.ev2.config import get_config
from openhands.ev2.db import create_engine, create_session_factory
from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role, UserRole
from openhands.ev2.security.security_models import Permission, Permitted
from openhands.ev2.user.user_models import User
from openhands.ev2.util.password import hash_password

# Per-entity ``Permission`` columns the seeded admin role grants unrestricted
# access to. Mirrors ``ROLE_ENTITY_COLUMNS`` (the canonical list on the model)
# so newly added entities are picked up automatically.
_ADMIN_ENTITY_COLUMNS: tuple[str, ...] = ROLE_ENTITY_COLUMNS
_ADMIN_ROLE_NAME = "admin"
_USER_ROLE_NAME = "user"

# Matches the RFC 5322-ish shape enforced by EmailStr loosely; the canonical
# validation lives in the pydantic schema, but this script does not route through
# it, so a cheap structural check guards the most common typos here.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_DEFAULT_ADMIN_USERNAME = "admin"
_DEFAULT_ADMIN_EMAIL = "admin@example.com"
_DEFAULT_ADMIN_PASSWORD = "changeme"

_DEFAULT_USER_USERNAME = "user"
_DEFAULT_USER_EMAIL = "user@example.com"
_DEFAULT_USER_PASSWORD = "changeme"


def _is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))


def _user_role_permissions() -> dict[str, Permission | None]:
    """Per-entity ``Permission`` columns for the regular-user role.

    Only ``api_key_permission`` is set (to :class:`ApiKeyAccess`); every other
    governed entity stays ``None`` (deny). A regular user can therefore manage
    their own API keys and nothing else without an additional grant.
    """
    return {"api_key_permission": ApiKeyAccess()}


async def seed_db(
    session: AsyncSession,
    *,
    admin_username: str,
    admin_email: str,
    admin_password: str,
    user_username: str | None = None,
    user_email: str | None = None,
    user_password: str | None = None,
) -> tuple[User, User | None]:
    """Seed the admin role/user and the regular-user role/user.

    Always ensures the ``admin`` and ``user`` roles exist (idempotent upsert of
    their per-entity ``Permission`` columns) and that the admin user is a member
    of the ``admin`` role. When *user_username* / *user_email* / *user_password*
    are all provided, also upserts a regular user and assigns it the ``user``
    role; returns ``(admin_user, regular_user_or_None)``. Raises ``ValueError``
    on invalid admin credentials, or on a partial regular-user credential set.
    """
    admin_username = admin_username.strip()
    if not admin_username:
        raise ValueError("admin username must be a non-empty string")
    if not _is_valid_email(admin_email):
        raise ValueError(f"invalid admin email: {admin_email!r}")
    if not admin_password:
        raise ValueError("admin password must be a non-empty string")

    user_creds_provided = any([user_username, user_email, user_password])
    regular: User | None = None
    if user_creds_provided:
        if not (user_username and user_email and user_password):
            raise ValueError(
                "regular user credentials must be fully provided "
                "(username, email, password) or all omitted."
            )
        user_username = user_username.strip()
        if not user_username:
            raise ValueError("user username must be a non-empty string")
        if not _is_valid_email(user_email):
            raise ValueError(f"invalid user email: {user_email!r}")
        if not user_password:
            raise ValueError("user password must be a non-empty string")
        # Narrowed: all three are str here.
        regular = await _upsert_user(
            session,
            username=user_username,
            email=user_email,
            password=user_password,
        )

    admin = await _upsert_user(
        session, username=admin_username, email=admin_email, password=admin_password
    )
    await _ensure_admin_role(session, admin)
    await _ensure_user_role(session)
    if regular is not None:
        await _assign_role(session, regular.id, _USER_ROLE_NAME)

    await session.commit()
    return admin, regular


async def seed_admin(
    session: AsyncSession,
    *,
    username: str,
    email: str,
    password: str,
) -> User:
    """Seed the admin user/role and the regular-user role (backward-compatible).

    Equivalent to :func:`seed_db` without a regular user; returns the admin
    user. Kept so existing callers/tests continue to work.
    """
    admin, _regular = await seed_db(
        session,
        admin_username=username,
        admin_email=email,
        admin_password=password,
    )
    return admin


async def _upsert_user(
    session: AsyncSession,
    *,
    username: str,
    email: str,
    password: str,
) -> User:
    """Insert a user or update its credentials if it already exists."""
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


async def _ensure_admin_role(session: AsyncSession, user: User) -> None:
    """Upsert the admin role (Permitted on every entity) and assign it to *user*.

    Idempotent: re-seeding refreshes the per-entity ``Permission`` columns to
    cover all current resource types and ensures the membership exists. Adding a
    new entity to ``ROLE_ENTITY_COLUMNS`` and re-running backfills the column.
    """
    desired: dict[str, Permission | None] = {col: Permitted() for col in _ADMIN_ENTITY_COLUMNS}
    role = await _upsert_role(session, _ADMIN_ROLE_NAME, desired)
    await _ensure_membership(session, role.id, user.id)


async def _ensure_user_role(session: AsyncSession) -> Role:
    """Upsert the regular-user role (ApiKeyAccess on api_key_permission).

    The ``api_key_permission`` column is set to :class:`ApiKeyAccess`; every
    other governed entity stays ``None`` (deny). Re-running refreshes the
    ``api_key_permission`` column if it was changed.
    """
    return await _upsert_role(session, _USER_ROLE_NAME, _user_role_permissions())


async def _upsert_role(
    session: AsyncSession,
    name: str,
    desired: dict[str, Permission | None],
) -> Role:
    """Insert a named role or refresh its per-entity columns if it exists."""
    role = await session.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(**desired, name=name)
        session.add(role)
        await session.flush()
        return role

    changed = False
    for col, value in desired.items():
        if getattr(role, col) != value:
            setattr(role, col, value)
            changed = True
    if changed:
        await session.flush()
    return role


async def _assign_role(session: AsyncSession, user_id: uuid.UUID, role_name: str) -> None:
    """Ensure *user_id* is a member of the named role."""
    role = await session.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        # _ensure_user_role is expected to have created it; guard regardless.
        raise RuntimeError(f"role {role_name!r} not found; ensure roles are seeded first")
    await _ensure_membership(session, role.id, user_id)


async def _ensure_membership(
    session: AsyncSession,
    role_id: uuid.UUID,
    user_id: uuid.UUID,
) -> None:
    existing = await session.scalar(
        select(UserRole).where(UserRole.role_id == role_id, UserRole.user_id == user_id)
    )
    if existing is None:
        session.add(UserRole(role_id=role_id, user_id=user_id))
        await session.flush()


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed the database with admin and regular-user roles/users.",
    )
    parser.add_argument(
        "--admin-username",
        default=os.environ.get("OHE_SEED_ADMIN_USERNAME", _DEFAULT_ADMIN_USERNAME),
        help="Admin username (default: env OHE_SEED_ADMIN_USERNAME or 'admin').",
    )
    parser.add_argument(
        "--admin-email",
        default=os.environ.get("OHE_SEED_ADMIN_EMAIL", _DEFAULT_ADMIN_EMAIL),
        help="Admin email (default: env OHE_SEED_ADMIN_EMAIL or 'admin@example.com').",
    )
    parser.add_argument(
        "--admin-password",
        default=os.environ.get("OHE_SEED_ADMIN_PASSWORD", _DEFAULT_ADMIN_PASSWORD),
        help="Admin password (default: env OHE_SEED_ADMIN_PASSWORD or 'changeme').",
    )
    parser.add_argument(
        "--user-username",
        default=os.environ.get("OHE_SEED_USER_USERNAME", _DEFAULT_USER_USERNAME),
        help="Regular user username (default: env OHE_SEED_USER_USERNAME or 'user').",
    )
    parser.add_argument(
        "--user-email",
        default=os.environ.get("OHE_SEED_USER_EMAIL", _DEFAULT_USER_EMAIL),
        help="Regular user email (default: env OHE_SEED_USER_EMAIL or 'user@example.com').",
    )
    parser.add_argument(
        "--user-password",
        default=os.environ.get("OHE_SEED_USER_PASSWORD", _DEFAULT_USER_PASSWORD),
        help="Regular user password (default: env OHE_SEED_USER_PASSWORD or 'changeme').",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


async def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    using_defaults = (
        args.admin_username == _DEFAULT_ADMIN_USERNAME
        and args.admin_email == _DEFAULT_ADMIN_EMAIL
        and args.admin_password == _DEFAULT_ADMIN_PASSWORD
    )
    if using_defaults:
        print(
            "WARNING: using default admin credentials (admin/admin@example.com/changeme). "
            "Set OHE_SEED_ADMIN_* env vars or --admin-* flags to override.",
            file=sys.stderr,
        )

    engine = create_engine(get_config().database_url)
    factory = create_session_factory(engine)
    try:
        async with factory() as session:
            admin, regular = await seed_db(
                session,
                admin_username=args.admin_username,
                admin_email=args.admin_email,
                admin_password=args.admin_password,
                user_username=args.user_username,
                user_email=args.user_email,
                user_password=args.user_password,
            )
            print(
                f"Seeded admin user: id={admin.id} username={admin.username} "
                f"email={admin.email} enabled={admin.enabled}",
                file=sys.stderr,
            )
            if regular is not None:
                print(
                    f"Seeded regular user: id={regular.id} username={regular.username} "
                    f"email={regular.email} enabled={regular.enabled}",
                    file=sys.stderr,
                )
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
