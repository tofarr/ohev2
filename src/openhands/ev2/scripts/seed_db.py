"""Seed the database with bootstrap roles, users, a default group, and a default
sandbox template.

Seeds two roles:

* ``admin`` — grants :class:`Permitted` (unrestricted access) on every shipped
  resource type. Assigned to the seeded admin user.
* ``user`` — a regular-user role granting :class:`ApiKeyAccess` on
  ``api_key_permission`` so a non-admin user can manage their own API keys
  (create/read/update/delete keys scoped to their own ``user_id``), and
  :class:`ConversationAccess` on ``conversation_permission`` so they can
  search/read conversations backed by sandbox configs they created. All other
  entity columns are ``NULL`` (deny). Assigned to the optional seeded regular
  user.

Also seeds a default :class:`Group` and adds every seeded user (the admin and,
when provided, the regular user) to it.

Finally, when ``sandbox_template_tag`` is provided, seeds a default
:class:`SandboxTemplate` for the ``ghcr.io/openhands/agent-server`` image: the
tag is resolved by :func:`fetch_latest_agent_server_tag` in ``main`` (it queries
the GHCR registry for the highest published version). The template exposes the
agent-server (8000) and vscode (8001) ports, snapshots ``/home/openhands`` on
deactivation, and carries Docker run directives in ``meta``.

Idempotent: re-running upserts the users (password, email, enabled) and
ensures both roles exist with the correct per-entity ``Permission`` columns,
then ensures each user is a member of its role and of the default group. Safe
to call on a fresh database, on one already seeded, or after adding new
resource types (re-running backfills the missing admin per-entity columns).

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
from collections.abc import Iterable, Sequence
from typing import Any

import httpx
from packaging.version import Version
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.api_key.api_key_security import ApiKeyAccess
from openhands.ev2.config import get_config
from openhands.ev2.conversation.conversation_security import ConversationAccess
from openhands.ev2.db import create_engine, create_session_factory
from openhands.ev2.group.group_models import Group, GroupUser
from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role, UserRole
from openhands.ev2.sandbox.sandbox_template_models import ExposedPort, SandboxTemplate
from openhands.ev2.security.security_models import Permission, Permitted
from openhands.ev2.user.user_models import User
from openhands.ev2.util.password import hash_password

# Per-entity ``Permission`` columns the seeded admin role grants unrestricted
# access to. Mirrors ``ROLE_ENTITY_COLUMNS`` (the canonical list on the model)
# so newly added entities are picked up automatically.
_ADMIN_ENTITY_COLUMNS: tuple[str, ...] = ROLE_ENTITY_COLUMNS
_ADMIN_ROLE_NAME = "admin"
_USER_ROLE_NAME = "user"
_DEFAULT_GROUP_NAME = "default"

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

# GHCR registry coordinates for the agent-server image. The registry requires
# an anonymous pull token even for public packages.
_AGENT_SERVER_REGISTRY = "ghcr.io"
_AGENT_SERVER_REPOSITORY = "openhands/agent-server"
_AGENT_SERVER_IMAGE = f"{_AGENT_SERVER_REGISTRY}/{_AGENT_SERVER_REPOSITORY}"
# Tag prefix used to identify the seeded default template regardless of which
# version was latest at seed time (idempotency key for re-seeds).
_AGENT_SERVER_TAG_PREFIX = f"{_AGENT_SERVER_IMAGE}:"
# The python+nodejs runtime variant is the default agent-server image.
_VARIANT_PREFERENCE = "nikolaik_s_python-nodejs"

# Exposed ports on the seeded default template: the agent server on 8000 and
# the VSCode server on 8001 (mirrors the Docker/K8s services' defaults).
_DEFAULT_EXPOSED_PORTS: tuple[ExposedPort, ...] = (
    ExposedPort(
        name="agent_server",
        description="The port on which the agent server runs within the container",
        container_port=8000,
    ),
    ExposedPort(
        name="vscode",
        description="The port on which the VSCode server runs within the container",
        container_port=8001,
    ),
)

# Docker run directives surfaced to the sandbox service via the template's
# ``meta`` (provider-specific hints). ``host.docker.internal`` is mapped to the
# host gateway so the sandbox can reach host-side services; ``detach`` and
# ``init`` match the Docker SDK's run defaults for a long-lived container.
_DEFAULT_TEMPLATE_META: dict[str, Any] = {
    "directives": {
        "extra_hosts": {"host.docker.internal": "host-gateway"},
        "detach": True,
        "init": True,
    }
}

_DEFAULT_WORKING_DIR = "/home/openhands"
_DEFAULT_SNAPSHOT_DIRS: list[str] = [_DEFAULT_WORKING_DIR]

# Matches a leading semver on a tag, e.g. ``v1.2.3`` or ``v1.0.0a6``. The
# registry tags carry variant/arch suffixes (``_nikolaik_s_...``, ``-amd64``)
# after the version; only the leading version is parsed.
_SEMVER_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?")
_REGISTRY_PAGE_SIZE = 1000
_REGISTRY_MAX_PAGES = 20
_REGISTRY_TIMEOUT_SECONDS = 30.0


def _is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))


def _user_role_permissions() -> dict[str, Permission | None]:
    """Per-entity ``Permission`` columns for the regular-user role.

    ``api_key_permission`` is set to :class:`ApiKeyAccess` (manage own API
    keys) and ``conversation_permission`` to :class:`ConversationAccess`
    (search/read conversations backed by sandbox configs the user created);
    every other governed entity stays ``None`` (deny).
    """
    return {
        "api_key_permission": ApiKeyAccess(),
        "conversation_permission": ConversationAccess(),
    }


# --------------------------------------------------------------------------- #
# Latest agent-server tag resolution (GHCR registry).
# --------------------------------------------------------------------------- #


def _parse_tag_version(tag: str) -> Version | None:
    """Parse the leading semver out of a registry tag, or ``None`` if none.

    Registry tags carry variant/arch suffixes after the version
    (``v1.1.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64``); only the
    leading ``vX.Y.Z[<pre><n>]`` portion is parsed.
    """
    m = _SEMVER_RE.match(tag)
    if m is None:
        return None
    major, minor, patch, pre_kind, pre_n = m.groups()
    base = f"{major}.{minor}.{patch}"
    if pre_kind:
        # packaging expects ``a1``/``b1``/``rc1`` immediately after the base.
        base = f"{base}.{pre_kind}{pre_n}"
    try:
        return Version(base)
    except ValueError:
        return None


def _pick_latest_tag(tags: Sequence[str]) -> str | None:
    """Select the latest version tag from *tags*.

    Filters to tags carrying a leading semver, picks the highest version, and
    among the tags sharing that version prefers the python+nodejs runtime
    variant (the default agent-server image) and an arch-agnostic manifest
    (no ``-amd64``/``-arm64`` suffix) when one exists, falling back to amd64.
    Returns ``None`` when no version tag is present.
    """
    versioned = [(ver, tag) for tag in tags if (ver := _parse_tag_version(tag)) is not None]
    if not versioned:
        return None
    top = max(versioned, key=lambda vt: vt[0])[0]
    same_version = [tag for ver, tag in versioned if ver == top]

    def _score(tag: str) -> tuple[int, int]:
        variant = 1 if _VARIANT_PREFERENCE in tag else 0
        arch_agnostic = 1 if not tag.endswith(("-amd64", "-arm64")) else 0
        return (variant, arch_agnostic)

    # Sort ascending by (variant match, arch-agnostic, amd64-flag, name); the
    # last element is the best (preferred variant, arch-agnostic, then amd64).
    same_version.sort(key=lambda t: (_score(t), 1 if t.endswith("-amd64") else 0, t))
    return same_version[-1]


async def _fetch_registry_token(client: httpx.AsyncClient) -> str:
    """Fetch an anonymous pull token for the agent-server repository."""
    resp = await client.get(
        f"https://{_AGENT_SERVER_REGISTRY}/token",
        params={
            "scope": f"repository:{_AGENT_SERVER_REPOSITORY}:pull",
            "service": _AGENT_SERVER_REGISTRY,
        },
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("GHCR token endpoint did not return a usable token")
    return token


def _next_page_cursor(link_header: str | None) -> str | None:
    """Extract the ``last`` cursor from a registry ``Link`` header, if any."""
    if not link_header:
        return None
    m = re.search(r"last=([^&>;]+)", link_header)
    return m.group(1) if m is not None else None


async def _fetch_all_tags(client: httpx.AsyncClient, token: str) -> list[str]:
    """Page through the registry tags list and return every tag."""
    tags: list[str] = []
    cursor: str | None = None
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(_REGISTRY_MAX_PAGES):
        params: dict[str, Any] = {"n": _REGISTRY_PAGE_SIZE}
        if cursor is not None:
            params["last"] = cursor
        resp = await client.get(
            f"https://{_AGENT_SERVER_REGISTRY}/v2/{_AGENT_SERVER_REPOSITORY}/tags/list",
            headers=headers,
            params=params,
        )
        resp.raise_for_status()
        data = resp.json()
        page = data.get("tags") or []
        tags.extend(page)
        cursor = _next_page_cursor(resp.headers.get("link"))
        if cursor is None or not page:
            break
    return tags


async def fetch_latest_agent_server_tag() -> str:
    """Resolve the latest published version tag of the agent-server image.

    Queries the GHCR registry (anonymous pull token), collects every tag, and
    returns the highest semver tag (preferred python+nodejs variant, arch
    agnostic). Raises :class:`RuntimeError` if the registry is unreachable or
    no version tag can be parsed.
    """
    async with httpx.AsyncClient(timeout=_REGISTRY_TIMEOUT_SECONDS) as client:
        token = await _fetch_registry_token(client)
        tags = await _fetch_all_tags(client, token)
    latest = _pick_latest_tag(tags)
    if latest is None:
        raise RuntimeError(
            f"no semver tags found for {_AGENT_SERVER_IMAGE!r} "
            f"(parsed {len(tags)} tag(s) from the registry)"
        )
    return f"{_AGENT_SERVER_IMAGE}:{latest}"


# --------------------------------------------------------------------------- #
# Default sandbox template seeding.
# --------------------------------------------------------------------------- #


def _default_template_payload(docker_image_tag: str) -> dict[str, Any]:
    """The field values for the seeded default sandbox template."""
    return {
        "docker_image_tag": docker_image_tag,
        "exposed_ports": [p.model_dump() for p in _DEFAULT_EXPOSED_PORTS],
        "env_vars": {},
        "working_dir": _DEFAULT_WORKING_DIR,
        "snapshot_dirs": list(_DEFAULT_SNAPSHOT_DIRS),
        "snapshot_on_deactivate": True,
        "meta": dict(_DEFAULT_TEMPLATE_META),
    }


async def _ensure_default_sandbox_template(
    session: AsyncSession,
    *,
    creator_id: uuid.UUID,
    docker_image_tag: str,
) -> SandboxTemplate:
    """Upsert the seeded default agent-server sandbox template.

    Idempotent: re-seeding finds the existing template by its creator and
    ``ghcr.io/openhands/agent-server:`` image-tag prefix (so a new latest tag
    replaces the old one rather than creating a duplicate) and refreshes its
    mutable fields. Returns the upserted template.
    """
    desired = _default_template_payload(docker_image_tag)
    rows = await session.scalars(
        select(SandboxTemplate)
        .where(
            SandboxTemplate.creator_id == creator_id,
            SandboxTemplate.docker_image_tag.startswith(_AGENT_SERVER_TAG_PREFIX),
        )
        .order_by(SandboxTemplate.created_at.desc())
    )
    existing = rows.first()

    if existing is None:
        template = SandboxTemplate(creator_id=creator_id, **desired)
        session.add(template)
        await session.flush()
        await session.refresh(template)
        return template

    existing.docker_image_tag = desired["docker_image_tag"]
    existing.exposed_ports = desired["exposed_ports"]
    existing.env_vars = desired["env_vars"]
    existing.working_dir = desired["working_dir"]
    existing.snapshot_dirs = desired["snapshot_dirs"]
    existing.snapshot_on_deactivate = desired["snapshot_on_deactivate"]
    existing.meta = desired["meta"]
    await session.flush()
    await session.refresh(existing)
    return existing


async def seed_db(
    session: AsyncSession,
    *,
    admin_username: str,
    admin_email: str,
    admin_password: str,
    user_username: str | None = None,
    user_email: str | None = None,
    user_password: str | None = None,
    sandbox_template_tag: str | None = None,
) -> tuple[User, User | None]:
    """Seed the admin role/user and the regular-user role/user.

    Always ensures the ``admin`` and ``user`` roles exist (idempotent upsert of
    their per-entity ``Permission`` columns) and that the admin user is a member
    of the ``admin`` role. When *user_username* / *user_email* / *user_password*
    are all provided, also upserts a regular user and assigns it the ``user``
    role; returns ``(admin_user, regular_user_or_None)``. Raises ``ValueError``
    on invalid admin credentials, or on a partial regular-user credential set.

    When *sandbox_template_tag* is provided, also upserts the default
    agent-server :class:`SandboxTemplate` attributed to the admin user. The
    ``main`` entrypoint resolves this tag from the GHCR registry via
    :func:`fetch_latest_agent_server_tag`; callers that wish to avoid the
    network (tests) pass an explicit tag and no registry call is made.
    """
    admin_username = admin_username.strip()
    if not admin_username:
        raise ValueError("admin username must be a non-empty string")
    if not _is_valid_email(admin_email):
        raise ValueError(f"invalid admin email: {admin_email!r}")
    if not admin_password:
        raise ValueError("admin password must be a non-empty string")

    regular = await _maybe_upsert_regular_user(
        session,
        user_username=user_username,
        user_email=user_email,
        user_password=user_password,
    )

    admin = await _upsert_user(
        session, username=admin_username, email=admin_email, password=admin_password
    )
    await _ensure_admin_role(session, admin)
    await _ensure_user_role(session)
    if regular is not None:
        await _assign_role(session, regular.id, _USER_ROLE_NAME)

    group = await _ensure_default_group(session, admin.id)
    for member in (admin, regular):
        if member is not None:
            await _ensure_group_member(session, group.id, member.id, admin.id)

    await _maybe_seed_default_sandbox_template(session, admin.id, sandbox_template_tag)

    await session.commit()
    return admin, regular


async def _maybe_seed_default_sandbox_template(
    session: AsyncSession,
    admin_id: uuid.UUID,
    sandbox_template_tag: str | None,
) -> None:
    """Seed the default agent-server template when a tag is provided."""
    if sandbox_template_tag is None:
        return
    await _ensure_default_sandbox_template(
        session, creator_id=admin_id, docker_image_tag=sandbox_template_tag
    )


async def _maybe_upsert_regular_user(
    session: AsyncSession,
    *,
    user_username: str | None,
    user_email: str | None,
    user_password: str | None,
) -> User | None:
    """Validate and upsert the optional regular user.

    Returns ``None`` when no regular-user credentials are provided. Raises
    ``ValueError`` on a partial or invalid credential set.
    """
    if not any([user_username, user_email, user_password]):
        return None
    if not (user_username and user_email and user_password):
        raise ValueError(
            "regular user credentials must be fully provided "
            "(username, email, password) or all omitted."
        )
    username = user_username.strip()
    if not username:
        raise ValueError("user username must be a non-empty string")
    if not _is_valid_email(user_email):
        raise ValueError(f"invalid user email: {user_email!r}")
    if not user_password:
        raise ValueError("user password must be a non-empty string")
    return await _upsert_user(session, username=username, email=user_email, password=user_password)


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
    """Insert a user or update its credentials if it already exists.

    Uses ``INSERT ... ON CONFLICT (username) DO UPDATE`` so concurrent seed
    calls (e.g. parallel e2e tests sharing one database) are resolved
    atomically by PostgreSQL rather than racing on a SELECT-then-INSERT.
    """
    hashed = hash_password(password)
    stmt = (
        pg_insert(User)
        .values(
            email=email,
            username=username,
            enabled=True,
            password=hashed,
        )
        .on_conflict_do_update(
            index_elements=["username"],
            set_={"email": email, "enabled": True, "password": hashed},
        )
        .returning(User.id)
    )
    result = await session.execute(stmt)
    user_id = result.scalar_one()
    user = await session.get(User, user_id)
    assert user is not None
    return user


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
    """Upsert the regular-user role (ApiKeyAccess + ConversationAccess).

    ``api_key_permission`` is set to :class:`ApiKeyAccess` and
    ``conversation_permission`` to :class:`ConversationAccess`; every other
    governed entity stays ``None`` (deny). Re-running refreshes both columns
    if they were changed.
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


async def _ensure_default_group(session: AsyncSession, creator_id: uuid.UUID) -> Group:
    """Upsert the default group, created by *creator_id*.

    Idempotent: re-seeding refreshes the group's creator_id/description if it
    already exists. The membership rows are ensured separately.
    """
    group = await session.scalar(select(Group).where(Group.name == _DEFAULT_GROUP_NAME))
    if group is None:
        group = Group(
            name=_DEFAULT_GROUP_NAME,
            description="Default group for seeded users.",
            creator_id=creator_id,
        )
        session.add(group)
        await session.flush()
        return group

    group.creator_id = creator_id
    group.description = "Default group for seeded users."
    await session.flush()
    return group


async def _ensure_group_member(
    session: AsyncSession,
    group_id: uuid.UUID,
    user_id: uuid.UUID,
    creator_id: uuid.UUID,
) -> None:
    """Ensure *user_id* is a member of *group_id*, attributed to *creator_id*."""
    existing = await session.scalar(
        select(GroupUser).where(GroupUser.group_id == group_id, GroupUser.user_id == user_id)
    )
    if existing is None:
        session.add(GroupUser(group_id=group_id, user_id=user_id, creator_id=creator_id))
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
    parser.add_argument(
        "--sandbox-template-tag",
        default=os.environ.get("OHE_SEED_SANDBOX_TEMPLATE_TAG"),
        help=(
            "Explicit agent-server image tag for the seeded default sandbox "
            "template (e.g. ghcr.io/openhands/agent-server:v1.1.0_...-amd64). "
            "When unset, the latest version is resolved from the GHCR registry "
            "at run time; pass --skip-sandbox-template to opt out entirely."
        ),
    )
    parser.add_argument(
        "--skip-sandbox-template",
        action="store_true",
        default=os.environ.get("OHE_SEED_SKIP_SANDBOX_TEMPLATE", "") != "",
        help="Do not seed the default sandbox template (skips the registry call).",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


async def _resolve_sandbox_template_tag(args: argparse.Namespace) -> str | None:
    """Determine the agent-server image tag to seed, or ``None`` to skip.

    An explicit ``--sandbox-template-tag`` wins; otherwise the latest version is
    fetched from GHCR. A failure to reach the registry is logged and treated as
    "skip" so a registry outage never blocks the rest of the seed.
    """
    if args.skip_sandbox_template:
        return None
    explicit = str(args.sandbox_template_tag) if args.sandbox_template_tag else None
    if explicit is not None:
        return explicit
    try:
        return await fetch_latest_agent_server_tag()
    except Exception as exc:  # never block seeding on a registry outage
        print(
            f"WARNING: could not resolve latest agent-server tag from GHCR "
            f"({exc}); skipping default sandbox template seeding. Pass "
            f"--sandbox-template-tag to set it explicitly.",
            file=sys.stderr,
        )
        return None


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

    sandbox_template_tag = await _resolve_sandbox_template_tag(args)

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
                sandbox_template_tag=sandbox_template_tag,
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
            print(
                f"Seeded default group '{_DEFAULT_GROUP_NAME}' with "
                f"{1 + (regular is not None)} member(s).",
                file=sys.stderr,
            )
            if sandbox_template_tag is not None:
                print(
                    f"Seeded default sandbox template (docker_image_tag={sandbox_template_tag!r}).",
                    file=sys.stderr,
                )
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
