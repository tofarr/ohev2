"""Unit tests for the database seed script (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.api_key.api_key_security import ApiKeyAccess, ApiKeyAccessFilter
from openhands.ev2.group.group_models import Group, GroupUser
from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role, UserRole
from openhands.ev2.sandbox.sandbox_models import ExposedPort
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
from openhands.ev2.scripts.seed_db import (
    _assign_role,
    _parse_args,
    _pick_latest_tag,
    seed_admin,
    seed_db,
)
from openhands.ev2.security.security_models import Action, Permitted
from openhands.ev2.user.user_models import User
from openhands.ev2.util.password import verify_password

_ADMIN_COLUMNS = ROLE_ENTITY_COLUMNS
_SEEDED_TAG = (
    "ghcr.io/openhands/agent-server:v1.3.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64"
)


class TestSeedAdmin:
    async def test_seeds_user_and_admin_role(self, session: AsyncSession) -> None:
        user = await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="s3cret!",
        )

        assert isinstance(user.id, uuid.UUID)
        assert user.username == "root"
        assert user.email == "root@example.com"
        assert user.enabled is True
        # Password is hashed, never plaintext, and verifies.
        assert user.password is not None
        assert user.password != "s3cret!"
        assert verify_password("s3cret!", user.password)

        role = await _admin_role(session, user.id)
        assert role.name == "admin"
        for column in _ADMIN_COLUMNS:
            assert isinstance(getattr(role, column), Permitted)
        # The regular-user role is also seeded.
        user_role = await _named_role(session, "user")
        assert isinstance(user_role.api_key_permission, ApiKeyAccess)

    async def test_rerun_is_idempotent(self, session: AsyncSession) -> None:
        await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="first",
        )
        # Second run with a new password/email — must update, not duplicate.
        user = await seed_admin(
            session,
            username="root",
            email="changed@example.com",
            password="second",
        )

        assert user.email == "changed@example.com"
        assert user.password is not None
        assert verify_password("second", user.password)
        assert not verify_password("first", user.password)

        users = await session.scalars(select(User).where(User.username == "root"))
        assert len(users.all()) == 1

        # Exactly one admin role, assigned once.
        roles = await session.scalars(select(Role).where(Role.name == "admin"))
        assert len(roles.all()) == 1
        memberships = await session.scalars(select(UserRole).where(UserRole.user_id == user.id))
        assert len(memberships.all()) == 1

    async def test_backfills_new_resource_types(self, session: AsyncSession) -> None:
        """A dropped per-entity column is restored on re-seed."""
        user = await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="pw",
        )
        role = await _admin_role(session, user.id)
        # Simulate a missing grant by clearing one column; re-running restores it.
        role.user_permission = None
        await session.commit()

        await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="pw",
        )

        role = await _admin_role(session, user.id)
        assert isinstance(role.user_permission, Permitted)

    async def test_invalid_email_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="invalid admin email"):
            await seed_admin(
                session,
                username="root",
                email="not-an-email",
                password="pw",
            )

    async def test_empty_username_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="admin username"):
            await seed_admin(
                session,
                username="   ",
                email="root@example.com",
                password="pw",
            )

    async def test_empty_password_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="admin password"):
            await seed_admin(
                session,
                username="root",
                email="root@example.com",
                password="",
            )


class TestSeedDbRegularUser:
    async def test_seeds_regular_user_with_user_role(self, session: AsyncSession) -> None:
        admin, regular = await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        assert admin.username == "root"
        assert regular is not None
        assert regular.username == "joe"
        assert verify_password("pw", regular.password)

        user_role = await _named_role(session, "user")
        assert isinstance(user_role.api_key_permission, ApiKeyAccess)
        # Every other entity column is denied (None).
        for col in _ADMIN_COLUMNS:
            if col == "api_key_permission":
                continue
            assert getattr(user_role, col) is None
        # The regular user is a member of the user role.
        membership = await session.scalar(select(UserRole).where(UserRole.user_id == regular.id))
        assert membership is not None
        assert membership.role_id == user_role.id

    async def test_user_role_rerun_is_idempotent(self, session: AsyncSession) -> None:
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="first",
        )
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="second",
        )
        roles = await session.scalars(select(Role).where(Role.name == "user"))
        assert len(roles.all()) == 1
        user_role = await _named_role(session, "user")
        assert isinstance(user_role.api_key_permission, ApiKeyAccess)

    async def test_user_role_backfills_api_key_permission(self, session: AsyncSession) -> None:
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        user_role = await _named_role(session, "user")
        user_role.api_key_permission = None
        await session.commit()
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        user_role = await _named_role(session, "user")
        assert isinstance(user_role.api_key_permission, ApiKeyAccess)

    async def test_partial_user_credentials_rejected(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="fully provided"):
            await seed_db(
                session,
                admin_username="root",
                admin_email="root@example.com",
                admin_password="pw",
                user_username="joe",
                user_email=None,
                user_password=None,
            )

    async def test_user_role_permission_is_self_scoped(self, session: AsyncSession) -> None:
        """The seeded user role's ApiKeyAccess scopes to the principal's own keys."""
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        user_role = await _named_role(session, "user")
        policy = user_role.api_key_permission
        assert isinstance(policy, ApiKeyAccess)
        uid = uuid.uuid4()
        filt = policy.to_search_filter(uid, Action.READ)
        assert isinstance(filt, ApiKeyAccessFilter)
        assert filt.creator_id == uid
        # Anonymous is denied (NoneSearchFilter, not None).
        assert policy.to_search_filter(None, Action.CREATE) is not None


async def _admin_role(session: AsyncSession, user_id: uuid.UUID) -> Role:
    """The admin role assigned to *user_id*."""
    stmt = (
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )
    role = await session.scalar(stmt)
    assert role is not None, "admin role not assigned to user"
    return role


async def _named_role(session: AsyncSession, name: str) -> Role:
    role = await session.scalar(select(Role).where(Role.name == name))
    assert role is not None, f"role {name!r} not seeded"
    return role


async def _default_group(session: AsyncSession) -> Group:
    group = await session.scalar(select(Group).where(Group.name == "default"))
    assert group is not None, "default group not seeded"
    return group


class TestSeedDbDefaultGroup:
    async def test_admin_only_in_default_group(self, session: AsyncSession) -> None:
        admin, regular = await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
        )
        assert regular is None

        group = await _default_group(session)
        assert group.creator_id == admin.id
        assert group.description == "Default group for seeded users."

        memberships = list(
            (await session.scalars(select(GroupUser).where(GroupUser.group_id == group.id))).all()
        )
        assert len(memberships) == 1
        assert memberships[0].user_id == admin.id
        assert memberships[0].creator_id == admin.id

    async def test_both_users_in_default_group(self, session: AsyncSession) -> None:
        admin, regular = await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        assert regular is not None

        group = await _default_group(session)
        member_ids = {
            m.user_id
            for m in (
                await session.scalars(select(GroupUser).where(GroupUser.group_id == group.id))
            ).all()
        }
        assert member_ids == {admin.id, regular.id}

    async def test_default_group_rerun_is_idempotent(self, session: AsyncSession) -> None:
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="second",
        )
        groups = await session.scalars(select(Group).where(Group.name == "default"))
        assert len(groups.all()) == 1
        group = await _default_group(session)
        memberships = list(
            (await session.scalars(select(GroupUser).where(GroupUser.group_id == group.id))).all()
        )
        assert len(memberships) == 2


class TestSeedDbValidation:
    async def test_empty_user_username_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="username"):
            await seed_db(
                session,
                admin_username="a",
                admin_email="a@e.com",
                admin_password="p",
                user_username="  ",
                user_email="u@e.com",
                user_password="p",
            )

    async def test_invalid_user_email_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="email"):
            await seed_db(
                session,
                admin_username="a",
                admin_email="a@e.com",
                admin_password="p",
                user_username="u",
                user_email="not-email",
                user_password="p",
            )

    async def test_empty_user_password_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="password"):
            await seed_db(
                session,
                admin_username="a",
                admin_email="a@e.com",
                admin_password="p",
                user_username="u",
                user_email="u@e.com",
                user_password="",
            )


class TestAssignRoleError:
    async def test_runtime_error_when_role_missing(self, session: AsyncSession) -> None:
        user = await seed_admin(session, username="x", email="x@e.com", password="p")
        with pytest.raises(RuntimeError, match="not found"):
            await _assign_role(session, user.id, "nonexistent-role")


class TestParseArgs:
    def test_defaults(self) -> None:
        args = _parse_args([])
        assert args.admin_username == "admin"
        assert args.admin_email == "admin@example.com"
        assert args.user_username == "user"

    def test_custom_flags(self) -> None:
        args = _parse_args(
            [
                "--admin-username",
                "boss",
                "--admin-email",
                "boss@e.com",
                "--admin-password",
                "s3cret",
                "--user-username",
                "worker",
                "--user-email",
                "w@e.com",
                "--user-password",
                "pw",
            ]
        )
        assert args.admin_username == "boss"
        assert args.admin_email == "boss@e.com"
        assert args.user_username == "worker"

    def test_env_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OHE_SEED_ADMIN_USERNAME", "envadmin")
        args = _parse_args([])
        assert args.admin_username == "envadmin"

    def test_sandbox_template_tag_flag(self) -> None:
        args = _parse_args(["--sandbox-template-tag", _SEEDED_TAG])
        assert args.sandbox_template_tag == _SEEDED_TAG
        assert args.skip_sandbox_template is False

    def test_skip_sandbox_template_flag(self) -> None:
        args = _parse_args(["--skip-sandbox-template"])
        assert args.skip_sandbox_template is True

    def test_skip_sandbox_template_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OHE_SEED_SKIP_SANDBOX_TEMPLATE", "1")
        assert _parse_args([]).skip_sandbox_template is True


class TestPickLatestTag:
    def test_prefers_highest_version(self) -> None:
        tags = [
            "v1.0.0a6_nikolaik_s_python-nodejs_tag_python3.12-nodejs22_binary",
            "v1.1.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64",
            "v1.3.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64",
            "main-python",
            "9f0aa47-python",
        ]
        assert _pick_latest_tag(tags) == (
            "v1.3.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64"
        )

    def test_prefers_python_nodejs_variant(self) -> None:
        tags = [
            "v1.3.0_eclipse-temurin_tag_17-jdk-amd64",
            "v1.3.0_golang_tag_1.21-bookworm-amd64",
            "v1.3.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64",
        ]
        picked = _pick_latest_tag(tags)
        assert picked is not None
        assert picked.startswith("v1.3.0_nikolaik_s_python-nodejs")

    def test_prefers_arch_agnostic_when_available(self) -> None:
        tags = [
            "v1.0.0a6_nikolaik_s_python-nodejs_tag_python3.12-nodejs22_binary",
            "v1.0.0a6_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64",
        ]
        assert _pick_latest_tag(tags) == (
            "v1.0.0a6_nikolaik_s_python-nodejs_tag_python3.12-nodejs22_binary"
        )

    def test_falls_back_to_amd64_when_no_arch_agnostic(self) -> None:
        tags = [
            "v1.3.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-arm64",
            "v1.3.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64",
        ]
        assert _pick_latest_tag(tags) == (
            "v1.3.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64"
        )

    def test_pre_release_ranks_below_stable(self) -> None:
        tags = [
            "v1.0.0a6_nikolaik_s_python-nodejs_tag_python3.12-nodejs22_binary",
            "v1.0.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64",
        ]
        assert _pick_latest_tag(tags) == (
            "v1.0.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64"
        )

    def test_no_version_tags_returns_none(self) -> None:
        assert _pick_latest_tag(["main-python", "9f0aa47-python", "foo"]) is None

    def test_empty_returns_none(self) -> None:
        assert _pick_latest_tag([]) is None


async def _seeded_template(session: AsyncSession) -> SandboxTemplate | None:
    return await session.scalar(select(SandboxTemplate))


class TestSeedDefaultSandboxTemplate:
    async def test_seeds_template_with_expected_fields(self, session: AsyncSession) -> None:
        admin, _regular = await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            sandbox_template_tag=_SEEDED_TAG,
        )
        template = await _seeded_template(session)
        assert template is not None
        assert template.creator_id == admin.id
        assert template.docker_image_tag == _SEEDED_TAG
        assert template.working_dir == "/home/openhands"
        assert template.env_vars == {}
        assert template.snapshot_dirs == ["/home/openhands"]
        assert template.snapshot_on_deactivate is True
        assert [ExposedPort(**p) for p in template.exposed_ports] == [
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
        ]
        assert template.meta == {
            "directives": {
                "extra_hosts": {"host.docker.internal": "host-gateway"},
                "detach": True,
                "init": True,
            }
        }

    async def test_no_tag_seeds_no_template(self, session: AsyncSession) -> None:
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
        )
        assert await _seeded_template(session) is None

    async def test_rerun_updates_tag_idempotently(self, session: AsyncSession) -> None:
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            sandbox_template_tag=_SEEDED_TAG,
        )
        new_tag = "ghcr.io/openhands/agent-server:v1.4.0_nikolaik_s_python-nodejs_tag_python3.12-nodejs22-amd64"
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            sandbox_template_tag=new_tag,
        )
        templates = list((await session.scalars(select(SandboxTemplate))).all())
        assert len(templates) == 1
        assert templates[0].docker_image_tag == new_tag
