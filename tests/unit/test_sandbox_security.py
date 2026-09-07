"""Unit tests for the sandbox permission policies and their search filters."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role, UserRole
from openhands.ev2.sandbox.sandbox_models import (
    RoleSandboxPermission,
    RoleSandboxSnapshotPermission,
    RoleSandboxTemplatePermission,
    SandboxTemplate,
)
from openhands.ev2.sandbox.sandbox_security import (
    SandboxAccessFilter,
    SandboxResourceAccess,
    SandboxSnapshotAccess,
    SandboxTemplateAccess,
)
from openhands.ev2.security.security_models import Action, Permitted
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter


async def _seed_template_grant(
    session: AsyncSession,
    *,
    read: bool = False,
    update: bool = False,
    delete: bool = False,
) -> tuple[User, SandboxTemplate, Role]:
    user = User(email="sb@example.com", username="sb")
    role = Role(name="r-" + uuid.uuid4().hex[:8])
    session.add(user)
    session.add(role)
    await session.flush()
    from openhands.ev2.sandbox.sandbox_models import (
        DockerSandboxTemplateSpec,
        FuseySandboxStorageSpec,
        OpenHandsAgentServerSpec,
    )

    template = SandboxTemplate(
        name="t-" + uuid.uuid4().hex[:6],
        provider_kind="docker",
        template_spec=DockerSandboxTemplateSpec(image="img"),
        server_spec=OpenHandsAgentServerSpec(internal_port=18000),
        storage_spec=FuseySandboxStorageSpec(mount_path="/ws"),
        user_id=user.id,
    )
    session.add(template)
    await session.flush()
    session.add(UserRole(role_id=role.id, user_id=user.id))
    session.add(
        RoleSandboxTemplatePermission(
            role_id=role.id,
            sandbox_template_id=template.id,
            read_enabled=read,
            update_enabled=update,
            delete_enabled=delete,
        )
    )
    await session.flush()
    return user, template, role


class TestSandboxAccessReduction:
    def test_create_yields_all_filter(self) -> None:
        filt = SandboxTemplateAccess().to_search_filter(uuid.uuid4(), Action.CREATE)
        assert isinstance(filt, AllSearchFilter)

    def test_anonymous_read_yields_none_filter(self) -> None:
        filt = SandboxTemplateAccess().to_search_filter(None, Action.READ)
        assert isinstance(filt, NoneSearchFilter)

    def test_read_yields_read_flag_filter(self) -> None:
        uid = uuid.uuid4()
        filt = SandboxTemplateAccess().to_search_filter(uid, Action.READ)
        assert isinstance(filt, SandboxAccessFilter)
        assert filt.flag == "read_enabled"
        assert filt.user_id == uid

    def test_search_uses_read_flag(self) -> None:
        filt = SandboxTemplateAccess().to_search_filter(uuid.uuid4(), Action.SEARCH)
        assert isinstance(filt, SandboxAccessFilter)
        assert filt.flag == "read_enabled"

    def test_update_yields_update_flag(self) -> None:
        filt = SandboxTemplateAccess().to_search_filter(uuid.uuid4(), Action.UPDATE)
        assert isinstance(filt, SandboxAccessFilter)
        assert filt.flag == "update_enabled"

    def test_delete_yields_delete_flag(self) -> None:
        filt = SandboxTemplateAccess().to_search_filter(uuid.uuid4(), Action.DELETE)
        assert isinstance(filt, SandboxAccessFilter)
        assert filt.flag == "delete_enabled"

    def test_resource_access_uses_sandbox_grant_model(self) -> None:
        filt = SandboxResourceAccess().to_search_filter(uuid.uuid4(), Action.READ)
        assert isinstance(filt, SandboxAccessFilter)
        assert filt.grant_model is RoleSandboxPermission
        assert filt.grant_resource_fk == "sandbox_id"

    def test_snapshot_access_uses_snapshot_grant_model(self) -> None:
        filt = SandboxSnapshotAccess().to_search_filter(uuid.uuid4(), Action.READ)
        assert isinstance(filt, SandboxAccessFilter)
        assert filt.grant_model is RoleSandboxSnapshotPermission
        assert filt.grant_resource_fk == "sandbox_snapshot_id"

    def test_template_access_uses_template_grant_model(self) -> None:
        filt = SandboxTemplateAccess().to_search_filter(uuid.uuid4(), Action.READ)
        assert isinstance(filt, SandboxAccessFilter)
        assert filt.grant_model is RoleSandboxTemplatePermission
        assert filt.grant_resource_fk == "sandbox_template_id"

    def test_matches_is_permissive(self) -> None:
        filt = SandboxAccessFilter(
            user_id=uuid.uuid4(),
            flag="read_enabled",
            grant_model=RoleSandboxTemplatePermission,
            resource_model=SandboxTemplate,
            grant_resource_fk="sandbox_template_id",
        )
        assert filt.matches(object()) is True


class TestSandboxAccessFilterSql:
    async def test_read_filter_admits_only_granted(self, session: AsyncSession) -> None:
        user, template, _ = await _seed_template_grant(session, read=True)
        from openhands.ev2.sandbox.sandbox_models import (
            DockerSandboxTemplateSpec,
            FuseySandboxStorageSpec,
            OpenHandsAgentServerSpec,
        )

        other = SandboxTemplate(
            name="other",
            provider_kind="docker",
            template_spec=DockerSandboxTemplateSpec(image="img2"),
            server_spec=OpenHandsAgentServerSpec(internal_port=18000),
            storage_spec=FuseySandboxStorageSpec(mount_path="/ws2"),
            user_id=user.id,
        )
        session.add(other)
        await session.flush()

        filt = SandboxAccessFilter(
            user_id=user.id,
            flag="read_enabled",
            grant_model=RoleSandboxTemplatePermission,
            resource_model=SandboxTemplate,
            grant_resource_fk="sandbox_template_id",
        )
        stmt = filt.filter_sql(select(SandboxTemplate).order_by(SandboxTemplate.name))
        result = (await session.execute(stmt)).scalars().all()
        ids = {t.id for t in result}
        assert template.id in ids
        assert other.id not in ids

    async def test_read_filter_excludes_when_flag_disabled(self, session: AsyncSession) -> None:
        user, template, _ = await _seed_template_grant(session, read=False, update=True)
        filt = SandboxAccessFilter(
            user_id=user.id,
            flag="read_enabled",
            grant_model=RoleSandboxTemplatePermission,
            resource_model=SandboxTemplate,
            grant_resource_fk="sandbox_template_id",
        )
        stmt = filt.filter_sql(select(SandboxTemplate))
        result = (await session.execute(stmt)).scalars().all()
        assert template.id not in {t.id for t in result}

    async def test_update_filter_admits_update_grant(self, session: AsyncSession) -> None:
        user, template, _ = await _seed_template_grant(session, update=True)
        filt = SandboxAccessFilter(
            user_id=user.id,
            flag="update_enabled",
            grant_model=RoleSandboxTemplatePermission,
            resource_model=SandboxTemplate,
            grant_resource_fk="sandbox_template_id",
        )
        stmt = filt.filter_sql(select(SandboxTemplate))
        result = (await session.execute(stmt)).scalars().all()
        assert template.id in {t.id for t in result}

    async def test_filter_excludes_other_users(self, session: AsyncSession) -> None:
        _user, template, _ = await _seed_template_grant(session, read=True)
        filt = SandboxAccessFilter(
            user_id=uuid.uuid4(),
            flag="read_enabled",
            grant_model=RoleSandboxTemplatePermission,
            resource_model=SandboxTemplate,
            grant_resource_fk="sandbox_template_id",
        )
        stmt = filt.filter_sql(select(SandboxTemplate))
        result = (await session.execute(stmt)).scalars().all()
        assert template.id not in {t.id for t in result}


class TestPermittedBypassesGrants:
    async def test_permitted_sees_all(self, session: AsyncSession) -> None:
        for action in (Action.READ, Action.UPDATE, Action.DELETE, Action.SEARCH, Action.CREATE):
            assert isinstance(Permitted().to_search_filter(uuid.uuid4(), action), AllSearchFilter)
