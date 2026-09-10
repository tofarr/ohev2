"""Unit tests for the generic :class:`SandboxService` CRUD helpers.

These exercise the shared base-class logic (search, count, batch, permission
scoping, error mapping, lifecycle) using a minimal in-memory implementation of
the provider hooks — no Docker daemon or database required. The Docker
implementation's provider hooks are covered separately in
``test_sandbox_v2.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

from openhands.ev2.sandbox_v2.docker_sandbox_models import DockerSandbox, DockerSandboxSnapshot
from openhands.ev2.sandbox_v2.sandbox_v2_models import (
    DockerSandboxTemplate,
    Sandbox,
    SandboxSnapshot,
    SandboxStatus,
    SandboxTemplate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_schemas import (
    SandboxBatchCreate,
    SandboxBatchDelete,
    SandboxCreate,
    SandboxSnapshotBatchDelete,
    SandboxSnapshotCreate,
    SandboxTemplateBatchCreate,
    SandboxTemplateBatchDelete,
    SandboxTemplateCreate,
    SandboxTemplateSearchFilter,
    SandboxUpdate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_service import (
    BatchPermissionDeniedError,
    SandboxConflictError,
    SandboxNotFoundError,
    SandboxPermissionScopeError,
    SandboxService,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotPermissionScopeError,
    SandboxSnapshotUnsupportedError,
    SandboxTemplateConflictError,
    SandboxTemplateNotFoundError,
    SandboxTemplatePermissionScopeError,
    resolve_sandbox_service_class,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, NONE, AttributeFilter, Condition, SearchFilter


class _MemorySandboxService(SandboxService):
    """Minimal in-memory provider used to drive the shared CRUD helpers."""

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._templates: dict[str, SandboxTemplate] = {}
        self._sandboxes: dict[str, Sandbox] = {}
        self._snapshots: dict[str, SandboxSnapshot] = {}
        self._closed = False

    async def _list_templates(self) -> list[SandboxTemplate]:
        return list(self._templates.values())

    async def _get_template(self, template_id: str) -> SandboxTemplate:
        try:
            return self._templates[template_id]
        except KeyError:
            raise SandboxTemplateNotFoundError(template_id) from None

    def _template_from_create(self, payload: SandboxTemplateCreate) -> SandboxTemplate:
        return DockerSandboxTemplate(
            id=payload.id,
            command=payload.command,
            initial_env=payload.initial_env,
            working_dir=payload.working_dir,
            idle_pause_seconds=payload.idle_pause_seconds,
            paused_delete_seconds=payload.paused_delete_seconds,
            max_age_seconds=payload.max_age_seconds,
            max_memory=payload.max_memory,
        )

    async def _create_template(self, template: SandboxTemplate) -> SandboxTemplate:
        if template.id in self._templates:
            raise SandboxTemplateConflictError(template.id)
        self._templates[template.id] = template
        return template

    async def _delete_template(self, template_id: str) -> None:
        if template_id not in self._templates:
            raise SandboxTemplateNotFoundError(template_id) from None
        del self._templates[template_id]

    async def _list_sandboxes(self) -> list[Sandbox]:
        return list(self._sandboxes.values())

    async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
        try:
            return self._sandboxes[sandbox_id]
        except KeyError:
            raise SandboxNotFoundError(sandbox_id) from None

    def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
        return DockerSandbox(
            id=payload.id,
            sandbox_spec_id=payload.sandbox_spec_id,
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
        )

    async def _create_sandbox(self, sandbox: Sandbox) -> Sandbox:
        if sandbox.id in self._sandboxes:
            raise SandboxConflictError(sandbox.id)
        self._sandboxes[sandbox.id] = sandbox
        return sandbox

    async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
        sandbox = self._sandboxes[sandbox_id]
        updated = sandbox.model_copy(
            update={
                "desired_status": payload.desired_status,
                "status": payload.desired_status,
            }
        )
        self._sandboxes[sandbox_id] = updated
        return updated

    async def _delete_sandbox(self, sandbox_id: str) -> None:
        if sandbox_id not in self._sandboxes:
            raise SandboxNotFoundError(sandbox_id) from None
        del self._sandboxes[sandbox_id]

    async def _list_snapshots(self) -> list[SandboxSnapshot]:
        return list(self._snapshots.values())

    async def _get_snapshot(self, snapshot_id: str) -> SandboxSnapshot:
        try:
            return self._snapshots[snapshot_id]
        except KeyError:
            raise SandboxSnapshotNotFoundError(snapshot_id) from None

    async def _snapshot_from_sandbox(
        self,
        payload: SandboxSnapshotCreate,
        sandbox: Sandbox,
    ) -> SandboxSnapshot:
        return DockerSandboxSnapshot(
            id=payload.id,
            image_id=f"img-{payload.id}",
            sandbox_id=sandbox.id,
            download_url=f"/sandbox_v2/sandbox-snapshots/{payload.id}/download",
        )

    async def _snapshot_from_file(
        self,
        payload: SandboxSnapshotCreate,
    ) -> SandboxSnapshot:
        return DockerSandboxSnapshot(
            id=payload.id,
            image_id=f"img-{payload.id}",
            sandbox_id=None,
            download_url=f"/sandbox_v2/sandbox-snapshots/{payload.id}/download",
        )

    async def _create_snapshot(
        self,
        snapshot: SandboxSnapshot,
        payload: SandboxSnapshotCreate,
    ) -> SandboxSnapshot:
        if snapshot.id in self._snapshots:
            raise SandboxSnapshotConflictError(snapshot.id)
        self._snapshots[snapshot.id] = snapshot
        return snapshot

    async def _delete_snapshot(self, snapshot_id: str) -> None:
        if snapshot_id not in self._snapshots:
            raise SandboxSnapshotNotFoundError(snapshot_id) from None
        del self._snapshots[snapshot_id]

    async def aclose(self) -> None:
        self._closed = True


def _create_payload(template_id: str = "img-a", **overrides: Any) -> SandboxTemplateCreate:
    return SandboxTemplateCreate.model_validate({"id": template_id, **overrides})


# --------------------------------------------------------------------------- #
# Lifecycle (async context manager).
# --------------------------------------------------------------------------- #


async def test_aenter_returns_self() -> None:
    service = _MemorySandboxService()
    async with service as ctx:
        assert ctx is service


async def test_aexit_invokes_aclose() -> None:
    service = _MemorySandboxService()
    await service.__aenter__()
    await service.__aexit__(None, None, None)
    assert service._closed is True


async def test_aclose_default_is_noop() -> None:
    # A service that does not override aclose inherits the no-op default.
    base = object.__new__(_MemorySandboxService)  # type: ignore[abstract]
    assert await SandboxService.aclose(base) is None  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# list_templates / get_template (permission scoping).
# --------------------------------------------------------------------------- #


async def test_list_templates_filters_by_perm_filter() -> None:
    service = _MemorySandboxService()
    a = _create_payload("img-a")
    b = _create_payload("img-b")
    await service.create_template(a)
    await service.create_template(b)
    deny_b = _deny_id_filter("img-b")
    visible = await service.list_templates(perm_filter=deny_b)
    assert [t.id for t in visible] == ["img-a"]


async def test_get_template_returns_template() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    template = await service.get_template("img-a")
    assert template.id == "img-a"


async def test_get_template_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxTemplateNotFoundError):
        await service.get_template("nope")


async def test_get_template_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    with pytest.raises(SandboxTemplateNotFoundError):
        await service.get_template("img-a", perm_filter=NONE)


# --------------------------------------------------------------------------- #
# create_template (permission scoping + provider conflict).
# --------------------------------------------------------------------------- #


async def test_create_template_persists() -> None:
    service = _MemorySandboxService()
    template = await service.create_template(_create_payload("img-a"))
    assert template.id == "img-a"
    assert (await service.get_template("img-a")).id == "img-a"


async def test_create_template_out_of_scope_raises_scope_error() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxTemplatePermissionScopeError):
        await service.create_template(_create_payload("img-a"), perm_filter=NONE)


async def test_create_template_conflict_propagates() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    with pytest.raises(SandboxTemplateConflictError):
        await service.create_template(_create_payload("img-a"))


# --------------------------------------------------------------------------- #
# delete_template (scopes via get_template, provider missing).
# --------------------------------------------------------------------------- #


async def test_delete_template_removes() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    await service.delete_template("img-a")
    with pytest.raises(SandboxTemplateNotFoundError):
        await service.get_template("img-a")


async def test_delete_template_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxTemplateNotFoundError):
        await service.delete_template("nope")


async def test_delete_template_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    with pytest.raises(SandboxTemplateNotFoundError):
        await service.delete_template("img-a", perm_filter=NONE)


# --------------------------------------------------------------------------- #
# get_templates (batch read).
# --------------------------------------------------------------------------- #


async def test_get_templates_aligned_with_none() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    await service.create_template(_create_payload("img-b"))
    results = await service.get_templates(["img-a", "missing", "img-b"])
    assert results[0] is not None and results[0].id == "img-a"
    assert results[1] is None
    assert results[2] is not None and results[2].id == "img-b"


async def test_get_templates_empty_list() -> None:
    service = _MemorySandboxService()
    assert await service.get_templates([]) == []


async def test_get_templates_respects_perm_filter() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    await service.create_template(_create_payload("img-b"))
    deny_a = _deny_id_filter("img-a")
    results = await service.get_templates(["img-a", "img-b"], perm_filter=deny_a)
    assert results[0] is None
    assert results[1] is not None and results[1].id == "img-b"


# --------------------------------------------------------------------------- #
# search_templates (sort, cursor, search_filter, next_cursor).
# --------------------------------------------------------------------------- #


async def test_search_templates_sorts_by_id() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-c"))
    await service.create_template(_create_payload("img-a"))
    await service.create_template(_create_payload("img-b"))
    page, next_cursor = await service.search_templates(limit=10)
    assert [t.id for t in page] == ["img-a", "img-b", "img-c"]
    assert next_cursor is None


async def test_search_templates_cursor_advances() -> None:
    service = _MemorySandboxService()
    for name in ("img-a", "img-b", "img-c"):
        await service.create_template(_create_payload(name))
    page, next_cursor = await service.search_templates(cursor="img-a", limit=10)
    assert [t.id for t in page] == ["img-b", "img-c"]
    assert next_cursor is None


async def test_search_templates_next_cursor_when_more_than_limit() -> None:
    service = _MemorySandboxService()
    for name in ("img-a", "img-b", "img-c"):
        await service.create_template(_create_payload(name))
    page, next_cursor = await service.search_templates(limit=2)
    assert [t.id for t in page] == ["img-a", "img-b"]
    assert next_cursor == "img-b"


async def test_search_templates_applies_search_filter() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a", idle_pause_seconds=10))
    await service.create_template(_create_payload("img-b", idle_pause_seconds=20))
    flt = SandboxTemplateSearchFilter.model_validate({"idle_pause_seconds__eq": 10})
    page, _ = await service.search_templates(search_filter=flt, limit=10)
    assert [t.id for t in page] == ["img-a"]


async def test_search_templates_respects_perm_filter() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    await service.create_template(_create_payload("img-b"))
    deny_a = _deny_id_filter("img-a")
    page, _ = await service.search_templates(perm_filter=deny_a, limit=10)
    assert [t.id for t in page] == ["img-b"]


# --------------------------------------------------------------------------- #
# count_templates.
# --------------------------------------------------------------------------- #


async def test_count_templates_total() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    await service.create_template(_create_payload("img-b"))
    assert await service.count_templates() == 2


async def test_count_templates_with_search_filter() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a", idle_pause_seconds=10))
    await service.create_template(_create_payload("img-b", idle_pause_seconds=20))
    flt = SandboxTemplateSearchFilter.model_validate({"idle_pause_seconds__eq": 10})
    assert await service.count_templates(flt) == 1


async def test_count_templates_respects_perm_filter() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    await service.create_template(_create_payload("img-b"))
    deny_a = _deny_id_filter("img-a")
    assert await service.count_templates(perm_filter=deny_a) == 1


# --------------------------------------------------------------------------- #
# apply_batch (mixed create/update/delete + permission denial).
# --------------------------------------------------------------------------- #


async def test_apply_batch_mixed_create_delete() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    results = await service.apply_batch(
        [
            SandboxTemplateBatchCreate(data=_create_payload("img-b")),
            SandboxTemplateBatchDelete(id="img-a"),
        ],
        {Action.CREATE: ALL, Action.DELETE: ALL},
    )
    assert results[0] is not None and results[0].id == "img-b"
    assert results[1] is None
    with pytest.raises(SandboxTemplateNotFoundError):
        await service.get_template("img-a")


async def test_apply_batch_create_denied_raises() -> None:
    service = _MemorySandboxService()
    with pytest.raises(BatchPermissionDeniedError):
        await service.apply_batch(
            [SandboxTemplateBatchCreate(data=_create_payload("img-a"))],
            {Action.CREATE: None, Action.DELETE: ALL},
        )


async def test_apply_batch_delete_denied_raises() -> None:
    service = _MemorySandboxService()
    await service.create_template(_create_payload("img-a"))
    with pytest.raises(BatchPermissionDeniedError):
        await service.apply_batch(
            [SandboxTemplateBatchDelete(id="img-a")],
            {Action.CREATE: ALL, Action.DELETE: None},
        )


async def test_apply_batch_unknown_op_raises_type_error() -> None:
    service = _MemorySandboxService()

    class _Unknown:
        pass

    with pytest.raises(TypeError):
        await service.apply_batch(  # type: ignore[list-item]
            [_Unknown()],
            {Action.CREATE: ALL, Action.DELETE: ALL},
        )


async def test_apply_batch_create_perm_filter_scopes_create() -> None:
    service = _MemorySandboxService()
    deny_a = _deny_id_filter("img-a")
    with pytest.raises(SandboxTemplatePermissionScopeError):
        await service.apply_batch(
            [SandboxTemplateBatchCreate(data=_create_payload("img-a"))],
            {Action.CREATE: deny_a, Action.DELETE: ALL},
        )


# --------------------------------------------------------------------------- #
# resolve_sandbox_service_class (factory error paths beyond the happy path).
# --------------------------------------------------------------------------- #


async def test_resolve_rejects_empty_class_name() -> None:
    with pytest.raises(ValueError):
        resolve_sandbox_service_class("no_module_segment")


async def test_resolve_rejects_nonexistent_attribute() -> None:
    with pytest.raises(TypeError):
        resolve_sandbox_service_class("openhands.ev2.sandbox_v2.sandbox_v2_service.NotARealService")


# --------------------------------------------------------------------------- #
# Helpers.
# --------------------------------------------------------------------------- #


def _deny_id_filter(denied_id: str) -> SearchFilter[SandboxTemplate]:
    """Return a filter that matches every template except *denied_id*."""
    return AttributeFilter[SandboxTemplate](
        attribute="id",
        value=denied_id,
        condition=Condition.NE,
    )


def _deny_sandbox_id_filter(denied_id: str) -> SearchFilter[Sandbox]:
    """Return a filter that matches every sandbox except *denied_id*."""
    return AttributeFilter[Sandbox](
        attribute="id",
        value=denied_id,
        condition=Condition.NE,
    )


def _deny_snapshot_id_filter(denied_id: str) -> SearchFilter[SandboxSnapshot]:
    """Return a filter that matches every snapshot except *denied_id*."""
    return AttributeFilter[SandboxSnapshot](
        attribute="id",
        value=denied_id,
        condition=Condition.NE,
    )


def _sandbox_payload(sandbox_id: str = "sb-a", spec: str = "img-a") -> SandboxCreate:
    return SandboxCreate.model_validate({"id": sandbox_id, "sandbox_spec_id": spec})


# --------------------------------------------------------------------------- #
# Sandbox CRUD (generic helpers over the provider hooks).
# --------------------------------------------------------------------------- #


async def test_list_sandboxes_filters_by_perm_filter() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    await service.create_sandbox(_sandbox_payload("sb-b"))
    visible = await service.list_sandboxes(perm_filter=_deny_sandbox_id_filter("sb-b"))
    assert [sb.id for sb in visible] == ["sb-a"]


async def test_get_sandbox_returns_sandbox() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    sandbox = await service.get_sandbox("sb-a")
    assert sandbox.id == "sb-a"


async def test_get_sandbox_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox("nope")


async def test_get_sandbox_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox("sb-a", perm_filter=NONE)


async def test_create_sandbox_persists() -> None:
    service = _MemorySandboxService()
    sandbox = await service.create_sandbox(_sandbox_payload("sb-a"))
    assert sandbox.id == "sb-a"
    assert (await service.get_sandbox("sb-a")).id == "sb-a"


async def test_create_sandbox_out_of_scope_raises_scope_error() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxPermissionScopeError):
        await service.create_sandbox(_sandbox_payload("sb-a"), perm_filter=NONE)


async def test_create_sandbox_conflict_propagates() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    with pytest.raises(SandboxConflictError):
        await service.create_sandbox(_sandbox_payload("sb-a"))


async def test_update_sandbox_changes_desired_status() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    updated = await service.update_sandbox(
        "sb-a", SandboxUpdate.model_validate({"desired_status": "active"})
    )
    assert updated.desired_status is SandboxStatus.ACTIVE
    assert updated.status is SandboxStatus.ACTIVE


async def test_update_sandbox_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxNotFoundError):
        await service.update_sandbox(
            "nope", SandboxUpdate.model_validate({"desired_status": "active"})
        )


async def test_update_sandbox_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    with pytest.raises(SandboxNotFoundError):
        await service.update_sandbox(
            "sb-a", SandboxUpdate.model_validate({"desired_status": "active"}), perm_filter=NONE
        )


async def test_delete_sandbox_removes() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    await service.delete_sandbox("sb-a")
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox("sb-a")


async def test_delete_sandbox_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxNotFoundError):
        await service.delete_sandbox("nope")


async def test_delete_sandbox_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    with pytest.raises(SandboxNotFoundError):
        await service.delete_sandbox("sb-a", perm_filter=NONE)


async def test_get_sandboxes_aligned_with_none() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    await service.create_sandbox(_sandbox_payload("sb-b"))
    results = await service.get_sandboxes(["sb-a", "missing", "sb-b"])
    assert results[0] is not None and results[0].id == "sb-a"
    assert results[1] is None
    assert results[2] is not None and results[2].id == "sb-b"


async def test_get_sandboxes_respects_perm_filter() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    await service.create_sandbox(_sandbox_payload("sb-b"))
    results = await service.get_sandboxes(
        ["sb-a", "sb-b"], perm_filter=_deny_sandbox_id_filter("sb-a")
    )
    assert results[0] is None
    assert results[1] is not None and results[1].id == "sb-b"


async def test_apply_sandbox_batch_create_and_delete() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    results = await service.apply_sandbox_batch(
        [
            SandboxBatchCreate(data=_sandbox_payload("sb-b")),
            SandboxBatchDelete(id="sb-a"),
        ],
        {Action.CREATE: ALL, Action.DELETE: ALL},
    )
    assert results[0] is not None and results[0].id == "sb-b"
    assert results[1] is None
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox("sb-a")


async def test_apply_sandbox_batch_create_denied_raises() -> None:
    service = _MemorySandboxService()
    with pytest.raises(BatchPermissionDeniedError):
        await service.apply_sandbox_batch(
            [SandboxBatchCreate(data=_sandbox_payload("sb-a"))],
            {Action.CREATE: None, Action.DELETE: ALL},
        )


async def test_apply_sandbox_batch_delete_denied_raises() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload("sb-a"))
    with pytest.raises(BatchPermissionDeniedError):
        await service.apply_sandbox_batch(
            [SandboxBatchDelete(id="sb-a")],
            {Action.CREATE: ALL, Action.DELETE: None},
        )


async def test_apply_sandbox_batch_unknown_op_raises_type_error() -> None:
    service = _MemorySandboxService()

    class _Unknown:
        pass

    with pytest.raises(TypeError):
        await service.apply_sandbox_batch(  # type: ignore[list-item]
            [_Unknown()],
            {Action.CREATE: ALL, Action.DELETE: ALL},
        )


# --------------------------------------------------------------------------- #
# Snapshot CRUD (generic helpers over the provider hooks).
# --------------------------------------------------------------------------- #


def _snapshot_from_sandbox_payload(
    snapshot_id: str = "snap-a",
    sandbox_id: str = "sb-a",
) -> SandboxSnapshotCreate:
    return SandboxSnapshotCreate.model_validate({"id": snapshot_id, "sandbox_id": sandbox_id})


def _snapshot_from_file_payload(snapshot_id: str = "snap-b") -> SandboxSnapshotCreate:
    return SandboxSnapshotCreate.model_validate(
        {"id": snapshot_id, "schema_type": "docker", "file_data": b"tarball-bytes"}
    )


async def test_create_snapshot_from_sandbox_persists() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)

    snapshot = await service.create_snapshot(
        _snapshot_from_sandbox_payload(),
        perm_filter=ALL,
        sandbox_perm_filter=ALL,
    )

    assert snapshot.id == "snap-a"
    assert snapshot.sandbox_id == "sb-a"
    assert snapshot.download_url is not None
    listed = await service.list_snapshots(perm_filter=ALL)
    assert [s.id for s in listed] == ["snap-a"]


async def test_create_snapshot_from_file_persists() -> None:
    service = _MemorySandboxService()
    snapshot = await service.create_snapshot(_snapshot_from_file_payload(), perm_filter=ALL)
    assert snapshot.id == "snap-b"
    assert snapshot.sandbox_id is None
    listed = await service.list_snapshots(perm_filter=ALL)
    assert [s.id for s in listed] == ["snap-b"]


async def test_create_snapshot_out_of_scope_raises_scope_error() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    with pytest.raises(SandboxSnapshotPermissionScopeError):
        await service.create_snapshot(
            _snapshot_from_sandbox_payload(),
            perm_filter=NONE,
            sandbox_perm_filter=ALL,
        )


async def test_create_snapshot_from_missing_sandbox_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxNotFoundError):
        await service.create_snapshot(
            _snapshot_from_sandbox_payload(sandbox_id="nope"),
            perm_filter=ALL,
            sandbox_perm_filter=ALL,
        )


async def test_create_snapshot_conflict_raises() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    payload = _snapshot_from_sandbox_payload()
    await service.create_snapshot(payload, perm_filter=ALL, sandbox_perm_filter=ALL)
    with pytest.raises(SandboxSnapshotConflictError):
        await service.create_snapshot(payload, perm_filter=ALL, sandbox_perm_filter=ALL)


async def test_get_snapshot_returns_snapshot() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload(), perm_filter=ALL, sandbox_perm_filter=ALL
    )
    snapshot = await service.get_snapshot("snap-a", perm_filter=ALL)
    assert snapshot.id == "snap-a"


async def test_get_snapshot_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.get_snapshot("nope", perm_filter=ALL)


async def test_get_snapshot_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload(), perm_filter=ALL, sandbox_perm_filter=ALL
    )
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.get_snapshot("snap-a", perm_filter=NONE)


async def test_list_snapshots_filters_by_perm_filter() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload("snap-a", "sb-a"),
        perm_filter=ALL,
        sandbox_perm_filter=ALL,
    )
    await service.create_snapshot(
        _snapshot_from_sandbox_payload("snap-b", "sb-a"),
        perm_filter=ALL,
        sandbox_perm_filter=ALL,
    )
    listed = await service.list_snapshots(perm_filter=_deny_snapshot_id_filter("snap-a"))
    assert [s.id for s in listed] == ["snap-b"]


async def test_delete_snapshot_removes() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload(), perm_filter=ALL, sandbox_perm_filter=ALL
    )
    await service.delete_snapshot("snap-a", perm_filter=ALL)
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.get_snapshot("snap-a", perm_filter=ALL)


async def test_delete_snapshot_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.delete_snapshot("nope", perm_filter=ALL)


async def test_delete_snapshot_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload(), perm_filter=ALL, sandbox_perm_filter=ALL
    )
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.delete_snapshot("snap-a", perm_filter=NONE)


async def test_get_snapshots_aligned_with_none() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload("snap-a", "sb-a"),
        perm_filter=ALL,
        sandbox_perm_filter=ALL,
    )
    result = await service.get_snapshots(["snap-a", "snap-b"], perm_filter=ALL)
    assert result[0] is not None and result[0].id == "snap-a"
    assert result[1] is None


async def test_search_snapshots_paginates_with_cursor() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    for i in range(5):
        await service.create_snapshot(
            _snapshot_from_sandbox_payload(f"snap-{i}", "sb-a"),
            perm_filter=ALL,
            sandbox_perm_filter=ALL,
        )
    page, next_cursor = await service.search_snapshots(cursor=None, limit=2, perm_filter=ALL)
    assert [s.id for s in page] == ["snap-0", "snap-1"]
    assert next_cursor == "snap-1"
    page, next_cursor = await service.search_snapshots(cursor=next_cursor, limit=2, perm_filter=ALL)
    assert [s.id for s in page] == ["snap-2", "snap-3"]
    assert next_cursor == "snap-3"
    page, next_cursor = await service.search_snapshots(cursor=next_cursor, limit=2, perm_filter=ALL)
    assert [s.id for s in page] == ["snap-4"]
    assert next_cursor is None


async def test_count_snapshots_respects_perm_filter() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload("snap-a", "sb-a"),
        perm_filter=ALL,
        sandbox_perm_filter=ALL,
    )
    await service.create_snapshot(
        _snapshot_from_sandbox_payload("snap-b", "sb-a"),
        perm_filter=ALL,
        sandbox_perm_filter=ALL,
    )
    assert await service.count_snapshots(perm_filter=ALL) == 2
    assert await service.count_snapshots(perm_filter=_deny_snapshot_id_filter("snap-a")) == 1


async def test_apply_snapshot_batch_delete_succeeds() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload("snap-a", "sb-a"),
        perm_filter=ALL,
        sandbox_perm_filter=ALL,
    )
    results = await service.apply_snapshot_batch(
        [SandboxSnapshotBatchDelete(id="snap-a")],
        {Action.DELETE: ALL},
    )
    assert results == [None]
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.get_snapshot("snap-a", perm_filter=ALL)


async def test_apply_snapshot_batch_delete_denied_raises() -> None:
    service = _MemorySandboxService()
    await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    await service.create_snapshot(
        _snapshot_from_sandbox_payload("snap-a", "sb-a"),
        perm_filter=ALL,
        sandbox_perm_filter=ALL,
    )
    with pytest.raises(BatchPermissionDeniedError):
        await service.apply_snapshot_batch(
            [SandboxSnapshotBatchDelete(id="snap-a")],
            {Action.DELETE: None},
        )


async def test_apply_snapshot_batch_unknown_op_raises_type_error() -> None:
    service = _MemorySandboxService()

    class _Unknown:
        pass

    with pytest.raises(TypeError):
        await service.apply_snapshot_batch(  # type: ignore[list-item]
            [_Unknown()],
            {Action.DELETE: ALL},
        )


async def test_unsupported_snapshot_service_raises_unsupported() -> None:

    class _UnsupportedService(SandboxService):
        async def _list_templates(self) -> list[SandboxTemplate]:
            return []

        async def _get_template(self, template_id: str) -> SandboxTemplate:
            raise SandboxTemplateNotFoundError(template_id)

        def _template_from_create(self, payload: SandboxTemplateCreate) -> SandboxTemplate:
            raise NotImplementedError

        async def _create_template(self, template: SandboxTemplate) -> SandboxTemplate:
            raise NotImplementedError

        async def _delete_template(self, template_id: str) -> None:
            pass

        async def _list_sandboxes(self) -> list[Sandbox]:
            return []

        async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
            raise SandboxNotFoundError(sandbox_id)

        def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
            raise NotImplementedError

        async def _create_sandbox(self, sandbox: Sandbox) -> Sandbox:
            raise NotImplementedError

        async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
            raise NotImplementedError

        async def _delete_sandbox(self, sandbox_id: str) -> None:
            pass

        async def aclose(self) -> None:
            pass

    service = _UnsupportedService()
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service.list_snapshots(perm_filter=ALL)
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service.stream_snapshot("snap-a")
