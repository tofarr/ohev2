"""Unit tests for the generic :class:`SandboxService` sandbox CRUD helpers.

These exercise the retained base-class surface (sandbox list/get/create/
update/delete, batch, permission scoping, lifecycle, and the unsupported-by-
default snapshot artifact hooks) using a minimal in-memory implementation of
the provider hooks — no Docker daemon or database required. Templates, configs,
and snapshot index rows are DB-backed and covered by their own route/service
tests; the Docker/K8s provider hooks are covered in ``test_sandbox.py`` and
``test_k8s_sandbox.py``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox
from openhands.ev2.sandbox.sandbox_models import Sandbox, SandboxStatus
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxBatchCreate,
    SandboxBatchDelete,
    SandboxCreate,
    SandboxUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    BatchPermissionDeniedError,
    SandboxNotFoundError,
    SandboxPermissionScopeError,
    SandboxService,
    SandboxSnapshotUnsupportedError,
    resolve_sandbox_service_class,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, NONE, AttributeFilter, Condition, SearchFilter


class _MemorySandboxService(SandboxService):
    """Minimal in-memory provider used to drive the shared sandbox CRUD helpers."""

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._sandboxes: dict[str, Sandbox] = {}
        self._closed = False

    async def _list_sandboxes(self) -> list[Sandbox]:
        return list(self._sandboxes.values())

    async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
        try:
            return self._sandboxes[sandbox_id]
        except KeyError:
            raise SandboxNotFoundError(sandbox_id) from None

    def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
        return DockerSandbox(
            sandbox_template_id=payload.sandbox_template_id,
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
        )

    async def _create_sandbox(self, sandbox: Sandbox, *, snapshot_id: str | None = None) -> Sandbox:
        # Assign a generated id (mimics the provider generating one).
        generated_id = f"sb-{uuid.uuid4().hex[:8]}"
        created = sandbox.model_copy(update={"id": generated_id})
        self._sandboxes[generated_id] = created
        return created

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

    async def aclose(self) -> None:
        self._closed = True


def _sandbox_payload(spec: str = "img-a") -> SandboxCreate:
    return SandboxCreate.model_validate({"sandbox_template_id": spec, "sandbox_config_id": "cfg-1"})


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
# resolve_sandbox_service_class.
# --------------------------------------------------------------------------- #


async def test_resolve_rejects_empty_class_name() -> None:
    with pytest.raises(ValueError):
        resolve_sandbox_service_class("")


async def test_resolve_rejects_nonexistent_attribute() -> None:
    with pytest.raises(TypeError):
        resolve_sandbox_service_class("openhands.ev2.sandbox.sandbox_service.NoSuchClass")


async def test_resolve_rejects_missing_module() -> None:
    with pytest.raises(ValueError):
        resolve_sandbox_service_class("nonexistent.module.Cls")


async def test_resolve_returns_subclass() -> None:
    cls = resolve_sandbox_service_class("openhands.ev2.sandbox.sandbox_service.SandboxService")
    assert cls is SandboxService


# --------------------------------------------------------------------------- #
# Helpers.
# --------------------------------------------------------------------------- #


def _deny_sandbox_id_filter(denied_id: str) -> SearchFilter[Sandbox]:
    """Return a filter that matches every sandbox except *denied_id*."""
    return AttributeFilter[Sandbox](
        attribute="id",
        value=denied_id,
        condition=Condition.NE,
    )


# --------------------------------------------------------------------------- #
# Sandbox CRUD (generic helpers over the provider hooks).
# --------------------------------------------------------------------------- #


async def test_list_sandboxes_filters_by_perm_filter() -> None:
    service = _MemorySandboxService()
    sb_a = await service.create_sandbox(_sandbox_payload())
    sb_b = await service.create_sandbox(_sandbox_payload())
    listed = await service.list_sandboxes(perm_filter=_deny_sandbox_id_filter(sb_b.id))
    assert [s.id for s in listed] == [sb_a.id]


async def test_get_sandbox_returns_sandbox() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    got = await service.get_sandbox(created.id, perm_filter=ALL)
    assert got.id == created.id


async def test_get_sandbox_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox("nope", perm_filter=ALL)


async def test_get_sandbox_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox(created.id, perm_filter=NONE)


async def test_create_sandbox_persists() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload(), perm_filter=ALL)
    assert created.id in service._sandboxes
    assert created.status is SandboxStatus.INACTIVE


async def test_create_sandbox_out_of_scope_raises_scope_error() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxPermissionScopeError):
        await service.create_sandbox(_sandbox_payload(), perm_filter=NONE)


async def test_update_sandbox_changes_desired_status() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    updated = await service.update_sandbox(
        created.id, SandboxUpdate(desired_status=SandboxStatus.ACTIVE), perm_filter=ALL
    )
    assert updated.desired_status is SandboxStatus.ACTIVE
    assert updated.status is SandboxStatus.ACTIVE


async def test_update_sandbox_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxNotFoundError):
        await service.update_sandbox(
            "nope", SandboxUpdate(desired_status=SandboxStatus.ACTIVE), perm_filter=ALL
        )


async def test_update_sandbox_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    with pytest.raises(SandboxNotFoundError):
        await service.update_sandbox(
            created.id, SandboxUpdate(desired_status=SandboxStatus.ACTIVE), perm_filter=NONE
        )


async def test_delete_sandbox_removes() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    await service.delete_sandbox(created.id, perm_filter=ALL)
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox(created.id, perm_filter=ALL)


async def test_delete_sandbox_missing_raises_not_found() -> None:
    service = _MemorySandboxService()
    with pytest.raises(SandboxNotFoundError):
        await service.delete_sandbox("nope", perm_filter=ALL)


async def test_delete_sandbox_out_of_scope_raises_not_found() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    with pytest.raises(SandboxNotFoundError):
        await service.delete_sandbox(created.id, perm_filter=NONE)


async def test_get_sandboxes_aligned_with_none() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    result = await service.get_sandboxes([created.id, "missing"], perm_filter=ALL)
    assert result[0] is not None and result[0].id == created.id
    assert result[1] is None


async def test_get_sandboxes_respects_perm_filter() -> None:
    service = _MemorySandboxService()
    sb_a = await service.create_sandbox(_sandbox_payload())
    sb_b = await service.create_sandbox(_sandbox_payload())
    result = await service.get_sandboxes(
        [sb_a.id, sb_b.id], perm_filter=_deny_sandbox_id_filter(sb_b.id)
    )
    assert result[0] is not None and result[0].id == sb_a.id
    assert result[1] is None


async def test_apply_sandbox_batch_create_and_delete() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    results = await service.apply_sandbox_batch(
        [SandboxBatchCreate(data=_sandbox_payload()), SandboxBatchDelete(id=created.id)],
        {Action.CREATE: ALL, Action.DELETE: ALL},
    )
    assert results[0] is not None
    assert results[1] is None
    assert results[0].id in service._sandboxes
    assert created.id not in service._sandboxes


async def test_apply_sandbox_batch_create_denied_raises() -> None:
    service = _MemorySandboxService()
    with pytest.raises(BatchPermissionDeniedError):
        await service.apply_sandbox_batch(
            [SandboxBatchCreate(data=_sandbox_payload())],
            {Action.CREATE: None, Action.DELETE: ALL},
        )


async def test_apply_sandbox_batch_delete_denied_raises() -> None:
    service = _MemorySandboxService()
    created = await service.create_sandbox(_sandbox_payload())
    with pytest.raises(BatchPermissionDeniedError):
        await service.apply_sandbox_batch(
            [SandboxBatchDelete(id=created.id)],
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
# Snapshot artifact hooks default to unsupported on the base class.
# --------------------------------------------------------------------------- #


async def test_base_snapshot_hooks_raise_unsupported() -> None:
    # A bare SandboxService subclass that does not override the snapshot hooks
    # inherits the unsupported defaults.
    class _BareService(SandboxService):
        async def _list_sandboxes(self) -> list[Sandbox]:
            return []

        async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
            raise SandboxNotFoundError(sandbox_id)

        def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
            raise NotImplementedError

        async def _create_sandbox(
            self, sandbox: Sandbox, *, snapshot_id: str | None = None
        ) -> Sandbox:
            raise NotImplementedError

        async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
            raise NotImplementedError

        async def _delete_sandbox(self, sandbox_id: str) -> None:
            pass

    service = _BareService()
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service.stream_snapshot("snap-a")
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service.capture_snapshot(uuid.uuid4(), "sb-a")
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service.import_snapshot_file(uuid.uuid4(), b"tar")
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service.delete_snapshot_artifact("snap-a")
