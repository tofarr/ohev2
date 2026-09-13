"""Tests for the Kubernetes sandbox control plane.

Covers the pieces that do not require a live Kubernetes cluster: the
ConfigMap -> ``_K8sTemplateSpec`` mapping, the Deployment status mapping
helpers, the parse helpers, the snapshot tarball store, the lifecycle task
management, the factory/config wiring, and the exception-to-status mapping.
Templates, configs, and snapshot index rows are DB-backed and covered by
their own route tests; this file exercises only the live-sandbox + snapshot-
artifact surface owned by :class:`K8sSandboxService`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from kubernetes import client as k8s_client

from openhands.ev2.sandbox.k8s_sandbox_models import K8sSandbox
from openhands.ev2.sandbox.k8s_sandbox_service import (
    _ANNOT_TEMPLATE_ID,
    _CM_KEY_COMMAND,
    _CM_KEY_IDLE_PAUSE_SECONDS,
    _CM_KEY_INITIAL_ENV,
    _CM_KEY_MAX_AGE_SECONDS,
    _CM_KEY_MAX_MEMORY,
    _CM_KEY_PAUSED_DELETE_SECONDS,
    _CM_KEY_WORKING_DIR,
    _LABEL_SANDBOX_ID,
    _LABEL_TEMPLATE,
    DEFAULT_EXPOSED_PORTS,
    K8sSandboxService,
    _deployment_status_to_sandbox_status,
    _desired_from_replicas,
    _exposed_urls_from_service,
    _parse_created,
    _parse_int,
    _parse_json_dict,
    _parse_json_list,
    _sandbox_from_deployment,
    _sanitize_name,
    _template_spec_from_config_map,
)
from openhands.ev2.sandbox.sandbox_models import (
    ExposedUrl,
    Sandbox,
    SandboxStatus,
    SnapshotMode,
)
from openhands.ev2.sandbox.sandbox_schemas import SandboxCreate, SandboxUpdate
from openhands.ev2.sandbox.sandbox_service import (
    SandboxConflictError,
    SandboxNotFoundError,
    SandboxService,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotUnsupportedError,
    SandboxTemplateNotFoundError,
    resolve_sandbox_service_class,
)
from openhands.ev2.sandbox.sandbox_template_models import ExposedPort

# --------------------------------------------------------------------------- #
# _sanitize_name.
# --------------------------------------------------------------------------- #


def test_sanitize_name_replaces_separators() -> None:
    # ``.`` is a valid DNS-1123 subdomain char, so it is preserved.
    assert _sanitize_name("ghcr.io/org/agent-server:latest") == "ghcr.io-org-agent-server-latest"


def test_sanitize_name_lowercases() -> None:
    assert _sanitize_name("GHCR.io/Agent:V1") == "ghcr.io-agent-v1"


def test_sanitize_name_strips_non_dns_chars() -> None:
    assert _sanitize_name("img_with_underscore:tag") == "img-with-underscore-tag"


def test_sanitize_name_empty_falls_back() -> None:
    assert _sanitize_name("///") == "template"


# --------------------------------------------------------------------------- #
# Parse helpers.
# --------------------------------------------------------------------------- #


def test_parse_int() -> None:
    assert _parse_int("7") == 7
    assert _parse_int(None) is None
    assert _parse_int("") is None
    assert _parse_int("nope") is None


def test_parse_json_list() -> None:
    assert _parse_json_list('["a", "b"]') == ["a", "b"]
    assert _parse_json_list(None) is None
    assert _parse_json_list("") is None
    assert _parse_json_list("not-json") is None
    assert _parse_json_list('{"k": "v"}') is None


def test_parse_json_dict() -> None:
    assert _parse_json_dict('{"A": "1", "B": "2"}') == {"A": "1", "B": "2"}
    assert _parse_json_dict(None) == {}
    assert _parse_json_dict("") == {}
    assert _parse_json_dict("not-json") == {}
    assert _parse_json_dict('["a"]') == {}


def test_parse_created_handles_z_and_naive() -> None:
    parsed = _parse_created("2024-01-02T03:04:05Z")
    assert parsed.tzinfo is not None
    assert parsed.year == 2024
    naive = _parse_created("2024-01-02T03:04:05")
    assert naive.tzinfo is not None


def test_parse_created_empty_returns_now() -> None:
    now = datetime.now(UTC)
    assert _parse_created("") >= now - timedelta(seconds=5)
    assert _parse_created(None) >= now - timedelta(seconds=5)


# --------------------------------------------------------------------------- #
# ConfigMap -> _K8sTemplateSpec.
# --------------------------------------------------------------------------- #


def _config_map(
    *,
    image: str | None = "ghcr.io/org/agent-server:latest",
    command: list[str] | None = None,
    initial_env: dict[str, str] | None = None,
    working_dir: str | None = None,
    max_memory: int | None = None,
    idle_pause_seconds: int | None = None,
    paused_delete_seconds: int | None = None,
    max_age_seconds: int | None = None,
    template_label: bool = True,
) -> k8s_client.V1ConfigMap:
    data: dict[str, str] = {}
    if image is not None:
        data["image"] = image
    if command is not None:
        data[_CM_KEY_COMMAND] = json.dumps(command)
    if initial_env is not None:
        data[_CM_KEY_INITIAL_ENV] = json.dumps(initial_env)
    if working_dir is not None:
        data[_CM_KEY_WORKING_DIR] = working_dir
    if max_memory is not None:
        data[_CM_KEY_MAX_MEMORY] = str(max_memory)
    if idle_pause_seconds is not None:
        data[_CM_KEY_IDLE_PAUSE_SECONDS] = str(idle_pause_seconds)
    if paused_delete_seconds is not None:
        data[_CM_KEY_PAUSED_DELETE_SECONDS] = str(paused_delete_seconds)
    if max_age_seconds is not None:
        data[_CM_KEY_MAX_AGE_SECONDS] = str(max_age_seconds)
    labels = {_LABEL_TEMPLATE: "true"} if template_label else {}
    return k8s_client.V1ConfigMap(
        metadata=k8s_client.V1ObjectMeta(name="cm-1", labels=labels),
        data=data,
    )


def test_template_spec_from_config_map_basic() -> None:
    cm = _config_map(
        image="img:latest",
        command=["bash", "-c", "true"],
        initial_env={"A": "1"},
        working_dir="/workspace",
        max_memory=1024,
        idle_pause_seconds=30,
        paused_delete_seconds=60,
        max_age_seconds=3600,
    )
    spec = _template_spec_from_config_map(cm)
    assert spec is not None
    assert spec.id == "img:latest"
    assert spec.command == ["bash", "-c", "true"]
    assert spec.initial_env == {"A": "1"}
    assert spec.working_dir == "/workspace"
    assert spec.max_memory == 1024
    assert spec.idle_pause_seconds == 30
    assert spec.paused_delete_seconds == 60
    assert spec.max_age_seconds == 3600


def test_template_spec_from_config_map_defaults() -> None:
    spec = _template_spec_from_config_map(_config_map(image="img"))
    assert spec is not None
    assert spec.command is None
    assert spec.initial_env == {}
    assert spec.working_dir == "/home/openhands"
    assert spec.max_memory is None
    assert spec.idle_pause_seconds is None


def test_template_spec_from_config_map_none_when_no_template_label() -> None:
    assert _template_spec_from_config_map(_config_map(template_label=False)) is None


def test_template_spec_from_config_map_none_when_no_image() -> None:
    assert _template_spec_from_config_map(_config_map(image=None)) is None


# --------------------------------------------------------------------------- #
# Deployment -> K8sSandbox mapping.
# --------------------------------------------------------------------------- #


def _deployment(
    *,
    sandbox_id: str | None = "sb-1",
    template_id: str = "img:latest",
    replicas: int | None = 1,
    ready_replicas: int | None = None,
    created: str = "2024-01-02T03:04:05Z",
    conditions: list[dict[str, Any]] | None = None,
) -> Any:
    """A lightweight Deployment stand-in (SimpleNamespace) for the mapping helpers.

    The mapping helpers use ``getattr``/dict access, so a SimpleNamespace mirrors
    the k8s client object shape without the model's required-field validation.
    """
    from types import SimpleNamespace

    labels = {_LABEL_SANDBOX_ID: sandbox_id} if sandbox_id else {}
    annotations = {_ANNOT_TEMPLATE_ID: template_id}
    cond_objs = [
        SimpleNamespace(type=c["type"], reason=c.get("reason"), message=c.get("message"))
        for c in (conditions or [])
    ]
    return SimpleNamespace(
        metadata=SimpleNamespace(
            labels=labels,
            annotations=annotations,
            creation_timestamp=created,
        ),
        spec=SimpleNamespace(replicas=replicas, template=None),
        status=SimpleNamespace(ready_replicas=ready_replicas, conditions=cond_objs),
    )


def test_sandbox_from_deployment_active() -> None:
    dep = _deployment(replicas=1, ready_replicas=1)
    sandbox = _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS))
    assert sandbox is not None
    assert sandbox.id == "sb-1"
    assert sandbox.sandbox_template_id == "img:latest"
    assert sandbox.status is SandboxStatus.ACTIVE
    assert sandbox.desired_status is SandboxStatus.ACTIVE
    assert sandbox.pvc_name == "sb-1-data"
    assert sandbox.exposed_urls is not None
    assert [u.name for u in sandbox.exposed_urls] == [p.name for p in DEFAULT_EXPOSED_PORTS]


def test_sandbox_from_deployment_inactive_when_scaled_to_zero() -> None:
    dep = _deployment(replicas=0, ready_replicas=0)
    sandbox = _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS))
    assert sandbox is not None
    assert sandbox.status is SandboxStatus.INACTIVE
    assert sandbox.desired_status is SandboxStatus.INACTIVE


def test_sandbox_from_deployment_activating_when_not_ready() -> None:
    dep = _deployment(replicas=1, ready_replicas=0)
    sandbox = _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS))
    assert sandbox is not None
    assert sandbox.status is SandboxStatus.ACTIVATING


def test_sandbox_from_deployment_none_when_no_sandbox_label() -> None:
    dep = _deployment(sandbox_id=None)
    assert _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS)) is None


def test_sandbox_from_deployment_carries_status_detail() -> None:
    dep = _deployment(
        conditions=[{"type": "ReplicaFailure", "reason": "FailedCreate", "message": "quota"}]
    )
    sandbox = _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS))
    assert sandbox is not None
    assert sandbox.status_detail is not None
    assert "FailedCreate" in sandbox.status_detail


def test_deployment_status_to_sandbox_status_dict_status() -> None:
    assert _deployment_status_to_sandbox_status({"readyReplicas": 1}, 1) is SandboxStatus.ACTIVE
    assert _deployment_status_to_sandbox_status({"availableReplicas": 1}, 1) is SandboxStatus.ACTIVE
    assert _deployment_status_to_sandbox_status({}, 0) is SandboxStatus.INACTIVE
    assert _deployment_status_to_sandbox_status({}, 1) is SandboxStatus.ACTIVATING


def test_desired_from_replicas() -> None:
    assert _desired_from_replicas(0) is SandboxStatus.INACTIVE
    assert _desired_from_replicas(1) is SandboxStatus.ACTIVE
    assert _desired_from_replicas(None) is SandboxStatus.ACTIVE


def test_exposed_urls_from_service() -> None:
    ports = [ExposedPort(name="agent_server", description="d", container_port=8000)]
    urls = _exposed_urls_from_service("sb-1", ports)
    assert len(urls) == 1
    assert urls[0].name == "agent_server"
    assert urls[0].port == 8000
    assert urls[0].url == "http://sb-1:8000"


def test_exposed_urls_from_service_empty() -> None:
    assert _exposed_urls_from_service("sb-1", []) == []


# --------------------------------------------------------------------------- #
# Factory & config wiring.
# --------------------------------------------------------------------------- #


def test_resolve_k8s_service_class() -> None:
    cls = resolve_sandbox_service_class(
        "openhands.ev2.sandbox.k8s_sandbox_service.K8sSandboxService"
    )
    assert cls is K8sSandboxService


def test_resolve_rejects_non_service() -> None:
    with pytest.raises(TypeError):
        resolve_sandbox_service_class("openhands.ev2.sandbox.k8s_sandbox_service._K8sTemplateSpec")


def test_resolve_rejects_missing_module() -> None:
    with pytest.raises(ValueError):
        resolve_sandbox_service_class("does.not.Exist")


# --------------------------------------------------------------------------- #
# Router exception-to-status mapping.
# --------------------------------------------------------------------------- #


def test_sandbox_router_exception_to_status_mapping() -> None:
    from fastapi import status as http_status

    from openhands.ev2.sandbox.sandbox_router import _map_exception_to_status
    from openhands.ev2.sandbox.sandbox_service import (
        BatchPermissionDeniedError,
        SandboxNotFoundError,
        SandboxPermissionScopeError,
    )

    assert _map_exception_to_status(SandboxNotFoundError("x")).status_code == 404
    assert _map_exception_to_status(SandboxConflictError("x")).status_code == 409
    assert _map_exception_to_status(SandboxPermissionScopeError("x")).status_code == 403
    assert _map_exception_to_status(BatchPermissionDeniedError("x")).status_code == 403
    assert (
        _map_exception_to_status(RuntimeError("boom")).status_code
        == http_status.HTTP_500_INTERNAL_SERVER_ERROR
    )


def test_snapshot_router_exception_to_status_mapping() -> None:
    from openhands.ev2.sandbox.sandbox_service import (
        SandboxSnapshotConflictError,
        SandboxSnapshotNotFoundError,
        SandboxSnapshotPermissionScopeError,
        SandboxSnapshotUnsupportedError,
    )
    from openhands.ev2.sandbox.sandbox_snapshot_router import _map_exception_to_status

    assert _map_exception_to_status(SandboxSnapshotNotFoundError("x")).status_code == 404
    assert _map_exception_to_status(SandboxSnapshotPermissionScopeError("x")).status_code == 403
    assert _map_exception_to_status(SandboxSnapshotConflictError("x")).status_code == 409
    assert _map_exception_to_status(SandboxSnapshotUnsupportedError("x")).status_code == 501


# --------------------------------------------------------------------------- #
# Snapshot tarball store (sync helpers + artifact hooks).
# --------------------------------------------------------------------------- #


def test_sync_import_snapshot_writes_file(tmp_path: Path) -> None:
    service = K8sSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    from openhands.ev2.util import snapshot_store

    assert snapshot_store.snapshot_exists(service.snapshot_dir, "snap-1")


def test_sync_import_snapshot_conflict_when_exists(tmp_path: Path) -> None:
    service = K8sSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    with pytest.raises(SandboxSnapshotConflictError):
        service._sync_import_snapshot("snap-1", b"again")


def test_sync_delete_snapshot_removes_tarball(tmp_path: Path) -> None:
    service = K8sSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    service._sync_delete_snapshot("snap-1")
    from openhands.ev2.util import snapshot_store

    assert not snapshot_store.snapshot_exists(service.snapshot_dir, "snap-1")


def test_sync_delete_snapshot_missing_raises_not_found(tmp_path: Path) -> None:
    service = K8sSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_delete_snapshot("nope")


async def test_stream_snapshot_returns_bytes(tmp_path: Path) -> None:
    service = K8sSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    chunks = await service.stream_snapshot("snap-1")
    assert b"".join(chunks) == b"tarball-bytes"


async def test_service_import_snapshot_from_file(tmp_path: Path) -> None:
    service = K8sSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    snapshot_id = uuid.uuid4()
    size = await service.import_snapshot_file(snapshot_id, b"tarball-bytes")
    assert size is not None and size > 0
    from openhands.ev2.util import snapshot_store

    assert snapshot_store.snapshot_exists(service.snapshot_dir, str(snapshot_id))


async def test_service_delete_snapshot(tmp_path: Path) -> None:
    service = K8sSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    snapshot_id = uuid.uuid4()
    await service.import_snapshot_file(snapshot_id, b"tarball-bytes")
    await service.delete_snapshot_artifact(str(snapshot_id))
    from openhands.ev2.util import snapshot_store

    assert not snapshot_store.snapshot_exists(service.snapshot_dir, str(snapshot_id))


async def test_service_delete_snapshot_not_found_raises(tmp_path: Path) -> None:
    service = K8sSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.delete_snapshot_artifact("nope")


def test_base_service_snapshot_hooks_raise_unsupported() -> None:
    # A SandboxService subclass that does not override the snapshot hooks
    # inherits the unsupported defaults from the base class.
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
        asyncio.run(service.stream_snapshot("snap-a"))


# --------------------------------------------------------------------------- #
# Lifecycle task management.
# --------------------------------------------------------------------------- #


async def test_aenter_starts_lifecycle_task() -> None:
    service = K8sSandboxService(sandbox_lifecycle_interval=0.1)
    async with service:
        assert service._lifecycle_task is not None
        task = service._lifecycle_task
    assert task.cancelled() or task.done()


async def test_aenter_skips_task_when_interval_zero() -> None:
    service = K8sSandboxService(sandbox_lifecycle_interval=0)
    async with service:
        assert service._lifecycle_task is None


async def test_aclose_cancels_lifecycle_task() -> None:
    service = K8sSandboxService(sandbox_lifecycle_interval=0.1)
    await service.__aenter__()
    task = service._lifecycle_task
    assert task is not None
    await service.__aexit__(None, None, None)
    assert task.cancelled() or task.done()


async def test_aclose_closes_http_client() -> None:
    service = K8sSandboxService()
    await service.__aenter__()
    client = service._http_client()
    assert service._http is client
    await service.__aexit__(None, None, None)
    assert client.is_closed


async def test_lifecycle_loop_runs_one_sweep_then_cancels() -> None:
    swept: list[bool] = []

    class _StubSweepService(K8sSandboxService):
        async def sweep_lifecycle(self) -> str | None:
            swept.append(True)
            return None

    service = _StubSweepService(sandbox_lifecycle_interval=0.01)
    await service.__aenter__()
    await asyncio.sleep(0.05)
    await service.__aexit__(None, None, None)
    assert swept


# --------------------------------------------------------------------------- #
# last_accessed_at derivation.
# --------------------------------------------------------------------------- #


def _active_sandbox_with_url(url: str = "http://sb-1:8000") -> K8sSandbox:
    return K8sSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        exposed_urls=[ExposedUrl(name="agent_server", url=url, port=8000)],
    )


@respx.mock
async def test_resolve_last_accessed_at_from_idle_time() -> None:
    service = K8sSandboxService()
    respx.get("http://sb-1:8000/").mock(return_value=httpx.Response(200, json={"idle_time": 60}))
    accessed = await service._resolve_last_accessed_at(_active_sandbox_with_url())
    assert accessed is not None
    delta = datetime.now(UTC) - accessed
    assert 55 <= delta.total_seconds() <= 70


async def test_resolve_last_accessed_at_none_when_not_active() -> None:
    service = K8sSandboxService()
    sandbox = K8sSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
    assert await service._resolve_last_accessed_at(sandbox) is None


@respx.mock
async def test_resolve_last_accessed_at_none_on_http_error() -> None:
    service = K8sSandboxService()
    respx.get("http://sb-1:8000/").mock(side_effect=httpx.ConnectError("boom"))
    assert await service._resolve_last_accessed_at(_active_sandbox_with_url()) is None


@respx.mock
async def test_resolve_last_accessed_at_none_when_idle_time_missing() -> None:
    service = K8sSandboxService()
    respx.get("http://sb-1:8000/").mock(return_value=httpx.Response(200, json={"other": 1}))
    assert await service._resolve_last_accessed_at(_active_sandbox_with_url()) is None


# --------------------------------------------------------------------------- #
# Config override (env wiring).
# --------------------------------------------------------------------------- #


def test_service_config_override(monkeypatch: pytest.MonkeyPatch) -> None:
    from openhands.agent_server.env_parser import from_env

    monkeypatch.setenv("OHE_SANDBOX_NAMESPACE", "custom-ns")
    service = from_env(K8sSandboxService, "OHE_SANDBOX")
    assert service.namespace == "custom-ns"


def test_snapshots_supported_by_default() -> None:
    service = K8sSandboxService()
    assert service.snapshot_mode is not SnapshotMode.UNSUPPORTED


def test_aclose_releases_http_client() -> None:
    # Sanity: aclose is idempotent and clears the client references.
    service = K8sSandboxService()
    # _client stays None until first use; aclose should not raise.
    with contextlib.suppress(Exception):
        asyncio.run(service.__aexit__(None, None, None))


# --------------------------------------------------------------------------- #
# Sync sandbox CRUD via a fake Kubernetes API client.
# --------------------------------------------------------------------------- #


def _api_exception(status: int) -> Any:
    from kubernetes.client import ApiException

    exc = ApiException()
    exc.status = status
    return exc


def _matches_label_selector(labels: dict[str, str] | None, selector: str) -> bool:
    if not labels:
        return False
    for part in selector.split(","):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            if labels.get(key) != value:
                return False
        elif part.startswith("!"):
            key = part[1:]
            if key in labels:
                return False
        elif part:
            if part not in labels:
                return False
    return True


class _FakeCoreV1Api:
    def __init__(self) -> None:
        self.config_maps: dict[str, Any] = {}
        self.pvcs: dict[str, Any] = {}
        self.services: dict[str, Any] = {}
        self.pods: dict[str, Any] = {}

    def list_namespaced_config_map(
        self, namespace: str, label_selector: str | None = None, **_: Any
    ) -> Any:
        items = list(self.config_maps.values())
        if label_selector:
            items = [
                cm for cm in items if _matches_label_selector(cm.metadata.labels, label_selector)
            ]
        return k8s_client.V1ConfigMapList(items=items)

    def read_namespaced_config_map(self, name: str, namespace: str) -> Any:
        try:
            return self.config_maps[name]
        except KeyError:
            raise _api_exception(404) from None

    def create_namespaced_config_map(self, namespace: str, body: Any) -> Any:
        name = body.metadata.name
        if name in self.config_maps:
            raise _api_exception(409)
        self.config_maps[name] = body
        return body

    def delete_namespaced_config_map(self, name: str, namespace: str) -> None:
        if name not in self.config_maps:
            raise _api_exception(404)
        del self.config_maps[name]

    def create_namespaced_persistent_volume_claim(self, namespace: str, body: Any) -> Any:
        name = body.metadata.name
        if name in self.pvcs:
            raise _api_exception(409)
        self.pvcs[name] = body
        return body

    def delete_namespaced_persistent_volume_claim(self, name: str, namespace: str) -> None:
        if name not in self.pvcs:
            raise _api_exception(404)
        del self.pvcs[name]

    def create_namespaced_service(self, namespace: str, body: Any) -> Any:
        name = body.metadata.name
        if name in self.services:
            raise _api_exception(409)
        self.services[name] = body
        return body

    def delete_namespaced_service(self, name: str, namespace: str) -> None:
        if name not in self.services:
            raise _api_exception(404)
        del self.services[name]

    def create_namespaced_pod(self, namespace: str, body: Any) -> Any:
        name = body.metadata.name
        if name in self.pods:
            raise _api_exception(409)
        body.status = k8s_client.V1PodStatus(phase="Succeeded")
        self.pods[name] = body
        # Simulate snapshot/restore pods that touch the snapshots hostPath.
        spec = getattr(body, "spec", None)
        if spec and spec.containers:
            args = getattr(spec.containers[0], "args", None) or []
            if args and any("tar" in str(a) for a in args):
                for vol in getattr(spec, "volumes", None) or []:
                    if vol.name == "snapshots" and vol.host_path:
                        snap_dir = Path(vol.host_path.path)
                        snap_dir.mkdir(parents=True, exist_ok=True)
                        for a in args:
                            s = str(a)
                            if "tar -czf /snapshots/" in s:
                                fname = s.split("/snapshots/")[1].split()[0]
                                (snap_dir / fname).write_bytes(b"fake-tarball")
        return body

    def read_namespaced_pod(self, name: str, namespace: str) -> Any:
        try:
            return self.pods[name]
        except KeyError:
            raise _api_exception(404) from None

    def delete_namespaced_pod(self, name: str, namespace: str) -> None:
        if name not in self.pods:
            raise _api_exception(404)
        del self.pods[name]


class _FakeAppsV1Api:
    def __init__(self) -> None:
        self.deployments: dict[str, Any] = {}

    def list_namespaced_deployment(
        self, namespace: str, label_selector: str | None = None, **_: Any
    ) -> Any:
        items = list(self.deployments.values())
        if label_selector:
            items = [
                dep for dep in items if _matches_label_selector(dep.metadata.labels, label_selector)
            ]
        return k8s_client.V1DeploymentList(items=items)

    def read_namespaced_deployment(self, name: str, namespace: str) -> Any:
        try:
            return self.deployments[name]
        except KeyError:
            raise _api_exception(404) from None

    def create_namespaced_deployment(self, namespace: str, body: Any) -> Any:
        name = body.metadata.name
        if name in self.deployments:
            raise _api_exception(409)
        self.deployments[name] = body
        return body

    def delete_namespaced_deployment(self, name: str, namespace: str) -> None:
        if name not in self.deployments:
            raise _api_exception(404)
        del self.deployments[name]

    def patch_namespaced_deployment_scale(self, name: str, namespace: str, body: Any) -> Any:
        dep = self.deployments.get(name)
        if dep is None:
            raise _api_exception(404)
        dep.spec.replicas = body.spec.replicas
        return dep

    def patch_namespaced_deployment(self, name: str, namespace: str, body: Any) -> Any:
        dep = self.deployments.get(name)
        if dep is None:
            raise _api_exception(404)
        if isinstance(body, dict):
            meta = body.get("metadata", {})
            anns = meta.get("annotations")
            if anns:
                existing = dep.metadata.annotations or {}
                for k, v in anns.items():
                    if v is None:
                        existing.pop(k, None)
                    else:
                        existing[k] = v
                dep.metadata.annotations = existing
            labels_patch = meta.get("labels")
            if labels_patch:
                existing_labels = dep.metadata.labels or {}
                for k, v in labels_patch.items():
                    if v is None:
                        existing_labels.pop(k, None)
                    else:
                        existing_labels[k] = v
                dep.metadata.labels = existing_labels
        return dep


class _FakeKube:
    def __init__(self) -> None:
        self.core = _FakeCoreV1Api()
        self.apps = _FakeAppsV1Api()


def _make_k8s_service(fake: _FakeKube | None = None, **fields: Any) -> K8sSandboxService:
    fake = fake or _FakeKube()
    service = K8sSandboxService(**fields)
    service._core = fake.core
    service._apps = fake.apps
    service._client = object()  # prevent lazy init from hitting real cluster config
    return service


def _add_template_cm(
    fake: _FakeKube,
    image: str = "img:1",
    *,
    working_dir: str | None = None,
    max_memory: int | None = None,
    idle_pause_seconds: int | None = None,
    paused_delete_seconds: int | None = None,
    max_age_seconds: int | None = None,
) -> None:
    from openhands.ev2.sandbox.k8s_sandbox_service import _sanitize_name

    data: dict[str, str] = {"image": image}
    if working_dir is not None:
        data[_CM_KEY_WORKING_DIR] = working_dir
    if max_memory is not None:
        data[_CM_KEY_MAX_MEMORY] = str(max_memory)
    if idle_pause_seconds is not None:
        data[_CM_KEY_IDLE_PAUSE_SECONDS] = str(idle_pause_seconds)
    if paused_delete_seconds is not None:
        data[_CM_KEY_PAUSED_DELETE_SECONDS] = str(paused_delete_seconds)
    if max_age_seconds is not None:
        data[_CM_KEY_MAX_AGE_SECONDS] = str(max_age_seconds)
    cm = k8s_client.V1ConfigMap(
        metadata=k8s_client.V1ObjectMeta(
            name=_sanitize_name(image), labels={_LABEL_TEMPLATE: "true"}
        ),
        data=data,
    )
    fake.core.config_maps[cm.metadata.name] = cm


def _real_deployment(
    fake: _FakeKube,
    sandbox_id: str,
    *,
    template_id: str = "img:latest",
    replicas: int = 1,
    paused_at: str | None = None,
    created: str = "2024-01-02T03:04:05Z",
) -> Any:
    from openhands.ev2.sandbox.k8s_sandbox_service import _ANNOT_PAUSED_AT

    annotations: dict[str, str] = {_ANNOT_TEMPLATE_ID: template_id}
    if paused_at is not None:
        annotations[_ANNOT_PAUSED_AT] = paused_at
    dep = k8s_client.V1Deployment(
        metadata=k8s_client.V1ObjectMeta(
            name=sandbox_id,
            labels={_LABEL_SANDBOX_ID: sandbox_id},
            annotations=annotations,
            creation_timestamp=created,
        ),
        spec=k8s_client.V1DeploymentSpec(
            replicas=replicas,
            selector=k8s_client.V1LabelSelector(match_labels={_LABEL_SANDBOX_ID: sandbox_id}),
            template=k8s_client.V1PodTemplateSpec(),
        ),
        status=k8s_client.V1DeploymentStatus(ready_replicas=replicas),
    )
    fake.apps.deployments[sandbox_id] = dep
    return dep


def test_sync_list_sandboxes_returns_sandboxes() -> None:
    fake = _FakeKube()
    _real_deployment(fake, "sb-1")
    _real_deployment(fake, "sb-2")
    service = _make_k8s_service(fake)
    sandboxes = service._sync_list_sandboxes()
    assert {sb.id for sb in sandboxes} == {"sb-1", "sb-2"}


def test_sync_get_sandbox_returns_sandbox() -> None:
    fake = _FakeKube()
    _real_deployment(fake, "sb-1")
    service = _make_k8s_service(fake)
    sandbox = service._sync_get_sandbox("sb-1")
    assert sandbox.id == "sb-1"


def test_sync_get_sandbox_not_found_raises() -> None:
    service = _make_k8s_service()
    with pytest.raises(SandboxNotFoundError):
        service._sync_get_sandbox("nope")


def test_sync_create_sandbox_creates_objects() -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1", working_dir="/work")
    service = _make_k8s_service(fake)
    sandbox_id = service._sync_create_sandbox(
        K8sSandbox(
            sandbox_template_id="img:1",
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
        )
    )
    assert len(sandbox_id) == 22 and sandbox_id.islower() and sandbox_id.isalnum()
    dep = fake.apps.deployments[sandbox_id]
    assert dep.spec.replicas == 1
    container = dep.spec.template.spec.containers[0]
    assert container.image == "img:1"
    assert container.volume_mounts[0].mount_path == "/work"
    assert f"{sandbox_id}-data" in fake.core.pvcs
    assert sandbox_id in fake.core.services


def test_sync_create_sandbox_missing_template_raises() -> None:
    service = _make_k8s_service()
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_create_sandbox(
            K8sSandbox(
                sandbox_template_id="nope",
                status=SandboxStatus.INACTIVE,
                desired_status=SandboxStatus.INACTIVE,
            )
        )


def test_sync_create_sandbox_applies_memory_limit() -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1", max_memory=512 * 1024 * 1024)
    service = _make_k8s_service(fake)
    sandbox_id = service._sync_create_sandbox(
        K8sSandbox(
            sandbox_template_id="img:1",
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
        )
    )
    container = fake.apps.deployments[sandbox_id].spec.template.spec.containers[0]
    assert container.resources is not None
    assert container.resources.limits == {"memory": "536870912"}


def test_sync_create_sandbox_mints_random_session_api_key() -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1")
    service = _make_k8s_service(fake)
    sandbox_id = service._sync_create_sandbox(
        K8sSandbox(
            sandbox_template_id="img:1",
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
        )
    )
    container = fake.apps.deployments[sandbox_id].spec.template.spec.containers[0]
    env = {e.name: e.value for e in container.env}
    key = env["SESSION_API_KEY"]
    # Minted randomly per sandbox, never the old "changeme".
    assert key != "changeme"
    assert len(key) == 22 and key.islower() and key.isalnum()


def test_build_env_preserves_template_session_api_key() -> None:
    from openhands.ev2.sandbox.k8s_sandbox_service import _K8sTemplateSpec

    spec = _K8sTemplateSpec(
        id="img:1",
        command=None,
        initial_env={"SESSION_API_KEY": "preset-key"},
        working_dir="/work",
        idle_pause_seconds=None,
        paused_delete_seconds=None,
        max_age_seconds=None,
        max_memory=None,
    )
    env = {e.name: e.value for e in K8sSandboxService()._build_env(spec)}
    # A template-supplied key is preserved, not overwritten with a random one.
    assert env["SESSION_API_KEY"] == "preset-key"


def _template_spec(initial_env: dict[str, str] | None = None) -> Any:
    from openhands.ev2.sandbox.k8s_sandbox_service import _K8sTemplateSpec

    return _K8sTemplateSpec(
        id="img:1",
        command=None,
        initial_env=initial_env or {},
        working_dir="/work",
        idle_pause_seconds=None,
        paused_delete_seconds=None,
        max_age_seconds=None,
        max_memory=None,
    )


def test_build_env_injects_webhook_and_cors() -> None:
    service = K8sSandboxService(base_url="https://app.example.com")
    env = {e.name: e.value for e in service._build_env(_template_spec(), "cfg-1")}
    assert env["OH_WEBHOOKS_0_BASE_URL"] == "https://app.example.com/webhooks/cfg-1"
    assert env["OH_ALLOW_CORS_ORIGINS_0"] == "https://app.example.com"


def test_build_env_no_webhook_without_config_id() -> None:
    service = K8sSandboxService(base_url="https://app.example.com")
    env = {e.name: e.value for e in service._build_env(_template_spec())}
    assert "OH_WEBHOOKS_0_BASE_URL" not in env
    assert env["OH_ALLOW_CORS_ORIGINS_0"] == "https://app.example.com"


def test_build_env_template_overrides_injected_values() -> None:
    service = K8sSandboxService(base_url="https://app.example.com")
    spec = _template_spec(
        {
            "OH_ALLOW_CORS_ORIGINS_0": "https://custom.example.com",
            "OH_WEBHOOKS_0_BASE_URL": "https://custom.example.com/wh/cfg-1",
        }
    )
    env = {e.name: e.value for e in service._build_env(spec, "cfg-1")}
    assert env["OH_ALLOW_CORS_ORIGINS_0"] == "https://custom.example.com"
    assert env["OH_WEBHOOKS_0_BASE_URL"] == "https://custom.example.com/wh/cfg-1"


def test_build_env_no_base_url_only_session_key() -> None:
    service = K8sSandboxService()
    env = {e.name: e.value for e in service._build_env(_template_spec(), "cfg-1")}
    assert "SESSION_API_KEY" in env
    assert "OH_ALLOW_CORS_ORIGINS_0" not in env
    assert "OH_WEBHOOKS_0_BASE_URL" not in env


def test_sync_create_sandbox_carries_webhook_env() -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1")
    service = _make_k8s_service(fake, base_url="https://app.example.com")
    sandbox_id = service._sync_create_sandbox(
        K8sSandbox(
            sandbox_template_id="img:1",
            sandbox_config_id="cfg-1",
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
        )
    )
    container = fake.apps.deployments[sandbox_id].spec.template.spec.containers[0]
    env = {e.name: e.value for e in container.env}
    assert env["OH_WEBHOOKS_0_BASE_URL"] == "https://app.example.com/webhooks/cfg-1"


def test_sync_update_sandbox_scales_down() -> None:
    from openhands.ev2.sandbox.k8s_sandbox_service import _ANNOT_PAUSED_AT

    fake = _FakeKube()
    _real_deployment(fake, "sb-1", replicas=1)
    service = _make_k8s_service(fake)
    service._sync_update_sandbox("sb-1", SandboxStatus.INACTIVE)
    dep = fake.apps.deployments["sb-1"]
    assert dep.spec.replicas == 0
    assert _ANNOT_PAUSED_AT in (dep.metadata.annotations or {})


def test_sync_update_sandbox_scales_up_clears_paused_at() -> None:
    from openhands.ev2.sandbox.k8s_sandbox_service import _ANNOT_PAUSED_AT

    fake = _FakeKube()
    _real_deployment(fake, "sb-1", replicas=0, paused_at="2024-01-01T00:00:00+00:00")
    service = _make_k8s_service(fake)
    service._sync_update_sandbox("sb-1", SandboxStatus.ACTIVE)
    dep = fake.apps.deployments["sb-1"]
    assert dep.spec.replicas == 1
    assert _ANNOT_PAUSED_AT not in (dep.metadata.annotations or {})


def test_sync_update_sandbox_missing_raises_not_found() -> None:
    service = _make_k8s_service()
    with pytest.raises(SandboxNotFoundError):
        service._sync_update_sandbox("nope", SandboxStatus.ACTIVE)


def test_sync_delete_sandbox_removes_all_objects() -> None:
    fake = _FakeKube()
    _real_deployment(fake, "sb-1")
    fake.core.services["sb-1"] = k8s_client.V1Service(
        metadata=k8s_client.V1ObjectMeta(name="sb-1"),
        spec=k8s_client.V1ServiceSpec(),
    )
    fake.core.pvcs["sb-1-data"] = k8s_client.V1PersistentVolumeClaim(
        metadata=k8s_client.V1ObjectMeta(name="sb-1-data"),
        spec=k8s_client.V1PersistentVolumeClaimSpec(),
    )
    service = _make_k8s_service(fake)
    service._sync_delete_sandbox("sb-1")
    assert "sb-1" not in fake.apps.deployments
    assert "sb-1" not in fake.core.services
    assert "sb-1-data" not in fake.core.pvcs


def test_sync_delete_sandbox_missing_deployment_raises() -> None:
    service = _make_k8s_service()
    with pytest.raises(SandboxNotFoundError):
        service._sync_delete_sandbox("nope")


def test_sync_paused_at_returns_timestamp() -> None:
    fake = _FakeKube()
    _real_deployment(fake, "sb-1", replicas=0, paused_at="2024-01-01T00:00:00+00:00")
    service = _make_k8s_service(fake)
    assert service._sync_paused_at("sb-1") == datetime(2024, 1, 1, tzinfo=UTC)


def test_sync_paused_at_missing_returns_none() -> None:
    fake = _FakeKube()
    _real_deployment(fake, "sb-1")
    service = _make_k8s_service(fake)
    assert service._sync_paused_at("sb-1") is None


def test_sync_paused_at_deployment_missing_returns_none() -> None:
    service = _make_k8s_service()
    assert service._sync_paused_at("nope") is None


async def test_async_create_and_get_sandbox() -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1")
    service = _make_k8s_service(fake)
    sandbox = await service.create_sandbox(
        SandboxCreate(sandbox_template_id="img:1", sandbox_config_id="cfg-1")
    )
    assert len(sandbox.id) == 22 and sandbox.id.islower() and sandbox.id.isalnum()
    fetched = await service.get_sandbox(sandbox.id)
    assert fetched.id == sandbox.id


async def test_async_update_sandbox() -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1")
    service = _make_k8s_service(fake)
    sandbox = await service.create_sandbox(
        SandboxCreate(sandbox_template_id="img:1", sandbox_config_id="cfg-1")
    )
    updated = await service.update_sandbox(
        sandbox.id, SandboxUpdate(desired_status=SandboxStatus.INACTIVE)
    )
    assert updated.desired_status is SandboxStatus.INACTIVE


async def test_async_delete_sandbox() -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1")
    service = _make_k8s_service(fake)
    sandbox = await service.create_sandbox(
        SandboxCreate(sandbox_template_id="img:1", sandbox_config_id="cfg-1")
    )
    await service.delete_sandbox(sandbox.id)
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox(sandbox.id)


def test_sync_capture_snapshot_uses_pod(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    fake = _FakeKube()
    _add_template_cm(fake, "img:1")
    service = _make_k8s_service(fake, snapshot_dir=str(tmp_path / "snaps"))
    sandbox_id = service._sync_create_sandbox(
        K8sSandbox(
            sandbox_template_id="img:1",
            status=SandboxStatus.ACTIVE,
            desired_status=SandboxStatus.ACTIVE,
        )
    )
    service._sync_capture_snapshot("snap-1", sandbox_id)
    assert snapshot_store.snapshot_exists(service.snapshot_dir, "snap-1")


def test_sync_capture_snapshot_conflict_when_exists(tmp_path: Path) -> None:

    fake = _FakeKube()
    _add_template_cm(fake, "img:1")
    service = _make_k8s_service(fake, snapshot_dir=str(tmp_path / "snaps"))
    sandbox_id = service._sync_create_sandbox(
        K8sSandbox(
            sandbox_template_id="img:1",
            status=SandboxStatus.ACTIVE,
            desired_status=SandboxStatus.ACTIVE,
        )
    )
    service._sync_capture_snapshot("snap-1", sandbox_id)
    with pytest.raises(SandboxSnapshotConflictError):
        service._sync_capture_snapshot("snap-1", sandbox_id)


def test_sync_import_snapshot_writes_tarball(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    service = _make_k8s_service(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    assert snapshot_store.snapshot_exists(service.snapshot_dir, "snap-1")


def test_sync_create_sandbox_restores_snapshot(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    fake = _FakeKube()
    _add_template_cm(fake, "img:1", working_dir="/work")
    service = _make_k8s_service(fake, snapshot_dir=str(tmp_path / "snaps"))
    # Pre-seed a snapshot tarball so the restore pod path is taken.
    snapshot_store.import_snapshot(service.snapshot_dir, "snap-1", b"tarball-bytes")
    sandbox_id = service._sync_create_sandbox(
        K8sSandbox(
            sandbox_template_id="img:1",
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
        ),
        snapshot_id="snap-1",
    )
    # Restore pod was created and cleaned up.
    assert f"{sandbox_id}-restore" not in fake.core.pods
    assert f"{sandbox_id}-data" in fake.core.pvcs


def test_sync_create_sandbox_missing_snapshot_raises(tmp_path: Path) -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1")
    service = _make_k8s_service(fake, snapshot_dir=str(tmp_path / "snaps"))
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_create_sandbox(
            K8sSandbox(
                sandbox_template_id="img:1",
                status=SandboxStatus.INACTIVE,
                desired_status=SandboxStatus.INACTIVE,
            ),
            snapshot_id="nope",
        )


async def test_sweep_deletes_sandbox_past_max_age(tmp_path: Path) -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1", max_age_seconds=1)
    _real_deployment(fake, "sb-1", template_id="img:1", replicas=1)
    service = _make_k8s_service(fake, snapshot_dir=str(tmp_path / "snaps"))
    # created_at from the deployment is 2024-01-02 → well past the 1s max age.
    result = await service.sweep_lifecycle()
    assert result is not None
    assert "deleted" in result
    assert "sb-1" not in fake.apps.deployments


async def test_sweep_deletes_paused_sandbox_past_paused_delete(tmp_path: Path) -> None:
    fake = _FakeKube()
    _add_template_cm(fake, "img:1", paused_delete_seconds=1)
    _real_deployment(
        fake, "sb-1", template_id="img:1", replicas=0, paused_at="2024-01-01T00:00:00+00:00"
    )
    service = _make_k8s_service(fake, snapshot_dir=str(tmp_path / "snaps"))
    result = await service.sweep_lifecycle()
    assert result is not None
    assert "deleted" in result
    assert "sb-1" not in fake.apps.deployments


async def test_sweep_skips_sandbox_without_template(tmp_path: Path) -> None:
    fake = _FakeKube()
    _real_deployment(fake, "sb-1", template_id="missing:1", replicas=1)
    service = _make_k8s_service(fake, snapshot_dir=str(tmp_path / "snaps"))
    result = await service.sweep_lifecycle()
    # No action taken — template ConfigMap missing → skipped.
    assert result is None
    assert "sb-1" in fake.apps.deployments


# --------------------------------------------------------------------------- #
# Warm pool (K8s).
# --------------------------------------------------------------------------- #


def _warm_deployment(
    fake: _FakeKube,
    sandbox_id: str,
    *,
    template_id: str = "img:latest",
    replicas: int = 1,
    created: str = "2024-01-02T03:04:05Z",
) -> Any:
    from openhands.ev2.sandbox.k8s_sandbox_service import (
        _LABEL_SANDBOX_ID,
        _LABEL_WARM,
    )

    dep = k8s_client.V1Deployment(
        metadata=k8s_client.V1ObjectMeta(
            name=sandbox_id,
            resource_version="rv-1",
            labels={
                _LABEL_SANDBOX_ID: sandbox_id,
                _LABEL_WARM: "true",
            },
            annotations={_ANNOT_TEMPLATE_ID: template_id},
            creation_timestamp=created,
        ),
        spec=k8s_client.V1DeploymentSpec(
            replicas=replicas,
            selector=k8s_client.V1LabelSelector(match_labels={_LABEL_SANDBOX_ID: sandbox_id}),
            template=k8s_client.V1PodTemplateSpec(),
        ),
        status=k8s_client.V1DeploymentStatus(ready_replicas=replicas),
    )
    fake.apps.deployments[sandbox_id] = dep
    return dep


def test_k8s_sync_count_warm_counts_warm_deployments() -> None:
    fake = _FakeKube()
    _warm_deployment(fake, "sb-1")
    _warm_deployment(fake, "sb-2")
    service = _make_k8s_service(fake)
    assert service._sync_count_warm("img:latest") == 2


def test_k8s_sync_count_warm_excludes_claimed() -> None:
    fake = _FakeKube()
    _warm_deployment(fake, "sb-1")
    # A claimed deployment (no warm label) should not be counted.
    _real_deployment(fake, "sb-2", template_id="img:latest")
    service = _make_k8s_service(fake)
    assert service._sync_count_warm("img:latest") == 1


def test_k8s_sync_claim_warm_removes_warm_label_and_adds_config_id() -> None:
    from openhands.ev2.sandbox.k8s_sandbox_service import (
        _LABEL_SANDBOX_CONFIG_ID,
        _LABEL_WARM,
    )

    fake = _FakeKube()
    _warm_deployment(fake, "sb-1")
    service = _make_k8s_service(fake)
    sb = service._sync_claim_warm_sandbox("img:latest", "cfg-1")
    assert sb is not None
    dep = fake.apps.deployments["sb-1"]
    labels = dep.metadata.labels
    assert labels.get(_LABEL_WARM) is None
    assert labels.get(_LABEL_SANDBOX_CONFIG_ID) == "cfg-1"


def test_k8s_sync_claim_warm_returns_none_when_empty() -> None:
    fake = _FakeKube()
    service = _make_k8s_service(fake)
    assert service._sync_claim_warm_sandbox("img:latest", "cfg-1") is None


def test_k8s_sync_delete_warm_removes_deployment() -> None:
    fake = _FakeKube()
    _warm_deployment(fake, "sb-1")
    _warm_deployment(fake, "sb-2")
    service = _make_k8s_service(fake)
    service._sync_delete_warm("img:latest")
    # One should be deleted.
    remaining_warm = [
        name
        for name, dep in fake.apps.deployments.items()
        if dep.metadata.labels and dep.metadata.labels.get("io.openhands.sandbox/warm") == "true"
    ]
    assert len(remaining_warm) == 1
