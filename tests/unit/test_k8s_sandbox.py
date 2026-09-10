"""Tests for the Kubernetes sandbox control plane.

Covers the pieces that do not require a live Kubernetes cluster: the template
model/schemas, the ConfigMap attribute mapping helpers, the Deployment status
mapping helpers, and the service CRUD with a fake Kubernetes client.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx
from kubernetes import client as k8s_client
from kubernetes.client import exceptions as k8s_exc

from openhands.ev2.sandbox.k8s_sandbox_models import K8sSandbox, K8sSandboxTemplate
from openhands.ev2.sandbox.k8s_sandbox_service import (
    _ANNOT_PAUSED_AT,
    _ANNOT_TEMPLATE_ID,
    _CM_KEY_COMMAND,
    _CM_KEY_EXPOSED_PORTS,
    _CM_KEY_IDLE_PAUSE_SECONDS,
    _CM_KEY_INITIAL_ENV,
    _CM_KEY_MAX_AGE_SECONDS,
    _CM_KEY_MAX_MEMORY,
    _CM_KEY_PAUSED_DELETE_SECONDS,
    _CM_KEY_SNAPSHOT_MODE,
    _CM_KEY_WORKING_DIR,
    _LABEL_SANDBOX_ID,
    _LABEL_TEMPLATE,
    DEFAULT_EXPOSED_PORTS,
    K8sSandboxService,
    _deployment_status_to_sandbox_status,
    _desired_from_replicas,
    _exposed_urls_from_service,
    _k8s_template_from_payload,
    _parse_created,
    _parse_exposed_ports,
    _parse_int,
    _parse_json_dict,
    _parse_json_list,
    _parse_snapshot_mode,
    _sandbox_from_deployment,
    _sanitize_name,
    _template_from_config_map,
    _template_to_config_map,
)
from openhands.ev2.sandbox.sandbox_models import (
    ExposedPort,
    SandboxStatus,
    SnapshotMode,
)
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxCreate,
    SandboxTemplateCreate,
    SandboxUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    SandboxNotFoundError,
    SandboxService,
    SandboxTemplateConflictError,
    SandboxTemplateNotFoundError,
    resolve_sandbox_service_class,
)

# --------------------------------------------------------------------------- #
# Models.
# --------------------------------------------------------------------------- #


def test_k8s_template_defaults() -> None:
    template = K8sSandboxTemplate(id="ghcr.io/org/agent-server:latest")
    assert template.command is None
    assert template.initial_env == {}
    assert template.working_dir == "/home/openhands"
    assert template.idle_pause_seconds is None
    assert template.paused_delete_seconds is None
    assert template.max_age_seconds is None
    assert template.max_memory is None
    assert template.exposed_ports == []
    assert template.kind == "K8sSandboxTemplate"


def test_k8s_template_carries_exposed_ports() -> None:
    ports = [ExposedPort(name="app", description="App port", container_port=9000)]
    template = K8sSandboxTemplate(
        id="ghcr.io/org/agent-server:latest",
        exposed_ports=ports,
        max_memory=512 * 1024 * 1024,
    )
    assert template.exposed_ports == ports
    assert template.max_memory == 536870912


def test_k8s_sandbox_defaults() -> None:
    sandbox = K8sSandbox(
        sandbox_template_id="img",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
    assert sandbox.id == ""
    assert sandbox.pvc_name is None
    assert sandbox.volume_mounts == []
    assert sandbox.kind == "K8sSandbox"


# --------------------------------------------------------------------------- #
# Sanitize name.
# --------------------------------------------------------------------------- #


def test_sanitize_name_basic() -> None:
    assert _sanitize_name("ghcr.io/org/agent-server:latest") == "ghcr.io-org-agent-server-latest"


def test_sanitize_name_uppercase() -> None:
    assert _sanitize_name("MyImage:V1") == "myimage-v1"


def test_sanitize_name_strips_leading_trailing_dashes() -> None:
    assert _sanitize_name("---weird---") == "weird"


def test_sanitize_name_empty_falls_back() -> None:
    assert _sanitize_name("///") == "template"


# --------------------------------------------------------------------------- #
# ConfigMap <-> template mapping.
# --------------------------------------------------------------------------- #


def _config_map(
    image: str = "ghcr.io/org/agent-server:latest",
    *,
    labels: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    creation_timestamp: str = "2024-01-02T03:04:05Z",
) -> k8s_client.V1ConfigMap:
    final_labels = {_LABEL_TEMPLATE: "true"}
    if labels:
        final_labels.update(labels)
    return k8s_client.V1ConfigMap(
        metadata=k8s_client.V1ObjectMeta(
            name=_sanitize_name(image),
            creation_timestamp=creation_timestamp,
            labels=final_labels,
        ),
        data=data
        or {
            "image": image,
            _CM_KEY_WORKING_DIR: "/home/openhands",
            _CM_KEY_IDLE_PAUSE_SECONDS: "300",
            _CM_KEY_PAUSED_DELETE_SECONDS: "600",
            _CM_KEY_MAX_AGE_SECONDS: "3600",
            _CM_KEY_MAX_MEMORY: "536870912",
            _CM_KEY_INITIAL_ENV: json.dumps({"FOO": "bar"}),
            _CM_KEY_EXPOSED_PORTS: json.dumps(
                [{"name": "agent_server", "description": "Agent", "container_port": 8000}]
            ),
            _CM_KEY_SNAPSHOT_MODE: "unsupported",
        },
    )


def test_template_from_config_map_returns_template() -> None:
    cm = _config_map()
    template = _template_from_config_map(cm, list(DEFAULT_EXPOSED_PORTS))
    assert template is not None
    assert template.id == "ghcr.io/org/agent-server:latest"
    assert template.idle_pause_seconds == 300
    assert template.paused_delete_seconds == 600
    assert template.max_age_seconds == 3600
    assert template.max_memory == 536870912
    assert template.initial_env == {"FOO": "bar"}
    assert template.working_dir == "/home/openhands"
    assert len(template.exposed_ports) == 1
    assert template.exposed_ports[0].name == "agent_server"
    assert template.snapshot_mode is SnapshotMode.UNSUPPORTED
    assert template.created_at == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_template_from_config_map_missing_label_returns_none() -> None:
    cm = k8s_client.V1ConfigMap(
        metadata=k8s_client.V1ObjectMeta(name="x", labels={}),
        data={"image": "img"},
    )
    assert _template_from_config_map(cm, list(DEFAULT_EXPOSED_PORTS)) is None


def test_template_from_config_map_missing_image_returns_none() -> None:
    cm = k8s_client.V1ConfigMap(
        metadata=k8s_client.V1ObjectMeta(name="x", labels={_LABEL_TEMPLATE: "true"}),
        data={},
    )
    assert _template_from_config_map(cm, list(DEFAULT_EXPOSED_PORTS)) is None


def test_template_from_config_map_uses_default_exposed_ports_when_empty() -> None:
    cm = _config_map(data={"image": "img"})
    template = _template_from_config_map(cm, list(DEFAULT_EXPOSED_PORTS))
    assert template is not None
    assert len(template.exposed_ports) == len(DEFAULT_EXPOSED_PORTS)


def test_template_to_config_map_round_trip() -> None:
    ports = [ExposedPort(name="app", description="App", container_port=9000)]
    template = K8sSandboxTemplate(
        id="ghcr.io/org/agent-server:1",
        idle_pause_seconds=100,
        paused_delete_seconds=200,
        max_age_seconds=400,
        max_memory=1024,
        initial_env={"A": "b"},
        working_dir="/work",
        exposed_ports=ports,
        snapshot_mode=SnapshotMode.MANUAL,
        command=["sh", "-c"],
    )
    cm = _template_to_config_map(template, "ohe-sandboxes")
    assert cm.metadata.name == _sanitize_name("ghcr.io/org/agent-server:1")
    assert cm.metadata.namespace == "ohe-sandboxes"
    assert cm.metadata.labels == {_LABEL_TEMPLATE: "true"}
    assert cm.data["image"] == "ghcr.io/org/agent-server:1"
    assert cm.data[_CM_KEY_IDLE_PAUSE_SECONDS] == "100"
    assert cm.data[_CM_KEY_PAUSED_DELETE_SECONDS] == "200"
    assert cm.data[_CM_KEY_MAX_AGE_SECONDS] == "400"
    assert cm.data[_CM_KEY_MAX_MEMORY] == "1024"
    assert cm.data[_CM_KEY_WORKING_DIR] == "/work"
    assert json.loads(cm.data[_CM_KEY_INITIAL_ENV]) == {"A": "b"}
    assert json.loads(cm.data[_CM_KEY_COMMAND]) == ["sh", "-c"]
    assert cm.data[_CM_KEY_SNAPSHOT_MODE] == "manual"
    # Round-trip back through _template_from_config_map.
    restored = _template_from_config_map(cm, list(DEFAULT_EXPOSED_PORTS), SnapshotMode.MANUAL)
    assert restored is not None
    assert restored.id == template.id
    assert restored.idle_pause_seconds == 100
    assert restored.max_memory == 1024
    assert restored.snapshot_mode is SnapshotMode.MANUAL
    assert restored.command == ["sh", "-c"]
    assert len(restored.exposed_ports) == 1
    assert restored.exposed_ports[0].name == "app"


def test_template_to_config_map_none_knobs_use_empty_string() -> None:
    template = K8sSandboxTemplate(id="img:1")
    cm = _template_to_config_map(template, "ns")
    assert cm.data[_CM_KEY_IDLE_PAUSE_SECONDS] == ""
    assert cm.data[_CM_KEY_MAX_MEMORY] == ""
    assert cm.data[_CM_KEY_COMMAND] == ""


def test_k8s_template_from_payload_uses_default_ports() -> None:
    payload = SandboxTemplateCreate(id="img:1")
    template = _k8s_template_from_payload(payload, list(DEFAULT_EXPOSED_PORTS))
    assert template.id == "img:1"
    assert len(template.exposed_ports) == len(DEFAULT_EXPOSED_PORTS)


def test_k8s_template_from_payload_respects_payload_ports() -> None:
    payload = SandboxTemplateCreate(
        id="img:1",
        exposed_ports=[{"name": "x", "description": "X", "container_port": 1}],
    )
    template = _k8s_template_from_payload(payload, list(DEFAULT_EXPOSED_PORTS))
    assert len(template.exposed_ports) == 1
    assert template.exposed_ports[0].name == "x"


def test_k8s_template_from_payload_snapshot_mode_override() -> None:
    payload = SandboxTemplateCreate(id="img:1", snapshot_mode=SnapshotMode.MANUAL)
    template = _k8s_template_from_payload(
        payload, list(DEFAULT_EXPOSED_PORTS), SnapshotMode.UNSUPPORTED
    )
    assert template.snapshot_mode is SnapshotMode.MANUAL


# --------------------------------------------------------------------------- #
# Deployment -> sandbox mapping.
# --------------------------------------------------------------------------- #


def _deployment(
    name: str = "sandbox-abcd",
    *,
    image: str = "ghcr.io/org/agent-server:latest",
    replicas: int = 1,
    ready_replicas: int = 1,
    creation_timestamp: str = "2024-01-02T03:04:05Z",
    annotations: dict[str, str] | None = None,
    paused_at: str | None = None,
) -> k8s_client.V1Deployment:
    final_annotations = dict(annotations or {})
    final_annotations[_ANNOT_TEMPLATE_ID] = image
    if paused_at is not None:
        final_annotations[_ANNOT_PAUSED_AT] = paused_at
    return k8s_client.V1Deployment(
        metadata=k8s_client.V1ObjectMeta(
            name=name,
            creation_timestamp=creation_timestamp,
            labels={
                _LABEL_SANDBOX_ID: name,
            },
            annotations=final_annotations,
        ),
        spec=k8s_client.V1DeploymentSpec(
            replicas=replicas,
            selector=k8s_client.V1LabelSelector(match_labels={_LABEL_SANDBOX_ID: name}),
            template=k8s_client.V1PodTemplateSpec(
                metadata=k8s_client.V1ObjectMeta(labels={_LABEL_SANDBOX_ID: name}),
                spec=k8s_client.V1PodSpec(
                    containers=[
                        k8s_client.V1Container(
                            name="sandbox",
                            image=image,
                            volume_mounts=[
                                k8s_client.V1VolumeMount(
                                    name="workspace", mount_path="/home/openhands"
                                )
                            ],
                        )
                    ],
                    volumes=[
                        k8s_client.V1Volume(
                            name="workspace",
                            persistent_volume_claim=k8s_client.V1PersistentVolumeClaimVolumeSource(
                                claim_name=f"{name}-data"
                            ),
                        )
                    ],
                ),
            ),
        ),
        status=k8s_client.V1DeploymentStatus(
            ready_replicas=ready_replicas, available_replicas=ready_replicas
        ),
    )


def test_sandbox_from_deployment_running() -> None:
    dep = _deployment("sb-1", replicas=1, ready_replicas=1)
    sandbox = _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS))
    assert isinstance(sandbox, K8sSandbox)
    assert sandbox.id == "sb-1"
    assert sandbox.status is SandboxStatus.ACTIVE
    assert sandbox.desired_status is SandboxStatus.ACTIVE
    assert sandbox.pvc_name == "sb-1-data"
    assert [u.name for u in (sandbox.exposed_urls or [])] == ["agent_server", "vscode"]
    assert sandbox.volume_mounts[0].container_path == "/home/openhands"


def test_sandbox_from_deployment_zero_replicas_is_inactive() -> None:
    dep = _deployment("sb-2", replicas=0, ready_replicas=0)
    sandbox = _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS))
    assert sandbox is not None
    assert sandbox.status is SandboxStatus.INACTIVE
    assert sandbox.desired_status is SandboxStatus.INACTIVE


def test_sandbox_from_deployment_pending_is_activating() -> None:
    dep = _deployment("sb-3", replicas=1, ready_replicas=0)
    sandbox = _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS))
    assert sandbox is not None
    assert sandbox.status is SandboxStatus.ACTIVATING


def test_sandbox_from_deployment_no_label_returns_none() -> None:
    dep = _deployment("anon")
    dep.metadata.labels = {}
    assert _sandbox_from_deployment(dep, list(DEFAULT_EXPOSED_PORTS)) is None


def test_deployment_status_to_sandbox_status_active() -> None:
    status = k8s_client.V1DeploymentStatus(ready_replicas=1, available_replicas=1)
    assert _deployment_status_to_sandbox_status(status, 1) is SandboxStatus.ACTIVE


def test_deployment_status_to_sandbox_status_inactive() -> None:
    status = k8s_client.V1DeploymentStatus(ready_replicas=0, available_replicas=0)
    assert _deployment_status_to_sandbox_status(status, 0) is SandboxStatus.INACTIVE


def test_deployment_status_to_sandbox_status_activating() -> None:
    status = k8s_client.V1DeploymentStatus(ready_replicas=0, available_replicas=0)
    assert _deployment_status_to_sandbox_status(status, 1) is SandboxStatus.ACTIVATING


def test_desired_from_replicas() -> None:
    assert _desired_from_replicas(0) is SandboxStatus.INACTIVE
    assert _desired_from_replicas(1) is SandboxStatus.ACTIVE
    assert _desired_from_replicas(None) is SandboxStatus.ACTIVE


def test_exposed_urls_from_service() -> None:
    urls = _exposed_urls_from_service("sb-1", list(DEFAULT_EXPOSED_PORTS))
    assert len(urls) == 2
    assert urls[0].name == "agent_server"
    assert urls[0].url == "http://sb-1:8000"
    assert urls[0].port == 8000


# --------------------------------------------------------------------------- #
# Parse helpers.
# --------------------------------------------------------------------------- #


def test_parse_int() -> None:
    assert _parse_int("42") == 42
    assert _parse_int("") is None
    assert _parse_int(None) is None
    assert _parse_int("abc") is None


def test_parse_json_list() -> None:
    assert _parse_json_list('["a", "b"]') == ["a", "b"]
    assert _parse_json_list("") is None
    assert _parse_json_list("not json") is None
    assert _parse_json_list('{"a": 1}') is None


def test_parse_json_dict() -> None:
    assert _parse_json_dict('{"a": "b"}') == {"a": "b"}
    assert _parse_json_dict("") == {}
    assert _parse_json_dict("not json") == {}


def test_parse_exposed_ports() -> None:
    ports = _parse_exposed_ports(
        json.dumps([{"name": "x", "description": "X", "container_port": 1}])
    )
    assert ports is not None
    assert len(ports) == 1
    assert ports[0].name == "x"


def test_parse_snapshot_mode() -> None:
    assert _parse_snapshot_mode("manual", SnapshotMode.UNSUPPORTED) is SnapshotMode.MANUAL
    assert _parse_snapshot_mode("", SnapshotMode.UNSUPPORTED) is SnapshotMode.UNSUPPORTED
    assert _parse_snapshot_mode("bogus", SnapshotMode.MANUAL) is SnapshotMode.MANUAL


def test_parse_created_valid() -> None:
    parsed = _parse_created("2024-01-02T03:04:05Z")
    assert parsed == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_parse_created_invalid_falls_back_to_now() -> None:
    parsed = _parse_created("not a date")
    assert parsed.tzinfo is not None
    assert (datetime.now(UTC) - parsed) < timedelta(seconds=5)


def test_parse_created_empty_falls_back_to_now() -> None:
    parsed = _parse_created("")
    assert (datetime.now(UTC) - parsed) < timedelta(seconds=5)


# --------------------------------------------------------------------------- #
# Fake Kubernetes client.
# --------------------------------------------------------------------------- #


class _FakeApiException(k8s_exc.ApiException):
    """ApiException with a configurable status code."""


def _api_exception(status: int) -> k8s_exc.ApiException:
    exc = k8s_exc.ApiException()
    exc.status = status
    return exc


class _FakeCoreV1Api:
    """Minimal fake of CoreV1Api for ConfigMap/PVC/Service operations."""

    def __init__(self) -> None:
        self.config_maps: dict[str, k8s_client.V1ConfigMap] = {}
        self.pvcs: dict[str, k8s_client.V1PersistentVolumeClaim] = {}
        self.services: dict[str, k8s_client.V1Service] = {}
        self.pods: dict[str, k8s_client.V1Pod] = {}

    def list_namespaced_config_map(
        self, namespace: str, label_selector: str | None = None, **_: Any
    ) -> k8s_client.V1ConfigMapList:
        items = list(self.config_maps.values())
        if label_selector:
            items = [
                cm for cm in items if _matches_label_selector(cm.metadata.labels, label_selector)
            ]
        return k8s_client.V1ConfigMapList(items=items)

    def read_namespaced_config_map(self, name: str, namespace: str) -> k8s_client.V1ConfigMap:
        try:
            return self.config_maps[name]
        except KeyError:
            raise _api_exception(404) from None

    def create_namespaced_config_map(
        self, namespace: str, body: k8s_client.V1ConfigMap
    ) -> k8s_client.V1ConfigMap:
        name = body.metadata.name
        if name in self.config_maps:
            raise _api_exception(409)
        self.config_maps[name] = body
        return body

    def delete_namespaced_config_map(self, name: str, namespace: str) -> None:
        if name not in self.config_maps:
            raise _api_exception(404)
        del self.config_maps[name]

    def create_namespaced_persistent_volume_claim(
        self, namespace: str, body: k8s_client.V1PersistentVolumeClaim
    ) -> k8s_client.V1PersistentVolumeClaim:
        name = body.metadata.name
        if name in self.pvcs:
            raise _api_exception(409)
        self.pvcs[name] = body
        return body

    def delete_namespaced_persistent_volume_claim(self, name: str, namespace: str) -> None:
        if name not in self.pvcs:
            raise _api_exception(404)
        del self.pvcs[name]

    def create_namespaced_service(
        self, namespace: str, body: k8s_client.V1Service
    ) -> k8s_client.V1Service:
        name = body.metadata.name
        if name in self.services:
            raise _api_exception(409)
        self.services[name] = body
        return body

    def delete_namespaced_service(self, name: str, namespace: str) -> None:
        if name not in self.services:
            raise _api_exception(404)
        del self.services[name]

    def create_namespaced_pod(self, namespace: str, body: k8s_client.V1Pod) -> k8s_client.V1Pod:
        name = body.metadata.name
        if name in self.pods:
            raise _api_exception(409)
        # Mark pod as immediately Succeeded for snapshot/restore one-shot pods.
        body.status = k8s_client.V1PodStatus(phase="Succeeded")
        self.pods[name] = body
        # Simulate snapshot pods that write a tarball to the snapshots volume.
        spec = getattr(body, "spec", None)
        if spec and spec.containers:
            args = getattr(spec.containers[0], "args", None) or []
            if args and any("tar -czf /snapshots/" in str(a) for a in args):
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

    def read_namespaced_pod(self, name: str, namespace: str) -> k8s_client.V1Pod:
        try:
            return self.pods[name]
        except KeyError:
            raise _api_exception(404) from None

    def delete_namespaced_pod(self, name: str, namespace: str) -> None:
        if name not in self.pods:
            raise _api_exception(404)
        del self.pods[name]


class _FakeAppsV1Api:
    """Minimal fake of AppsV1Api for Deployment operations."""

    def __init__(self) -> None:
        self.deployments: dict[str, k8s_client.V1Deployment] = {}

    def list_namespaced_deployment(
        self, namespace: str, label_selector: str | None = None, **_: Any
    ) -> k8s_client.V1DeploymentList:
        items = list(self.deployments.values())
        if label_selector:
            items = [
                dep for dep in items if _matches_label_selector(dep.metadata.labels, label_selector)
            ]
        return k8s_client.V1DeploymentList(items=items)

    def read_namespaced_deployment(self, name: str, namespace: str) -> k8s_client.V1Deployment:
        try:
            return self.deployments[name]
        except KeyError:
            raise _api_exception(404) from None

    def create_namespaced_deployment(
        self, namespace: str, body: k8s_client.V1Deployment
    ) -> k8s_client.V1Deployment:
        name = body.metadata.name
        if name in self.deployments:
            raise _api_exception(409)
        self.deployments[name] = body
        return body

    def delete_namespaced_deployment(self, name: str, namespace: str) -> None:
        if name not in self.deployments:
            raise _api_exception(404)
        del self.deployments[name]

    def patch_namespaced_deployment_scale(
        self, name: str, namespace: str, body: Any
    ) -> k8s_client.V1Deployment:
        dep = self.deployments.get(name)
        if dep is None:
            raise _api_exception(404)
        dep.spec.replicas = body.spec.replicas
        return dep

    def patch_namespaced_deployment(
        self, name: str, namespace: str, body: Any
    ) -> k8s_client.V1Deployment:
        dep = self.deployments.get(name)
        if dep is None:
            raise _api_exception(404)
        # Apply annotation patches.
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
        return dep


class _FakeKube:
    """Holds both fake APIs and patches the service to use them."""

    def __init__(self) -> None:
        self.core = _FakeCoreV1Api()
        self.apps = _FakeAppsV1Api()


def _matches_label_selector(labels: dict[str, str] | None, selector: str) -> bool:
    """Minimal label-selector match: supports ``key`` and ``key=value``."""
    if not labels:
        return False
    for part in selector.split(","):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            if labels.get(key) != value:
                return False
        else:
            if part not in labels:
                return False
    return True


def _make_service(fake: _FakeKube | None = None, **fields: Any) -> K8sSandboxService:
    """Build a K8sSandboxService wired to fake APIs (no cluster connection)."""
    fake = fake or _FakeKube()
    service = K8sSandboxService(**fields)
    service._core = fake.core
    service._apps = fake.apps
    service._client = object()  # prevent lazy init from hitting real config
    return service


def _add_template(fake: _FakeKube, image: str = "img:1", **kw: Any) -> K8sSandboxTemplate:
    template = K8sSandboxTemplate(id=image, **kw)
    cm = _template_to_config_map(template, "ohe-sandboxes")
    fake.core.config_maps[cm.metadata.name] = cm
    return template


# --------------------------------------------------------------------------- #
# Template CRUD.
# --------------------------------------------------------------------------- #


def test_sync_list_templates_returns_templates() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1")
    _add_template(fake, "img:2")
    service = _make_service(fake)
    templates = service._sync_list_templates()
    ids = {t.id for t in templates}
    assert ids == {"img:1", "img:2"}


def test_sync_list_templates_skips_non_template_config_maps() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1")
    # Add a ConfigMap without the template label.
    fake.core.config_maps["other"] = k8s_client.V1ConfigMap(
        metadata=k8s_client.V1ObjectMeta(name="other", labels={}),
        data={"image": "nope"},
    )
    service = _make_service(fake)
    templates = service._sync_list_templates()
    assert len(templates) == 1
    assert templates[0].id == "img:1"


def test_sync_get_template_returns_template() -> None:
    fake = _FakeKube()
    _add_template(fake, "ghcr.io/org/agent-server:latest")
    service = _make_service(fake)
    template = service._sync_get_template("ghcr.io/org/agent-server:latest")
    assert template.id == "ghcr.io/org/agent-server:latest"


def test_sync_get_template_missing_raises_not_found() -> None:
    service = _make_service()
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_get_template("nope:1")


def test_sync_create_template_creates_config_map() -> None:
    fake = _FakeKube()
    service = _make_service(fake)
    template = K8sSandboxTemplate(id="img:new", idle_pause_seconds=100)
    service._sync_create_template(template)
    cm = fake.core.config_maps[_sanitize_name("img:new")]
    assert cm.data["image"] == "img:new"
    assert cm.data[_CM_KEY_IDLE_PAUSE_SECONDS] == "100"


def test_sync_create_template_conflict_raises() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:dup")
    service = _make_service(fake)
    with pytest.raises(SandboxTemplateConflictError):
        service._sync_create_template(K8sSandboxTemplate(id="img:dup"))


def test_sync_delete_template_removes() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1")
    service = _make_service(fake)
    service._sync_delete_template("img:1")
    assert _sanitize_name("img:1") not in fake.core.config_maps


def test_sync_delete_template_missing_raises_not_found() -> None:
    service = _make_service()
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_delete_template("nope:1")


# --------------------------------------------------------------------------- #
# Sandbox CRUD.
# --------------------------------------------------------------------------- #


def test_sync_list_sandboxes_returns_sandboxes() -> None:
    fake = _FakeKube()
    fake.apps.deployments["sb-1"] = _deployment("sb-1", replicas=1, ready_replicas=1)
    fake.apps.deployments["sb-2"] = _deployment("sb-2", replicas=0, ready_replicas=0)
    service = _make_service(fake)
    sandboxes = service._sync_list_sandboxes()
    ids = {s.id for s in sandboxes}
    assert ids == {"sb-1", "sb-2"}


def test_sync_get_sandbox_returns_sandbox() -> None:
    fake = _FakeKube()
    fake.apps.deployments["sb-1"] = _deployment("sb-1")
    service = _make_service(fake)
    sandbox = service._sync_get_sandbox("sb-1")
    assert sandbox.id == "sb-1"
    assert sandbox.status is SandboxStatus.ACTIVE


def test_sync_get_sandbox_missing_raises_not_found() -> None:
    service = _make_service()
    with pytest.raises(SandboxNotFoundError):
        service._sync_get_sandbox("nope")


def test_sync_create_sandbox_creates_objects() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1", working_dir="/work")
    service = _make_service(fake)
    sandbox = K8sSandbox(
        sandbox_template_id="img:1",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
    sandbox_id = service._sync_create_sandbox(sandbox)
    assert sandbox_id.startswith("sandbox-")
    # Deployment created with 1 replica.
    dep = fake.apps.deployments[sandbox_id]
    assert dep.spec.replicas == 1
    container = dep.spec.template.spec.containers[0]
    assert container.image == "img:1"
    assert container.volume_mounts[0].mount_path == "/work"
    # PVC created.
    assert f"{sandbox_id}-data" in fake.core.pvcs
    # Service created.
    assert sandbox_id in fake.core.services


def test_sync_create_sandbox_missing_template_raises() -> None:
    service = _make_service()
    sandbox = K8sSandbox(
        sandbox_template_id="nope",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_create_sandbox(sandbox)


def test_sync_create_sandbox_applies_memory_limit() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1", max_memory=512 * 1024 * 1024)
    service = _make_service(fake)
    sandbox_id = service._sync_create_sandbox(
        K8sSandbox(
            sandbox_template_id="img:1",
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
        )
    )
    dep = fake.apps.deployments[sandbox_id]
    container = dep.spec.template.spec.containers[0]
    assert container.resources is not None
    assert container.resources.limits == {"memory": "536870912"}


def test_sync_update_sandbox_scales_down() -> None:
    fake = _FakeKube()
    fake.apps.deployments["sb-1"] = _deployment("sb-1", replicas=1, ready_replicas=1)
    service = _make_service(fake)
    service._sync_update_sandbox("sb-1", SandboxStatus.INACTIVE)
    dep = fake.apps.deployments["sb-1"]
    assert dep.spec.replicas == 0
    # paused_at annotation stamped.
    assert _ANNOT_PAUSED_AT in (dep.metadata.annotations or {})


def test_sync_update_sandbox_scales_up_clears_paused_at() -> None:
    fake = _FakeKube()
    dep = _deployment("sb-1", replicas=0, ready_replicas=0, paused_at="2024-01-01T00:00:00+00:00")
    fake.apps.deployments["sb-1"] = dep
    service = _make_service(fake)
    service._sync_update_sandbox("sb-1", SandboxStatus.ACTIVE)
    dep = fake.apps.deployments["sb-1"]
    assert dep.spec.replicas == 1
    assert _ANNOT_PAUSED_AT not in (dep.metadata.annotations or {})


def test_sync_update_sandbox_missing_raises_not_found() -> None:
    service = _make_service()
    with pytest.raises(SandboxNotFoundError):
        service._sync_update_sandbox("nope", SandboxStatus.ACTIVE)


def test_sync_delete_sandbox_removes_all_objects() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1")
    fake.apps.deployments["sb-1"] = _deployment("sb-1")
    fake.core.services["sb-1"] = k8s_client.V1Service(
        metadata=k8s_client.V1ObjectMeta(name="sb-1"),
        spec=k8s_client.V1ServiceSpec(),
    )
    fake.core.pvcs["sb-1-data"] = k8s_client.V1PersistentVolumeClaim(
        metadata=k8s_client.V1ObjectMeta(name="sb-1-data"),
        spec=k8s_client.V1PersistentVolumeClaimSpec(),
    )
    service = _make_service(fake)
    service._sync_delete_sandbox("sb-1")
    assert "sb-1" not in fake.apps.deployments
    assert "sb-1" not in fake.core.services
    assert "sb-1-data" not in fake.core.pvcs


def test_sync_delete_sandbox_missing_deployment_raises() -> None:
    service = _make_service()
    with pytest.raises(SandboxNotFoundError):
        service._sync_delete_sandbox("nope")


def test_sync_paused_at_returns_timestamp() -> None:
    fake = _FakeKube()
    fake.apps.deployments["sb-1"] = _deployment(
        "sb-1", replicas=0, ready_replicas=0, paused_at="2024-01-01T00:00:00+00:00"
    )
    service = _make_service(fake)
    paused_at = service._sync_paused_at("sb-1")
    assert paused_at == datetime(2024, 1, 1, tzinfo=UTC)


def test_sync_paused_at_missing_returns_none() -> None:
    fake = _FakeKube()
    fake.apps.deployments["sb-1"] = _deployment("sb-1")
    service = _make_service(fake)
    assert service._sync_paused_at("sb-1") is None


def test_sync_paused_at_deployment_missing_returns_none() -> None:
    service = _make_service()
    assert service._sync_paused_at("nope") is None


# --------------------------------------------------------------------------- #
# Async service CRUD (through the base class public API).
# --------------------------------------------------------------------------- #


async def test_async_list_templates_filters_by_perm_filter() -> None:
    from openhands.ev2.util.search_filter import NONE

    fake = _FakeKube()
    _add_template(fake, "img:1")
    service = _make_service(fake)
    result = await service.list_templates(perm_filter=NONE)
    assert result == []


async def test_async_create_and_get_template() -> None:
    fake = _FakeKube()
    service = _make_service(fake)
    template = await service.create_template(
        SandboxTemplateCreate(id="img:1", idle_pause_seconds=100)
    )
    assert template.id == "img:1"
    fetched = await service.get_template("img:1")
    assert fetched.id == "img:1"


async def test_async_create_and_get_sandbox() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1")
    service = _make_service(fake)
    sandbox = await service.create_sandbox(SandboxCreate(sandbox_template_id="img:1"))
    assert sandbox.id.startswith("sandbox-")
    fetched = await service.get_sandbox(sandbox.id)
    assert fetched.id == sandbox.id


async def test_async_update_sandbox() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1")
    service = _make_service(fake)
    sandbox = await service.create_sandbox(SandboxCreate(sandbox_template_id="img:1"))
    updated = await service.update_sandbox(
        sandbox.id, SandboxUpdate(desired_status=SandboxStatus.INACTIVE)
    )
    assert updated.desired_status is SandboxStatus.INACTIVE


async def test_async_delete_sandbox() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1")
    service = _make_service(fake)
    sandbox = await service.create_sandbox(SandboxCreate(sandbox_template_id="img:1"))
    await service.delete_sandbox(sandbox.id)
    with pytest.raises(SandboxNotFoundError):
        await service.get_sandbox(sandbox.id)


# --------------------------------------------------------------------------- #
# Lifecycle sweep.
# --------------------------------------------------------------------------- #


async def test_sweep_max_age_deletes() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1", max_age_seconds=1)
    dep = _deployment("sb-old", image="img:1", creation_timestamp="2020-01-01T00:00:00Z")
    fake.apps.deployments["sb-old"] = dep
    service = _make_service(fake)
    summary = await service.sweep_lifecycle()
    assert summary is not None
    assert "deleted" in summary
    assert "sb-old" not in fake.apps.deployments


async def test_sweep_idle_pauses() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1", idle_pause_seconds=1)
    dep = _deployment("sb-1", image="img:1", replicas=1, ready_replicas=1)
    fake.apps.deployments["sb-1"] = dep
    service = _make_service(fake)
    # Mock last_accessed_at to be old enough to trigger pause.
    with patch.object(
        K8sSandboxService,
        "_resolve_last_accessed_at",
        return_value=datetime.now(UTC) - timedelta(seconds=100),
    ):
        summary = await service.sweep_lifecycle()
    assert summary is not None
    assert "paused" in summary
    assert fake.apps.deployments["sb-1"].spec.replicas == 0


async def test_sweep_paused_delete_removes() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1", paused_delete_seconds=1)
    dep = _deployment(
        "sb-1",
        image="img:1",
        replicas=0,
        ready_replicas=0,
        paused_at="2020-01-01T00:00:00+00:00",
    )
    fake.apps.deployments["sb-1"] = dep
    service = _make_service(fake)
    summary = await service.sweep_lifecycle()
    assert summary is not None
    assert "deleted" in summary
    assert "sb-1" not in fake.apps.deployments


async def test_sweep_idle_no_action() -> None:
    fake = _FakeKube()
    _add_template(fake, "img:1")
    dep = _deployment("sb-1", image="img:1", replicas=1, ready_replicas=1)
    fake.apps.deployments["sb-1"] = dep
    service = _make_service(fake)
    summary = await service.sweep_lifecycle()
    assert summary is None


async def test_lifecycle_loop_disabled_when_interval_zero() -> None:
    service = _make_service(sandbox_lifecycle_interval=0)
    await service.__aenter__()
    assert service._lifecycle_task is None
    await service.aclose()


async def test_lifecycle_loop_started_when_interval_positive() -> None:
    service = _make_service(sandbox_lifecycle_interval=1.0)
    await service.__aenter__()
    assert service._lifecycle_task is not None
    await service.aclose()
    assert service._lifecycle_task is None


# --------------------------------------------------------------------------- #
# last_accessed_at probe.
# --------------------------------------------------------------------------- #


@respx.mock
async def test_resolve_last_accessed_at_probes_agent_server() -> None:
    fake = _FakeKube()
    dep = _deployment("sb-1", replicas=1, ready_replicas=1)
    fake.apps.deployments["sb-1"] = dep
    service = _make_service(fake)
    sandbox = service._sync_get_sandbox("sb-1")
    respx.get("http://sb-1:8000/").mock(return_value=httpx.Response(200, json={"idle_time": 30}))
    accessed = await service._resolve_last_accessed_at(sandbox)
    assert accessed is not None
    assert (datetime.now(UTC) - accessed) >= timedelta(seconds=29)


@respx.mock
async def test_resolve_last_accessed_at_returns_none_on_error() -> None:
    fake = _FakeKube()
    dep = _deployment("sb-1", replicas=1, ready_replicas=1)
    fake.apps.deployments["sb-1"] = dep
    service = _make_service(fake)
    sandbox = service._sync_get_sandbox("sb-1")
    respx.get("http://sb-1:8000/").mock(return_value=httpx.Response(500))
    assert await service._resolve_last_accessed_at(sandbox) is None


async def test_resolve_last_accessed_at_returns_none_when_inactive() -> None:
    fake = _FakeKube()
    dep = _deployment("sb-1", replicas=0, ready_replicas=0)
    fake.apps.deployments["sb-1"] = dep
    service = _make_service(fake)
    sandbox = service._sync_get_sandbox("sb-1")
    assert await service._resolve_last_accessed_at(sandbox) is None


# --------------------------------------------------------------------------- #
# Factory / config wiring.
# --------------------------------------------------------------------------- #


def test_resolve_sandbox_service_class_finds_k8s() -> None:
    cls = resolve_sandbox_service_class(
        "openhands.ev2.sandbox.k8s_sandbox_service.K8sSandboxService"
    )
    assert cls is K8sSandboxService
    assert issubclass(cls, SandboxService)


def test_resolve_rejects_non_subclass() -> None:
    with pytest.raises(TypeError):
        resolve_sandbox_service_class("openhands.ev2.sandbox.k8s_sandbox_models.K8sSandbox")


def test_service_defaults() -> None:
    service = K8sSandboxService()
    assert service.namespace == "ohe-sandboxes"
    assert service.image_pull_policy == "IfNotPresent"
    assert service.pvc_size == "10Gi"
    assert service.service_type == "ClusterIP"
    assert service.snapshot_mode is SnapshotMode.MANUAL
    assert service.sandbox_lifecycle_interval == 60.0
    assert service.agent_server_probe_timeout == 2.0


def test_service_config_override() -> None:
    service = K8sSandboxService(
        namespace="custom-ns",
        pvc_size="5Gi",
        service_type="NodePort",
        image_pull_policy="Always",
    )
    assert service.namespace == "custom-ns"
    assert service.pvc_size == "5Gi"
    assert service.service_type == "NodePort"
    assert service.image_pull_policy == "Always"


# --------------------------------------------------------------------------- #
# Snapshots unsupported.
# --------------------------------------------------------------------------- #


async def test_snapshots_supported_by_default(tmp_path: Path) -> None:
    """K8s snapshots use the tarball store and should not raise unsupported."""
    from openhands.ev2.util import snapshot_store

    service = _make_service()
    service.snapshot_dir = str(tmp_path / "snapshots")
    snapshot_store.import_snapshot(service.snapshot_dir, "snap-1", b"dummy")
    snapshots = await service._list_snapshots()
    assert {s.id for s in snapshots} == {"snap-1"}
    snapshot = await service._get_snapshot("snap-1")
    assert snapshot.id == "snap-1"


def test_k8s_sync_get_snapshot_not_found_raises(tmp_path: Path) -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError

    service = _make_service()
    service.snapshot_dir = str(tmp_path / "snapshots")
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_get_snapshot("nope")


def test_k8s_sync_list_snapshots_empty(tmp_path: Path) -> None:
    service = _make_service()
    service.snapshot_dir = str(tmp_path / "snapshots")
    assert service._sync_list_snapshots() == []


def test_k8s_sync_import_and_delete_snapshot(tmp_path: Path) -> None:
    from openhands.ev2.sandbox.k8s_sandbox_models import K8sSandboxSnapshot
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError
    from openhands.ev2.util import snapshot_store

    service = _make_service()
    service.snapshot_dir = str(tmp_path / "snapshots")
    snap = K8sSandboxSnapshot(
        id="snap-import",
        archive_path=str(snapshot_store.snapshot_path(service.snapshot_dir, "snap-import")),
    )
    service._sync_import_snapshot(snap, b"dummy-data")
    assert snapshot_store.snapshot_exists(service.snapshot_dir, "snap-import")
    service._sync_delete_snapshot("snap-import")
    assert not snapshot_store.snapshot_exists(service.snapshot_dir, "snap-import")
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_delete_snapshot("snap-import")


def test_k8s_sync_capture_snapshot_conflict_raises(tmp_path: Path) -> None:
    from openhands.ev2.sandbox.k8s_sandbox_models import K8sSandboxSnapshot
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotConflictError
    from openhands.ev2.util import snapshot_store

    service = _make_service()
    service.snapshot_dir = str(tmp_path / "snapshots")
    snapshot_store.import_snapshot(service.snapshot_dir, "snap-dup", b"dummy")
    snap = K8sSandboxSnapshot(
        id="snap-dup",
        archive_path=str(snapshot_store.snapshot_path(service.snapshot_dir, "snap-dup")),
    )
    with pytest.raises(SandboxSnapshotConflictError):
        service._sync_capture_snapshot(snap, "sb-1")


def test_k8s_sync_capture_snapshot_creates_pod(tmp_path: Path) -> None:
    """Snapshot capture creates a one-shot pod and cleans it up."""
    from openhands.ev2.sandbox.k8s_sandbox_models import K8sSandboxSnapshot
    from openhands.ev2.util import snapshot_store

    fake = _FakeKube()
    _add_template(fake, "img:1", working_dir="/work")
    # Create a sandbox deployment so _sync_get_sandbox can find it.
    fake.apps.deployments["sb-1"] = _deployment("sb-1", image="img:1")
    service = _make_service(fake)
    service.snapshot_dir = str(tmp_path / "snapshots")
    snap = K8sSandboxSnapshot(
        id="snap-cap",
        archive_path=str(snapshot_store.snapshot_path(service.snapshot_dir, "snap-cap")),
    )
    service._sync_capture_snapshot(snap, "sb-1")
    # The snapshot pod was created and then cleaned up.
    assert "sb-1-snapshot" not in fake.core.pods


def test_k8s_sync_import_snapshot_conflict_raises(tmp_path: Path) -> None:
    from openhands.ev2.sandbox.k8s_sandbox_models import K8sSandboxSnapshot
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotConflictError
    from openhands.ev2.util import snapshot_store

    service = _make_service()
    service.snapshot_dir = str(tmp_path / "snapshots")
    snapshot_store.import_snapshot(service.snapshot_dir, "snap-exist", b"dummy")
    snap = K8sSandboxSnapshot(
        id="snap-exist",
        archive_path=str(snapshot_store.snapshot_path(service.snapshot_dir, "snap-exist")),
    )
    with pytest.raises(SandboxSnapshotConflictError):
        service._sync_import_snapshot(snap, b"more-data")


def test_k8s_sync_create_sandbox_with_snapshot_restores_pvc(tmp_path: Path) -> None:
    """Creating a sandbox from a snapshot runs a restore pod before the deployment."""
    from openhands.ev2.util import snapshot_store

    fake = _FakeKube()
    _add_template(fake, "img:1", working_dir="/work")
    service = _make_service(fake)
    service.snapshot_dir = str(tmp_path / "snapshots")
    snapshot_store.import_snapshot(service.snapshot_dir, "snap-restore", b"dummy")
    sandbox = K8sSandbox(
        sandbox_template_id="img:1",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
    sandbox_id = service._sync_create_sandbox(sandbox, snapshot_id="snap-restore")
    # Restore pod was created and cleaned up.
    assert f"{sandbox_id}-restore" not in fake.core.pods
    # PVC and deployment were created.
    assert f"{sandbox_id}-data" in fake.core.pvcs
    assert sandbox_id in fake.apps.deployments


def test_k8s_sync_create_sandbox_with_missing_snapshot_raises(tmp_path: Path) -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError

    fake = _FakeKube()
    _add_template(fake, "img:1")
    service = _make_service(fake)
    service.snapshot_dir = str(tmp_path / "snapshots")
    sandbox = K8sSandbox(
        sandbox_template_id="img:1",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_create_sandbox(sandbox, snapshot_id="nope")


@pytest.mark.asyncio
async def test_k8s_snapshot_from_sandbox_and_file(tmp_path: Path) -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxSnapshotCreate

    service = _make_service()
    service.snapshot_dir = str(tmp_path / "snapshots")
    payload_sb = SandboxSnapshotCreate(id="snap-new", sandbox_id="sb-1")
    sandbox = K8sSandbox(
        id="sb-1",
        sandbox_template_id="img:1",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
    )
    result = await service._snapshot_from_sandbox(payload_sb, sandbox)
    assert result.id == "snap-new"
    assert result.archive_path.endswith("snap-new.tar.gz")
    payload_file = SandboxSnapshotCreate.model_construct(id="snap-file")
    result2 = await service._snapshot_from_file(payload_file)
    assert result2.id == "snap-file"
    assert result2.sandbox_id is None


@pytest.mark.asyncio
async def test_k8s_create_and_delete_snapshot_through_service(tmp_path: Path) -> None:
    from openhands.ev2.sandbox.k8s_sandbox_models import K8sSandboxSnapshot
    from openhands.ev2.sandbox.sandbox_schemas import SandboxSnapshotCreate
    from openhands.ev2.util import snapshot_store

    fake = _FakeKube()
    _add_template(fake, "img:1", working_dir="/work")
    fake.apps.deployments["sb-1"] = _deployment("sb-1", image="img:1")
    service = _make_service(fake)
    service.snapshot_dir = str(tmp_path / "snapshots")
    payload = SandboxSnapshotCreate(id="snap-svc", sandbox_id="sb-1")
    snap = K8sSandboxSnapshot(
        id="snap-svc",
        archive_path=str(snapshot_store.snapshot_path(service.snapshot_dir, "snap-svc")),
    )
    await service._create_snapshot(snap, payload)
    # The snapshot pod ran and was cleaned up.
    assert "sb-1-snapshot" not in fake.core.pods
    await service.delete_snapshot("snap-svc")
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError

    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.get_snapshot("snap-svc")


# --------------------------------------------------------------------------- #
# aclose.
# --------------------------------------------------------------------------- #


async def test_aclose_releases_http_client() -> None:
    service = _make_service()
    service._http = httpx.AsyncClient()
    await service.aclose()
    assert service._http is None
