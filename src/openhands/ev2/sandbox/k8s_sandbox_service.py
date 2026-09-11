"""Kubernetes implementation of the sandbox control plane.

This module is intentionally isolated from :mod:`sandbox_service` so the
Kubernetes client is only imported when a Kubernetes-backed service is actually
selected (the Docker implementation lives in :mod:`docker_sandbox_service`).
``K8sSandboxService`` backs template CRUD with Kubernetes *ConfigMaps* and
sandbox CRUD with *Deployments* (one pod, one container) plus a *PVC* and a
*ClusterIP Service*:

* a template's ``id`` is the container image reference, and the lifecycle
  metadata (``idle_pause_seconds``, ``paused_delete_seconds``,
  ``max_age_seconds``) are stored as annotations on a ConfigMap in the sandbox
  namespace;
* a sandbox's ``id`` is the Deployment name. ``desired_status`` maps to
  ``active`` (scale replicas to 1) and ``inactive`` (scale replicas to 0,
  effectively stopping the pod while the PVC persists).

Each sandbox is backed by a PVC mounted at the template's ``working_dir``
(default ``/home/openhands``). Snapshots are gzip tarballs of the PVC workspace,
stored in ``snapshot_dir`` on the control-plane host. Capture runs a one-shot
pod that tars the workspace to the shared snapshot store; restore runs a
one-shot pod that extracts the tarball into a fresh PVC before the sandbox
Deployment is created — mirroring the Kubernetes VolumeSnapshot model and
letting snapshots round-trip between the Docker and K8s providers.

The Kubernetes client is synchronous (urllib3-based), so every call is
offloaded to a thread via :func:`asyncio.to_thread`, exactly as the Docker
service offloads the Docker SDK calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple, cast

import httpx
from kubernetes import client as k8s_client  # type: ignore[import-untyped]
from kubernetes.client import exceptions as k8s_exc  # type: ignore[import-untyped]
from pydantic import Field

from openhands.ev2.sandbox.k8s_sandbox_models import K8sSandbox
from openhands.ev2.sandbox.sandbox_models import (
    ExposedUrl,
    Sandbox,
    SandboxStatus,
    SnapshotMode,
    VolumeMount,
)
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxCreate,
    SandboxUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    SandboxConflictError,
    SandboxNotFoundError,
    SandboxService,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotUnsupportedError,
    SandboxTemplateNotFoundError,
)
from openhands.ev2.sandbox.sandbox_template_models import ExposedPort
from openhands.ev2.util import snapshot_store
from openhands.ev2.util.search_filter import ALL, SearchFilter

logger = logging.getLogger(__name__)

# ConfigMap / Deployment / Service label keys marking objects as sandbox-owned.
# The sandbox-id label value is a valid DNS-1123 name (the generated sandbox id),
# so it can be a label selector target. The template-id is stored as an
# annotation instead because an image reference is not a valid label value
# (it may contain ``/``, ``:``, and uppercase characters).
_LABEL_TEMPLATE = "io.openhands.sandbox/template"
_LABEL_SANDBOX_ID = "io.openhands.sandbox/sandbox-id"
_ANNOT_TEMPLATE_ID = "io.openhands.sandbox/template-id"

# Annotation carrying the wall-clock time a sandbox was paused by the lifecycle
# sweep, so ``paused_delete_seconds`` can be enforced across restarts. Cleared
# whenever the sandbox is resumed.
_ANNOT_PAUSED_AT = "io.openhands.sandbox/paused-at"

# ConfigMap data keys for template lifespan metadata.
_CM_KEY_IDLE_PAUSE_SECONDS = "idle_pause_seconds"
_CM_KEY_PAUSED_DELETE_SECONDS = "paused_delete_seconds"
_CM_KEY_MAX_AGE_SECONDS = "max_age_seconds"
_CM_KEY_MAX_MEMORY = "max_memory"
_CM_KEY_WORKING_DIR = "working_dir"
_CM_KEY_COMMAND = "command"
_CM_KEY_INITIAL_ENV = "initial_env"
_CM_KEY_EXPOSED_PORTS = "exposed_ports"
_CM_KEY_SNAPSHOT_MODE = "snapshot_mode"

# Names of the default exposed ports surfaced on every K8s sandbox.
AGENT_SERVER = "agent_server"
VSCODE = "vscode"

DEFAULT_EXPOSED_PORTS: tuple[ExposedPort, ...] = (
    ExposedPort(
        name=AGENT_SERVER,
        description="The port on which the agent server runs within the container",
        container_port=8000,
    ),
    ExposedPort(
        name=VSCODE,
        description="The port on which the VSCode server runs within the container",
        container_port=8001,
    ),
)

# Kubernetes object names must be lowercase, DNS-1123 subdomain names: at most
# 253 chars, matching ``[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*``.
# An image reference like ``ghcr.io/org/agent-server:latest`` is not a valid
# name, so we sanitize it into one for the ConfigMap object name.
_MAX_NAME_LEN = 253


class K8sSandboxService(SandboxService):
    """Kubernetes-backed sandbox control plane.

    Template state is stored as ConfigMaps in ``namespace``: each ConfigMap
    carries the image reference (template ``id``) and lifespan metadata as
    data/annotations. Sandbox state is the Deployment inventory: a Deployment
    whose labels mark it as a sandbox is a valid sandbox. ``desired_status``
    maps to ``active`` (scale to 1 replica) and ``inactive`` (scale to 0,
    effectively stopping the pod while the PVC persists).

    Each sandbox is backed by a PVC mounted at the template's ``working_dir``
    (default ``/home/openhands``), giving the sandbox a persistent workspace.
    Snapshots are gzip tarballs of that workspace, stored in ``snapshot_dir``
    on the control plane host and restored into a new PVC via an init container
    before the sandbox starts — mirroring the Kubernetes VolumeSnapshot model
    and letting snapshots round-trip between the Docker and K8s providers.

    The Kubernetes client is created lazily so the server can boot without a
    reachable cluster; the first sandbox operation surfaces any connection
    error. When running inside a cluster, in-cluster config is used; otherwise
    the kubeconfig file (``~/.kube/config`` by default) is loaded.
    """

    namespace: str = Field(
        default="ohe-sandboxes",
        description="Kubernetes namespace in which sandbox objects are created.",
    )
    exposed_ports: list[ExposedPort] = Field(
        default_factory=lambda: list(DEFAULT_EXPOSED_PORTS),
        description="Exposed ports declared on every K8s sandbox by default.",
    )
    image_pull_policy: str = Field(
        default="IfNotPresent",
        description="Kubernetes image pull policy for sandbox containers.",
    )
    pvc_storage_class: str | None = Field(
        default=None,
        description=("StorageClass for sandbox PVCs. Null uses the cluster default StorageClass."),
    )
    pvc_size: str = Field(
        default="10Gi",
        description="Size of the PersistentVolumeClaim created for each sandbox.",
    )
    service_type: str = Field(
        default="ClusterIP",
        description=(
            "Kubernetes Service type for exposed sandbox ports. ClusterIP is "
            "in-cluster only; NodePort/LoadBalancer expose ports externally."
        ),
    )
    snapshot_dir: str = Field(
        default_factory=lambda: str(Path.home() / ".openhands" / "enterprise" / "snapshots"),
        description=(
            "Host directory storing snapshot tarballs "
            "(``<snapshot_dir>/<snapshot_id>.tar.gz``), shared with the Docker "
            "provider so snapshots round-trip between providers."
        ),
    )
    snapshot_mode: SnapshotMode = Field(
        default=SnapshotMode.MANUAL,
        description=(
            "Snapshot strategy advertised by every K8s sandbox/template. "
            "Kubernetes supports manual workspace snapshots (gzip tarball of the "
            "PVC workspace) by default; set to ``unsupported`` to disable."
        ),
    )
    sandbox_lifecycle_interval: float = Field(
        default=60.0,
        ge=0,
        description=(
            "Seconds between background sweeps that enforce the template "
            "lifespan knobs (``idle_pause_seconds``, ``paused_delete_seconds``, "
            "``max_age_seconds``) on every sandbox. When 0 the in-process loop "
            "is disabled and the sweep must be driven by an external scheduler "
            "calling ``K8sSandboxService.sweep_lifecycle``."
        ),
    )
    agent_server_probe_timeout: float = Field(
        default=2.0,
        ge=0,
        description=(
            "Per-sandbox HTTP timeout (seconds) for probing the agent server "
            "root endpoint to derive ``last_accessed_at`` from its reported "
            "``idle_time``."
        ),
    )
    kubeconfig_path: str | None = Field(
        default=None,
        description=(
            "Path to a kubeconfig file for out-of-cluster access. When null, "
            "in-cluster config is attempted first, then the default kubeconfig."
        ),
    )

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._client: k8s_client.ApiClient | None = None
        self._core: k8s_client.CoreV1Api | None = None
        self._apps: k8s_client.AppsV1Api | None = None
        self._http: httpx.AsyncClient | None = None
        self._lifecycle_task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> K8sSandboxService:
        await self.refresh_templates()
        self._start_lifecycle_loop()
        return self

    async def aclose(self) -> None:
        task = self._lifecycle_task
        self._lifecycle_task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self._http is not None:
            await self._http.aclose()
            self._http = None
        if self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()
            self._client = None
            self._core = None
            self._apps = None

    # ------------------------------------------------------------------ #
    # Kubernetes client access (lazily initialized).
    # ------------------------------------------------------------------ #
    def _ensure_client(self) -> None:
        """Initialize the Kubernetes client if not already connected."""
        if self._client is not None:
            return
        if self.kubeconfig_path is not None:
            k8s_client.Configuration.set_default(self._load_kube_config(self.kubeconfig_path))
        else:
            try:
                k8s_client.config.load_incluster_config()
            except k8s_client.config.ConfigException:
                k8s_client.config.load_kube_config()
        self._client = k8s_client.ApiClient()
        self._core = k8s_client.CoreV1Api(self._client)
        self._apps = k8s_client.AppsV1Api(self._client)

    @property
    def _core_api(self) -> k8s_client.CoreV1Api:
        self._ensure_client()
        assert self._core is not None
        return self._core

    @property
    def _apps_api(self) -> k8s_client.AppsV1Api:
        self._ensure_client()
        assert self._apps is not None
        return self._apps

    @staticmethod
    def _load_kube_config(path: str) -> k8s_client.Configuration:
        """Load a kubeconfig file into a Configuration object."""
        config = k8s_client.Configuration()
        k8s_client.config.load_kube_config(config_file=path, client_configuration=config)
        return config

    # ------------------------------------------------------------------ #
    # Provider hooks — sandboxes.
    # ------------------------------------------------------------------ #
    async def _list_sandboxes(self) -> list[Sandbox]:
        sandboxes = cast("list[K8sSandbox]", await asyncio.to_thread(self._sync_list_sandboxes))
        await asyncio.gather(*(self._enrich_last_accessed_at(sb) for sb in sandboxes))
        return cast("list[Sandbox]", sandboxes)

    async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
        sandbox = cast(K8sSandbox, await asyncio.to_thread(self._sync_get_sandbox, sandbox_id))
        await self._enrich_last_accessed_at(sandbox)
        return cast(Sandbox, sandbox)

    def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
        # ``id`` is assigned by the provider during ``_create_sandbox``; the
        # pre-persistence model carries only the template id for scope checks.
        return K8sSandbox(
            sandbox_template_id=payload.sandbox_template_id,
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
            snapshot_mode=self.snapshot_mode,
            session_api_key=None,
            exposed_urls=[],
            status_detail=None,
            pvc_name=None,
            volume_mounts=[],
        )

    async def _create_sandbox(self, sandbox: Sandbox, *, snapshot_id: str | None = None) -> Sandbox:
        k8s_sandbox = cast(K8sSandbox, sandbox)
        if snapshot_id is not None and self.snapshot_mode is SnapshotMode.UNSUPPORTED:
            raise SandboxSnapshotUnsupportedError("snapshots are not supported")
        sandbox_id = await asyncio.to_thread(self._sync_create_sandbox, k8s_sandbox, snapshot_id)
        return await self._get_sandbox(sandbox_id)

    async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
        await asyncio.to_thread(self._sync_update_sandbox, sandbox_id, payload.desired_status)
        return await self._get_sandbox(sandbox_id)

    async def _delete_sandbox(self, sandbox_id: str) -> None:
        await asyncio.to_thread(self._sync_delete_sandbox, sandbox_id)

    # ------------------------------------------------------------------ #
    # Snapshot artifact hooks. A K8s snapshot is a gzip tarball of the sandbox
    # PVC workspace, stored in ``snapshot_dir`` (shared with the Docker
    # provider). Capture runs a one-shot pod that tars the workspace into the
    # store; import writes raw bytes; download streams the tarball; restore (at
    # create time) runs a one-shot pod that extracts into a fresh PVC. These
    # operate on snapshot ids; the DB index row is owned by
    # ``SandboxSnapshotService``.
    # ------------------------------------------------------------------ #
    async def stream_snapshot(self, snapshot_id: str) -> Any:
        """Stream the snapshot tarball (gzip) for download."""
        return snapshot_store.stream_snapshot(self.snapshot_dir, snapshot_id)

    async def capture_snapshot(
        self,
        sandbox_id: str,
        *,
        sandbox_perm_filter: SearchFilter[Any] = ALL,
    ) -> tuple[str, int | None]:
        """Capture a workspace tarball from a live sandbox's PVC.

        Returns ``(snapshot_id, size_bytes)``.
        """
        snapshot_id = uuid.uuid4().hex
        await asyncio.to_thread(self._sync_capture_snapshot, snapshot_id, sandbox_id)
        size = snapshot_store.snapshot_size(self.snapshot_dir, snapshot_id)
        return snapshot_id, size

    async def import_snapshot_file(
        self,
        file_data: bytes | None,
        *,
        schema_type: str | None = None,
    ) -> tuple[str, int | None]:
        """Store an uploaded tarball and return ``(snapshot_id, size_bytes)``."""
        assert file_data is not None
        snapshot_id = uuid.uuid4().hex
        await asyncio.to_thread(self._sync_import_snapshot, snapshot_id, file_data)
        size = snapshot_store.snapshot_size(self.snapshot_dir, snapshot_id)
        return snapshot_id, size

    async def delete_snapshot_artifact(self, snapshot_id: str) -> None:
        """Delete the stored tarball for a snapshot."""
        await asyncio.to_thread(self._sync_delete_snapshot, snapshot_id)

    # ------------------------------------------------------------------ #
    # last_accessed_at derivation + lifecycle sweep.
    # ------------------------------------------------------------------ #
    def _http_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.agent_server_probe_timeout)
        return self._http

    def _agent_server_url(self, sandbox: K8sSandbox) -> str | None:
        """Return the agent server root URL for *sandbox*, or ``None``.

        Only an ``active`` sandbox exposes a reachable agent server; sandboxes
        in any other state have no URL to probe.
        """
        if sandbox.status is not SandboxStatus.ACTIVE or not sandbox.exposed_urls:
            return None
        for url in sandbox.exposed_urls:
            if url.name == AGENT_SERVER:
                return url.url.rstrip("/")
        return None

    async def _resolve_last_accessed_at(self, sandbox: K8sSandbox) -> datetime | None:
        """Probe the agent server root to derive ``last_accessed_at``.

        The agent server exposes ``{"idle_time": <seconds>}`` at ``/``; the
        last-accessed time is ``now - idle_time``. Returns ``None`` when the
        sandbox has no agent server URL, the probe fails, or the payload omits
        a usable ``idle_time``.
        """
        root = self._agent_server_url(sandbox)
        if root is None:
            return None
        try:
            response = await self._http_client().get(f"{root}/")
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        idle = payload.get("idle_time") if isinstance(payload, dict) else None
        if not isinstance(idle, (int, float)) or idle < 0:
            return None
        return datetime.now(UTC) - timedelta(seconds=float(idle))

    async def _enrich_last_accessed_at(self, sandbox: K8sSandbox) -> None:
        """Fill ``last_accessed_at`` from the agent server probe, best-effort."""
        accessed = await self._resolve_last_accessed_at(sandbox)
        sandbox.last_accessed_at = accessed

    def _start_lifecycle_loop(self) -> None:
        """Start the background lifecycle sweep if configured (``interval > 0``)."""
        if self.sandbox_lifecycle_interval <= 0 or self._lifecycle_task is not None:
            return
        self._lifecycle_task = asyncio.create_task(
            self._lifecycle_loop(), name="k8s-sandbox-lifecycle"
        )

    async def _lifecycle_loop(self) -> None:
        """Run :meth:`sweep_lifecycle` every interval until cancelled."""
        while True:
            await asyncio.sleep(self.sandbox_lifecycle_interval)
            try:
                summary = await self.sweep_lifecycle()
            except Exception:
                logger.exception("sandbox lifecycle sweep failed; will retry next interval")
            else:
                if summary:
                    logger.info("sandbox lifecycle: %s", summary)

    async def sweep_lifecycle(self) -> str | None:
        """Enforce template lifespan knobs across every sandbox.

        For each sandbox the template's ``idle_pause_seconds``,
        ``paused_delete_seconds`` and ``max_age_seconds`` are consulted (a
        ``None`` knob is not enforced). Actions, in priority order:

        * ``max_age_seconds`` — delete a sandbox whose ``created_at`` is older.
        * ``idle_pause_seconds`` — pause an ``active`` sandbox whose agent
          server reports idle time beyond the threshold.
        * ``paused_delete_seconds`` — delete an ``inactive`` sandbox paused
          longer than the threshold (the pause time is read from the
          ``io.openhands.sandbox/paused-at`` Deployment annotation).

        Returns a one-line summary of actions taken, or ``None`` when idle.
        """
        sandboxes = cast("list[K8sSandbox]", await self._list_sandboxes())
        paused = 0
        deleted = 0
        for sandbox in sandboxes:
            knobs = await self._safe_template(sandbox.sandbox_template_id)
            if knobs is None:
                continue
            action = await self._lifecycle_action(sandbox, knobs)
            if action == "deleted":
                deleted += 1
            elif action == "paused":
                paused += 1
        parts: list[str] = []
        if paused:
            parts.append(f"paused {paused} idle sandbox(es)")
        if deleted:
            parts.append(f"deleted {deleted} sandbox(es)")
        return "; ".join(parts) if parts else None

    async def _safe_template(self, template_id: str) -> _K8sTemplateSpec | None:
        try:
            return await asyncio.to_thread(self._sync_get_template, template_id)
        except SandboxTemplateNotFoundError:
            return None

    async def _lifecycle_action(self, sandbox: K8sSandbox, knobs: _K8sTemplateSpec) -> str | None:
        """Apply the highest-priority lifespan action to *sandbox*."""
        now = datetime.now(UTC)
        if knobs.max_age_seconds is not None and (now - sandbox.created_at) > timedelta(
            seconds=knobs.max_age_seconds
        ):
            await self._delete_sandbox(sandbox.id)
            return "deleted"
        if sandbox.status is SandboxStatus.ACTIVE and knobs.idle_pause_seconds is not None:
            idle_seconds = self._idle_seconds(sandbox)
            if idle_seconds is not None and idle_seconds > knobs.idle_pause_seconds:
                await self._update_sandbox(
                    sandbox.id, SandboxUpdate(desired_status=SandboxStatus.INACTIVE)
                )
                return "paused"
        if sandbox.status is SandboxStatus.INACTIVE and knobs.paused_delete_seconds is not None:
            paused_at = await asyncio.to_thread(self._sync_paused_at, sandbox.id)
            if paused_at is not None and (now - paused_at) > timedelta(
                seconds=knobs.paused_delete_seconds
            ):
                await self._delete_sandbox(sandbox.id)
                return "deleted"
        return None

    @staticmethod
    def _idle_seconds(sandbox: K8sSandbox) -> float | None:
        if sandbox.last_accessed_at is None:
            return None
        return (datetime.now(UTC) - sandbox.last_accessed_at).total_seconds()

    def _sync_paused_at(self, sandbox_id: str) -> datetime | None:
        """Return the ``paused-at`` annotation timestamp for a sandbox, or ``None``."""
        try:
            deployment = self._apps_api.read_namespaced_deployment(
                name=sandbox_id, namespace=self.namespace
            )
        except k8s_exc.ApiException as exc:
            if exc.status == 404:
                return None
            raise
        annotations = (deployment.metadata.annotations or {}) if deployment.metadata else {}
        raw = annotations.get(_ANNOT_PAUSED_AT)
        if not raw:
            return None
        return _parse_created(raw)

    # ------------------------------------------------------------------ #
    # Synchronous Kubernetes API calls (offloaded from the event loop).
    # ------------------------------------------------------------------ #
    def _sync_get_template(self, template_id: str) -> _K8sTemplateSpec:
        """Read a template's image + lifespan knobs from its ConfigMap.

        Templates are DB-backed; the ConfigMap is the provider-side mirror the
        sandbox creation path reads for image/env/working_dir/memory and the
        sweep reads for lifespan knobs.
        """
        name = _sanitize_name(template_id)
        try:
            cm = self._core_api.read_namespaced_config_map(name=name, namespace=self.namespace)
        except k8s_exc.ApiException as exc:
            if exc.status == 404:
                raise SandboxTemplateNotFoundError(template_id) from None
            raise
        spec = _template_spec_from_config_map(cm)
        if spec is None:
            raise SandboxTemplateNotFoundError(template_id)
        return spec

    # ------------------------------------------------------------------ #
    # Synchronous Deployment / PVC / Service calls.
    # ------------------------------------------------------------------ #
    def _sync_list_sandboxes(self) -> list[K8sSandbox]:
        dep_list = self._apps_api.list_namespaced_deployment(
            namespace=self.namespace,
            label_selector=f"{_LABEL_SANDBOX_ID}",
        )
        return [
            sandbox
            for dep in dep_list.items
            if (sandbox := _sandbox_from_deployment(dep, self.exposed_ports, self.snapshot_mode))
            is not None
        ]

    def _sync_get_sandbox(self, sandbox_id: str) -> K8sSandbox:
        try:
            deployment = self._apps_api.read_namespaced_deployment(
                name=sandbox_id, namespace=self.namespace
            )
        except k8s_exc.ApiException as exc:
            if exc.status == 404:
                raise SandboxNotFoundError(sandbox_id) from None
            raise
        sandbox = _sandbox_from_deployment(deployment, self.exposed_ports, self.snapshot_mode)
        if sandbox is None:
            raise SandboxNotFoundError(sandbox_id)
        return sandbox

    def _sync_create_sandbox(self, sandbox: K8sSandbox, snapshot_id: str | None = None) -> str:
        template = self._sync_get_template(sandbox.sandbox_template_id)
        sandbox_id = _generate_sandbox_name()
        pvc_name = f"{sandbox_id}-data"

        self._create_pvc(pvc_name, self.namespace)
        if snapshot_id is not None:
            self._restore_snapshot_into_pvc(sandbox_id, pvc_name, snapshot_id, template.working_dir)
        self._create_service(sandbox_id, self.namespace, self.exposed_ports, self.service_type)
        self._create_deployment(
            sandbox_id=sandbox_id,
            template=template,
            pvc_name=pvc_name,
            namespace=self.namespace,
            image_pull_policy=self.image_pull_policy,
            exposed_ports=self.exposed_ports,
            replicas=1,
        )
        return sandbox_id

    def _restore_snapshot_into_pvc(
        self, sandbox_id: str, pvc_name: str, snapshot_id: str, working_dir: str
    ) -> None:
        """Restore a snapshot tarball into a freshly created PVC.

        Runs a one-shot pod that mounts the PVC and a hostPath of the snapshot
        store, extracts the tarball into the working directory, then exits. The
        pod is removed after completion. This is the Kubernetes analog of
        creating a PVC from a VolumeSnapshot.
        """
        archive = snapshot_store.snapshot_path(self.snapshot_dir, snapshot_id)
        if not Path(archive).is_file():
            raise SandboxSnapshotNotFoundError(snapshot_id)
        pod_name = f"{sandbox_id}-restore"
        pod = k8s_client.V1Pod(
            metadata=k8s_client.V1ObjectMeta(
                name=pod_name,
                namespace=self.namespace,
                labels={_LABEL_SANDBOX_ID: sandbox_id},
            ),
            spec=k8s_client.V1PodSpec(
                restart_policy="Never",
                volumes=[
                    k8s_client.V1Volume(
                        name="workspace",
                        persistent_volume_claim=k8s_client.V1PersistentVolumeClaimVolumeSource(
                            claim_name=pvc_name
                        ),
                    ),
                    k8s_client.V1Volume(
                        name="snapshots",
                        host_path=k8s_client.V1HostPathVolumeSource(
                            path=str(Path(self.snapshot_dir).resolve()),
                            type="Directory",
                        ),
                    ),
                ],
                containers=[
                    k8s_client.V1Container(
                        name="restore",
                        image="busybox:latest",
                        command=["sh", "-c"],
                        args=[
                            f"mkdir -p {working_dir} && "
                            f"tar -xzf /snapshots/{archive.name} -C {working_dir}"
                        ],
                        volume_mounts=[
                            k8s_client.V1VolumeMount(name="workspace", mount_path=working_dir),
                            k8s_client.V1VolumeMount(name="snapshots", mount_path="/snapshots"),
                        ],
                    )
                ],
            ),
        )
        self._core_api.create_namespaced_pod(namespace=self.namespace, body=pod)
        # Wait for the restore pod to finish (best-effort, bounded).
        self._wait_for_pod_completion(pod_name)
        with contextlib.suppress(k8s_exc.ApiException):
            self._core_api.delete_namespaced_pod(name=pod_name, namespace=self.namespace)

    def _wait_for_pod_completion(self, pod_name: str, timeout: float = 120.0) -> None:
        """Poll a pod until it reaches a terminal phase or *timeout* elapses."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pod = self._core_api.read_namespaced_pod(name=pod_name, namespace=self.namespace)
            except k8s_exc.ApiException as exc:
                if exc.status == 404:
                    return
                raise
            phase = getattr(pod.status, "phase", "") if pod.status else ""
            if phase in ("Succeeded", "Failed"):
                return
            time.sleep(1)

    def _create_pvc(self, pvc_name: str, namespace: str) -> None:
        spec: dict[str, Any] = {
            "access_modes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": self.pvc_size}},
        }
        if self.pvc_storage_class is not None:
            spec["storage_class_name"] = self.pvc_storage_class
        pvc = k8s_client.V1PersistentVolumeClaim(
            metadata=k8s_client.V1ObjectMeta(
                name=pvc_name,
                namespace=namespace,
                labels={
                    _LABEL_SANDBOX_ID: _sanitize_name(pvc_name),
                },
            ),
            spec=k8s_client.V1PersistentVolumeClaimSpec(
                access_modes=spec["access_modes"],
                resources=k8s_client.V1ResourceRequirements(requests=spec["resources"]["requests"]),
                storage_class_name=self.pvc_storage_class,
            ),
        )
        try:
            self._core_api.create_namespaced_persistent_volume_claim(namespace=namespace, body=pvc)
        except k8s_exc.ApiException as exc:
            if exc.status == 409:
                raise SandboxConflictError(pvc_name) from None
            raise

    def _create_service(
        self,
        sandbox_id: str,
        namespace: str,
        exposed_ports: list[ExposedPort],
        service_type: str,
    ) -> None:
        ports = [
            k8s_client.V1ServicePort(
                name=p.name, port=p.container_port, target_port=p.container_port
            )
            for p in exposed_ports
        ]
        service = k8s_client.V1Service(
            metadata=k8s_client.V1ObjectMeta(
                name=sandbox_id,
                namespace=namespace,
                labels={
                    _LABEL_SANDBOX_ID: sandbox_id,
                },
            ),
            spec=k8s_client.V1ServiceSpec(
                type=service_type,
                selector={_LABEL_SANDBOX_ID: sandbox_id},
                ports=ports,
            ),
        )
        try:
            self._core_api.create_namespaced_service(namespace=namespace, body=service)
        except k8s_exc.ApiException as exc:
            if exc.status == 409:
                raise SandboxConflictError(sandbox_id) from None
            raise

    def _create_deployment(
        self,
        *,
        sandbox_id: str,
        template: _K8sTemplateSpec,
        pvc_name: str,
        namespace: str,
        image_pull_policy: str,
        exposed_ports: list[ExposedPort],
        replicas: int,
    ) -> None:
        container = self._build_container(template, image_pull_policy, exposed_ports)
        pod_template = k8s_client.V1PodTemplateSpec(
            metadata=k8s_client.V1ObjectMeta(labels={_LABEL_SANDBOX_ID: sandbox_id}),
            spec=k8s_client.V1PodSpec(
                containers=[container],
                volumes=[
                    k8s_client.V1Volume(
                        name="workspace",
                        persistent_volume_claim=k8s_client.V1PersistentVolumeClaimVolumeSource(
                            claim_name=pvc_name
                        ),
                    )
                ],
            ),
        )
        deployment = k8s_client.V1Deployment(
            metadata=self._deployment_meta(sandbox_id, namespace, template.id, replicas),
            spec=k8s_client.V1DeploymentSpec(
                replicas=replicas,
                selector=k8s_client.V1LabelSelector(match_labels={_LABEL_SANDBOX_ID: sandbox_id}),
                template=pod_template,
            ),
        )
        try:
            self._apps_api.create_namespaced_deployment(namespace=namespace, body=deployment)
        except k8s_exc.ApiException as exc:
            if exc.status == 409:
                raise SandboxConflictError(sandbox_id) from None
            raise

    def _build_container(
        self,
        template: _K8sTemplateSpec,
        image_pull_policy: str,
        exposed_ports: list[ExposedPort],
    ) -> k8s_client.V1Container:
        """Build the sandbox container spec from the template."""
        container_ports = [
            k8s_client.V1ContainerPort(name=p.name, container_port=p.container_port)
            for p in exposed_ports
        ]
        env = self._build_env(template)
        resources = self._build_resources(template)
        return k8s_client.V1Container(
            name="sandbox",
            image=template.id,
            image_pull_policy=image_pull_policy,
            command=template.command,
            ports=container_ports,
            env=env,
            resources=resources,
            volume_mounts=[
                k8s_client.V1VolumeMount(name="workspace", mount_path=template.working_dir)
            ],
        )

    @staticmethod
    def _build_env(template: _K8sTemplateSpec) -> list[k8s_client.V1EnvVar]:
        """Build the container env list, ensuring SESSION_API_KEY is present."""
        env = [k8s_client.V1EnvVar(name=k, value=v) for k, v in template.initial_env.items()]
        # Temporary measure: the agent server does not start with --host 0.0.0.0
        # by default unless a session api key is set.
        if not any(e.name == "SESSION_API_KEY" for e in env):
            env.append(k8s_client.V1EnvVar(name="SESSION_API_KEY", value="changeme"))
        return env

    @staticmethod
    def _build_resources(template: _K8sTemplateSpec) -> k8s_client.V1ResourceRequirements | None:
        if template.max_memory is None:
            return None
        return k8s_client.V1ResourceRequirements(limits={"memory": str(template.max_memory)})

    @staticmethod
    def _deployment_meta(
        sandbox_id: str, namespace: str, template_id: str, replicas: int
    ) -> k8s_client.V1ObjectMeta:
        annotations: dict[str, str] = {_ANNOT_TEMPLATE_ID: template_id}
        if replicas == 0:
            annotations[_ANNOT_PAUSED_AT] = _iso_utc_now()
        return k8s_client.V1ObjectMeta(
            name=sandbox_id,
            namespace=namespace,
            labels={_LABEL_SANDBOX_ID: sandbox_id},
            annotations=annotations,
        )

    def _sync_update_sandbox(self, sandbox_id: str, desired: SandboxStatus) -> None:
        self._require_sandbox_exists(sandbox_id)
        replicas, annotation = self._update_params(desired)
        if replicas is None:
            return
        if annotation is not None:
            self._patch_deployment_annotations(sandbox_id, annotation)
        self._scale_deployment(sandbox_id, replicas)

    def _require_sandbox_exists(self, sandbox_id: str) -> None:
        """Read a Deployment to confirm the sandbox exists; raise 404→not found."""
        try:
            self._apps_api.read_namespaced_deployment(name=sandbox_id, namespace=self.namespace)
        except k8s_exc.ApiException as exc:
            if exc.status == 404:
                raise SandboxNotFoundError(sandbox_id) from None
            raise

    @staticmethod
    def _update_params(
        desired: SandboxStatus,
    ) -> tuple[int | None, dict[str, str | None] | None]:
        """Resolve (replicas, annotation-patch) for a desired status."""
        if desired is SandboxStatus.ACTIVE:
            return 1, {_ANNOT_PAUSED_AT: None}
        if desired is SandboxStatus.INACTIVE:
            return 0, {_ANNOT_PAUSED_AT: _iso_utc_now()}
        return None, None

    def _scale_deployment(self, sandbox_id: str, replicas: int) -> None:
        scale = k8s_client.V1Scale(
            metadata=k8s_client.V1ObjectMeta(name=sandbox_id, namespace=self.namespace),
            spec=k8s_client.V1ScaleSpec(replicas=replicas),
        )
        self._apps_api.patch_namespaced_deployment_scale(
            name=sandbox_id, namespace=self.namespace, body=scale
        )

    def _patch_deployment_annotations(
        self, sandbox_id: str, annotations: dict[str, str | None]
    ) -> None:
        body = {"metadata": {"annotations": annotations}}
        with contextlib.suppress(k8s_exc.ApiException):
            self._apps_api.patch_namespaced_deployment(
                name=sandbox_id, namespace=self.namespace, body=body
            )

    def _sync_delete_sandbox(self, sandbox_id: str) -> None:
        # Delete the Deployment, Service, and PVC. Each is best-effort after
        # the first; a missing Deployment is a SandboxNotFoundError.
        try:
            self._apps_api.delete_namespaced_deployment(name=sandbox_id, namespace=self.namespace)
        except k8s_exc.ApiException as exc:
            if exc.status == 404:
                raise SandboxNotFoundError(sandbox_id) from None
            raise
        with contextlib.suppress(k8s_exc.ApiException):
            self._core_api.delete_namespaced_service(name=sandbox_id, namespace=self.namespace)
        pvc_name = f"{sandbox_id}-data"
        with contextlib.suppress(k8s_exc.ApiException):
            self._core_api.delete_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=self.namespace
            )

    # ------------------------------------------------------------------ #
    # Synchronous snapshot store calls (offloaded from the event loop).
    # ------------------------------------------------------------------ #
    def _sync_capture_snapshot(self, snapshot_id: str, sandbox_id: str) -> None:
        if snapshot_store.snapshot_exists(self.snapshot_dir, snapshot_id):
            raise SandboxSnapshotConflictError(snapshot_id)
        sandbox = self._sync_get_sandbox(sandbox_id)
        template = self._sync_get_template(sandbox.sandbox_template_id)
        working_dir = template.working_dir or "/home/openhands"
        pvc_name = f"{sandbox_id}-data"
        pod_name = f"{sandbox_id}-snapshot"
        archive_name = snapshot_store.snapshot_path(self.snapshot_dir, snapshot_id).name
        pod = k8s_client.V1Pod(
            metadata=k8s_client.V1ObjectMeta(
                name=pod_name,
                namespace=self.namespace,
                labels={_LABEL_SANDBOX_ID: sandbox_id},
            ),
            spec=k8s_client.V1PodSpec(
                restart_policy="Never",
                volumes=[
                    k8s_client.V1Volume(
                        name="workspace",
                        persistent_volume_claim=k8s_client.V1PersistentVolumeClaimVolumeSource(
                            claim_name=pvc_name
                        ),
                    ),
                    k8s_client.V1Volume(
                        name="snapshots",
                        host_path=k8s_client.V1HostPathVolumeSource(
                            path=str(Path(self.snapshot_dir).resolve()),
                            type="DirectoryOrCreate",
                        ),
                    ),
                ],
                containers=[
                    k8s_client.V1Container(
                        name="snapshot",
                        image="busybox:latest",
                        command=["sh", "-c"],
                        args=[f"tar -czf /snapshots/{archive_name} -C {working_dir} ."],
                        volume_mounts=[
                            k8s_client.V1VolumeMount(
                                name="workspace", mount_path=working_dir, read_only=True
                            ),
                            k8s_client.V1VolumeMount(name="snapshots", mount_path="/snapshots"),
                        ],
                    )
                ],
            ),
        )
        self._core_api.create_namespaced_pod(namespace=self.namespace, body=pod)
        self._wait_for_pod_completion(pod_name)
        with contextlib.suppress(k8s_exc.ApiException):
            self._core_api.delete_namespaced_pod(name=pod_name, namespace=self.namespace)

    def _sync_import_snapshot(self, snapshot_id: str, file_data: bytes) -> None:
        try:
            snapshot_store.import_snapshot(self.snapshot_dir, snapshot_id, file_data)
        except FileExistsError as exc:
            raise SandboxSnapshotConflictError(snapshot_id) from exc

    def _sync_delete_snapshot(self, snapshot_id: str) -> None:
        if not snapshot_store.snapshot_exists(self.snapshot_dir, snapshot_id):
            raise SandboxSnapshotNotFoundError(snapshot_id) from None
        snapshot_store.delete_snapshot(self.snapshot_dir, snapshot_id)


def _sanitize_name(template_id: str) -> str:
    """Convert a template id (image ref) into a valid Kubernetes object name.

    Kubernetes names must be DNS-1123 subdomains: lowercase alphanumeric,
    ``-``, and ``.``. The image ref ``ghcr.io/org/agent-server:latest`` becomes
    ``ghcr-io-org-agent-server-latest``.
    """
    # Replace tag separator and path/scope separators with dashes.
    replaced = template_id.replace(":", "-").replace("/", "-").replace("@", "-")
    lowered = replaced.lower()
    sanitized = re.sub(r"[^a-z0-9.-]", "-", lowered)
    sanitized = re.sub(r"^[^a-z0-9]+", "", sanitized)
    sanitized = re.sub(r"[^a-z0-9]+$", "", sanitized)
    if not sanitized:
        sanitized = "template"
    return sanitized[:_MAX_NAME_LEN]


def _generate_sandbox_name() -> str:
    """Generate a unique sandbox name (Deployment name).

    Uses a short random suffix to avoid collisions, prefixed with ``sandbox-``.
    """
    suffix = secrets.token_hex(4)
    return f"sandbox-{suffix}"


class _K8sTemplateSpec(NamedTuple):
    """Image + lifespan knobs read from a template's ConfigMap.

    Templates are DB-backed; the ConfigMap is the provider-side mirror the
    sandbox creation path and the lifecycle sweep read for the fields they
    need (image, command, env, working_dir, memory, lifespan knobs).
    """

    id: str
    command: list[str] | None
    initial_env: dict[str, str]
    working_dir: str
    max_memory: int | None
    idle_pause_seconds: int | None
    paused_delete_seconds: int | None
    max_age_seconds: int | None


def _template_spec_from_config_map(cm: Any) -> _K8sTemplateSpec | None:
    """Build a :class:`_K8sTemplateSpec` from a ConfigMap, or ``None``.

    Returns ``None`` when the ConfigMap does not carry the template label or
    is missing the image (template id) data.
    """
    labels = (cm.metadata.labels or {}) if cm.metadata else {}
    if labels.get(_LABEL_TEMPLATE) != "true":
        return None
    data = cm.data or {}
    template_id = data.get("image")
    if not template_id:
        return None
    return _K8sTemplateSpec(
        id=template_id,
        command=_parse_json_list(data.get(_CM_KEY_COMMAND)),
        initial_env=_parse_json_dict(data.get(_CM_KEY_INITIAL_ENV)),
        working_dir=data.get(_CM_KEY_WORKING_DIR) or "/home/openhands",
        max_memory=_parse_int(data.get(_CM_KEY_MAX_MEMORY)),
        idle_pause_seconds=_parse_int(data.get(_CM_KEY_IDLE_PAUSE_SECONDS)),
        paused_delete_seconds=_parse_int(data.get(_CM_KEY_PAUSED_DELETE_SECONDS)),
        max_age_seconds=_parse_int(data.get(_CM_KEY_MAX_AGE_SECONDS)),
    )


def _sandbox_from_deployment(
    deployment: Any,
    exposed_ports: list[ExposedPort],
    snapshot_mode: SnapshotMode = SnapshotMode.UNSUPPORTED,
) -> K8sSandbox | None:
    """Build a :class:`K8sSandbox` from a Deployment, or ``None``.

    Returns ``None`` when the Deployment does not carry the sandbox-id label.
    """
    labels = (deployment.metadata.labels or {}) if deployment.metadata else {}
    sandbox_id = labels.get(_LABEL_SANDBOX_ID)
    if not sandbox_id:
        return None
    annotations = (deployment.metadata.annotations or {}) if deployment.metadata else {}
    template_id_raw = annotations.get(_ANNOT_TEMPLATE_ID) or ""
    spec = deployment.spec or {}
    replicas = spec.replicas if hasattr(spec, "replicas") else None
    status = deployment.status or {}
    return K8sSandbox(
        id=str(sandbox_id),
        sandbox_template_id=template_id_raw,
        status=_deployment_status_to_sandbox_status(status, replicas),
        desired_status=_desired_from_replicas(replicas),
        snapshot_mode=snapshot_mode,
        session_api_key=None,
        exposed_urls=_exposed_urls_from_service(sandbox_id, exposed_ports),
        created_at=_parse_created(
            (deployment.metadata.creation_timestamp or "") if deployment.metadata else ""
        ),
        status_detail=_status_detail(status),
        pvc_name=f"{sandbox_id}-data",
        volume_mounts=_volume_mounts_from_deployment(spec),
    )


def _deployment_status_to_sandbox_status(status: Any, replicas: int | None) -> SandboxStatus:
    """Map a Deployment status + replica count to a :class:`SandboxStatus`."""
    ready = getattr(status, "ready_replicas", None) if status else None
    if ready is None and isinstance(status, dict):
        ready = status.get("readyReplicas")
    available = getattr(status, "available_replicas", None) if status else None
    if available is None and isinstance(status, dict):
        available = status.get("availableReplicas")
    if (ready or 0) >= 1 or (available or 0) >= 1:
        return SandboxStatus.ACTIVE
    if replicas is not None and replicas == 0:
        return SandboxStatus.INACTIVE
    # Replicas desired but none ready yet — still activating.
    return SandboxStatus.ACTIVATING


def _desired_from_replicas(replicas: int | None) -> SandboxStatus:
    """Resolve the desired status from the Deployment's replica count."""
    if replicas is not None and replicas == 0:
        return SandboxStatus.INACTIVE
    return SandboxStatus.ACTIVE


def _exposed_urls_from_service(
    sandbox_id: str,
    exposed_ports: list[ExposedPort],
) -> list[ExposedUrl]:
    """Build :class:`ExposedUrl` entries from the per-sandbox Service.

    A ClusterIP Service is reachable in-cluster as
    ``http://{sandbox_id}.{namespace}.svc:{port}``. The namespace is not known
    here (only the sandbox id), so the short form ``http://{sandbox_id}:{port}``
    is used — resolvable within the same namespace via DNS.
    """
    return [
        ExposedUrl(
            name=port.name,
            url=f"http://{sandbox_id}:{port.container_port}",
            port=port.container_port,
        )
        for port in exposed_ports
    ]


def _volume_mounts_from_deployment(spec: Any) -> list[VolumeMount]:
    """Extract PVC volume mounts from a Deployment's pod spec."""
    mounts: list[VolumeMount] = []
    template_spec = getattr(spec, "template", None)
    if template_spec is None:
        return mounts
    pod_spec = getattr(template_spec, "spec", None)
    if pod_spec is None:
        return mounts
    container_list = getattr(pod_spec, "containers", None) or []
    container = container_list[0] if container_list else None
    if container is None:
        return mounts
    for vm in getattr(container, "volume_mounts", None) or []:
        mounts.append(
            VolumeMount(
                host_path="",
                container_path=getattr(vm, "mount_path", ""),
                mode="rw",
            )
        )
    return mounts


def _status_detail(status: Any) -> str | None:
    """Extract a human-readable status detail from the Deployment status."""
    conditions = getattr(status, "conditions", None) if status else None
    if not conditions and status is not None:
        conditions = status.get("conditions") if isinstance(status, dict) else None
    if not conditions:
        return None
    for cond in conditions:
        reason = getattr(cond, "reason", None) or (
            cond.get("reason") if isinstance(cond, dict) else None
        )
        message = getattr(cond, "message", None) or (
            cond.get("message") if isinstance(cond, dict) else None
        )
        cond_type = getattr(cond, "type", None) or (
            cond.get("type") if isinstance(cond, dict) else None
        )
        if cond_type in ("ReplicaFailure", "Progressing") and reason:
            return f"{reason}: {message}" if message else str(reason)
    return None


def _parse_int(value: str | None) -> int | None:
    """Parse an integer string, returning ``None`` when absent or invalid."""
    if not value:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_json_list(value: str | None) -> list[str] | None:
    """Parse a JSON list from a string, returning ``None`` when absent/invalid."""
    if not value:
        return None

    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, list):
        return [str(item) for item in parsed]
    return None


def _parse_json_dict(value: str | None) -> dict[str, str]:
    """Parse a JSON dict from a string, returning ``{}`` when absent/invalid."""
    if not value:
        return {}

    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    if isinstance(parsed, dict):
        return {str(k): str(v) for k, v in parsed.items()}
    return {}


def _parse_created(created: object) -> datetime:
    """Parse a Kubernetes timestamp into an aware UTC datetime."""
    if isinstance(created, str) and created:
        try:
            parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    return datetime.now(UTC)


def _iso_utc_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(UTC).isoformat()
