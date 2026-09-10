"""Kubernetes-specific sandbox models.

:class:`K8sSandbox` is the Kubernetes Deployment projection of the
provider-neutral :class:`Sandbox`, and :class:`K8sSandboxTemplate` is the
Kubernetes ConfigMap projection of :class:`SandboxTemplate`. They live in
their own module so the Kubernetes implementation details
(:mod:`k8s_sandbox_service`) are decoupled from the provider-neutral models,
mirroring the Docker layout in :mod:`docker_sandbox_models`.

A template's ``id`` is the container image reference (e.g.
``ghcr.io/org/agent-server:latest``); the lifespan metadata are stored as
annotations on a ConfigMap in the sandbox namespace. A sandbox's ``id`` is the
Deployment name; each sandbox is backed by a Deployment (one pod, one
container), a PVC for persistent data, and a ClusterIP Service exposing the
container ports.
"""

from __future__ import annotations

from pydantic import Field

from openhands.ev2.sandbox.sandbox_models import (
    ExposedPort,
    Sandbox,
    SandboxTemplate,
    VolumeMount,
)


class K8sSandboxTemplate(SandboxTemplate):
    """A sandbox template backed by a Kubernetes ConfigMap.

    The ``id`` is the container image reference. ``max_memory`` is the memory
    limit (in bytes) applied to the sandbox container. ``exposed_ports`` are
    the named container ports exposed via a per-sandbox Service.
    """

    max_memory: int | None = None
    exposed_ports: list[ExposedPort] = Field(
        default_factory=list,
        description="Named container ports exposed via a per-sandbox Service.",
    )


class K8sSandbox(Sandbox):
    """A sandbox backed by a Kubernetes Deployment.

    ``volume_mounts`` are the PVC mounts attached to the container so callers
    can locate the persistent volume backing the container filesystem.
    ``pvc_name`` is the name of the PersistentVolumeClaim created for the
    sandbox.
    """

    pvc_name: str | None = None
    volume_mounts: list[VolumeMount] = Field(default_factory=list)
