"""Kubernetes-specific sandbox models.

:class:`K8sSandbox` is the Kubernetes Deployment projection of the
provider-neutral :class:`Sandbox`. It lives in its own module so the
Kubernetes implementation details (:mod:`k8s_sandbox_service`) are decoupled
from the provider-neutral models, mirroring the Docker layout in
:mod:`docker_sandbox_models`.

A sandbox's ``id`` is the Deployment name; each sandbox is backed by a
Deployment (one pod, one container), a PVC for persistent data, and a
ClusterIP Service exposing the container ports. Templates and snapshots are
DB-backed governed resources (see :mod:`sandbox_template_models` and
:mod:`sandbox_snapshot_models`).
"""

from __future__ import annotations

from pydantic import Field

from openhands.ev2.sandbox.sandbox_models import Sandbox, VolumeMount


class K8sSandbox(Sandbox):
    """A sandbox backed by a Kubernetes Deployment.

    ``volume_mounts`` are the PVC mounts attached to the container so callers
    can locate the persistent volume backing the container filesystem.
    ``pvc_name`` is the name of the PersistentVolumeClaim created for the
    sandbox.
    """

    pvc_name: str | None = None
    volume_mounts: list[VolumeMount] = Field(default_factory=list)
