"""Docker-specific sandbox models.

:class:`DockerSandbox` is the Docker container projection of the provider-neutral
:class:`Sandbox`, and :class:`DockerSandboxSnapshot` is the Docker image
projection of :class:`SandboxSnapshot`. They live in their own module so the
Docker implementation details (:mod:`docker_sandbox_service`) are decoupled
from the provider-neutral models.
"""

from __future__ import annotations

from pydantic import Field

from openhands.ev2.sandbox_v2.sandbox_v2_models import Sandbox, SandboxSnapshot, VolumeMount


class DockerSandbox(Sandbox):
    """A sandbox backed by a Docker container.

    ``volume_mounts`` are the bind mounts attached to the container so callers
    can locate the host directories backing the container filesystem.
    """

    volume_mounts: list[VolumeMount] = Field(default_factory=list)


class DockerSandboxSnapshot(SandboxSnapshot):
    """A snapshot backed by a Docker image.

    A Docker snapshot is produced by ``docker commit`` of the sandbox
    container into a new image. The ``image_id`` is the committed image
    reference and ``download_url`` points at a ``docker save`` tarball route.
    ``sandbox_id`` is the source sandbox when the snapshot was created from
    one; it is ``None`` for snapshots imported from an uploaded tarball.
    """

    image_id: str
    sandbox_id: str | None = None


__all__ = ["DockerSandbox", "DockerSandboxSnapshot"]
