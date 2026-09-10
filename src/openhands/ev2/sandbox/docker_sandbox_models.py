"""Docker-specific sandbox models.

:class:`DockerSandbox` is the Docker container projection of the provider-neutral
:class:`Sandbox`, and :class:`DockerSandboxSnapshot` is the tarball-store
projection of :class:`SandboxSnapshot`. They live in their own module so the
Docker implementation details (:mod:`docker_sandbox_service`) are decoupled
from the provider-neutral models.
"""

from __future__ import annotations

from pydantic import Field

from openhands.ev2.sandbox.sandbox_models import Sandbox, SandboxSnapshot, VolumeMount


class DockerSandbox(Sandbox):
    """A sandbox backed by a Docker container.

    ``volume_mounts`` are the bind mounts attached to the container so callers
    can locate the host directories backing the container filesystem.
    """

    volume_mounts: list[VolumeMount] = Field(default_factory=list)


class DockerSandboxSnapshot(SandboxSnapshot):
    """A snapshot backed by a gzip tarball in the snapshot store.

    A Docker snapshot is produced by tarring the sandbox workspace bind-mount
    directory (while the sandbox is paused) into
    ``<snapshot_dir>/<snapshot_id>.tar.gz``. ``archive_path`` is the host
    filesystem path of the stored tarball. ``sandbox_id`` is the source sandbox
    when the snapshot was created from one; it is ``None`` for snapshots
    imported from an uploaded tarball.
    """

    archive_path: str | None = None
