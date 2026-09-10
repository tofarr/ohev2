"""Docker-specific sandbox model.

:class:`DockerSandbox` is the Docker container projection of the provider-neutral
:class:`Sandbox`. It lives in its own module so the Docker implementation details
(:mod:`docker_sandbox_service`) are decoupled from the provider-neutral models.
"""

from __future__ import annotations

from pydantic import Field

from openhands.ev2.sandbox_v2.sandbox_v2_models import Sandbox, VolumeMount


class DockerSandbox(Sandbox):
    """A sandbox backed by a Docker container.

    ``volume_mounts`` are the bind mounts attached to the container so callers
    can locate the host directories backing the container filesystem.
    """

    volume_mounts: list[VolumeMount] = Field(default_factory=list)


__all__ = ["DockerSandbox"]
