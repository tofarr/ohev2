"""Start a local development sandbox backed by a Docker container.

This is a convenience orchestrator for local development only. It drives the
public sandbox REST API — authenticating through the built-in dev identity
provider — to register and activate a sandbox, then launches the real Docker
container that backs it. It is not part of the request path and intentionally
not async.

Flow:

1. ensure the Docker daemon is reachable and the target image is present;
2. wait for the app to be healthy at ``--base-url``;
3. log in via ``POST /auth/dev/login`` and capture the session cookie;
4. create a Docker sandbox template, create a sandbox from it, and activate it
   via ``POST /sandbox-templates`` → ``POST /sandboxes`` →
   ``POST /sandboxes/{id}/activate``;
5. run the backing container from the template image, publishing
   ``--host-port`` to the server's internal port.

Defaults mirror the seeded admin credentials and the
``docker-compose.yml`` dev setup, so a fresh checkout works out of the box:

* app base URL: ``http://localhost:8000``
* admin credentials: ``admin`` / ``changeme`` (as produced by
  :mod:`openhands.ev2.scripts.seed_db`)
* template image: ``ghcr.io/openhands/agent-server:latest``
* backing container name: ``ohe-sandbox``

Run via ``uv run python -m openhands.ev2.scripts.start_local_dev_sandbox``.
Pass ``--help`` for options.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from collections.abc import Iterable
from typing import Any, cast

import httpx

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "changeme"
DEFAULT_COOKIE_NAME = "ohesession"
DEFAULT_IMAGE = "ghcr.io/openhands/agent-server:latest"
DEFAULT_TEMPLATE_NAME = "dev-template"
DEFAULT_SANDBOX_NAME = "dev-sandbox"
DEFAULT_CONTAINER_NAME = "ohe-sandbox"
DEFAULT_HOST_PORT = 18000
DEFAULT_INTERNAL_PORT = 18000
DEFAULT_HEALTH_PATH = "/health"

# The app may still be booting (uvicorn --reload, migrations, etc.); poll its
# health endpoint until it reports ready.
_HEALTH_POLL_INTERVAL_SECONDS = 1
_HEALTH_POLL_TIMEOUT_SECONDS = 60


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Start a local dev sandbox: drive the sandbox REST API to register "
            "and activate a sandbox, then run the backing Docker container."
        ),
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OHE_BASE_URL", DEFAULT_BASE_URL),
        help="Base URL of the running app (default: env OHE_BASE_URL or 'http://localhost:8000').",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("OHE_SEED_ADMIN_USERNAME", DEFAULT_USERNAME),
        help="Dev login username (default: env OHE_SEED_ADMIN_USERNAME or 'admin').",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("OHE_SEED_ADMIN_PASSWORD", DEFAULT_PASSWORD),
        help="Dev login password (default: env OHE_SEED_ADMIN_PASSWORD or 'changeme').",
    )
    parser.add_argument(
        "--cookie-name",
        default=os.environ.get("OHE_AUTH_COOKIE_NAME", DEFAULT_COOKIE_NAME),
        help="Session cookie name (default: env OHE_AUTH_COOKIE_NAME or 'ohesession').",
    )
    parser.add_argument(
        "--image",
        default=os.environ.get("OHE_SANDBOX_IMAGE", DEFAULT_IMAGE),
        help="Docker image backing the sandbox (default: env OHE_SANDBOX_IMAGE or "
        "'ghcr.io/openhands/agent-server:latest').",
    )
    parser.add_argument(
        "--template-name",
        default=DEFAULT_TEMPLATE_NAME,
        help="Name for the created sandbox template (default: 'dev-template').",
    )
    parser.add_argument(
        "--name",
        default=DEFAULT_SANDBOX_NAME,
        help="Name for the created sandbox (default: 'dev-sandbox').",
    )
    parser.add_argument(
        "--container-name",
        default=DEFAULT_CONTAINER_NAME,
        help="Name of the backing Docker container to remove/recreate (default: 'ohe-sandbox').",
    )
    parser.add_argument(
        "--host-port",
        type=int,
        default=DEFAULT_HOST_PORT,
        help="Host port to publish to the server's internal port (default: 18000).",
    )
    parser.add_argument(
        "--internal-port",
        type=int,
        default=DEFAULT_INTERNAL_PORT,
        help="Internal port the sandbox server listens on (default: 18000).",
    )
    parser.add_argument(
        "--health-path",
        default=DEFAULT_HEALTH_PATH,
        help="Health path advertised on the sandbox server (default: '/health').",
    )
    parser.add_argument(
        "--no-pull",
        action="store_true",
        help="Skip `docker pull` of the backing image (assume it is already present).",
    )
    parser.add_argument(
        "--keep-if-exists",
        action="store_true",
        help="Do not remove an existing backing container; abort instead.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def _run(
    cmd: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command, streaming output to the inherited stdout/stderr."""
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, check=check, text=True)


def _json(response: httpx.Response) -> dict[str, Any]:
    return cast("dict[str, Any]", response.json())


def _auth_headers(cookie: str) -> dict[str, str]:
    return {"Cookie": cookie}


def _extract_cookie(set_cookie: str, name: str) -> str | None:
    """Pull ``<name>=<value>`` out of a Set-Cookie header value."""
    prefix = f"{name}="
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith(prefix):
            return part[len(prefix) :]
    return None


def _docker_ready() -> bool:
    result = subprocess.run(
        ["docker", "info"],
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _ensure_docker() -> None:
    if _docker_ready():
        return
    raise RuntimeError(
        "Docker daemon is not reachable. Start it (e.g. `sudo dockerd` or Docker "
        "Desktop) before running this script."
    )


def _container_exists(name: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip() == name


def _remove_container(name: str) -> None:
    print(f"Removing existing container {name!r}...", file=sys.stderr)
    _run(["docker", "rm", "-f", name])


def _pull(image: str) -> None:
    print(f"Pulling image {image!r}...", file=sys.stderr)
    _run(["docker", "pull", image])


def _run_container(*, name: str, image: str, host_port: int, internal_port: int) -> str:
    print(f"Starting backing container {name!r} from {image!r}...", file=sys.stderr)
    _run(
        [
            "docker",
            "run",
            "--name",
            name,
            "-p",
            f"{host_port}:{internal_port}",
            "-d",
            image,
        ]
    )
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name=^{name}$", "--format", "{{.ID}}"],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def _wait_for_app(base_url: str) -> None:
    print(f"Waiting for app at {base_url!r} to become healthy...", file=sys.stderr)
    url = f"{base_url.rstrip('/')}/health"
    deadline = time.monotonic() + _HEALTH_POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=2.0)
        except httpx.HTTPError:
            response = None
        if response is not None and response.status_code == 200:
            print("app is healthy.", file=sys.stderr)
            return
        time.sleep(_HEALTH_POLL_INTERVAL_SECONDS)
    raise RuntimeError(
        f"app at {base_url!r} did not become healthy within "
        f"{_HEALTH_POLL_TIMEOUT_SECONDS}s. Start it with "
        "`uv run uvicorn openhands.ev2.app:app --reload` and retry."
    )


def _login(
    client: httpx.Client,
    *,
    username: str,
    password: str,
    cookie_name: str,
) -> str:
    response = client.post(
        "/auth/dev/login",
        json={"username": username, "password": password},
    )
    response.raise_for_status()
    set_cookie = response.headers.get("set-cookie")
    if set_cookie is None:
        raise RuntimeError("login response did not set a session cookie")
    value = _extract_cookie(set_cookie, cookie_name)
    if value is None:
        raise RuntimeError(f"session cookie {cookie_name!r} not found in Set-Cookie")
    return f"{cookie_name}={value}"


def _template_payload(
    *,
    name: str,
    image: str,
    internal_port: int,
    health_path: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "provider_kind": "docker",
        "template_spec": {
            "kind": "DockerSandboxTemplateSpec",
            "provider_kind": "docker",
            "image": image,
            "ports": [{"name": "agent", "port": internal_port, "protocol": "http"}],
        },
        "server_spec": {
            "kind": "OpenHandsAgentServerSpec",
            "server_kind": "openhands_agent_server",
            "internal_port": internal_port,
            "health_path": health_path,
        },
        "storage_spec": {
            "kind": "FuseySandboxStorageSpec",
            "storage_kind": "fusey",
            "mount_path": "/workspace",
        },
    }


def _create_template(
    client: httpx.Client,
    *,
    cookie: str,
    name: str,
    image: str,
    internal_port: int,
    health_path: str,
) -> dict[str, Any]:
    response = client.post(
        "/sandbox-templates",
        json=_template_payload(
            name=name,
            image=image,
            internal_port=internal_port,
            health_path=health_path,
        ),
        headers=_auth_headers(cookie),
    )
    response.raise_for_status()
    return _json(response)


def _create_sandbox(
    client: httpx.Client,
    *,
    cookie: str,
    name: str,
    template_id: str,
) -> dict[str, Any]:
    response = client.post(
        "/sandboxes",
        json={"name": name, "template_id": template_id},
        headers=_auth_headers(cookie),
    )
    response.raise_for_status()
    return _json(response)


def _activate_sandbox(
    client: httpx.Client,
    *,
    cookie: str,
    sandbox_id: str,
) -> dict[str, Any]:
    response = client.post(
        f"/sandboxes/{sandbox_id}/activate",
        headers=_auth_headers(cookie),
    )
    response.raise_for_status()
    return _json(response)


def _register_sandbox(
    client: httpx.Client,
    *,
    cookie: str,
    template_name: str,
    sandbox_name: str,
    image: str,
    internal_port: int,
    health_path: str,
) -> dict[str, Any]:
    """Create a template + sandbox and activate it, returning the activated sandbox."""
    template = _create_template(
        client,
        cookie=cookie,
        name=template_name,
        image=image,
        internal_port=internal_port,
        health_path=health_path,
    )
    sandbox = _create_sandbox(
        client,
        cookie=cookie,
        name=sandbox_name,
        template_id=str(template["id"]),
    )
    return _activate_sandbox(
        client,
        cookie=cookie,
        sandbox_id=str(sandbox["id"]),
    )


def _prepare_backing_container(args: argparse.Namespace) -> int | None:
    """Pull the image and clear an existing backing container, if any.

    Returns an exit code when the run should abort, or ``None`` to continue.
    """
    if not args.no_pull:
        _pull(args.image)
    if not _container_exists(args.container_name):
        return None
    if args.keep_if_exists:
        print(
            f"Container {args.container_name!r} already exists and "
            "--keep-if-exists was set; aborting to avoid clobbering it.",
            file=sys.stderr,
        )
        return 1
    _remove_container(args.container_name)
    return None


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)

    _ensure_docker()
    _wait_for_app(args.base_url)

    abort_code = _prepare_backing_container(args)
    if abort_code is not None:
        return abort_code

    base_url = args.base_url.rstrip("/")
    try:
        with httpx.Client(base_url=base_url, timeout=30.0) as client:
            cookie = _login(
                client,
                username=args.username,
                password=args.password,
                cookie_name=args.cookie_name,
            )
            activated = _register_sandbox(
                client,
                cookie=cookie,
                template_name=args.template_name,
                sandbox_name=args.name,
                image=args.image,
                internal_port=args.internal_port,
                health_path=args.health_path,
            )
    except httpx.HTTPError as exc:
        print(f"REST request failed: {exc}", file=sys.stderr)
        return 1

    container_id = _run_container(
        name=args.container_name,
        image=args.image,
        host_port=args.host_port,
        internal_port=args.internal_port,
    )

    print(
        f"Sandbox started: id={activated['id']} status={activated['status']} "
        f"container={container_id} url=http://localhost:{args.host_port}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
