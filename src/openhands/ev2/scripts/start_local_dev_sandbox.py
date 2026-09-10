"""Start a local development sandbox via the sandbox REST API.

This is a convenience orchestrator for local development only. It drives the
public sandbox REST API — authenticating through the built-in dev identity
provider — to register a sandbox template, create a sandbox from it, and set the
sandbox ``desired_status`` to ``active``. The configured sandbox service (the
Docker-backed implementation by default) does the real work: it pulls the
template image and runs/pauses the backing container server-side, so this script
does not touch Docker directly. It is not part of the request path and is
intentionally not async.

Flow:

1. wait for the app to be healthy at ``--base-url``;
2. log in via ``POST /auth/dev/login`` and capture the session cookie;
3. ensure a sandbox template exists (reuse it if present, otherwise create it)
   via ``GET/POST /sandbox/sandbox-templates``;
4. create a sandbox from the template via ``POST /sandbox/sandboxes``;
5. activate the sandbox via ``PATCH /sandbox/sandboxes/{id}`` with
   ``{"desired_status": "active"}``.

Defaults mirror the seeded admin credentials and the ``docker-compose.yml`` dev
setup, so a fresh checkout works out of the box:

* app base URL: ``http://localhost:8000``
* admin credentials: ``admin`` / ``changeme`` (as produced by
  :mod:`openhands.ev2.scripts.seed_db`)
* template image (the template id): ``ghcr.io/openhands/agent-server:latest``

Run via ``uv run python -m openhands.ev2.scripts.start_local_dev_sandbox``.
Pass ``--help`` for options.
"""

from __future__ import annotations

import argparse
import os
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

# The app may still be booting (uvicorn --reload, migrations, etc.); poll its
# health endpoint until it reports ready.
_HEALTH_POLL_INTERVAL_SECONDS = 1
_HEALTH_POLL_TIMEOUT_SECONDS = 60

# Template create pulls the image server-side, which can take a while on a cold
# cache; keep the HTTP client timeout generous.
_REQUEST_TIMEOUT_SECONDS = 300.0


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Start a local dev sandbox via the sandbox REST API: ensure a "
            "template, create a sandbox, and activate it (the Docker-backed "
            "sandbox service runs the container server-side)."
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
        help="Sandbox template id / Docker image (default: env OHE_SANDBOX_IMAGE or "
        "'ghcr.io/openhands/agent-server:latest').",
    )
    parser.add_argument(
        "--idle-pause-seconds",
        type=int,
        default=None,
        help="Idle time before a sandbox is automatically paused (default: unset).",
    )
    parser.add_argument(
        "--paused-delete-seconds",
        type=int,
        default=None,
        help="Idle time before a paused sandbox is automatically deleted (default: unset).",
    )
    parser.add_argument(
        "--max-age-seconds",
        type=int,
        default=None,
        help="Maximum sandbox age before deletion (default: unset).",
    )
    parser.add_argument(
        "--max-memory",
        type=int,
        default=None,
        help="Maximum memory (bytes) for the sandbox container (default: unset).",
    )
    parser.add_argument(
        "--snapshot-mode",
        choices=["unsupported", "manual", "automatic"],
        default=None,
        help="Snapshot strategy advertised by the template (default: provider's choice).",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


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


def _template_payload(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "id": args.image,
        "idle_pause_seconds": args.idle_pause_seconds,
        "paused_delete_seconds": args.paused_delete_seconds,
        "max_age_seconds": args.max_age_seconds,
        "max_memory": args.max_memory,
        "snapshot_mode": args.snapshot_mode,
    }


def _create_template(
    client: httpx.Client,
    *,
    cookie: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(
        "/sandbox/sandbox-templates",
        json=payload,
        headers=_auth_headers(cookie),
    )
    response.raise_for_status()
    return _json(response)


def _ensure_template(
    client: httpx.Client,
    *,
    cookie: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return the existing template or create it when missing.

    A template id is the Docker image name; the service pulls it on create, so
    reusing an already-present template avoids a redundant pull/conflict.
    """
    template_id = str(payload["id"])
    response = client.get(
        f"/sandbox/sandbox-templates/{template_id}",
        headers=_auth_headers(cookie),
    )
    if response.status_code == 200:
        print(f"Reusing existing sandbox template {template_id!r}.", file=sys.stderr)
        return _json(response)
    if response.status_code != 404:
        response.raise_for_status()
    return _create_template(client, cookie=cookie, payload=payload)


def _create_sandbox(
    client: httpx.Client,
    *,
    cookie: str,
    template_id: str,
) -> dict[str, Any]:
    response = client.post(
        "/sandbox/sandboxes",
        json={"sandbox_template_id": template_id},
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
    response = client.patch(
        f"/sandbox/sandboxes/{sandbox_id}",
        json={"desired_status": "active"},
        headers=_auth_headers(cookie),
    )
    response.raise_for_status()
    return _json(response)


def _print_result(sandbox: dict[str, Any]) -> None:
    urls = ", ".join(u["url"] for u in sandbox.get("exposed_urls") or []) or "(none)"
    print(
        f"Sandbox started: id={sandbox.get('id')} status={sandbox.get('status')} "
        f"desired_status={sandbox.get('desired_status')} exposed_urls={urls}",
        file=sys.stderr,
    )


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    _wait_for_app(args.base_url)

    base_url = args.base_url.rstrip("/")
    try:
        with httpx.Client(base_url=base_url, timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            cookie = _login(
                client,
                username=args.username,
                password=args.password,
                cookie_name=args.cookie_name,
            )
            _ensure_template(
                client,
                cookie=cookie,
                payload=_template_payload(args),
            )
            sandbox = _create_sandbox(
                client,
                cookie=cookie,
                template_id=args.image,
            )
            activated = _activate_sandbox(
                client,
                cookie=cookie,
                sandbox_id=str(sandbox["id"]),
            )
    except httpx.HTTPError as exc:
        print(f"REST request failed: {exc}", file=sys.stderr)
        return 1

    _print_result(activated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
