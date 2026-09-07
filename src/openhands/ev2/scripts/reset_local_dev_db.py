"""Reset the local development PostgreSQL database.

Tears down the local Docker PostgreSQL container, recreates it from the
``postgres:16`` image (matching ``docker-compose.yml``), waits for it to accept
connections, applies the Alembic migrations, and seeds the bootstrap roles/users
via :mod:`openhands.ev2.scripts.seed_db`.

This is a convenience orchestrator for local development only — it shells out
to ``docker``, ``uv run alembic``, and ``uv run python -m ...seed_db``. It is
not part of the request path and intentionally not async.

Container / DB defaults mirror the README's "local PostgreSQL instance" setup
and ``docker-compose.yml``:

* container name: ``ohe-postgres``
* image: ``postgres:16``
* host port: ``5432``
* ``POSTGRES_USER`` / ``POSTGRES_PASSWORD`` / ``POSTGRES_DB``: read from the
  ``OHE_DB_CONFIG_*`` env vars (same defaults as :class:`DbConfig` so a fresh
  checkout with no ``.env`` works out of the box).

Run via ``uv run python -m openhands.ev2.scripts.reset_local_dev_db``. Pass
``--help`` for options.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from collections.abc import Iterable

DEFAULT_CONTAINER_NAME = "ohe-postgres"
DEFAULT_IMAGE = "postgres:16"
_DEFAULT_HOST = "localhost"
_DEFAULT_PORT = 5432
_DEFAULT_DB_NAME = "ohev"
_DEFAULT_USERNAME = "ohev"
_DEFAULT_PASSWORD = "ohev"

# Postgres takes a moment to be ready even after the container is "running";
# poll pg_isready inside the container until it reports acceptance.
_HEALTH_POLL_INTERVAL_SECONDS = 1
_HEALTH_POLL_TIMEOUT_SECONDS = 60


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reset the local dev DB: recreate the Docker postgres container, "
            "run Alembic migrations, and seed bootstrap roles/users."
        ),
    )
    parser.add_argument(
        "--container-name",
        default=os.environ.get("OHE_DB_CONTAINER_NAME", DEFAULT_CONTAINER_NAME),
        help=(
            "Name of the local Docker postgres container to remove/recreate "
            "(default: env OHE_DB_CONTAINER_NAME or 'ohe-postgres')."
        ),
    )
    parser.add_argument(
        "--image",
        default=os.environ.get("OHE_DB_IMAGE", DEFAULT_IMAGE),
        help="Postgres image to use (default: env OHE_DB_IMAGE or 'postgres:16').",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("OHE_DB_CONFIG_HOST", _DEFAULT_HOST),
        help="Published host port is mapped here; used for the readiness note only "
        "(default: env OHE_DB_CONFIG_HOST or 'localhost').",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("OHE_DB_CONFIG_PORT", _DEFAULT_PORT)),
        help="Host port to publish to the container's 5432 (default: env "
        "OHE_DB_CONFIG_PORT or 5432).",
    )
    parser.add_argument(
        "--db-name",
        default=os.environ.get("OHE_DB_CONFIG_DB_NAME", _DEFAULT_DB_NAME),
        help="POSTGRES_DB (default: env OHE_DB_CONFIG_DB_NAME or 'ohev').",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("OHE_DB_CONFIG_USERNAME", _DEFAULT_USERNAME),
        help="POSTGRES_USER (default: env OHE_DB_CONFIG_USERNAME or 'ohev').",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("OHE_DB_CONFIG_PASSWORD", _DEFAULT_PASSWORD),
        help="POSTGRES_PASSWORD (default: env OHE_DB_CONFIG_PASSWORD or 'ohev').",
    )
    parser.add_argument(
        "--no-migrate",
        action="store_true",
        help="Skip running `uv run alembic upgrade head` after creating the container.",
    )
    parser.add_argument(
        "--no-seed",
        action="store_true",
        help="Skip running `uv run python -m openhands.ev2.scripts.seed_db` after migrating.",
    )
    parser.add_argument(
        "--keep-if-exists",
        action="store_true",
        help="Do not remove an existing container; abort instead. "
        "Useful to avoid clobbering a container you did not mean to reset.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def _run(
    cmd: list[str],
    *,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command, streaming output to the inherited stdout/stderr."""
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, check=check, text=True, env=env)


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
    # `docker rm -f` works whether the container is running or not.
    _run(["docker", "rm", "-f", name])


def _create_container(
    *,
    name: str,
    image: str,
    port: int,
    db_name: str,
    username: str,
    password: str,
) -> None:
    print(f"Creating container {name!r} from {image!r}...", file=sys.stderr)
    _run(
        [
            "docker",
            "run",
            "--name",
            name,
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-e",
            f"POSTGRES_USER={username}",
            "-e",
            f"POSTGRES_DB={db_name}",
            "-p",
            f"{port}:5432",
            "-d",
            image,
        ]
    )


def _wait_for_ready(name: str) -> None:
    print(f"Waiting for postgres in {name!r} to accept connections...", file=sys.stderr)
    deadline = time.monotonic() + _HEALTH_POLL_TIMEOUT_SECONDS
    last_err = ""
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "exec", name, "pg_isready", "-U", "postgres"],
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            print("postgres is ready.", file=sys.stderr)
            return
        last_err = result.stdout.strip() or result.stderr.strip()
        time.sleep(_HEALTH_POLL_INTERVAL_SECONDS)
    raise RuntimeError(
        f"postgres in container {name!r} did not become ready within "
        f"{_HEALTH_POLL_TIMEOUT_SECONDS}s (last: {last_err!r})"
    )


def _export_db_env(env: dict[str, str], args: argparse.Namespace) -> dict[str, str]:
    """Augment *env* with OHE_DB_CONFIG_* so alembic/seed target the new container.

    Alembic's env.py reads OHE_DB_CONFIG_* directly (it deliberately avoids the
    full AppConfig), and seed_db reads the same vars via AppConfig. Setting
    them explicitly here means the script works even if the caller's shell env
    points at a different DB.
    """
    env = dict(env)
    env["OHE_DB_CONFIG_HOST"] = "localhost"
    env["OHE_DB_CONFIG_PORT"] = str(args.port)
    env["OHE_DB_CONFIG_DB_NAME"] = args.db_name
    env["OHE_DB_CONFIG_USERNAME"] = args.username
    env["OHE_DB_CONFIG_PASSWORD"] = args.password
    return env


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)

    if _container_exists(args.container_name):
        if args.keep_if_exists:
            print(
                f"Container {args.container_name!r} already exists and "
                "--keep-if-exists was set; aborting to avoid clobbering it.",
                file=sys.stderr,
            )
            return 1
        _remove_container(args.container_name)

    _create_container(
        name=args.container_name,
        image=args.image,
        port=args.port,
        db_name=args.db_name,
        username=args.username,
        password=args.password,
    )
    _wait_for_ready(args.container_name)

    child_env = _export_db_env(os.environ.copy(), args)

    if not args.no_migrate:
        print("Running Alembic migrations...", file=sys.stderr)
        _run(["uv", "run", "alembic", "upgrade", "head"], check=True, env=child_env)
    else:
        print("Skipping Alembic migrations (--no-migrate).", file=sys.stderr)

    if not args.no_seed:
        print("Seeding database...", file=sys.stderr)
        _run(
            ["uv", "run", "python", "-m", "openhands.ev2.scripts.seed_db"],
            check=True,
            env=child_env,
        )
    else:
        print("Skipping seed (--no-seed).", file=sys.stderr)

    print(
        f"Local dev DB reset: container={args.container_name!r} "
        f"host={args.host}:{args.port} db={args.db_name} user={args.username}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
