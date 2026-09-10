"""Filesystem-backed snapshot store shared by sandbox providers.

Both the Docker and Kubernetes sandbox providers persist snapshots as
gzip-compressed tarballs of the sandbox workspace directory in a configured
snapshot directory. This module centralizes the tar / untar / list / delete
operations so the two providers share identical artifact semantics, mirroring
the way a Kubernetes VolumeSnapshot can be restored into a new PVC.

A snapshot tarball is stored at ``<snapshot_dir>/<snapshot_id>.tar.gz``. The
store is intentionally simple: it owns no metadata beyond the files on disk;
the snapshot id is the filename stem and the created-at timestamp is the
file's mtime. Providers layer their own :class:`SandboxSnapshot` models on top
for the source-sandbox and user-id bookkeeping.
"""

from __future__ import annotations

import contextlib
import gzip
import logging
import os
import tarfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_SNAPSHOT_SUFFIX = ".tar.gz"


def snapshot_path(snapshot_dir: str | os.PathLike[str], snapshot_id: str) -> Path:
    """Return the on-disk tarball path for *snapshot_id* in *snapshot_dir*."""
    return Path(snapshot_dir) / f"{snapshot_id}{_SNAPSHOT_SUFFIX}"


def ensure_snapshot_dir(snapshot_dir: str | os.PathLike[str]) -> Path:
    """Create the snapshot directory (and parents) if missing, returning it."""
    path = Path(snapshot_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def list_snapshot_ids(snapshot_dir: str | os.PathLike[str]) -> list[str]:
    """Return the ids of every tarball in *snapshot_dir*."""
    directory = Path(snapshot_dir)
    if not directory.is_dir():
        return []
    ids: list[str] = []
    for entry in directory.iterdir():
        if entry.is_file() and entry.name.endswith(_SNAPSHOT_SUFFIX):
            ids.append(entry.name[: -len(_SNAPSHOT_SUFFIX)])
    return ids


def snapshot_exists(snapshot_dir: str | os.PathLike[str], snapshot_id: str) -> bool:
    """Return ``True`` when the tarball for *snapshot_id* is present."""
    return snapshot_path(snapshot_dir, snapshot_id).is_file()


def snapshot_size(snapshot_dir: str | os.PathLike[str], snapshot_id: str) -> int | None:
    """Return the tarball size in bytes, or ``None`` when absent."""
    path = snapshot_path(snapshot_dir, snapshot_id)
    try:
        return path.stat().st_size
    except OSError:
        return None


def snapshot_created_at(snapshot_dir: str | os.PathLike[str], snapshot_id: str) -> datetime | None:
    """Return the tarball mtime as an aware UTC datetime, or ``None``."""
    path = snapshot_path(snapshot_dir, snapshot_id)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    return datetime.fromtimestamp(mtime, tz=UTC)


def create_snapshot(
    snapshot_dir: str | os.PathLike[str],
    snapshot_id: str,
    workspace_path: str | os.PathLike[str],
) -> Path:
    """Tar+gzip *workspace_path* into ``<snapshot_dir>/<snapshot_id>.tar.gz``.

    The archive records the *contents* of the workspace directory (not the
    directory itself), so restoring into a fresh workspace reproduces the same
    file tree. Raises :class:`FileExistsError` if a tarball for *snapshot_id*
    already exists. The caller is responsible for ensuring the workspace is
    quiescent (sandbox paused) before invoking this.
    """
    ensure_snapshot_dir(snapshot_dir)
    target = snapshot_path(snapshot_dir, snapshot_id)
    if target.exists():
        raise FileExistsError(f"snapshot {snapshot_id!r} already exists at {target}")
    src = Path(workspace_path)
    # Stream into a gzip file to avoid loading the whole archive into memory.
    with gzip.open(target, "wb") as gz, tarfile.open(fileobj=gz, mode="w|") as tar:
        tar.add(src, arcname=".")
    logger.info("created snapshot %s from %s (%s bytes)", snapshot_id, src, target.stat().st_size)
    return target


def restore_snapshot(
    snapshot_dir: str | os.PathLike[str],
    snapshot_id: str,
    workspace_path: str | os.PathLike[str],
) -> Path:
    """Extract ``<snapshot_dir>/<snapshot_id>.tar.gz`` into *workspace_path*.

    The workspace directory is created (with parents) if missing. Raises
    :class:`FileNotFoundError` when the tarball is absent. Existing contents
    are not wiped first — callers should restore into a fresh workspace to
    avoid mixing generations.
    """
    archive = snapshot_path(snapshot_dir, snapshot_id)
    if not archive.is_file():
        raise FileNotFoundError(f"snapshot {snapshot_id!r} not found at {archive}")
    dest = Path(workspace_path)
    dest.mkdir(parents=True, exist_ok=True)
    with gzip.open(archive, "rb") as gz, tarfile.open(fileobj=gz, mode="r|") as tar:
        tar.extractall(dest, filter="data")
    logger.info("restored snapshot %s into %s", snapshot_id, dest)
    return dest


def import_snapshot(
    snapshot_dir: str | os.PathLike[str],
    snapshot_id: str,
    file_data: bytes,
) -> Path:
    """Write uploaded *file_data* as ``<snapshot_dir>/<snapshot_id>.tar.gz``.

    Raises :class:`FileExistsError` if a tarball for *snapshot_id* already
    exists. The bytes are expected to be a gzip-compressed tarball; this is a
    raw write so the provider can surface a download of the exact artifact.
    """
    ensure_snapshot_dir(snapshot_dir)
    target = snapshot_path(snapshot_dir, snapshot_id)
    if target.exists():
        raise FileExistsError(f"snapshot {snapshot_id!r} already exists at {target}")
    target.write_bytes(file_data)
    logger.info("imported snapshot %s (%s bytes)", snapshot_id, len(file_data))
    return target


def delete_snapshot(snapshot_dir: str | os.PathLike[str], snapshot_id: str) -> None:
    """Remove the tarball for *snapshot_id*; silent if absent."""
    path = snapshot_path(snapshot_dir, snapshot_id)
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


def stream_snapshot(snapshot_dir: str | os.PathLike[str], snapshot_id: str) -> Iterator[bytes]:
    """Yield chunks of the tarball for streaming download."""
    path = snapshot_path(snapshot_dir, snapshot_id)
    if not path.is_file():
        raise FileNotFoundError(f"snapshot {snapshot_id!r} not found at {path}")
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(64 * 1024)
            if not chunk:
                break
            yield chunk
