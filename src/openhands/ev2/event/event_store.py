"""Backing store for full event bodies.

Every event's full body is written to a backing store — filesystem by
default, S3 optional — at a key derivable from the event's own identity::

    <event_date, ISO>/<event_id[:2]>/<event_id>.json

Because the key is derivable from the event row, the ``events`` table needs
no ``body_uri`` column and is identical in every deployment shape. Because
*all* events land in the store (not just the over-cap ones), the Postgres
projection is reconstructable from the store — the ``/body`` endpoint and the
reconciliation/backfill job both rely on this.

The stored object is a self-describing JSON envelope (not a bare payload) so
the backfill job can rebuild rows without consulting Postgres::

    {
      "id": "<uuid>",
      "conversation_id": "<uuid>",
      "kind": "<discriminator>",
      "timestamp": "<iso8601>",
      "size_bytes": <int>,
      "body": <payload>
    }

:class:`EventBodyStore` is a small ABC; the concrete
:class:`FilesystemEventBodyStore` is the default and :class:`S3EventBodyStore`
(``event/s3_event_store.py``) is an optional implementation selected via the
``event.body_store_class`` config value. The resolver mirrors
``SandboxService.resolve_sandbox_service_class``.
"""

from __future__ import annotations

import importlib
import logging
import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import date
from pathlib import Path

logger = logging.getLogger(__name__)


class StoredEventBody:
    """Object layout shared by every store implementation.

    Subclasses use :meth:`object_key` to derive the storing key, keeping the
    convention in one place — ABC helpers are concrete, backends only
    implement bytes-in/bytes-out.
    """

    @staticmethod
    def object_key(event_id: uuid.UUID, event_date: date) -> str:
        """The derivable object key for an event body."""
        return f"{event_date.isoformat()}/{str(event_id)[:2]}/{event_id}.json"


class EventBodyStore(StoredEventBody, ABC):
    """Interface for storing/retrieving full event bodies.

    Subclasses take a single ``location`` string at construction (a directory
    for the filesystem store, a bucket name for the S3 store); the resolver +
    config factory instantiates the configured class with one argument.
    """

    def __init__(self, location: str = "") -> None:
        _ = location

    @abstractmethod
    def store_body(self, event_id: uuid.UUID, event_date: date, payload: bytes) -> None:
        """Write *payload* at the derivable key for *(event_id, event_date)*."""

    @abstractmethod
    def load_body(self, event_id: uuid.UUID, event_date: date) -> bytes | None:
        """Read the stored body for *(event_id, event_date)*, or ``None``."""

    @abstractmethod
    def delete_day(self, event_date: date) -> int:
        """Delete every object under the ``<event_date>/`` prefix.

        Called by the partition manager when a daily partition is dropped so
        the store cleanup aligns with the table's date prefix. Returns the
        number of objects removed.
        """

    @abstractmethod
    def iter_envelopes(self) -> Iterator[tuple[uuid.UUID, date, bytes]]:
        """Yield ``(event_id, event_date, payload)`` for every stored object.

        Drives the reconciliation/backfill job (S3 → Postgres). The concrete
        implementations yield only ``<2-hex>/<id>.json`` entries so empty
        prefixes and stale directory entries are skipped.
        """


class FilesystemEventBodyStore(EventBodyStore):
    """Filesystem-backed store under a configured base directory."""

    def __init__(self, base_dir: str = "") -> None:
        # An empty base dir means "store disabled" — treat as configured only
        # when non-empty. Config defaults to an absolute path; tests pass a
        # tmp dir.
        self._base = Path(base_dir) if base_dir else None

    def _path(self, event_id: uuid.UUID, event_date: date) -> Path | None:
        if self._base is None:
            return None
        return self._base / self.object_key(event_id, event_date)

    def store_body(self, event_id: uuid.UUID, event_date: date, payload: bytes) -> None:
        path = self._path(event_id, event_date)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def load_body(self, event_id: uuid.UUID, event_date: date) -> bytes | None:
        path = self._path(event_id, event_date)
        if path is None or not path.is_file():
            return None
        return path.read_bytes()

    def delete_day(self, event_date: date) -> int:
        if self._base is None:
            return 0
        day_dir = self._base / event_date.isoformat()
        if not day_dir.is_dir():
            return 0
        removed = 0
        for entry in day_dir.rglob("*.json"):
            entry.unlink()
            removed += 1
        # Prune the (now possibly empty) day + prefix directories.
        for entry in sorted(day_dir.glob("*"), reverse=True):
            if entry.is_dir():
                entry.rmdir()
        day_dir.rmdir()
        return removed

    def iter_envelopes(self) -> Iterator[tuple[uuid.UUID, date, bytes]]:
        if self._base is None:
            return
        for day_dir in sorted(self._base.iterdir()):
            day = _day_from_envelope_path(day_dir)
            if day is None:
                continue
            for entry in sorted(day_dir.rglob("*.json")):
                parsed = _id_from_envelope_file(entry)
                if parsed is not None:
                    yield parsed, day, entry.read_bytes()


def _day_from_envelope_path(day_dir: Path) -> date | None:
    """The ISO date of an ``<event_date>/`` prefix directory, or ``None``."""
    if not day_dir.is_dir():
        return None
    try:
        return date.fromisoformat(day_dir.name)
    except ValueError:
        return None


def _id_from_envelope_file(entry: Path) -> uuid.UUID | None:
    """The event id parsed from an ``<id>.json`` filename, or ``None``."""
    try:
        return uuid.UUID(entry.stem)
    except ValueError:
        return None


def resolve_event_body_store_class(fqcn: str) -> type[EventBodyStore]:
    """Resolve a fully qualified class name to an ``EventBodyStore`` subclass."""
    module_name, _, class_name = fqcn.rpartition(".")
    if not module_name or not class_name:
        raise ValueError(f"Invalid event body_store class name: {fqcn!r}")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ValueError(f"Cannot import event body_store module {module_name!r}") from exc
    candidate = getattr(module, class_name, None)
    if not (isinstance(candidate, type) and issubclass(candidate, EventBodyStore)):
        raise TypeError(f"{fqcn!r} is not an EventBodyStore subclass.")
    return candidate
