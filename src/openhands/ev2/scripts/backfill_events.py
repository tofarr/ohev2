"""Backfill ``events`` rows from the event body store (store → Postgres).

Covers the Postgres-down failure mode: the ingestion path wrote each event's
self-describing envelope to the backing store (S3/filesystem) even when the
database insert failed, so the reconciliation job can restore the missing
rows once Postgres recovers. Idempotent: every stored object is checked for
an existing row by id before insertion, and the stored id/timestamp stamp
the restored row (over-cap bodies are re-stubbed exactly as the write path).

Run via ``uv run python -m openhands.ev2.scripts.backfill_events``. The
configured store (``event.body_store_class`` / ``event.body_dir``) and body
cap (``event.body_cap_bytes``) resolve from the environment (``OHE_EVENT_*``
nested-prefixed vars / the same defaults the app uses).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from openhands.ev2.config import get_config
from openhands.ev2.db import create_engine, create_session_factory
from openhands.ev2.event.event_service import EventService


async def main(argv: Iterable[str] | None = None) -> int:
    """Restore missing ``events`` rows from the configured body store.

    Prints the number of restored rows to stdout. Exits 1 when no body store
    is configured (the sweep must run somewhere with a store).
    """
    _ = argv  # reserved for flags
    config = get_config()
    store = config.get_event_store()
    engine = create_engine(config.database_url)
    factory = create_session_factory(engine)
    try:
        async with factory() as session:
            service = EventService(
                session,
                store=store,
                body_cap_bytes=config.event.body_cap_bytes,
            )
            restored = await service.backfill()
            print(f"Restored {restored} event row(s) from the body store.")
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
