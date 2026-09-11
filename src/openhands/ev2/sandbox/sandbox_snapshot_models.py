"""ORM model for persisted sandbox snapshots.

A :class:`SandboxSnapshot` is the DB index row for a gzip-compressed tarball of
a sandbox workspace. The artifact itself is stored by the sandbox service
(local file for Docker, S3 bucket for K8s) — the DB row only carries the
``download_url`` the service produces. Listing snapshots never enumerates the
filesystem/bucket.

``sandbox_id`` is nullable: null for snapshots imported from an uploaded file
that did not come from a sandbox.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)


class SandboxSnapshot(Base):
    """A DB-indexed sandbox workspace snapshot.

    The artifact storage is hidden inside the sandbox service; this row is the
    queryable index. ``schema`` is a compatibility tag (e.g.
    ``docker-workspace-tar-v1``) used to validate restore compatibility.
    """

    __tablename__ = "sandbox_snapshots"
    __table_args__ = {"comment": "DB-indexed sandbox workspace snapshots (tarball artifacts)"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    sandbox_template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sandbox_templates.id", ondelete="RESTRICT"),
        index=True,
        comment="Template the snapshot is scoped to (for restore compatibility).",
    )
    schema: Mapped[str] = mapped_column(
        String(255),
        comment="Compatibility tag (e.g. docker-workspace-tar-v1).",
    )
    download_url: Mapped[str] = mapped_column(
        String(2048),
        comment="URL to stream the snapshot artifact.",
    )
    sandbox_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
        comment="Source sandbox id (container name) the snapshot was created from; null for file imports.",
    )
    size_bytes: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        default=None,
        comment="Size of the stored tarball artifact in bytes, when known.",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
    )
