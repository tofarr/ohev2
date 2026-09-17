"""add progress and status_code to jobs

Revision ID: 0003_job_progress_status_code
Revises: 0002_sandbox_config_secret_key
Create Date: 2026-06-05

Adds two runner-managed columns to the range-partitioned ``jobs`` table,
placed immediately after ``status``:

* ``progress`` (float, default 0.0, range [0.0, 1.0] enforced by a CHECK) —
  fractional progress a job body reports mid-run via the
  :class:`~openhands.ev2.job.job_models.JobProgressReporter` handle. Set to
  0.0 on create/claim and to 1.0 by the runner on ``COMPLETED``.
* ``status_code`` (nullable str) — an optional machine-readable sub-status a
  multi-stage job may update mid-run (e.g. a stage name). Free-form.

Both are runner-managed, not client-settable: they do not appear on
``JobCreate`` / ``JobUpdate`` and are exposed read-only on ``JobRead``.

``ALTER TABLE ... ADD COLUMN`` on a partitioned parent propagates to every
existing child partition (and to partitions created afterwards), so no
per-partition DDL is needed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_job_progress_status_code"
down_revision: str | None = "0002_sandbox_config_secret_key"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column(
            "progress",
            sa.Float(),
            nullable=False,
            server_default=sa.text("0.0"),
            comment="Runner-managed fractional progress in [0.0, 1.0].",
        ),
    )
    op.add_column(
        "jobs",
        sa.Column(
            "status_code",
            sa.String(length=255),
            nullable=True,
            comment="Runner-managed machine-readable sub-status (e.g. a stage name).",
        ),
    )
    op.create_check_constraint(
        "ck_jobs_progress_range",
        "jobs",
        "progress >= 0.0 AND progress <= 1.0",
    )


def downgrade() -> None:
    op.drop_constraint("ck_jobs_progress_range", "jobs", type_="check")
    op.drop_column("jobs", "status_code")
    op.drop_column("jobs", "progress")
