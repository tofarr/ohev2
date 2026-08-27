"""add global allowed_origins table and cors_origin permission type

Revision ID: 0006_global_allowed_origins
Revises: 0005_auth2
Create Date: 2026-06-05

Adds the global CORS allow-list schema:

* ``allowed_origins`` — the single table holding the serialized browser
  origins (``scheme://host[:port]``, RFC 6454) permitted to make cross-origin
  requests to this API. The list is **global** (not linked to an OAuth client);
  it is a deployment-level concern, managed via the ``/cors-origins`` REST
  resource and read by the CORS middleware (cached, invalidated on mutation).

Also extends the ``permission_resource_type`` enum with ``cors_origin`` so
CORS-origin management can be permission-gated.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_global_allowed_origins"
down_revision: str | None = "0005_auth2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "allowed_origins",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("origin", sa.String(length=2048), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("origin"),
    )
    op.create_index(
        "ix_allowed_origins_origin",
        "allowed_origins",
        ["origin"],
    )

    # Extend the permission_resource_type enum with the new cors_origin value.
    op.execute("ALTER TYPE permission_resource_type ADD VALUE IF NOT EXISTS 'cors_origin'")


def downgrade() -> None:
    # Postgres cannot remove a single value from an enum type; leave the
    # 'cors_origin' value in place (harmless if unused).
    op.drop_index("ix_allowed_origins_origin", table_name="allowed_origins")
    op.drop_table("allowed_origins")
