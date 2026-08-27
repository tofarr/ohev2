"""add oauth_client_allowed_origins

Revision ID: 0006_auth2_allowed_origins
Revises: 0005_auth2
Create Date: 2026-06-05

Adds the ``oauth_client_allowed_origins`` table (AGENTS.md §9 — XSRF defense
for the ``response_type=cookie`` flow). Each row is a serialized browser origin
(scheme://host[:port], RFC 6454) permitted to initiate a cookie flow for an
OAuth client. An empty allow-list means "no origin restriction"; a non-empty
list gates the cookie flow on a matching ``Origin``/``Referer``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_auth2_allowed_origins"
down_revision: str | None = "0005_auth2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oauth_client_allowed_origins",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("origin", sa.String(length=2048), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["client_id"], ["oauth_clients.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_oauth_client_allowed_origins_client_id",
        "oauth_client_allowed_origins",
        ["client_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_oauth_client_allowed_origins_client_id",
        table_name="oauth_client_allowed_origins",
    )
    op.drop_table("oauth_client_allowed_origins")
