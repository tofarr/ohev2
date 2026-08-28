"""add idp_access_tokens table

Revision ID: 0007_auth2_access_tokens
Revises: 0006_allowed_origins
Create Date: 2026-06-05

Persists the IdP access token alongside the IdP refresh token so the project
can sync the local minted token expiries to the federated source and perform
server-side refresh on an authenticated request when the access token is about
to expire (cookie flow).

* ``idp_access_tokens`` — encrypted IdP access token + drift-adjusted expiry,
  1:1 with ``idp_refresh_tokens`` (cascade delete). The local access-token JWE
  handed to clients carries this row's id and has its ``exp`` synced to the
  row's ``expires_at``.

The ``idp_refresh_tokens.expires_at`` semantics change in the same step: it
now holds the IdP *refresh*-token expiry (previously it held the access-token
``expires_in``, which was incorrect). Existing rows are left in place; the
next refresh rewrites both rows with the corrected, IdP-sourced expiries.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_auth2_access_tokens"
down_revision: str | None = "0006_allowed_origins"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "idp_access_tokens",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("refresh_token_id", sa.Uuid(), nullable=False),
        sa.Column("access_token", sa.String(length=8192), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["refresh_token_id"],
            ["idp_refresh_tokens.id"],
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_idp_access_tokens_refresh_token_id",
        "idp_access_tokens",
        ["refresh_token_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_idp_access_tokens_refresh_token_id",
        table_name="idp_access_tokens",
    )
    op.drop_table("idp_access_tokens")
