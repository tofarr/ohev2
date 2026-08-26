"""add api_keys and refresh_tokens tables

Revision ID: 0004_auth_tokens
Revises: 0003_user_fields
Create Date: 2026-06-05

Adds two backing tables for the auth feature (AGENTS.md §9):

* ``api_keys`` — revocable backing rows for API-key credentials. Each row
  shares its ``jti`` with the API-key JWE token; a token whose jti has no live
  row is rejected even if the JWE itself is decryptable and unexpired.
* ``refresh_tokens`` — backing rows for OAuth2 refresh tokens, supporting
  rotation (the old row is disabled and a successor row with a fresh jti is
  created). ``expires_at`` is the absolute cap of the sliding refresh window.

Also extends the ``permission_resource_type`` enum with ``api_key`` so API-key
management can be permission-gated.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_auth_tokens"
down_revision: str | None = "0003_user_fields"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("jti", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("jti", name="uq_api_keys_jti"),
    )
    op.create_index("ix_api_keys_jti", "api_keys", ["jti"], unique=True)
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])

    op.create_table(
        "refresh_tokens",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("jti", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("replaced_by", sa.Uuid(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("jti", name="uq_refresh_tokens_jti"),
    )
    op.create_index("ix_refresh_tokens_jti", "refresh_tokens", ["jti"], unique=True)
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])

    # Extend the permission_resource_type enum with the new api_key value.
    op.execute("ALTER TYPE permission_resource_type ADD VALUE IF NOT EXISTS 'api_key'")


def downgrade() -> None:
    # Postgres cannot remove a single value from an enum type; leave the
    # 'api_key' value in place (it is harmless if unused) rather than recreate
    # the type, which would fail if any row references it.
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_jti", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_index("ix_api_keys_jti", table_name="api_keys")
    op.drop_table("api_keys")
