"""add enabled, username, password columns to users

Revision ID: 0003_user_fields
Revises: 0002_perm_nullable_search_filter
Create Date: 2026-06-05

Adds three columns to the ``users`` table:

* ``enabled`` — non-null boolean, defaults to ``true``.
* ``username`` — non-null string (max 64), unique with its own index.
* ``password`` — nullable string (max 2048) holding a bcrypt salted hash
  ($2b$…); never stores plaintext (AGENTS.md §9). Verification re-hashes the
  candidate password and compares; the stored value is not reversible.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_user_fields"
down_revision: str | None = "0002_perm_nullable_search_filter"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # `enabled` and `password` are nullable for the initial add on populated
    # tables; we then backfill defaults and enforce NOT NULL so existing rows
    # are upgraded cleanly. `username` requires a value too: backfill a
    # placeholder derived from the row id so the NOT NULL + unique add works,
    # then enforce uniqueness via the index.
    op.add_column(
        "users",
        sa.Column("enabled", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("username", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("password", sa.String(length=2048), nullable=True),
    )

    # Backfill: existing rows become enabled, get a unique placeholder username.
    op.execute("UPDATE users SET enabled = TRUE")
    op.execute("UPDATE users SET username = 'user_' || id::text WHERE username IS NULL")

    op.alter_column("users", "enabled", existing_type=sa.Boolean(), nullable=False)
    op.alter_column(
        "users",
        "username",
        existing_type=sa.String(length=64),
        nullable=False,
    )

    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_username", table_name="users")
    op.drop_column("users", "password")
    op.drop_column("users", "username")
    op.drop_column("users", "enabled")
