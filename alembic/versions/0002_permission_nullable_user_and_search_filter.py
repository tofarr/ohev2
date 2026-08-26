"""nullable user_id and search_filter on permissions

Revision ID: 0002_permission_nullable_user_and_search_filter
Revises: 0001_users_permissions
Create Date: 2026-06-05

Makes ``permissions.user_id`` nullable so a permission can be defined for the
anonymous (not-logged-in) principal, and adds the ``search_filter`` JSONB
column carrying the row-level scope of a grant (NULL = unrestricted).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_permission_nullable_user_and_search_filter"
down_revision: str | None = "0001_users_permissions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "permissions",
        "user_id",
        existing_type=sa.Uuid(),
        nullable=True,
    )
    op.add_column(
        "permissions",
        sa.Column(
            "search_filter",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Serialized search filter scoping the grant; null = unrestricted.",
        ),
    )


def downgrade() -> None:
    op.drop_column("permissions", "search_filter")
    op.alter_column(
        "permissions",
        "user_id",
        existing_type=sa.Uuid(),
        nullable=False,
    )
