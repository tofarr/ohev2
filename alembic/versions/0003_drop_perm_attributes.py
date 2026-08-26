"""drop attributes column from permissions

Revision ID: 0003_drop_perm_attributes
Revises: 0002_perm_nullable_search_filter
Create Date: 2026-06-05

Removes the ``attributes`` column from the ``permissions`` table.
Attribute-level filtering is no longer modeled on the permission itself; when a
different attribute set is needed, define a distinct schema/router over the
same underlying model that filters out the unwanted attributes.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_drop_perm_attributes"
down_revision: str | None = "0002_perm_nullable_search_filter"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("permissions", "attributes")


def downgrade() -> None:
    op.add_column(
        "permissions",
        sa.Column("attributes", postgresql.ARRAY(sa.String()), nullable=True),
    )
