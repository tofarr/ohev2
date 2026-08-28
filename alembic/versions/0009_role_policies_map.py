"""add roles.policies JSONB map column

Revision ID: 0009_role_policies_map
Revises: 0008_roles
Create Date: 2026-06-05

Adds a ``policies`` JSONB column to ``roles`` mapping a resource-type name
(e.g. ``"user"``, ``"api_key"``) to a serialized :class:`Permission2` policy.
This is the canonical, extensible store for per-resource role policies: new
resource types are governed by adding a map key rather than a dedicated column.
The legacy ``role_permission`` / ``user_permission`` columns are retained for
backward compatibility with existing data.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_role_policies_map"
down_revision: str | None = "0008_roles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "roles",
        sa.Column(
            "policies",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Map of resource-type name -> Permission2 policy; missing key = deny.",
        ),
    )


def downgrade() -> None:
    op.drop_column("roles", "policies")
