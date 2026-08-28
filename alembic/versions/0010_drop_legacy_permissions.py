"""drop legacy permissions table and enums

Revision ID: 0010_drop_legacy_permissions
Revises: 0009_role_policies_map
Create Date: 2026-06-05

Drops the legacy ABAC ``permissions`` table and the two enum types it owned
(``permission_action``, ``permission_resource_type``). Authorization is now
handled entirely by the security module's role-based ``Permission2`` policies
and the auth2 dependency layer (AGENTS.md §9).

The ``api_keys`` and ``refresh_tokens`` tables created in 0004 are retained —
they back the API-key and refresh-token credentials now owned by the auth2
package. Only the legacy ``permissions`` table and its enums are removed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_drop_legacy_permissions"
down_revision: str | None = "0009_role_policies_map"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("ix_permissions_resource_type", table_name="permissions")
    op.drop_index("ix_permissions_user_id", table_name="permissions")
    op.drop_table("permissions")
    sa.Enum(name="permission_resource_type").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="permission_action").drop(op.get_bind(), checkfirst=True)


def downgrade() -> None:
    from sqlalchemy.dialects import postgresql

    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column(
            "action",
            sa.Enum(
                "all",
                "create",
                "read",
                "update",
                "delete",
                "search",
                "use",
                name="permission_action",
            ),
            nullable=False,
        ),
        sa.Column(
            "resource_type",
            sa.Enum(
                "user",
                "permission",
                "api_key",
                "oauth_client",
                "cors_origin",
                name="permission_resource_type",
            ),
            nullable=False,
        ),
        sa.Column("attributes", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column(
            "search_filter",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE", name="fk_permissions_user_id_users"
        ),
        sa.PrimaryKeyConstraint("id"),
        comment="ABAC permission grants",
    )
    op.create_index("ix_permissions_user_id", "permissions", ["user_id"], unique=False)
    op.create_index("ix_permissions_resource_type", "permissions", ["resource_type"], unique=False)
