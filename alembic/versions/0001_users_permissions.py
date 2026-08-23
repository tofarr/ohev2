"""create users and permissions tables

Revision ID: 0001_users_permissions
Revises:
Create Date: 2026-06-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_users_permissions"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "action",
            sa.Enum("*", "create", "read", "write", "delete", "use", name="permission_action"),
            nullable=False,
        ),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("custom_action", sa.String(length=64), nullable=True),
        sa.Column(
            "selector_kind",
            sa.Enum("all", "by_id", "by_tag", name="permission_selector_kind"),
            nullable=False,
        ),
        sa.Column("selector_value", sa.String(length=255), nullable=True),
        sa.Column("attributes", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE", name="fk_permissions_user_id_users"
        ),
        sa.PrimaryKeyConstraint("id"),
        comment="ABAC permission grants",
    )
    op.create_index("ix_permissions_user_id", "permissions", ["user_id"], unique=False)
    op.create_index("ix_permissions_resource_type", "permissions", ["resource_type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_permissions_resource_type", table_name="permissions")
    op.drop_index("ix_permissions_user_id", table_name="permissions")
    op.drop_table("permissions")
    sa.Enum(name="permission_selector_kind").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="permission_action").drop(op.get_bind(), checkfirst=True)
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
