"""add roles and role_users tables

Revision ID: 0008_roles
Revises: 0007_auth2_access_tokens
Create Date: 2026-06-05

Introduces the security module's role-based foundation. ``roles`` bundles
per-resource :class:`Permission2` policies (discriminated-union JSON) in two
JSONB columns (``role_permission``, ``user_permission``). ``role_users`` links
roles to users. This is additive only — the legacy ``permissions`` table and
its auth dependencies are untouched in this step.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_roles"
down_revision: str | None = "0007_auth2_access_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("role_permission", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("user_permission", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        comment="Named role bundling permission2 policies",
    )
    op.create_index("ix_roles_name", "roles", ["name"], unique=True)

    op.create_table(
        "role_users",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"], ["roles.id"], ondelete="CASCADE", name="fk_role_users_role_id_roles"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE", name="fk_role_users_user_id_users"
        ),
        sa.PrimaryKeyConstraint("id"),
        comment="Role-to-user assignments",
    )
    op.create_index("ix_role_users_role_id", "role_users", ["role_id"], unique=False)
    op.create_index("ix_role_users_user_id", "role_users", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_role_users_user_id", table_name="role_users")
    op.drop_index("ix_role_users_role_id", table_name="role_users")
    op.drop_table("role_users")
    op.drop_index("ix_roles_name", table_name="roles")
    op.drop_table("roles")
