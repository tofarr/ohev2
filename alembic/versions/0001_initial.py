"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-05

Single consolidated initial migration for the openhands.ev2 schema. Created by
collapsing the prior incremental migrations (0001-0010) into one baseline now
that the project is still in initial development and nothing has been
published. The schema reflects the current ORM models exactly: there is no
legacy ``permissions`` table or its enum types.

Tables:

* ``users``                  — local users, with federated IdP subject link.
* ``api_keys``               — revocable backing rows for API-key JWEs.
* ``refresh_tokens``         — backing rows for OAuth2 refresh tokens (rotation).
* ``idp_refresh_tokens``     — encrypted IdP refresh tokens (federated auth).
* ``idp_access_tokens``     — encrypted IdP access tokens (1:1 with refresh).
* ``oauth_clients``          — OAuth provider client registrations.
* ``oauth_client_redirect_uris`` — permitted redirect URIs per client.
* ``allowed_origins``        — CORS allow-list.
* ``roles``                  — named role bundling per-entity Permission policies.
* ``user_roles``             — role-to-user assignments.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ------------------------------------------------------------------ #
    # users
    # ------------------------------------------------------------------ #
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("password", sa.String(length=2048), nullable=True),
        sa.Column(
            "idp_user_id",
            sa.String(length=255),
            nullable=True,
            comment="Stable IdP subject for federated lookup; null for local users.",
        ),
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
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_idp_user_id", "users", ["idp_user_id"])

    # ------------------------------------------------------------------ #
    # api_keys
    # ------------------------------------------------------------------ #
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
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
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

    # ------------------------------------------------------------------ #
    # refresh_tokens
    # ------------------------------------------------------------------ #
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
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
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

    # ------------------------------------------------------------------ #
    # idp_refresh_tokens
    # ------------------------------------------------------------------ #
    op.create_table(
        "idp_refresh_tokens",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("refresh_token", sa.String(length=8192), nullable=False),
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
    )
    op.create_index("ix_idp_refresh_tokens_user_id", "idp_refresh_tokens", ["user_id"])

    # ------------------------------------------------------------------ #
    # idp_access_tokens
    # ------------------------------------------------------------------ #
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

    # ------------------------------------------------------------------ #
    # oauth_clients
    # ------------------------------------------------------------------ #
    op.create_table(
        "oauth_clients",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("client_id", sa.String(length=128), nullable=False),
        sa.Column("client_secret", sa.String(length=8192), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
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
        sa.UniqueConstraint("client_id", name="uq_oauth_clients_client_id"),
    )
    op.create_index("ix_oauth_clients_client_id", "oauth_clients", ["client_id"], unique=True)

    # ------------------------------------------------------------------ #
    # oauth_client_redirect_uris
    # ------------------------------------------------------------------ #
    op.create_table(
        "oauth_client_redirect_uris",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("uri", sa.String(length=2048), nullable=False),
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
        "ix_oauth_client_redirect_uris_client_id",
        "oauth_client_redirect_uris",
        ["client_id"],
    )

    # ------------------------------------------------------------------ #
    # allowed_origins
    # ------------------------------------------------------------------ #
    op.create_table(
        "allowed_origins",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("origin", sa.String(length=2048), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("origin"),
    )
    op.create_index(
        "ix_allowed_origins_origin",
        "allowed_origins",
        ["origin"],
    )

    # ------------------------------------------------------------------ #
    # roles
    # ------------------------------------------------------------------ #
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "user_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for user resources; null = deny.",
        ),
        sa.Column(
            "role_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for role resources; null = deny.",
        ),
        sa.Column(
            "user_role_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for user-role assignment resources; null = deny.",
        ),
        sa.Column(
            "api_key_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for api_key resources; null = deny.",
        ),
        sa.Column(
            "oauth_client_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for oauth_client resources; null = deny.",
        ),
        sa.Column(
            "cors_origin_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for cors_origin resources; null = deny.",
        ),
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
        comment="Named role bundling per-entity permission policies",
    )
    op.create_index("ix_roles_name", "roles", ["name"], unique=True)

    # ------------------------------------------------------------------ #
    # user_roles
    # ------------------------------------------------------------------ #
    op.create_table(
        "user_roles",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["role_id"], ["roles.id"], ondelete="CASCADE", name="fk_user_roles_role_id_roles"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE", name="fk_user_roles_user_id_users"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("role_id", "user_id", name="uq_user_roles_role_id_user_id"),
        comment="Role-to-user assignments",
    )
    op.create_index("ix_user_roles_role_id", "user_roles", ["role_id"], unique=False)
    op.create_index("ix_user_roles_user_id", "user_roles", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_user_roles_user_id", table_name="user_roles")
    op.drop_index("ix_user_roles_role_id", table_name="user_roles")
    op.drop_table("user_roles")
    op.drop_index("ix_roles_name", table_name="roles")
    op.drop_table("roles")
    op.drop_index("ix_allowed_origins_origin", table_name="allowed_origins")
    op.drop_table("allowed_origins")
    op.drop_index(
        "ix_oauth_client_redirect_uris_client_id",
        table_name="oauth_client_redirect_uris",
    )
    op.drop_table("oauth_client_redirect_uris")
    op.drop_index("ix_oauth_clients_client_id", table_name="oauth_clients")
    op.drop_table("oauth_clients")
    op.drop_index(
        "ix_idp_access_tokens_refresh_token_id",
        table_name="idp_access_tokens",
    )
    op.drop_table("idp_access_tokens")
    op.drop_index("ix_idp_refresh_tokens_user_id", table_name="idp_refresh_tokens")
    op.drop_table("idp_refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_jti", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_index("ix_api_keys_jti", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_users_idp_user_id", table_name="users")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
