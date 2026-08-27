"""add auth2 tables and users.idp_user_id

Revision ID: 0005_auth2
Revises: 0004_auth_tokens
Create Date: 2026-06-05

Adds the federated OAuth (auth2) schema (AGENTS.md §9):

* ``users.idp_user_id`` — indexed nullable string holding the stable identity
  provider subject used to look up the local user on callback.
* ``idp_refresh_tokens`` — encrypted IdP refresh tokens, one per local user,
  with an expiry adjusted by ``idp_expire_drift_tolerance``. The IdP access
  token is not persisted (short-lived; refresh needs only the refresh token).
* ``oauth_clients`` — clients registered to use this project as an OAuth
  provider; ``client_secret`` is encrypted at rest.
* ``oauth_client_redirect_uris`` — permitted redirect URIs (wildcard segments
  allowed) for each OAuth client.

Also extends the ``permission_resource_type`` enum with ``oauth_client`` so
OAuth-client management can be permission-gated.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_auth2"
down_revision: str | None = "0004_auth_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # users.idp_user_id — stable IdP subject for federated lookup.
    op.add_column(
        "users",
        sa.Column("idp_user_id", sa.String(length=255), nullable=True),
    )
    op.create_index("ix_users_idp_user_id", "users", ["idp_user_id"])

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
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
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

    # Extend the permission_resource_type enum with the new oauth_client value.
    op.execute("ALTER TYPE permission_resource_type ADD VALUE IF NOT EXISTS 'oauth_client'")


def downgrade() -> None:
    # Postgres cannot remove a single value from an enum type; leave the
    # 'oauth_client' value in place (harmless if unused).
    op.drop_index(
        "ix_oauth_client_redirect_uris_client_id",
        table_name="oauth_client_redirect_uris",
    )
    op.drop_table("oauth_client_redirect_uris")
    op.drop_index("ix_oauth_clients_client_id", table_name="oauth_clients")
    op.drop_table("oauth_clients")
    op.drop_index("ix_idp_refresh_tokens_user_id", table_name="idp_refresh_tokens")
    op.drop_table("idp_refresh_tokens")
    op.drop_index("ix_users_idp_user_id", table_name="users")
    op.drop_column("users", "idp_user_id")
