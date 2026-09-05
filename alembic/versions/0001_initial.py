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
* ``api_keys``               — revocable backing rows for API keys (hash + prefix).
* ``refresh_tokens``         — backing rows for OAuth2 refresh tokens (rotation).
* ``idp_refresh_tokens``     — encrypted IdP refresh tokens (federated auth).
* ``idp_access_tokens``     — encrypted IdP access tokens (1:1 with refresh).
* ``oauth_clients``          — OAuth provider client registrations.
* ``oauth_client_redirect_uris`` — permitted redirect URIs per client.
* ``allowed_origins``        — CORS allow-list.
* ``roles``                  — named role bundling per-entity Permission policies.
* ``user_roles``             — role-to-user assignments.
* ``secrets``                — named secrets with encrypted values.
* ``role_secret_permissions``           — per-role grants of access to secrets.
* ``user_secret_permissions``           — per-user grants of access to secrets.
* ``mcp_server_configs``    — stored MCP server configurations.
* ``role_mcp_server_config_permissions`` — per-role grants for MCP configs.
* ``provider_connections``   — shared LLM provider credential bundles (encrypted api_key).
* ``llms``                   — stored LLM profiles referencing a provider connection.
* ``feature_flags``          — named feature flags keyed by a string id.
* ``feature_flag_role_assignments``     — per-role overrides of feature flags.
* ``sandbox_templates``      — reusable sandbox activation templates.
* ``sandbox_filesystems``    — durable Fusey-backed sandbox filesystems.
* ``sandboxes``              — user-facing durable sandbox environments.
* ``sandbox_snapshots``      — named Fusey filesystem generation pins.
* ``sandbox_computes``       — internal replaceable compute attachments.
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
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=32), nullable=False),
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
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
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
            "secret_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for secret resources; null = deny.",
        ),
        sa.Column(
            "secret_grant_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for role-secret grant resources; null = deny.",
        ),
        sa.Column(
            "mcp_server_config_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for mcp_server_config resources; null = deny.",
        ),
        sa.Column(
            "mcp_server_config_grant_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for role-MCP-config grant resources; null = deny.",
        ),
        sa.Column(
            "provider_connection_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for provider_connection resources; null = deny.",
        ),
        sa.Column(
            "llm_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for llm resources; null = deny.",
        ),
        sa.Column(
            "llm_aggregated_usage_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for llm_aggregated_usage resources; null = deny.",
        ),
        sa.Column(
            "feature_flag_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for feature_flag resources; null = deny.",
        ),
        sa.Column(
            "feature_flag_role_assignment_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for feature_flag_role_assignment resources; null = deny.",
        ),
        sa.Column(
            "feature_flag_user_assignment_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for feature_flag_user_assignment resources; null = deny.",
        ),
        sa.Column(
            "sandbox_template_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for sandbox_template resources; null = deny.",
        ),
        sa.Column(
            "sandbox_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for sandbox resources; null = deny.",
        ),
        sa.Column(
            "sandbox_snapshot_permission",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Permission policy for sandbox_snapshot resources; null = deny.",
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

    # ------------------------------------------------------------------ #
    # secrets
    # ------------------------------------------------------------------ #
    op.create_table(
        "secrets",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("code", sa.String(length=255), nullable=False),
        sa.Column("value", sa.Text(), nullable=False, comment="Encrypted value (JWE ciphertext)."),
        sa.Column("description", sa.Text(), nullable=True),
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
        sa.UniqueConstraint("code"),
    )
    op.create_index("ix_secrets_code", "secrets", ["code"], unique=True)

    # ------------------------------------------------------------------ #
    # role_secret_permissions
    # ------------------------------------------------------------------ #
    op.create_table(
        "role_secret_permissions",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("secret_id", sa.Uuid(), nullable=False),
        sa.Column("read_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("update_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("delete_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            ondelete="CASCADE",
            name="fk_role_secret_permissions_role_id_roles",
        ),
        sa.ForeignKeyConstraint(
            ["secret_id"],
            ["secrets.id"],
            ondelete="CASCADE",
            name="fk_role_secret_permissions_secret_id_secrets",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "role_id", "secret_id", name="uq_role_secret_permissions_role_id_secret_id"
        ),
        comment="Per-role grants of access to secrets",
    )
    op.create_index(
        "ix_role_secret_permissions_role_id", "role_secret_permissions", ["role_id"], unique=False
    )

    # ------------------------------------------------------------------ #
    # mcp_server_configs
    # ------------------------------------------------------------------ #
    op.create_table(
        "mcp_server_configs",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=True),
        sa.Column("transport", sa.String(length=32), nullable=True),
        sa.Column("command", sa.String(length=2048), nullable=True),
        sa.Column("args", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "env",
            sa.Text(),
            nullable=True,
            comment="Encrypted JSON map of MCP environment variables.",
        ),
        sa.Column("cwd", sa.String(length=2048), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("icon", sa.String(length=2048), nullable=True),
        sa.Column("timeout", sa.Float(), nullable=True),
        sa.Column("sse_read_timeout", sa.Float(), nullable=True),
        sa.Column("keep_alive", sa.Boolean(), nullable=True),
        sa.Column(
            "headers",
            sa.Text(),
            nullable=True,
            comment="Encrypted JSON map of MCP HTTP headers.",
        ),
        sa.Column(
            "auth",
            sa.Text(),
            nullable=True,
            comment="Encrypted JSON MCP auth credential.",
        ),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("enable_proxy", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        comment="Stored MCP server configurations",
    )
    op.create_index("ix_mcp_server_configs_user_id", "mcp_server_configs", ["user_id"])

    # ------------------------------------------------------------------ #
    # role_mcp_server_config_permissions
    # ------------------------------------------------------------------ #
    op.create_table(
        "role_mcp_server_config_permissions",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("mcp_server_config_id", sa.Uuid(), nullable=False),
        sa.Column("read_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("update_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("delete_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            ondelete="CASCADE",
            name="fk_role_mcp_server_config_permissions_role_id_roles",
        ),
        sa.ForeignKeyConstraint(
            ["mcp_server_config_id"],
            ["mcp_server_configs.id"],
            ondelete="CASCADE",
            name="fk_role_mcp_server_config_permissions_config_id_configs",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "role_id",
            "mcp_server_config_id",
            name="uq_role_mcp_server_config_permissions_role_id_config_id",
        ),
        comment="Per-role grants of access to MCP server configs",
    )
    op.create_index(
        "ix_role_mcp_server_config_permissions_role_id",
        "role_mcp_server_config_permissions",
        ["role_id"],
        unique=False,
    )
    op.create_index(
        "ix_role_mcp_server_config_permissions_mcp_server_config_id",
        "role_mcp_server_config_permissions",
        ["mcp_server_config_id"],
        unique=False,
    )

    op.create_index(
        "ix_role_secret_permissions_secret_id",
        "role_secret_permissions",
        ["secret_id"],
        unique=False,
    )

    # ------------------------------------------------------------------ #
    # user_secret_permissions
    # ------------------------------------------------------------------ #
    op.create_table(
        "user_secret_permissions",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("secret_id", sa.Uuid(), nullable=False),
        sa.Column("read_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("update_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("delete_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name="fk_user_secret_permissions_user_id_users",
        ),
        sa.ForeignKeyConstraint(
            ["secret_id"],
            ["secrets.id"],
            ondelete="CASCADE",
            name="fk_user_secret_permissions_secret_id_secrets",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id", "secret_id", name="uq_user_secret_permissions_user_id_secret_id"
        ),
        comment="Per-user grants of access to secrets",
    )
    op.create_index(
        "ix_user_secret_permissions_user_id",
        "user_secret_permissions",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_user_secret_permissions_secret_id",
        "user_secret_permissions",
        ["secret_id"],
        unique=False,
    )

    # ------------------------------------------------------------------ #
    # provider_connections
    # ------------------------------------------------------------------ #
    op.create_table(
        "provider_connections",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=128), nullable=False),
        sa.Column(
            "api_key",
            sa.String(length=8192),
            nullable=True,
            comment="Encrypted API key (JWE ciphertext); null when unset.",
        ),
        sa.Column("base_url", sa.String(length=2048), nullable=True),
        sa.Column("enable_proxy", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name="fk_provider_connections_user_id_users",
        ),
        sa.PrimaryKeyConstraint("id"),
        comment="Shared LLM provider credential bundles (encrypted api_key)",
    )
    op.create_index(
        "ix_provider_connections_user_id", "provider_connections", ["user_id"], unique=False
    )

    # ------------------------------------------------------------------ #
    # llms
    # ------------------------------------------------------------------ #
    op.create_table(
        "llms",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("provider_connection_id", sa.Uuid(), nullable=False),
        sa.Column("model", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            comment="Serialized SDK LLM config (all fields except model/provider/api_key/base_url).",
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
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE", name="fk_llms_user_id_users"
        ),
        sa.ForeignKeyConstraint(
            ["provider_connection_id"],
            ["provider_connections.id"],
            ondelete="CASCADE",
            name="fk_llms_provider_connection_id_provider_connections",
        ),
        sa.PrimaryKeyConstraint("id"),
        comment="Stored LLM profiles referencing a provider connection",
    )
    op.create_index("ix_llms_user_id", "llms", ["user_id"], unique=False)
    op.create_index(
        "ix_llms_provider_connection_id", "llms", ["provider_connection_id"], unique=False
    )

    # ------------------------------------------------------------------ #
    # feature_flags
    # ------------------------------------------------------------------ #
    op.create_table(
        "feature_flags",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("description", sa.String(length=2048), nullable=True),
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
        comment="Named feature flags keyed by a string id",
    )

    # ------------------------------------------------------------------ #
    # feature_flag_role_assignments
    # ------------------------------------------------------------------ #
    op.create_table(
        "feature_flag_role_assignments",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("feature_flag_id", sa.String(length=128), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["feature_flag_id"],
            ["feature_flags.id"],
            ondelete="CASCADE",
            name="fk_feature_flag_role_assignments_feature_flag_id_feature_flags",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            ondelete="CASCADE",
            name="fk_feature_flag_role_assignments_role_id_roles",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "feature_flag_id", "role_id", name="uq_feature_flag_role_assignments_flag_id_role_id"
        ),
        comment="Per-role overrides of feature flags",
    )
    op.create_index(
        "ix_feature_flag_role_assignments_feature_flag_id",
        "feature_flag_role_assignments",
        ["feature_flag_id"],
        unique=False,
    )
    op.create_index(
        "ix_feature_flag_role_assignments_role_id",
        "feature_flag_role_assignments",
        ["role_id"],
        unique=False,
    )

    # ------------------------------------------------------------------ #
    # feature_flag_user_assignments
    # ------------------------------------------------------------------ #
    op.create_table(
        "feature_flag_user_assignments",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("feature_flag_id", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["feature_flag_id"],
            ["feature_flags.id"],
            ondelete="CASCADE",
            name="fk_feature_flag_user_assignments_feature_flag_id_feature_flags",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name="fk_feature_flag_user_assignments_user_id_users",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "feature_flag_id", "user_id", name="uq_feature_flag_user_assignments_flag_id_user_id"
        ),
        comment="Per-user overrides of feature flags",
    )
    op.create_index(
        "ix_feature_flag_user_assignments_feature_flag_id",
        "feature_flag_user_assignments",
        ["feature_flag_id"],
        unique=False,
    )
    op.create_index(
        "ix_feature_flag_user_assignments_user_id",
        "feature_flag_user_assignments",
        ["user_id"],
        unique=False,
    )

    # ------------------------------------------------------------------ #
    # sandbox_templates
    # ------------------------------------------------------------------ #
    op.create_table(
        "sandbox_templates",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("provider_kind", sa.String(length=32), nullable=False),
        sa.Column("template_spec", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("server_spec", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("storage_spec", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("idle_timeout_seconds", sa.Integer(), nullable=True),
        sa.Column("max_lifetime_seconds", sa.Integer(), nullable=True),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        comment="Reusable sandbox activation templates",
    )
    op.create_index("ix_sandbox_templates_name", "sandbox_templates", ["name"], unique=False)
    op.create_index(
        "ix_sandbox_templates_provider_kind", "sandbox_templates", ["provider_kind"], unique=False
    )
    op.create_index("ix_sandbox_templates_user_id", "sandbox_templates", ["user_id"], unique=False)

    # ------------------------------------------------------------------ #
    # sandbox_filesystems
    # ------------------------------------------------------------------ #
    op.create_table(
        "sandbox_filesystems",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("storage_kind", sa.String(length=32), nullable=False),
        sa.Column("object_prefix", sa.String(length=2048), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status", sa.String(length=32), server_default=sa.text("'ready'"), nullable=False
        ),
        sa.Column("head_generation", sa.String(length=255), nullable=True),
        sa.Column("mount_path_default", sa.String(length=1024), nullable=False),
        sa.Column("max_size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("size_bytes_estimate", sa.BigInteger(), nullable=True),
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
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("object_prefix"),
        comment="Durable Fusey-backed sandbox filesystems",
    )
    op.create_index(
        "ix_sandbox_filesystems_storage_kind", "sandbox_filesystems", ["storage_kind"], unique=False
    )
    op.create_index(
        "ix_sandbox_filesystems_status", "sandbox_filesystems", ["status"], unique=False
    )
    op.create_index(
        "ix_sandbox_filesystems_user_id", "sandbox_filesystems", ["user_id"], unique=False
    )

    # ------------------------------------------------------------------ #
    # sandboxes
    # ------------------------------------------------------------------ #
    op.create_table(
        "sandboxes",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("template_id", sa.Uuid(), nullable=False),
        sa.Column("filesystem_id", sa.Uuid(), nullable=False),
        sa.Column("provider_kind", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status", sa.String(length=32), server_default=sa.text("'inactive'"), nullable=False
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("current_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("current_compute_id", sa.Uuid(), nullable=True),
        sa.Column(
            "exposed_urls",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("idle_timeout_seconds", sa.Integer(), nullable=True),
        sa.Column("max_lifetime_seconds", sa.Integer(), nullable=True),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delete_started_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(["filesystem_id"], ["sandbox_filesystems.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["template_id"], ["sandbox_templates.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        comment="Durable user-facing sandbox environments",
    )
    op.create_index("ix_sandboxes_name", "sandboxes", ["name"], unique=False)
    op.create_index("ix_sandboxes_template_id", "sandboxes", ["template_id"], unique=False)
    op.create_index("ix_sandboxes_filesystem_id", "sandboxes", ["filesystem_id"], unique=False)
    op.create_index("ix_sandboxes_provider_kind", "sandboxes", ["provider_kind"], unique=False)
    op.create_index("ix_sandboxes_user_id", "sandboxes", ["user_id"], unique=False)
    op.create_index("ix_sandboxes_status", "sandboxes", ["status"], unique=False)

    # ------------------------------------------------------------------ #
    # sandbox_snapshots
    # ------------------------------------------------------------------ #
    op.create_table(
        "sandbox_snapshots",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("filesystem_id", sa.Uuid(), nullable=False),
        sa.Column("storage_kind", sa.String(length=32), nullable=False),
        sa.Column("generation", sa.String(length=255), nullable=False),
        sa.Column("snapshot_artifact", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_sandbox_id", sa.Uuid(), nullable=True),
        sa.Column(
            "status", sa.String(length=32), server_default=sa.text("'ready'"), nullable=False
        ),
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
        sa.ForeignKeyConstraint(["filesystem_id"], ["sandbox_filesystems.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_sandbox_id"], ["sandboxes.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "filesystem_id",
            "generation",
            "name",
            name="uq_sandbox_snapshots_filesystem_generation_name",
        ),
        comment="Named Fusey filesystem generation snapshots",
    )
    op.create_index("ix_sandbox_snapshots_name", "sandbox_snapshots", ["name"], unique=False)
    op.create_index(
        "ix_sandbox_snapshots_filesystem_id", "sandbox_snapshots", ["filesystem_id"], unique=False
    )
    op.create_index(
        "ix_sandbox_snapshots_storage_kind", "sandbox_snapshots", ["storage_kind"], unique=False
    )
    op.create_index(
        "ix_sandbox_snapshots_generation", "sandbox_snapshots", ["generation"], unique=False
    )
    op.create_index("ix_sandbox_snapshots_user_id", "sandbox_snapshots", ["user_id"], unique=False)
    op.create_index(
        "ix_sandbox_snapshots_source_sandbox_id",
        "sandbox_snapshots",
        ["source_sandbox_id"],
        unique=False,
    )
    op.create_index("ix_sandbox_snapshots_status", "sandbox_snapshots", ["status"], unique=False)

    # ------------------------------------------------------------------ #
    # sandbox_computes
    # ------------------------------------------------------------------ #
    op.create_table(
        "sandbox_computes",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("provider_kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("runtime_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("server_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("template_id", sa.Uuid(), nullable=True),
        sa.Column("sandbox_id", sa.Uuid(), nullable=True),
        sa.Column("mount_lease_id", sa.Uuid(), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_health_check_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.Column("terminated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["sandbox_id"], ["sandboxes.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["template_id"], ["sandbox_templates.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        comment="Internal replaceable sandbox compute attachments",
    )
    op.create_index(
        "ix_sandbox_computes_provider_kind", "sandbox_computes", ["provider_kind"], unique=False
    )
    op.create_index("ix_sandbox_computes_status", "sandbox_computes", ["status"], unique=False)
    op.create_index(
        "ix_sandbox_computes_template_id", "sandbox_computes", ["template_id"], unique=False
    )
    op.create_index(
        "ix_sandbox_computes_sandbox_id", "sandbox_computes", ["sandbox_id"], unique=False
    )

    # ------------------------------------------------------------------ #
    # llm_usage (range-partitioned parent by created_at; partitions are
    # created by the background partition manager at runtime — see README
    # 'LLM usage logging'. A DEFAULT partition is created here so inserts
    # never fail before the manager's first sweep.)
    # ------------------------------------------------------------------ #
    op.create_table(
        "llm_usage",
        sa.Column(
            "id",
            sa.BigInteger(),
            server_default=sa.text("nextval(pg_get_serial_sequence('llm_usage', 'id'))"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("provider_connection_id", sa.Uuid(), nullable=False),
        sa.Column("llm_id", sa.Uuid(), nullable=True),
        sa.Column("response_id", sa.String(length=255), nullable=True),
        sa.Column("model", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("prompt_tokens", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "completion_tokens",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "cache_read_tokens",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "cache_write_tokens",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "reasoning_tokens",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("context_window", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("per_turn_token", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "accumulated_cost",
            sa.Numeric(precision=18, scale=6),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id", "created_at"),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE", name="fk_llm_usage_user_id_users"
        ),
        sa.ForeignKeyConstraint(
            ["provider_connection_id"],
            ["provider_connections.id"],
            ondelete="CASCADE",
            name="fk_llm_usage_provider_connection_id_provider_connections",
        ),
        sa.ForeignKeyConstraint(
            ["llm_id"], ["llms.id"], ondelete="SET NULL", name="fk_llm_usage_llm_id_llms"
        ),
        comment="Raw LLM invocation records, daily-partitioned by created_at",
        postgresql_partition_by="RANGE(created_at)",
    )
    op.create_index("ix_llm_usage_user_id", "llm_usage", ["user_id"], unique=False)
    op.create_index(
        "ix_llm_usage_provider_connection_id",
        "llm_usage",
        ["provider_connection_id"],
        unique=False,
    )
    op.create_index("ix_llm_usage_llm_id", "llm_usage", ["llm_id"], unique=False)
    op.create_index("ix_llm_usage_created_at", "llm_usage", ["created_at"], unique=False)
    # DEFAULT partition so inserts succeed before the manager allocates the
    # day's partition (or when a row's created_at falls outside any allocated
    # day). Created with raw SQL: op.create_table does not emit PARTITION OF.
    op.execute("CREATE TABLE llm_usage_default PARTITION OF llm_usage DEFAULT")

    # ------------------------------------------------------------------ #
    # llm_aggregated_usage
    # ------------------------------------------------------------------ #
    op.create_table(
        "llm_aggregated_usage",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("minute", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("invocations", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("prompt_tokens", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "completion_tokens",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "cache_read_tokens",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "cache_write_tokens",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "reasoning_tokens",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("context_window", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("per_turn_token", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "accumulated_cost",
            sa.Numeric(precision=18, scale=6),
            server_default=sa.text("0"),
            nullable=False,
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
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name="fk_llm_aggregated_usage_user_id_users",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "minute", name="uq_llm_aggregated_usage_user_id_minute"),
        comment="Per-minute, per-user rollup of llm_usage",
    )
    op.create_index(
        "ix_llm_aggregated_usage_minute", "llm_aggregated_usage", ["minute"], unique=False
    )
    op.create_index(
        "ix_llm_aggregated_usage_user_id", "llm_aggregated_usage", ["user_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_llm_aggregated_usage_user_id", table_name="llm_aggregated_usage")
    op.drop_index("ix_llm_aggregated_usage_minute", table_name="llm_aggregated_usage")
    op.drop_table("llm_aggregated_usage")
    op.drop_index("ix_llm_usage_created_at", table_name="llm_usage")
    op.drop_index("ix_llm_usage_llm_id", table_name="llm_usage")
    op.drop_index("ix_llm_usage_provider_connection_id", table_name="llm_usage")
    op.drop_index("ix_llm_usage_user_id", table_name="llm_usage")
    op.drop_table("llm_usage")
    op.drop_index("ix_sandbox_computes_sandbox_id", table_name="sandbox_computes")
    op.drop_index("ix_sandbox_computes_template_id", table_name="sandbox_computes")
    op.drop_index("ix_sandbox_computes_status", table_name="sandbox_computes")
    op.drop_index("ix_sandbox_computes_provider_kind", table_name="sandbox_computes")
    op.drop_table("sandbox_computes")
    op.drop_index("ix_sandbox_snapshots_status", table_name="sandbox_snapshots")
    op.drop_index("ix_sandbox_snapshots_source_sandbox_id", table_name="sandbox_snapshots")
    op.drop_index("ix_sandbox_snapshots_user_id", table_name="sandbox_snapshots")
    op.drop_index("ix_sandbox_snapshots_generation", table_name="sandbox_snapshots")
    op.drop_index("ix_sandbox_snapshots_storage_kind", table_name="sandbox_snapshots")
    op.drop_index("ix_sandbox_snapshots_filesystem_id", table_name="sandbox_snapshots")
    op.drop_index("ix_sandbox_snapshots_name", table_name="sandbox_snapshots")
    op.drop_table("sandbox_snapshots")
    op.drop_index("ix_sandboxes_status", table_name="sandboxes")
    op.drop_index("ix_sandboxes_user_id", table_name="sandboxes")
    op.drop_index("ix_sandboxes_provider_kind", table_name="sandboxes")
    op.drop_index("ix_sandboxes_filesystem_id", table_name="sandboxes")
    op.drop_index("ix_sandboxes_template_id", table_name="sandboxes")
    op.drop_index("ix_sandboxes_name", table_name="sandboxes")
    op.drop_table("sandboxes")
    op.drop_index("ix_sandbox_filesystems_user_id", table_name="sandbox_filesystems")
    op.drop_index("ix_sandbox_filesystems_status", table_name="sandbox_filesystems")
    op.drop_index("ix_sandbox_filesystems_storage_kind", table_name="sandbox_filesystems")
    op.drop_table("sandbox_filesystems")
    op.drop_index("ix_sandbox_templates_user_id", table_name="sandbox_templates")
    op.drop_index("ix_sandbox_templates_provider_kind", table_name="sandbox_templates")
    op.drop_index("ix_sandbox_templates_name", table_name="sandbox_templates")
    op.drop_table("sandbox_templates")

    op.drop_index(
        "ix_feature_flag_user_assignments_user_id", table_name="feature_flag_user_assignments"
    )
    op.drop_index(
        "ix_feature_flag_user_assignments_feature_flag_id",
        table_name="feature_flag_user_assignments",
    )
    op.drop_table("feature_flag_user_assignments")
    op.drop_index(
        "ix_feature_flag_role_assignments_role_id", table_name="feature_flag_role_assignments"
    )
    op.drop_index(
        "ix_feature_flag_role_assignments_feature_flag_id",
        table_name="feature_flag_role_assignments",
    )
    op.drop_table("feature_flag_role_assignments")
    op.drop_table("feature_flags")
    op.drop_index("ix_llms_provider_connection_id", table_name="llms")
    op.drop_index("ix_llms_user_id", table_name="llms")
    op.drop_table("llms")
    op.drop_index("ix_provider_connections_user_id", table_name="provider_connections")
    op.drop_table("provider_connections")
    op.drop_index("ix_user_secret_permissions_user_id", table_name="user_secret_permissions")
    op.drop_index("ix_user_secret_permissions_secret_id", table_name="user_secret_permissions")
    op.drop_table("user_secret_permissions")
    op.drop_index(
        "ix_role_mcp_server_config_permissions_mcp_server_config_id",
        table_name="role_mcp_server_config_permissions",
    )
    op.drop_index(
        "ix_role_mcp_server_config_permissions_role_id",
        table_name="role_mcp_server_config_permissions",
    )
    op.drop_table("role_mcp_server_config_permissions")
    op.drop_index("ix_mcp_server_configs_user_id", table_name="mcp_server_configs")
    op.drop_table("mcp_server_configs")
    op.drop_index("ix_role_secret_permissions_secret_id", table_name="role_secret_permissions")
    op.drop_index("ix_role_secret_permissions_role_id", table_name="role_secret_permissions")
    op.drop_table("role_secret_permissions")
    op.drop_index("ix_secrets_code", table_name="secrets")
    op.drop_table("secrets")
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
    op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_users_idp_user_id", table_name="users")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
