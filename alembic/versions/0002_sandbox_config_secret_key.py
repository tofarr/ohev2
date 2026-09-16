"""add secret_key to sandbox_configs

Revision ID: 0002_sandbox_config_secret_key
Revises: 0001_initial
Create Date: 2026-06-05

Adds a per-sandbox ``secret_key`` column to ``sandbox_configs``, holding JWE
ciphertext of the ``OH_SECRET_KEY`` injected into each sandbox container (the
agent server derives its Fernet Cipher from it). Mirrors the existing
``session_api_key`` pattern. Existing rows are backfilled with a minted +
encrypted random key so none is left without one; the column is then set
``NOT NULL``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.util.random_id import generate_random_id

revision: str = "0002_sandbox_config_secret_key"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add nullable first so existing rows can be backfilled.
    op.add_column(
        "sandbox_configs",
        sa.Column("secret_key", sa.String(length=8192), nullable=True),
    )
    # Backfill each existing row with a freshly minted + encrypted secret key.
    enc = get_encryption_service()
    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id FROM sandbox_configs")).fetchall()
    for (config_id,) in rows:
        ciphertext = enc.encrypt_value(generate_random_id())
        connection.execute(
            sa.text("UPDATE sandbox_configs SET secret_key = :c WHERE id = :id"),
            {"c": ciphertext, "id": config_id},
        )
    op.alter_column("sandbox_configs", "secret_key", nullable=False)
    op.alter_column(
        "sandbox_configs",
        "secret_key",
        existing_type=sa.String(length=8192),
        comment="Encrypted OH_SECRET_KEY for the sandbox agent server (JWE ciphertext).",
    )


def downgrade() -> None:
    op.drop_column("sandbox_configs", "secret_key")
