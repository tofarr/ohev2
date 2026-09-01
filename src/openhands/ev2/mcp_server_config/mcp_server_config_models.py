"""ORM models for persisted MCP server configuration.

``MCPServerConfig`` stores the parameters needed to materialize the SDK
``MCPServer`` class. Secret-bearing MCP fields (``env``, ``headers``, and
``auth``) are stored as encrypted JSON blobs and decrypted only when an SDK
object or masked API response is materialized.

``RoleMCPServerConfigPermission`` mirrors ``role_secret_permissions``: a role
gets per-config read/update/delete grants through this link table, while create
is governed by the role's ``mcp_server_config_permission`` policy.

An ``enable_proxy`` flag selects whether the config's effective ``url`` points
at this service's MCP proxy endpoint (built from :attr:`AppConfig.base_url`) or
at the stored ``url``.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base
from openhands.ev2.encryption.encryption_service import EncryptionService

if TYPE_CHECKING:
    from openhands.sdk.mcp.config import MCPServer

_TZ = DateTime(timezone=True)


def encrypt_json_blob(enc: EncryptionService, value: Any | None) -> str | None:
    """Encrypt a JSON-serializable value as a single JWE blob."""
    if value is None:
        return None
    return enc.encrypt_value(json.dumps(value, separators=(",", ":"), sort_keys=True))


def decrypt_json_blob(enc: EncryptionService, ciphertext: str | None) -> Any | None:
    """Decrypt a JWE JSON blob persisted by :func:`encrypt_json_blob`."""
    if ciphertext is None:
        return None
    return json.loads(enc.decrypt_value(ciphertext))


class MCPServerConfig(Base):
    """Stored parameters for an SDK :class:`MCPServer`."""

    __tablename__ = "mcp_server_configs"
    __table_args__ = {"comment": "Stored MCP server configurations"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    display_name: Mapped[str] = mapped_column(String(128))
    url: Mapped[str | None] = mapped_column(String(2048), default=None, nullable=True)
    transport: Mapped[str | None] = mapped_column(String(32), default=None, nullable=True)
    command: Mapped[str | None] = mapped_column(String(2048), default=None, nullable=True)
    args: Mapped[list[str] | None] = mapped_column(JSONB, default=None, nullable=True)
    env: Mapped[str | None] = mapped_column(
        Text,
        default=None,
        nullable=True,
        comment="Encrypted JSON map of MCP environment variables.",
    )
    cwd: Mapped[str | None] = mapped_column(String(2048), default=None, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, default=None, nullable=True)
    icon: Mapped[str | None] = mapped_column(String(2048), default=None, nullable=True)
    timeout: Mapped[float | None] = mapped_column(Float, default=None, nullable=True)
    sse_read_timeout: Mapped[float | None] = mapped_column(Float, default=None, nullable=True)
    keep_alive: Mapped[bool | None] = mapped_column(Boolean, default=None, nullable=True)
    headers: Mapped[str | None] = mapped_column(
        Text,
        default=None,
        nullable=True,
        comment="Encrypted JSON map of MCP HTTP headers.",
    )
    auth: Mapped[str | None] = mapped_column(
        Text,
        default=None,
        nullable=True,
        comment="Encrypted JSON MCP auth credential.",
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    enable_proxy: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def to_plain_mcp_dict(
        self,
        enc: EncryptionService,
        *,
        proxy_url: str | None = None,
        use_proxy: bool = True,
    ) -> dict[str, Any]:
        """Return plaintext SDK ``MCPServer`` constructor fields for this row.

        When ``enable_proxy`` and ``use_proxy`` are both ``True`` the effective
        ``url`` is *proxy_url*; otherwise the stored ``url`` is used. Set
        ``use_proxy=False`` when serving the proxy endpoint itself so forwarding
        goes to the stored server URL.
        """
        data: dict[str, Any] = {"enabled": self.enabled}
        for field in (
            "url",
            "transport",
            "command",
            "args",
            "cwd",
            "description",
            "icon",
            "timeout",
            "sse_read_timeout",
            "keep_alive",
        ):
            value = getattr(self, field)
            if value is not None:
                data[field] = value
        # When proxy is enabled and requested, use the proxy URL instead.
        if self.enable_proxy and use_proxy and proxy_url is not None:
            data["url"] = proxy_url
        if self.env is not None:
            data["env"] = decrypt_json_blob(enc, self.env)
        if self.headers is not None:
            data["headers"] = decrypt_json_blob(enc, self.headers)
        if self.auth is not None:
            data["auth"] = decrypt_json_blob(enc, self.auth)
        return data

    def to_mcp_server(
        self,
        enc: EncryptionService,
        *,
        proxy_url: str | None = None,
        use_proxy: bool = True,
    ) -> MCPServer:
        """Materialize the SDK :class:`MCPServer` represented by this row.

        When ``enable_proxy`` and ``use_proxy`` are both ``True`` the effective
        ``url`` is *proxy_url*; otherwise the stored ``url`` is used. Set
        ``use_proxy=False`` when serving the proxy endpoint itself so forwarding
        goes to the stored server URL.
        """
        from openhands.sdk.mcp.config import MCPServer

        return MCPServer.model_validate(
            self.to_plain_mcp_dict(enc, proxy_url=proxy_url, use_proxy=use_proxy)
        )


class RoleMCPServerConfigPermission(Base):
    """A per-role grant of access to an :class:`MCPServerConfig`."""

    __tablename__ = "role_mcp_server_config_permissions"
    __table_args__ = (
        UniqueConstraint(
            "role_id",
            "mcp_server_config_id",
            name="uq_role_mcp_server_config_permissions_role_id_config_id",
        ),
        {"comment": "Per-role grants of access to MCP server configs"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"),
        index=True,
    )
    mcp_server_config_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("mcp_server_configs.id", ondelete="CASCADE"),
        index=True,
    )
    read_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    update_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    delete_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


__all__ = [
    "MCPServerConfig",
    "RoleMCPServerConfigPermission",
    "decrypt_json_blob",
    "encrypt_json_blob",
]
