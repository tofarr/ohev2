"""Pydantic schemas for MCP server configuration resources."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from openhands.ev2.mcp_server_config.mcp_server_config_models import MCPServerConfig
from openhands.ev2.util.search_filter import BaseSearchFilter

MCPTransport = Literal["stdio", "http", "streamable-http", "sse"]
MCP_SERVER_FIELD_NAMES = (
    "url",
    "transport",
    "command",
    "args",
    "env",
    "cwd",
    "description",
    "icon",
    "timeout",
    "sse_read_timeout",
    "keep_alive",
    "headers",
    "auth",
    "enabled",
)


def _secret_map_to_plain(value: dict[str, SecretStr] | None) -> dict[str, str] | None:
    if value is None:
        return None
    return {key: item.get_secret_value() for key, item in value.items()}


def mcp_payload_to_plain_dict(
    payload: MCPServerConfigCreate | MCPServerConfigUpdate,
    *,
    exclude_unset: bool = False,
) -> dict[str, Any]:
    """Convert schema payload fields into plaintext MCPServer constructor data."""
    data: dict[str, Any] = {}
    fields_set = payload.model_fields_set
    for field in MCP_SERVER_FIELD_NAMES:
        if exclude_unset and field not in fields_set:
            continue
        value = getattr(payload, field)
        if field in {"env", "headers"}:
            data[field] = _secret_map_to_plain(value)
        else:
            data[field] = value
    return data


def validate_mcp_server_data(data: dict[str, Any]) -> None:
    """Validate MCP fields by constructing the SDK ``MCPServer``."""
    from openhands.sdk.mcp.config import MCPServer

    MCPServer.model_validate(data)


class MCPServerConfigCreate(BaseModel):
    """Payload to create an MCP server configuration."""

    model_config = ConfigDict(populate_by_name=True)

    display_name: str = Field(min_length=1, max_length=128)
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    transport: MCPTransport | None = None
    command: str | None = Field(default=None, min_length=1, max_length=2048)
    args: list[str] | None = None
    env: dict[str, SecretStr] | None = None
    cwd: str | None = Field(default=None, max_length=2048)
    description: str | None = None
    icon: str | None = Field(default=None, max_length=2048)
    timeout: float | None = None
    sse_read_timeout: float | None = None
    keep_alive: bool | None = None
    headers: dict[str, SecretStr] | None = None
    auth: dict[str, Any] | None = None
    enabled: bool = True

    @field_validator("display_name")
    @classmethod
    def _strip_display_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("display_name must be a non-empty string")
        return value

    @model_validator(mode="after")
    def _validate_mcp_server(self) -> MCPServerConfigCreate:
        validate_mcp_server_data(mcp_payload_to_plain_dict(self))
        return self


class MCPServerConfigUpdate(BaseModel):
    """Partial update of an MCP server configuration."""

    model_config = ConfigDict(populate_by_name=True)

    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    transport: MCPTransport | None = None
    command: str | None = Field(default=None, min_length=1, max_length=2048)
    args: list[str] | None = None
    env: dict[str, SecretStr] | None = None
    cwd: str | None = Field(default=None, max_length=2048)
    description: str | None = None
    icon: str | None = Field(default=None, max_length=2048)
    timeout: float | None = None
    sse_read_timeout: float | None = None
    keep_alive: bool | None = None
    headers: dict[str, SecretStr] | None = None
    auth: dict[str, Any] | None = None
    enabled: bool | None = None

    @field_validator("display_name")
    @classmethod
    def _strip_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("display_name must be a non-empty string")
        return value


class MCPServerConfigRead(BaseModel):
    """MCP server configuration returned by the API.

    Secret-bearing fields are serialized through SDK ``MCPServer`` defaults, so
    values are masked rather than exposed in plaintext.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    display_name: str
    url: str | None = None
    transport: MCPTransport | None = None
    command: str | None = None
    args: list[str] | None = None
    env: dict[str, str | None] | None = None
    cwd: str | None = None
    description: str | None = None
    icon: str | None = None
    timeout: float | None = None
    sse_read_timeout: float | None = None
    keep_alive: bool | None = None
    headers: dict[str, str | None] | None = None
    auth: dict[str, Any] | None = None
    enabled: bool
    created_at: datetime
    updated_at: datetime


class MCPServerConfigSearchFilter(BaseSearchFilter[MCPServerConfig]):
    """Optional filter clauses for ``GET /mcp-server-configs``."""

    display_name__contains: str | None = Field(default=None)
    transport__eq: MCPTransport | None = Field(default=None)
    user_id__eq: uuid.UUID | None = Field(default=None)
    enabled__eq: bool | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class MCPServerConfigSearchResult(BaseModel):
    """Paginated collection of MCP server configurations."""

    items: list[MCPServerConfigRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class MCPServerConfigBatchCreate(BaseModel):
    """Create operation within an MCP server config batch write."""

    op: Literal["create"] = "create"
    data: MCPServerConfigCreate


class MCPServerConfigBatchUpdate(BaseModel):
    """Update operation within an MCP server config batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: MCPServerConfigUpdate


class MCPServerConfigBatchDelete(BaseModel):
    """Delete operation within an MCP server config batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


MCPServerConfigBatchOp = Annotated[
    MCPServerConfigBatchCreate | MCPServerConfigBatchUpdate | MCPServerConfigBatchDelete,
    Field(discriminator="op"),
]


class MCPServerConfigBatchWriteRequest(BaseModel):
    """Request body for ``POST /mcp-server-configs/batch``."""

    operations: list[MCPServerConfigBatchOp] = Field(min_length=1, max_length=100)
