"""Permission policy and search filter for MCP server configurations."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.sql.elements import ColumnElement

from openhands.ev2.mcp_server_config.mcp_server_config_models import (
    MCPServerConfig,
    RoleMCPServerConfigPermission,
)
from openhands.ev2.role.role_models import UserRole
from openhands.ev2.security.security_models import Action, Permission
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter, SearchFilter, T

_ACTION_FLAG: dict[Action, str] = {
    Action.READ: "read_enabled",
    Action.SEARCH: "read_enabled",
    Action.UPDATE: "update_enabled",
    Action.DELETE: "delete_enabled",
}


class MCPServerConfigAccessFilter(SearchFilter[T]):
    """Filter admitting MCP configs granted through role link rows."""

    user_id: uuid.UUID
    flag: str

    def matches(self, item: T) -> bool:
        _ = item
        return True

    def sql_condition(self) -> ColumnElement[bool] | None:
        flag_col = getattr(RoleMCPServerConfigPermission, self.flag)
        granted = (
            select(RoleMCPServerConfigPermission.mcp_server_config_id)
            .join(UserRole, UserRole.role_id == RoleMCPServerConfigPermission.role_id)
            .where(UserRole.user_id == self.user_id, flag_col.is_(True))
        )
        return MCPServerConfig.id.in_(granted)


class MCPServerConfigAccess(Permission):
    """Permission policy for MCP server configurations.

    ``CREATE`` is governed by the policy alone; ``READ``/``SEARCH``, ``UPDATE``,
    and ``DELETE`` require a matching ``role_mcp_server_config_permissions`` row.
    """

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        if action is Action.CREATE:
            return AllSearchFilter[Any]()
        if user_id is None:
            return NoneSearchFilter[Any]()
        flag = _ACTION_FLAG[action]
        return MCPServerConfigAccessFilter[Any](user_id=user_id, flag=flag)
