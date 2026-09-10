"""Permission policy and search filter for MCP server configurations.

MCP server configs now use the generic :class:`AclPermission` policy (or
:class:`Permitted` / :class:`Denied`) stored in the role's JSONB
``mcp_server_config_permission`` column. The per-config link table
(``role_mcp_server_config_permissions``) has been removed; item-level grants
are expressed as permitted ids inside the :class:`AclPermission` payload.

This module is kept as a placeholder so the import side-effect that
registers the resource's security context continues to work. No custom
:class:`Permission` subclass is needed — the built-in policies suffice.
"""

from __future__ import annotations

# No custom permission class needed — AclPermission / Permitted / Denied
# cover all use cases for MCP server config access control.
