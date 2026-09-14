"""Permission policy and search filter for the conversation template resource.

Conversation templates use the generic :class:`CreatorPermission` policy (or
:class:`Permitted` / :class:`Denied`) stored in the role's JSONB
``conversation_template_permission`` column. ``CreatorPermission`` gives the
template *creator* management access (``on_match``) and lets an admin/operator
grant non-creators ``USE`` via ``on_mismatch`` (the action the start-conversation
path checks, issue #2). A ``NULL`` column means "deny" for this entity.

This module is kept as a placeholder so the import side-effect that registers
the resource's security context continues to work — exactly like
``mcp_server_config_security``. No custom :class:`Permission` subclass is
needed; the built-in policies suffice.
"""

from __future__ import annotations

# No custom permission class needed — CreatorPermission / Permitted / Denied
# cover all use cases for conversation template access control.
