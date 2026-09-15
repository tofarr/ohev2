"""Permission policy for the event callback resource.

Event callbacks use the generic :class:`CreatorPermission` policy (or
:class:`Permitted` / :class:`Denied`) stored in the role's JSONB
``event_callback_permission`` column. ``CreatorPermission`` gives the callback
*creator* management access (``on_match``) and lets an admin/operator grant
non-creators access via ``on_mismatch``. A ``NULL`` column means "deny" for
this entity.

This module is kept as a placeholder so the import side-effect that registers
the resource's security context continues to work — exactly like
``conversation_template_security``. No custom :class:`Permission` subclass is
needed; the built-in policies suffice.
"""

from __future__ import annotations

# No custom permission class needed — CreatorPermission / Permitted / Denied
# cover all use cases for event callback access control.
