"""Permission policy for the job resource.

Jobs use the generic :class:`CreatorPermission` policy (or
:class:`Permitted` / :class:`Denied`) stored in the role's JSONB
``job_permission`` column. ``CreatorPermission`` gives the job *creator*
management access (``on_match``) and lets an admin/operator grant non-creators
access via ``on_mismatch``. A ``NULL`` column means "deny" for this entity.

This module is kept as a placeholder so the import side-effect that registers
the resource's security context continues to work — exactly like other
placeholder security modules (e.g. ``job_security``). No custom
:class:`Permission` subclass is needed; the built-in policies suffice.
"""

from __future__ import annotations

# No custom permission class needed — CreatorPermission / Permitted / Denied
# cover all use cases for job access control.
