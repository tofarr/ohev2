"""Permission policy and search filter for the secret resource.

Secrets now use the generic :class:`AclPermission` policy (or
:class:`Permitted` / :class:`Denied`) stored in the role's JSONB
``secret_permission`` column. The per-secret link tables
(``role_secret_permissions``, ``user_secret_permissions``) have been removed;
item-level grants are expressed as permitted ids inside the
:class:`AclPermission` payload.

The :class:`SecretValueAccess` policy remains for the ``/secret-values``
reveal projection (``secret_value_permission`` column). It reduces every
action to the read-grant shape: the value is revealable iff the principal's
``secret_value_permission`` admits the secret. The ``/secret-values`` service
ANDs this filter with the read-access filter, so a secret is revealed only
when *both* admit it (defense in depth, AGENTS.md §12).
"""

from __future__ import annotations

import uuid
from typing import Any

from openhands.ev2.security.security_models import Action, Permission
from openhands.ev2.util.search_filter import AllSearchFilter, SearchFilter


class SecretValueAccess(Permission):
    """Permission policy for the ``/secret-values`` reveal projection.

    Stored on the ``secret_value_permission`` column (separate from
    ``secret_permission``). Every action reduces to the read-grant shape:
    the value is revealable iff the principal's ``secret_value_permission``
    admits the secret (e.g. via :class:`AclPermission` with the secret id in
    ``item_ids`` and ``on_match`` admitting READ, or :class:`Permitted` for
    full access). The ``/secret-values`` service ANDs this filter with the
    read-access filter, so a secret is revealed only when *both* admit it
    (defense in depth, AGENTS.md §12).

    ``CREATE``/``UPDATE``/``DELETE`` are not meaningful for a read-only
    projection; this policy treats every action as a read.
    """

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
        groups: frozenset[uuid.UUID] = frozenset(),
    ) -> SearchFilter[Any]:
        _ = action, groups, user_id  # reveal is read-only; every action uses the read grant shape
        return AllSearchFilter[Any]()
