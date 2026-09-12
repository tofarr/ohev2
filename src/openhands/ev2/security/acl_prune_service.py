"""Background pruning of orphaned item ids from AclPermission policies.

An :class:`AclPermission` stores item ids as JSONB on a Role column. When an
entity is deleted, its id remains in every ACL that referenced it — there is
no FK to cascade. This service scans roles for AclPermission policies, checks
which ids still exist in the corresponding entity table, and removes the
orphans.

The column-to-entity-model mapping is derived from the ``_RESOURCE_POLICY``
registry in ``auth_dependencies`` (model → column), reversed to column → model.
The secret columns (``secret_permission``, and ``secret_value_permission`` —
the documented §12.2 exception not in ``_RESOURCE_POLICY``) are mapped to
:class:`SqlSecret` explicitly: the registered model is the provider-neutral
Pydantic ``Secret``, but the canonical id space for pruning is the SQL table
maintained by the default ``SqlSecretsService``.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role
from openhands.ev2.security.security_models import AclPermission


async def prune_orphaned_acl_ids(session: AsyncSession) -> int:
    """Remove orphaned item ids from all AclPermission policies on all roles.

    Returns the number of roles whose AclPermission was modified.
    """
    column_to_model = _build_column_to_model_map()

    result = await session.execute(select(Role))
    roles = list(result.scalars())
    pruned_count = 0

    for role in roles:
        changed = False
        for column in ROLE_ENTITY_COLUMNS:
            policy = getattr(role, column, None)
            if not isinstance(policy, AclPermission):
                continue
            model = column_to_model.get(column)
            if model is None:
                continue
            if await _prune_policy(policy, model, session):
                # SQLAlchemy does not detect in-place mutation of a JSONB-backed
                # Pydantic model; flag the column dirty so the update flushes.
                flag_modified(role, column)
                changed = True
        if changed:
            pruned_count += 1

    if pruned_count:
        await session.commit()
    return pruned_count


async def _entity_ids_exist(
    session: AsyncSession, model: type[Any], ids: list[uuid.UUID]
) -> set[uuid.UUID]:
    """Return the subset of *ids* that exist in *model*'s table."""
    if not ids:
        return set()
    result = await session.execute(select(model.id).where(model.id.in_(ids)))
    return {row[0] for row in result}


async def _prune_policy(
    policy: AclPermission,
    model: type[Any],
    session: AsyncSession,
) -> bool:
    """Remove orphaned ids from *policy* in-place. Returns whether it changed.

    Checks every id in ``item_ids`` against *model*'s table and drops the ones
    that no longer exist.
    """
    if not policy.item_ids:
        return False

    existing = await _entity_ids_exist(session, model, list(policy.item_ids))
    orphaned = set(policy.item_ids) - existing
    if not orphaned:
        return False

    policy.item_ids = [id_ for id_ in policy.item_ids if id_ not in orphaned]
    return True


def _build_column_to_model_map() -> dict[str, type]:
    """Reverse ``_RESOURCE_POLICY`` (model → column) to column → model."""
    from openhands.ev2.auth.auth_dependencies import _RESOURCE_POLICY
    from openhands.ev2.secret.sql_secrets_models import SqlSecret

    mapping: dict[str, type] = {}
    for model, column in _RESOURCE_POLICY.items():
        mapping[column] = model
    # The registered model for the secret columns is the provider-neutral
    # Pydantic Secret; the id space to prune against is the SQL table.
    # secret_value_permission is the documented §12.2 exception not in
    # _RESOURCE_POLICY — it governs a projection over the same table.
    mapping["secret_permission"] = SqlSecret
    mapping["secret_value_permission"] = SqlSecret
    return mapping
