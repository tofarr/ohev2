"""HTTP routes for the feature_flag feature.

Uniform REST surface (AGENTS.md §3). Two collections:

* ``/feature-flags`` — full CRUD (GET paginated, POST, GET/{id}, PATCH/{id},
  DELETE/{id}) plus batch read/write and count. The ``id`` path param is the
  caller-supplied string primary key.
* ``/feature-flag-roles`` — immutable link rows (GET paginated, POST, GET/{id},
  DELETE/{id}) plus batch read/write and count; no ``PATCH``.

Handlers validate, call a service, and serialize — no business logic here.
Every endpoint is guarded by the centralized permission checker (AGENTS.md §9);
the returned :class:`SearchFilter` scopes the service SQL to rows the principal
may see.

Feature flags use a string cursor (the flag id), unlike the UUID cursors used
by UUID-keyed resources.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
    depends_role_ids,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.feature_flag.feature_flag_models import FeatureFlag, FeatureFlagRole
from openhands.ev2.feature_flag.feature_flag_schemas import (
    EnabledFeatureFlags,
    FeatureFlagBatchWriteRequest,
    FeatureFlagCreate,
    FeatureFlagRead,
    FeatureFlagRoleBatchWriteRequest,
    FeatureFlagRoleCreate,
    FeatureFlagRoleRead,
    FeatureFlagRoleSearchFilter,
    FeatureFlagRoleSearchResult,
    FeatureFlagSearchFilter,
    FeatureFlagSearchResult,
    FeatureFlagUpdate,
)
from openhands.ev2.feature_flag.feature_flag_service import (
    BatchPermissionDeniedError,
    FeatureFlagConflictError,
    FeatureFlagNotFoundError,
    FeatureFlagPermissionScopeError,
    FeatureFlagRoleConflictError,
    FeatureFlagRoleNotFoundError,
    FeatureFlagRoleOrphanError,
    FeatureFlagRoleService,
    FeatureFlagService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/feature-flags", tags=["feature-flags"])
overrides_router = APIRouter(prefix="/feature-flag-roles", tags=["feature-flag-roles"])


def _cursor(value: str) -> str:
    """Validate the opaque string cursor (the previous page's last flag id).

    The cursor is the flag id itself (keyset pagination over the string PK), so
    any non-empty string is accepted; an empty cursor is a client error.
    """
    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a non-empty string.",
        )
    return value


# ====================================================================== #
# Feature flags
# ====================================================================== #


@router.get("", response_model=FeatureFlagSearchResult)
async def search_feature_flags(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlag],
        Depends(depends_permissions(FeatureFlag, Action.SEARCH)),
    ],
    search_filter: FeatureFlagSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque string cursor (a flag id)")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> FeatureFlagSearchResult:
    service = FeatureFlagService(session, perm_filter)
    cur = _cursor(cursor) if cursor is not None else None
    flags, next_cursor = await service.search(
        cursor=cur,
        limit=limit,
        search_filter=search_filter,
    )
    return FeatureFlagSearchResult(
        items=[FeatureFlagRead.model_validate(f) for f in flags],
        next_cursor=next_cursor,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_feature_flags(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlag],
        Depends(depends_permissions(FeatureFlag, Action.SEARCH)),
    ],
    search_filter: FeatureFlagSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = FeatureFlagService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.get("/enabled", response_model=EnabledFeatureFlags)
async def get_enabled_feature_flags(
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    role_ids: Annotated[list[uuid.UUID], Depends(depends_role_ids)],
) -> EnabledFeatureFlags:
    """Return the feature-flag ids enabled for the current user.

    Self-service endpoint: every authenticated user may see their own effective
    flags (no ``feature_flag_permission`` required). A flag is included when it
    is globally enabled or when the user holds a role with an override row for
    that flag. Anonymous access (no token) is rejected with 401.
    """
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = FeatureFlagService(session)
    flag_ids = await service.enabled_for_roles(role_ids)
    return EnabledFeatureFlags(flags=flag_ids)


@router.post(
    "",
    response_model=FeatureFlagRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_feature_flag(
    payload: FeatureFlagCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlag],
        Depends(depends_permissions(FeatureFlag, Action.CREATE)),
    ],
) -> FeatureFlagRead:
    service = FeatureFlagService(session, perm_filter)
    try:
        flag = await service.create(payload)
    except FeatureFlagPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Feature flag falls outside your create scope: {exc}",
        ) from exc
    except FeatureFlagConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Feature flag with id already exists: {exc}",
        ) from exc
    await session.commit()
    return FeatureFlagRead.model_validate(flag)


@router.get(
    "/batch",
    response_model=BatchReadResult[FeatureFlagRead],
)
async def get_feature_flags_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlag], Depends(depends_permissions(FeatureFlag, Action.READ))
    ],
    # Declared before `/{flag_id}` so the static `/batch` path matches ahead of
    # the string path param. Default to an empty list so an omitted `ids` param
    # is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[str], Query(default_factory=list)],
) -> BatchReadResult[FeatureFlagRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = FeatureFlagService(session, perm_filter)
    flags = await service.get_many(ids)
    return BatchReadResult(
        items=[FeatureFlagRead.model_validate(f) if f is not None else None for f in flags],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[FeatureFlagRead],
)
async def write_feature_flags_batch(
    payload: FeatureFlagBatchWriteRequest,
    session: SessionDep,
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. Declared before `/{flag_id}` so the static `/batch`
    # path matches ahead of the string path param.
    create_filter: Annotated[
        SearchFilter[FeatureFlag] | None,
        Depends(depends_permissions_or_none(FeatureFlag, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[FeatureFlag] | None,
        Depends(depends_permissions_or_none(FeatureFlag, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[FeatureFlag] | None,
        Depends(depends_permissions_or_none(FeatureFlag, Action.DELETE)),
    ],
) -> BatchWriteResult[FeatureFlagRead]:
    service = FeatureFlagService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except FeatureFlagPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Feature flag falls outside your create scope: {exc}",
        ) from exc
    except FeatureFlagConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Feature flag with id already exists: {exc}",
        ) from exc
    except FeatureFlagNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature flag not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[FeatureFlagRead.model_validate(f) if f is not None else None for f in results],
    )


@router.get("/{flag_id}", response_model=FeatureFlagRead)
async def get_feature_flag(
    flag_id: str,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlag], Depends(depends_permissions(FeatureFlag, Action.READ))
    ],
) -> FeatureFlagRead:
    service = FeatureFlagService(session, perm_filter)
    try:
        flag = await service.get(flag_id)
    except FeatureFlagNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature flag not found: {exc}",
        ) from exc
    return FeatureFlagRead.model_validate(flag)


@router.patch("/{flag_id}", response_model=FeatureFlagRead)
async def update_feature_flag(
    flag_id: str,
    payload: FeatureFlagUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlag], Depends(depends_permissions(FeatureFlag, Action.UPDATE))
    ],
) -> FeatureFlagRead:
    service = FeatureFlagService(session, perm_filter)
    try:
        flag = await service.update(flag_id, payload)
    except FeatureFlagNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature flag not found: {exc}",
        ) from exc
    await session.commit()
    return FeatureFlagRead.model_validate(flag)


@router.delete("/{flag_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_feature_flag(
    flag_id: str,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlag], Depends(depends_permissions(FeatureFlag, Action.DELETE))
    ],
) -> None:
    service = FeatureFlagService(session, perm_filter)
    try:
        await service.delete(flag_id)
    except FeatureFlagNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature flag not found: {exc}",
        ) from exc
    await session.commit()


# ====================================================================== #
# Feature flag role overrides
# ====================================================================== #


def _uuid_cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@overrides_router.get(
    "",
    response_model=FeatureFlagRoleSearchResult,
)
async def search_feature_flag_roles(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlagRole],
        Depends(depends_permissions(FeatureFlagRole, Action.SEARCH)),
    ],
    search_filter: FeatureFlagRoleSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> FeatureFlagRoleSearchResult:
    service = FeatureFlagRoleService(session, perm_filter)
    cur = _uuid_cursor(cursor) if cursor is not None else None
    links, next_cursor = await service.search(
        cursor=cur,
        limit=limit,
        search_filter=search_filter,
    )
    return FeatureFlagRoleSearchResult(
        items=[FeatureFlagRoleRead.model_validate(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@overrides_router.get(
    "/count",
    response_model=CountResult,
)
async def count_feature_flag_roles(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlagRole],
        Depends(depends_permissions(FeatureFlagRole, Action.SEARCH)),
    ],
    search_filter: FeatureFlagRoleSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = FeatureFlagRoleService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@overrides_router.post(
    "",
    response_model=FeatureFlagRoleRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_feature_flag_role(
    payload: FeatureFlagRoleCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlagRole],
        Depends(depends_permissions(FeatureFlagRole, Action.CREATE)),
    ],
) -> FeatureFlagRoleRead:
    service = FeatureFlagRoleService(session, perm_filter)
    try:
        link = await service.create(payload)
    except FeatureFlagRoleConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Override already exists: {exc}",
        ) from exc
    except FeatureFlagRoleOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced feature flag or role not found: {exc}",
        ) from exc
    await session.commit()
    return FeatureFlagRoleRead.model_validate(link)


@overrides_router.get(
    "/batch",
    response_model=BatchReadResult[FeatureFlagRoleRead],
)
async def get_feature_flag_roles_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlagRole],
        Depends(depends_permissions(FeatureFlagRole, Action.READ)),
    ],
    # Declared before `/{override_id}` so the static `/batch` path matches ahead
    # of the UUID path param. Default to an empty list so an omitted `ids` param
    # is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[FeatureFlagRoleRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = FeatureFlagRoleService(session, perm_filter)
    links = await service.get_many(ids)
    return BatchReadResult(
        items=[
            FeatureFlagRoleRead.model_validate(link) if link is not None else None for link in links
        ],
    )


@overrides_router.post(
    "/batch",
    response_model=BatchWriteResult[FeatureFlagRoleRead],
)
async def write_feature_flag_roles_batch(
    payload: FeatureFlagRoleBatchWriteRequest,
    session: SessionDep,
    # Resolve per-action filters without raising so a CD batch does not 403 on
    # an unused action. Declared before `/{override_id}` so the static `/batch`
    # path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[FeatureFlagRole] | None,
        Depends(depends_permissions_or_none(FeatureFlagRole, Action.CREATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[FeatureFlagRole] | None,
        Depends(depends_permissions_or_none(FeatureFlagRole, Action.DELETE)),
    ],
) -> BatchWriteResult[FeatureFlagRoleRead]:
    service = FeatureFlagRoleService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except FeatureFlagRoleConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Override already exists: {exc}",
        ) from exc
    except FeatureFlagRoleOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced feature flag or role not found: {exc}",
        ) from exc
    except FeatureFlagRoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Override not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[
            FeatureFlagRoleRead.model_validate(link) if link is not None else None
            for link in results
        ],
    )


@overrides_router.get(
    "/{override_id}",
    response_model=FeatureFlagRoleRead,
)
async def get_feature_flag_role(
    override_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlagRole],
        Depends(depends_permissions(FeatureFlagRole, Action.READ)),
    ],
) -> FeatureFlagRoleRead:
    service = FeatureFlagRoleService(session, perm_filter)
    try:
        link = await service.get(override_id)
    except FeatureFlagRoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Override not found: {exc}",
        ) from exc
    return FeatureFlagRoleRead.model_validate(link)


@overrides_router.delete(
    "/{override_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_feature_flag_role(
    override_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[FeatureFlagRole],
        Depends(depends_permissions(FeatureFlagRole, Action.DELETE)),
    ],
) -> None:
    service = FeatureFlagRoleService(session, perm_filter)
    try:
        await service.delete(override_id)
    except FeatureFlagRoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Override not found: {exc}",
        ) from exc
    await session.commit()
