"""HTTP routes for the LLM feature.

Uniform REST surface (AGENTS.md §3): the collections are
``/provider-connections`` and ``/llms`` with cursor pagination; create is
``POST``, retrieve is ``GET``, update is ``PATCH``, remove is ``DELETE``.
Every endpoint is guarded by the centralized permission checker (AGENTS.md §9)
over the ``provider_connection`` / ``llm`` resource types; the returned
:class:`SearchFilter` scopes the service SQL to rows the principal may see.

The ``api_key`` on a provider connection is write-only: accepted on create/
update (plaintext, encrypted before persistence) but never returned.

The action endpoint ``POST /llm/completion/{llm_id}`` proxies a completion
request through a stored LLM profile, inferring the provider connection from
the LLM. It requires the ``USE`` action on the ``llm`` resource; the
provider connection is resolved from the LLM purely to source credentials.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.llm.llm_models import (
    LlmAggregatedUsage,
    StoredLLM,
    StoredProviderConnection,
)
from openhands.ev2.llm.llm_schemas import (
    AggregatedUsageRead,
    AggregatedUsageSearchFilter,
    AggregatedUsageSearchResult,
    CompletionRequest,
    CompletionResponse,
    LLMBatchWriteRequest,
    LLMCreate,
    LLMRead,
    LLMSearchFilter,
    LLMSearchResult,
    LLMUpdate,
    ProviderConnectionBatchWriteRequest,
    ProviderConnectionCreate,
    ProviderConnectionRead,
    ProviderConnectionSearchFilter,
    ProviderConnectionSearchResult,
    ProviderConnectionUpdate,
)
from openhands.ev2.llm.llm_service import (
    BatchPermissionDeniedError,
    LLMConfigError,
    LLMNotFoundError,
    LLMPermissionScopeError,
    LLMService,
    ProviderConnectionNotFoundError,
    ProviderConnectionPermissionScopeError,
    ProviderConnectionService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/llm", tags=["llm"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


# ====================================================================== #
# Provider connections
# ====================================================================== #


@router.get(
    "/provider-connections",
    response_model=ProviderConnectionSearchResult,
)
async def search_provider_connections(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredProviderConnection],
        Depends(depends_permissions(StoredProviderConnection, Action.SEARCH)),
    ],
    search_filter: ProviderConnectionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ProviderConnectionSearchResult:
    service = ProviderConnectionService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return ProviderConnectionSearchResult(
        items=[ProviderConnectionRead.model_validate(r) for r in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get(
    "/provider-connections/count",
    response_model=CountResult,
)
async def count_provider_connections(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredProviderConnection],
        Depends(depends_permissions(StoredProviderConnection, Action.SEARCH)),
    ],
    search_filter: ProviderConnectionSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = ProviderConnectionService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post(
    "/provider-connections",
    response_model=ProviderConnectionRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider_connection(
    payload: ProviderConnectionCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredProviderConnection],
        Depends(depends_permissions(StoredProviderConnection, Action.CREATE)),
    ],
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
) -> ProviderConnectionRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    service = ProviderConnectionService(session, perm_filter)
    try:
        conn = await service.create(payload, user_id=user_id)
    except ProviderConnectionPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Provider connection falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    return ProviderConnectionRead.model_validate(conn)


@router.get(
    "/provider-connections/batch",
    response_model=BatchReadResult[ProviderConnectionRead],
)
async def get_provider_connections_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredProviderConnection],
        Depends(depends_permissions(StoredProviderConnection, Action.READ)),
    ],
    # Declared before `/{connection_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[ProviderConnectionRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = ProviderConnectionService(session, perm_filter)
    conns = await service.get_many(ids)
    return BatchReadResult(
        items=[ProviderConnectionRead.model_validate(c) if c is not None else None for c in conns],
    )


@router.post(
    "/provider-connections/batch",
    response_model=BatchWriteResult[ProviderConnectionRead],
)
async def write_provider_connections_batch(
    payload: ProviderConnectionBatchWriteRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. Declared before `/{connection_id}` so the static
    # `/batch` path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[StoredProviderConnection] | None,
        Depends(depends_permissions_or_none(StoredProviderConnection, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[StoredProviderConnection] | None,
        Depends(depends_permissions_or_none(StoredProviderConnection, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[StoredProviderConnection] | None,
        Depends(depends_permissions_or_none(StoredProviderConnection, Action.DELETE)),
    ],
) -> BatchWriteResult[ProviderConnectionRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    service = ProviderConnectionService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters, user_id=user_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except ProviderConnectionPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Provider connection falls outside your create scope: {exc}",
        ) from exc
    except ProviderConnectionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider connection not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[
            ProviderConnectionRead.model_validate(c) if c is not None else None for c in results
        ],
    )


@router.get(
    "/provider-connections/{connection_id}",
    response_model=ProviderConnectionRead,
)
async def get_provider_connection(
    connection_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredProviderConnection],
        Depends(depends_permissions(StoredProviderConnection, Action.READ)),
    ],
) -> ProviderConnectionRead:
    service = ProviderConnectionService(session, perm_filter)
    try:
        conn = await service.get(connection_id)
    except ProviderConnectionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider connection not found: {exc}",
        ) from exc
    return ProviderConnectionRead.model_validate(conn)


@router.patch(
    "/provider-connections/{connection_id}",
    response_model=ProviderConnectionRead,
)
async def update_provider_connection(
    connection_id: uuid.UUID,
    payload: ProviderConnectionUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredProviderConnection],
        Depends(depends_permissions(StoredProviderConnection, Action.UPDATE)),
    ],
) -> ProviderConnectionRead:
    service = ProviderConnectionService(session, perm_filter)
    try:
        conn = await service.update(connection_id, payload)
    except ProviderConnectionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider connection not found: {exc}",
        ) from exc
    await session.commit()
    return ProviderConnectionRead.model_validate(conn)


@router.delete(
    "/provider-connections/{connection_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_provider_connection(
    connection_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredProviderConnection],
        Depends(depends_permissions(StoredProviderConnection, Action.DELETE)),
    ],
) -> None:
    service = ProviderConnectionService(session, perm_filter)
    try:
        await service.delete(connection_id)
    except ProviderConnectionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider connection not found: {exc}",
        ) from exc
    await session.commit()


# ====================================================================== #
# LLMs
# ====================================================================== #


@router.get("/llms", response_model=LLMSearchResult)
async def search_llms(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredLLM], Depends(depends_permissions(StoredLLM, Action.SEARCH))
    ],
    search_filter: LLMSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> LLMSearchResult:
    service = LLMService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return LLMSearchResult(
        items=[LLMRead.model_validate(r) for r in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/llms/count", response_model=CountResult)
async def count_llms(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredLLM], Depends(depends_permissions(StoredLLM, Action.SEARCH))
    ],
    search_filter: LLMSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = LLMService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("/llms", response_model=LLMRead, status_code=status.HTTP_201_CREATED)
async def create_llm(
    payload: LLMCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredLLM], Depends(depends_permissions(StoredLLM, Action.CREATE))
    ],
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
) -> LLMRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    service = LLMService(session, perm_filter)
    try:
        llm = await service.create(payload, user_id=user_id)
    except LLMPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"LLM falls outside your create scope: {exc}",
        ) from exc
    except LLMConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid LLM config: {exc}",
        ) from exc
    await session.commit()
    return LLMRead.model_validate(llm)


@router.get(
    "/llms/batch",
    response_model=BatchReadResult[LLMRead],
)
async def get_llms_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredLLM], Depends(depends_permissions(StoredLLM, Action.READ))
    ],
    # Declared before `/{llm_id}` so the static `/batch` path matches ahead of
    # the UUID path param. Default to an empty list so an omitted `ids` param
    # is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[LLMRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = LLMService(session, perm_filter)
    llms = await service.get_many(ids)
    return BatchReadResult(
        items=[LLMRead.model_validate(llm) if llm is not None else None for llm in llms],
    )


@router.post(
    "/llms/batch",
    response_model=BatchWriteResult[LLMRead],
)
async def write_llms_batch(
    payload: LLMBatchWriteRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. Declared before `/{llm_id}` so the static `/batch`
    # path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[StoredLLM] | None,
        Depends(depends_permissions_or_none(StoredLLM, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[StoredLLM] | None,
        Depends(depends_permissions_or_none(StoredLLM, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[StoredLLM] | None,
        Depends(depends_permissions_or_none(StoredLLM, Action.DELETE)),
    ],
) -> BatchWriteResult[LLMRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    service = LLMService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters, user_id=user_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except LLMPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"LLM falls outside your create scope: {exc}",
        ) from exc
    except LLMNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM not found: {exc}",
        ) from exc
    except LLMConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid LLM config: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[LLMRead.model_validate(llm) if llm is not None else None for llm in results],
    )


@router.get("/llms/{llm_id}", response_model=LLMRead)
async def get_llm(
    llm_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredLLM], Depends(depends_permissions(StoredLLM, Action.READ))
    ],
) -> LLMRead:
    service = LLMService(session, perm_filter)
    try:
        llm = await service.get(llm_id)
    except LLMNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM not found: {exc}",
        ) from exc
    return LLMRead.model_validate(llm)


@router.patch("/llms/{llm_id}", response_model=LLMRead)
async def update_llm(
    llm_id: uuid.UUID,
    payload: LLMUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredLLM], Depends(depends_permissions(StoredLLM, Action.UPDATE))
    ],
) -> LLMRead:
    service = LLMService(session, perm_filter)
    try:
        llm = await service.update(llm_id, payload)
    except LLMNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM not found: {exc}",
        ) from exc
    except LLMPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"LLM falls outside your update scope: {exc}",
        ) from exc
    except LLMConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid LLM config: {exc}",
        ) from exc
    await session.commit()
    return LLMRead.model_validate(llm)


@router.delete("/llms/{llm_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_llm(
    llm_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredLLM], Depends(depends_permissions(StoredLLM, Action.DELETE))
    ],
) -> None:
    service = LLMService(session, perm_filter)
    try:
        await service.delete(llm_id)
    except LLMNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM not found: {exc}",
        ) from exc
    await session.commit()


# ====================================================================== #
# Completion action
# ====================================================================== #


@router.post(
    "/completion/{llm_id}",
    response_model=CompletionResponse,
)
async def completion(
    llm_id: uuid.UUID,
    payload: CompletionRequest,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredLLM],
        Depends(depends_permissions(StoredLLM, Action.USE)),
    ],
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
) -> CompletionResponse:
    """Proxy a completion through a stored LLM profile.

    Authorizes ``USE`` on the named stored LLM (must be in the principal's
    ``USE`` scope), resolves its provider connection purely to source
    credentials (no separate ``USE`` check on the connection — the LLM and
    connection share an owner, enforced at LLM create/update time), materializes
    the SDK :class:`LLM`, and runs :meth:`LLM.acompletion`. The SDK
    :class:`Message` and :class:`ToolDefinition` inputs are validated from the
    request dicts.
    """
    from openhands.sdk.llm.message import Message
    from openhands.sdk.tool.tool import ToolDefinition

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )

    llm_service = LLMService(session, perm_filter)
    try:
        llm = await llm_service.get(llm_id)
    except LLMNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM not found: {exc}",
        ) from exc

    try:
        messages = [Message.model_validate(m) for m in payload.messages]
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid messages: {exc}",
        ) from exc

    tools: list[ToolDefinition[Any, Any]] | None = None
    if payload.tools is not None:
        try:
            tools = [ToolDefinition.model_validate(t) for t in payload.tools]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid tools: {exc}",
            ) from exc

    try:
        sdk_llm = await llm_service.materialize_llm(llm)
    except LLMNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM not found: {exc}",
        ) from exc

    try:
        response = await sdk_llm.acompletion(messages=messages, tools=tools, **payload.params)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM completion failed: {exc}",
        ) from exc
    # Record raw usage (best-effort; never fails the already-succeeded completion).
    await _record_usage(session, user_id, llm.provider_connection_id, llm.id, response)
    return _to_completion_response(response)


async def _record_usage(
    session: AsyncSession,
    user_id: uuid.UUID,
    provider_connection_id: uuid.UUID,
    llm_id: uuid.UUID,
    response: Any,
) -> None:
    """Append a raw LlmUsage row for a completed call.

    Best-effort: a logging failure is swallowed so it cannot fail a completion
    that already succeeded. The usage insert is committed in its own transaction
    after the response is built (the caller has not committed the request
    session at this point, but usage recording is independent of the request's
    own transactional work, which is read-only here).
    """
    from openhands.ev2.llm.llm_usage_service import LlmUsageService

    try:
        service = LlmUsageService(session)
        await service.record_usage(
            user_id=user_id,
            provider_connection_id=provider_connection_id,
            llm_id=llm_id,
            response_id=getattr(response, "id", None),
            model=getattr(getattr(response, "metrics", None), "model_name", "")
            or getattr(response, "model", "")
            or "",
            sdk_metrics=getattr(response, "metrics", None),
        )
        await session.commit()
    except Exception:
        # Roll back the usage insert only; the completion response is already
        # built and returned regardless. Logged in the service on rollback.
        await session.rollback()


def _to_completion_response(response) -> CompletionResponse:  # type: ignore[no-untyped-def]
    """Map an SDK :class:`LLMResponse` to the API :class:`CompletionResponse`."""
    return CompletionResponse(
        id=response.id,
        message=response.message.model_dump(mode="json"),
        metrics=response.metrics.model_dump(mode="json"),
    )


# ====================================================================== #
# Aggregated usage (read-only)
# ====================================================================== #
#
# The raw ``llm_usage`` table is intentionally not exposed: it is a
# high-volume, daily-partitioned append-only log. Usage queries go through the
# ``llm_aggregated_usage`` projection (per-minute, per-user rollups) exposed
# read-only here. Only SEARCH / READ / batch-read are wired — there is no
# create/update/delete (the projection is populated by the background
# aggregator), so per AGENTS.md §3 no batch write endpoint is required.


@router.get(
    "/aggregated-usage",
    response_model=AggregatedUsageSearchResult,
)
async def search_aggregated_usage(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[LlmAggregatedUsage],
        Depends(depends_permissions(LlmAggregatedUsage, Action.SEARCH)),
    ],
    search_filter: AggregatedUsageSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> AggregatedUsageSearchResult:
    """List per-minute, per-user usage rollups (paginated, scoped by permissions)."""
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    stmt = perm_filter.filter_sql(select(LlmAggregatedUsage).order_by(LlmAggregatedUsage.id))
    if search_filter is not None:
        stmt = search_filter.filter_sql(stmt)
    if cursor_uuid is not None:
        stmt = stmt.where(LlmAggregatedUsage.id > cursor_uuid)
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    rows = list(result.scalars().all())
    next_cursor = rows[-1].id if len(rows) == limit else None
    return AggregatedUsageSearchResult(
        items=[AggregatedUsageRead.model_validate(r) for r in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/aggregated-usage/count", response_model=CountResult)
async def count_aggregated_usage(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[LlmAggregatedUsage],
        Depends(depends_permissions(LlmAggregatedUsage, Action.SEARCH)),
    ],
    search_filter: AggregatedUsageSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    """Count per-minute, per-user usage rollups in the principal's scope."""
    stmt = perm_filter.filter_sql(select(func.count()).select_from(LlmAggregatedUsage))
    if search_filter is not None:
        stmt = search_filter.filter_sql(stmt)
    result = await session.execute(stmt)
    return CountResult(count=int(result.scalar_one()))


@router.get(
    "/aggregated-usage/batch",
    response_model=BatchReadResult[AggregatedUsageRead],
)
async def get_aggregated_usage_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[LlmAggregatedUsage],
        Depends(depends_permissions(LlmAggregatedUsage, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[AggregatedUsageRead]:
    """Batch read aggregated-usage rows by id (positional, null for missing)."""
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    if not ids:
        return BatchReadResult(items=[])
    stmt = perm_filter.filter_sql(select(LlmAggregatedUsage).where(LlmAggregatedUsage.id.in_(ids)))
    result = await session.execute(stmt)
    by_id: dict[uuid.UUID, LlmAggregatedUsage] = {row.id: row for row in result.scalars().all()}
    return BatchReadResult(
        items=[AggregatedUsageRead.model_validate(by_id[i]) if i in by_id else None for i in ids],
    )


@router.get(
    "/aggregated-usage/{row_id}",
    response_model=AggregatedUsageRead,
)
async def get_aggregated_usage(
    row_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[LlmAggregatedUsage],
        Depends(depends_permissions(LlmAggregatedUsage, Action.READ)),
    ],
) -> AggregatedUsageRead:
    """Retrieve one aggregated-usage rollup by id."""
    stmt = perm_filter.filter_sql(select(LlmAggregatedUsage).where(LlmAggregatedUsage.id == row_id))
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Aggregated usage not found: {row_id}",
        )
    return AggregatedUsageRead.model_validate(row)
