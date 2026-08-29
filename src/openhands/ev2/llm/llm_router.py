"""HTTP routes for the LLM feature.

Uniform REST surface (AGENTS.md §3): the collections are
``/provider-connections`` and ``/llms`` with cursor pagination; create is
``POST``, retrieve is ``GET``, update is ``PATCH``, remove is ``DELETE``.
Every endpoint is guarded by the centralized permission checker (AGENTS.md §9)
over the ``provider_connection`` / ``llm`` resource types; the returned
:class:`SearchFilter` scopes the service SQL to rows the principal may see.

The ``api_key`` on a provider connection is write-only: accepted on create/
update (plaintext, encrypted before persistence) but never returned.

The action endpoint ``POST /llm/completion/{provider_connection_id}`` proxies a
completion request through a stored LLM, sourcing credentials from the named
provider connection. It requires the ``USE`` action on the
``provider_connection`` resource.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import depends_permissions, depends_user_id
from openhands.ev2.db import SessionDep
from openhands.ev2.llm.llm_models import StoredLLM, StoredProviderConnection
from openhands.ev2.llm.llm_schemas import (
    CompletionRequest,
    CompletionResponse,
    LLMCreate,
    LLMRead,
    LLMSearchFilter,
    LLMSearchResult,
    LLMUpdate,
    ProviderConnectionCreate,
    ProviderConnectionRead,
    ProviderConnectionSearchFilter,
    ProviderConnectionSearchResult,
    ProviderConnectionUpdate,
)
from openhands.ev2.llm.llm_service import (
    LLMConfigError,
    LLMNotFoundError,
    LLMPermissionScopeError,
    LLMService,
    ProviderConnectionNotFoundError,
    ProviderConnectionPermissionScopeError,
    ProviderConnectionService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import CountResult
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
    "/completion/{provider_connection_id}",
    response_model=CompletionResponse,
)
async def completion(
    provider_connection_id: uuid.UUID,
    payload: CompletionRequest,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StoredProviderConnection],
        Depends(depends_permissions(StoredProviderConnection, Action.USE)),
    ],
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
) -> CompletionResponse:
    """Proxy a completion through a stored LLM.

    Resolves the named provider connection (must be in the principal's
    ``USE`` scope), selects the stored LLM profile (``payload.llm_id`` or the
    first LLM on the connection owned by the principal), materializes the SDK
    :class:`LLM`, and runs :meth:`LLM.acompletion`. The SDK :class:`Message`
    and :class:`ToolDefinition` inputs are validated from the request dicts.
    """
    from openhands.sdk.llm.message import Message
    from openhands.sdk.tool.tool import ToolDefinition

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )

    conn_service = ProviderConnectionService(session, perm_filter)
    try:
        conn = await conn_service.get(provider_connection_id)
    except ProviderConnectionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider connection not found: {exc}",
        ) from exc

    llm_service = LLMService(session)
    llm = await _resolve_llm(llm_service, conn, user_id, payload.llm_id)

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
    return _to_completion_response(response)


async def _resolve_llm(
    service: LLMService,
    conn: StoredProviderConnection,
    user_id: uuid.UUID,
    llm_id: uuid.UUID | None,
) -> StoredLLM:
    """Resolve the stored LLM to run, by explicit id or first on the connection."""
    if llm_id is not None:
        try:
            return await service.get(llm_id)
        except LLMNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"LLM not found: {exc}",
            ) from exc
    llm = await service.first_for_connection(conn.id, user_id=user_id)
    if llm is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No stored LLM found for this provider connection.",
        )
    return llm


def _to_completion_response(response) -> CompletionResponse:  # type: ignore[no-untyped-def]
    """Map an SDK :class:`LLMResponse` to the API :class:`CompletionResponse`."""
    return CompletionResponse(
        id=response.id,
        message=response.message.model_dump(mode="json"),
        metrics=response.metrics.model_dump(mode="json"),
    )
