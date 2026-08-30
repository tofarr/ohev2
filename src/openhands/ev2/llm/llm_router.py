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

import asyncio
import hmac
import json
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.llm.llm_models import StoredLLM, StoredProviderConnection
from openhands.ev2.llm.llm_schemas import (
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
) -> CompletionResponse | StreamingResponse:
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
        sdk_llm = await llm_service.materialize_llm(llm, use_proxy=False)
    except LLMNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM not found: {exc}",
        ) from exc

    params = dict(payload.params)
    if params.get("stream") is True:
        return StreamingResponse(
            _stream_completion(
                session,
                user_id,
                llm.provider_connection_id,
                llm.id,
                sdk_llm,
                messages,
                tools,
                params,
            ),
            media_type="text/event-stream",
        )

    try:
        response = await sdk_llm.acompletion(messages=messages, tools=tools, **params)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM completion failed: {exc}",
        ) from exc
    await _record_usage(session, user_id, llm.provider_connection_id, llm.id, response)
    return _to_completion_response(response)


@router.post(
    "/completion/{llm_id}/chat/completions",
    response_model=None,
    include_in_schema=False,
)
async def chat_completions_proxy(
    llm_id: uuid.UUID,
    request: Request,
    session: SessionDep,
) -> Response | StreamingResponse:
    """OpenAI-compatible passthrough for SDK clients using the proxy base URL."""
    llm_service = LLMService(session)
    try:
        llm = await llm_service.get(llm_id)
        conn = await llm_service.connection_for_llm(llm)
    except LLMNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM not found: {exc}",
        ) from exc

    provider_key = _provider_api_key(conn)
    if provider_key is None or not _proxy_auth_matches(request, provider_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid proxy credentials.",
        )
    if conn.base_url is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Provider connection has no base_url to proxy.",
        )

    body = await request.body()
    target = f"{conn.base_url.rstrip('/')}/chat/completions"
    headers = _proxy_headers(request, provider_key)
    if _body_requests_stream(body):
        client = httpx.AsyncClient(timeout=None)
        upstream = await client.send(
            client.build_request(
                "POST",
                target,
                content=body,
                headers=headers,
                params=request.query_params,
            ),
            stream=True,
        )
        if upstream.status_code >= 400:
            content = await upstream.aread()
            await upstream.aclose()
            await client.aclose()
            return Response(
                content=content,
                status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type"),
            )
        return StreamingResponse(
            _proxy_stream_response(
                session,
                llm.user_id,
                conn.id,
                llm.id,
                client,
                upstream,
                llm.model,
            ),
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "text/event-stream"),
        )

    async with httpx.AsyncClient(timeout=None) as client:
        upstream = await client.post(
            target,
            content=body,
            headers=headers,
            params=request.query_params,
        )
    if 200 <= upstream.status_code < 300:
        await _record_openai_usage(session, llm.user_id, conn.id, llm.id, llm.model, upstream)
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
    )


def _provider_api_key(conn: StoredProviderConnection) -> str | None:
    if conn.api_key is None:
        return None
    from openhands.ev2.encryption.encryption_service import get_encryption_service

    return get_encryption_service().decrypt_value(conn.api_key)


def _proxy_auth_matches(request: Request, expected_api_key: str) -> bool:
    supplied = request.headers.get("x-api-key")
    auth_header = request.headers.get("authorization", "")
    if supplied is None and auth_header.lower().startswith("bearer "):
        supplied = auth_header[7:].strip()
    return supplied is not None and hmac.compare_digest(supplied, expected_api_key)


def _proxy_headers(request: Request, provider_key: str) -> dict[str, str]:
    headers = {"authorization": f"Bearer {provider_key}"}
    for name in ("accept", "content-type"):
        value = request.headers.get(name)
        if value is not None:
            headers[name] = value
    return headers


def _body_requests_stream(body: bytes) -> bool:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict) and payload.get("stream") is True


async def _proxy_stream_response(
    session: AsyncSession,
    user_id: uuid.UUID,
    provider_connection_id: uuid.UUID,
    llm_id: uuid.UUID,
    client: httpx.AsyncClient,
    upstream: httpx.Response,
    fallback_model: str,
) -> AsyncIterator[bytes]:
    usage_payload: dict[str, Any] | None = None
    buffer = ""
    try:
        async for chunk in upstream.aiter_bytes():
            buffer, parsed_usage = _parse_stream_usage(buffer, chunk)
            if parsed_usage is not None:
                usage_payload = parsed_usage
            yield chunk
        if usage_payload is not None:
            await _record_usage_from_openai_payload(
                session,
                user_id,
                provider_connection_id,
                llm_id,
                fallback_model,
                usage_payload,
            )
    finally:
        await upstream.aclose()
        await client.aclose()


def _parse_stream_usage(
    buffer: str,
    chunk: bytes,
) -> tuple[str, dict[str, Any] | None]:
    buffer += chunk.decode(errors="ignore")
    lines = buffer.splitlines(keepends=True)
    buffer = lines.pop() if lines and not lines[-1].endswith(("\n", "\r")) else ""
    usage_payload: dict[str, Any] | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("data:"):
            continue
        raw = stripped.removeprefix("data:").strip()
        if raw == "[DONE]":
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("usage"), dict):
            usage_payload = payload
    return buffer, usage_payload


async def _record_openai_usage(
    session: AsyncSession,
    user_id: uuid.UUID,
    provider_connection_id: uuid.UUID,
    llm_id: uuid.UUID,
    fallback_model: str,
    response: httpx.Response,
) -> None:
    try:
        payload = response.json()
    except ValueError:
        return
    if isinstance(payload, dict):
        await _record_usage_from_openai_payload(
            session,
            user_id,
            provider_connection_id,
            llm_id,
            fallback_model,
            payload,
        )


async def _record_usage_from_openai_payload(
    session: AsyncSession,
    user_id: uuid.UUID,
    provider_connection_id: uuid.UUID,
    llm_id: uuid.UUID,
    fallback_model: str,
    payload: dict[str, Any],
) -> None:
    usage = payload.get("usage") or {}
    if not isinstance(usage, dict):
        return
    prompt_details = usage.get("prompt_tokens_details") or {}
    completion_details = usage.get("completion_tokens_details") or {}
    metrics = {
        "model_name": payload.get("model") or fallback_model,
        "accumulated_cost": 0.0,
        "accumulated_token_usage": {
            "model": payload.get("model") or fallback_model,
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "cache_read_tokens": prompt_details.get("cached_tokens", 0)
            if isinstance(prompt_details, dict)
            else 0,
            "cache_write_tokens": 0,
            "reasoning_tokens": completion_details.get("reasoning_tokens", 0)
            if isinstance(completion_details, dict)
            else 0,
            "context_window": 0,
            "per_turn_token": usage.get("total_tokens", 0),
        },
    }
    from openhands.ev2.llm.llm_usage_service import LlmUsageService

    row = await LlmUsageService(session).record_usage(
        user_id=user_id,
        provider_connection_id=provider_connection_id,
        llm_id=llm_id,
        response_id=payload.get("id") if isinstance(payload.get("id"), str) else None,
        model=str(payload.get("model") or fallback_model),
        sdk_metrics=metrics,
    )
    if row is not None:
        await session.commit()


async def _stream_completion(
    session: AsyncSession,
    user_id: uuid.UUID,
    provider_connection_id: uuid.UUID,
    llm_id: uuid.UUID,
    sdk_llm: Any,
    messages: list[Any],
    tools: list[Any] | None,
    params: dict[str, Any],
) -> AsyncIterator[bytes]:
    """Stream SDK chunks as SSE and record final usage."""
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def _on_token(chunk: Any) -> None:
        await queue.put(_completion_chunk_to_sse(chunk))

    async def _run_completion() -> None:
        try:
            response = await sdk_llm.acompletion(
                messages=messages,
                tools=tools,
                on_token=_on_token,
                **params,
            )
            await _record_usage(session, user_id, provider_connection_id, llm_id, response)
            await queue.put(b"data: [DONE]\n\n")
        except Exception as exc:
            error = json.dumps({"detail": f"LLM completion failed: {exc}"})
            await queue.put(f"event: error\ndata: {error}\n\n".encode())
        finally:
            await queue.put(None)

    task = asyncio.create_task(_run_completion())
    try:
        while True:
            item = await queue.get()
            if item is None:
                break
            yield item
    finally:
        if not task.done():
            task.cancel()


def _completion_chunk_to_sse(chunk: Any) -> bytes:
    """Serialize one LiteLLM stream chunk as an SSE data event."""
    if hasattr(chunk, "model_dump"):
        data = chunk.model_dump(mode="json")
    elif hasattr(chunk, "to_dict"):
        data = chunk.to_dict()
    elif isinstance(chunk, dict):
        data = chunk
    else:
        data = str(chunk)
    return f"data: {json.dumps(data)}\n\n".encode()


async def _record_usage(
    session: AsyncSession,
    user_id: uuid.UUID,
    provider_connection_id: uuid.UUID,
    llm_id: uuid.UUID,
    response: Any,
) -> None:
    """Best-effort raw usage recording for a completed proxy call."""
    from openhands.ev2.llm.llm_usage_service import LlmUsageService

    service = LlmUsageService(session)
    row = await service.record_usage(
        user_id=user_id,
        provider_connection_id=provider_connection_id,
        llm_id=llm_id,
        response_id=getattr(response, "id", None),
        model=getattr(getattr(response, "metrics", None), "model_name", "")
        or getattr(response, "model", "")
        or "",
        sdk_metrics=getattr(response, "metrics", None),
    )
    if row is not None:
        await session.commit()


def _to_completion_response(response) -> CompletionResponse:  # type: ignore[no-untyped-def]
    """Map an SDK :class:`LLMResponse` to the API :class:`CompletionResponse`."""
    return CompletionResponse(
        id=response.id,
        message=response.message.model_dump(mode="json"),
        metrics=response.metrics.model_dump(mode="json"),
    )
