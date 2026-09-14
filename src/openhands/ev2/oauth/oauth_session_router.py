"""HTTP routes for the ``/oauth/sessions`` resource + login/consent flow.

Endpoints (AGENTS.md §3):

* ``POST /oauth/providers/{provider_id}/authorize`` — **authenticated**;
  requires ``CREATE`` on ``OAuthSession`` + ``USE`` on ``OAuthProvider``.
  Returns the provider authorize URL + signed state.
* ``GET  /oauth/providers/{provider_id}/callback`` — **public** (IdP redirect
  target); registered in ``PERMISSION_DEPENDENCY_OVERRIDES``. Exchanges the
  code and persists the ``OAuthSession``.
* ``POST /oauth/sessions/{session_id}/refresh`` — **authenticated**, requires
  ``USE`` on the session. Explicit refresh.
* ``DELETE /oauth/sessions/{session_id}`` — **authenticated**, requires
  ``DELETE`` on the session.
* Standard CRUD: ``GET /oauth/sessions``, ``GET /oauth/sessions/{id}``,
  ``PATCH /oauth/sessions/{id}``, ``GET /oauth/sessions/batch``,
  ``POST /oauth/sessions/batch``, ``GET /oauth/sessions/count``.
"""

from __future__ import annotations

import uuid
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
    depends_user_id,
)
from openhands.ev2.config import get_config
from openhands.ev2.db import SessionDep
from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.oauth.oauth_provider_service import (
    OAuthProviderNotFoundError,
    OAuthProviderService,
)
from openhands.ev2.oauth.oauth_session_models import OAuthSession
from openhands.ev2.oauth.oauth_session_schemas import (
    AuthorizeRequest,
    AuthorizeResponse,
    OAuthSessionBatchWriteRequest,
    OAuthSessionRead,
    OAuthSessionSearchFilter,
    OAuthSessionSearchResult,
    OAuthSessionUpdate,
)
from openhands.ev2.oauth.oauth_session_service import (
    BatchPermissionDeniedError,
    OAuthProviderDisabledError,
    OAuthProviderError,
    OAuthSessionNotFoundError,
    OAuthSessionService,
    OAuthSessionUnrecoverableError,
    RefreshLockTimeoutError,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/oauth/sessions", tags=["oauth-sessions"])
flow_router = APIRouter(prefix="/oauth/providers", tags=["oauth-sessions"])


def _callback_url(provider_id: uuid.UUID) -> str:
    base_url = get_config().base_url.rstrip("/")
    return f"{base_url}/oauth/providers/{provider_id}/callback"


async def _load_provider(
    provider_id: uuid.UUID,
    session: SessionDep,
) -> OAuthProvider:
    service = OAuthProviderService(session)
    try:
        return await service.get(provider_id)
    except OAuthProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@flow_router.post(
    "/{provider_id}/authorize",
    response_model=AuthorizeResponse,
)
async def authorize_oauth_session(
    provider_id: uuid.UUID,
    payload: AuthorizeRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    session_perm_filter: Annotated[
        SearchFilter[OAuthSession],
        Depends(depends_permissions(OAuthSession, Action.CREATE)),
    ],
    provider_perm_filter: Annotated[
        SearchFilter[OAuthProvider],
        Depends(depends_permissions(OAuthProvider, Action.USE)),
    ],
) -> AuthorizeResponse:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    provider = await _load_provider(provider_id, session)
    service = OAuthSessionService(session, session_perm_filter)
    try:
        url = await service.build_authorize_url(
            provider,
            user_id=user_id,
            redirect_uri=payload.redirect_uri,
            client_state=payload.state,
            scope=payload.scope,
            code_challenge=payload.code_challenge,
            code_challenge_method=payload.code_challenge_method,
            callback_url=_callback_url(provider_id),
        )
    except OAuthProviderDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
    return AuthorizeResponse(authorize_url=url, state="")


@flow_router.get("/{provider_id}/callback")
async def oauth_callback(
    provider_id: uuid.UUID,
    session: SessionDep,
    code: Annotated[str, Query()],
    state: Annotated[str, Query()],
) -> RedirectResponse:
    """Public callback target for the provider OAuth redirect.

    Registered in ``PERMISSION_DEPENDENCY_OVERRIDES`` as a public route.
    """
    provider = await _load_provider(provider_id, session)
    service = OAuthSessionService(session)
    try:
        oauth_session = await service.handle_callback(
            provider,
            code=code,
            state=state,
            callback_url=_callback_url(provider_id),
        )
    except OAuthProviderError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()

    enc = service._enc
    payload = enc.decrypt_jwe_token(state)
    redirect_uri = str(payload.get("ruri", ""))
    client_state = payload.get("cst")
    params: dict[str, str] = {"session_id": str(oauth_session.id)}
    if client_state is not None:
        params["state"] = str(client_state)
    location = f"{redirect_uri}?{urlencode(params)}" if redirect_uri else ""
    if not location:
        return RedirectResponse(
            url=get_config().base_url,
            status_code=status.HTTP_302_FOUND,
        )
    return RedirectResponse(url=location, status_code=status.HTTP_302_FOUND)


@router.post("/{session_id}/refresh", response_model=OAuthSessionRead)
async def refresh_oauth_session(
    session_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthSession],
        Depends(depends_permissions(OAuthSession, Action.USE)),
    ],
) -> OAuthSessionRead:
    service = OAuthSessionService(session, perm_filter)
    try:
        oauth_session = await service.get(session_id)
        provider = await _load_provider(oauth_session.oauth_provider_id, session)
        refreshed = await service.explicit_refresh(oauth_session, provider)
    except OAuthSessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (OAuthSessionUnrecoverableError, RefreshLockTimeoutError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except OAuthProviderError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
    return service.to_read(refreshed)


@router.get("", response_model=OAuthSessionSearchResult)
async def search_oauth_sessions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthSession],
        Depends(depends_permissions(OAuthSession, Action.SEARCH)),
    ],
    search_filter: OAuthSessionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> OAuthSessionSearchResult:
    service = OAuthSessionService(session, perm_filter)
    try:
        cursor_uuid = uuid.UUID(cursor) if cursor is not None else None
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc
    sessions, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return OAuthSessionSearchResult(
        items=[service.to_read(s) for s in sessions],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_oauth_sessions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthSession],
        Depends(depends_permissions(OAuthSession, Action.READ)),
    ],
    search_filter: OAuthSessionSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = OAuthSessionService(session, perm_filter)
    try:
        return CountResult(count=await service.count(search_filter))
    finally:
        await service.aclose()


@router.get(
    "/batch",
    response_model=BatchReadResult[OAuthSessionRead],
)
async def get_oauth_sessions_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthSession],
        Depends(depends_permissions(OAuthSession, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[OAuthSessionRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = OAuthSessionService(session, perm_filter)
    try:
        sessions = await service.get_many(ids)
    finally:
        await service.aclose()
    return BatchReadResult(
        items=[service.to_read(s) if s is not None else None for s in sessions],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[OAuthSessionRead],
)
async def write_oauth_sessions_batch(
    payload: OAuthSessionBatchWriteRequest,
    session: SessionDep,
    update_filter: Annotated[
        SearchFilter[OAuthSession] | None,
        Depends(depends_permissions_or_none(OAuthSession, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[OAuthSession] | None,
        Depends(depends_permissions_or_none(OAuthSession, Action.DELETE)),
    ],
) -> BatchWriteResult[OAuthSessionRead]:
    service = OAuthSessionService(session)
    perm_filters = {
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except OAuthSessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
    return BatchWriteResult(
        items=[service.to_read(s) if s is not None else None for s in results],
    )


@router.get("/{session_id}", response_model=OAuthSessionRead)
async def get_oauth_session(
    session_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthSession],
        Depends(depends_permissions(OAuthSession, Action.READ)),
    ],
) -> OAuthSessionRead:
    service = OAuthSessionService(session, perm_filter)
    try:
        oauth_session = await service.get(session_id)
    except OAuthSessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    finally:
        await service.aclose()
    return service.to_read(oauth_session)


@router.patch("/{session_id}", response_model=OAuthSessionRead)
async def update_oauth_session(
    session_id: uuid.UUID,
    payload: OAuthSessionUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthSession],
        Depends(depends_permissions(OAuthSession, Action.UPDATE)),
    ],
) -> OAuthSessionRead:
    service = OAuthSessionService(session, perm_filter)
    try:
        oauth_session = await service.update(session_id, payload)
    except OAuthSessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
    return service.to_read(oauth_session)


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_oauth_session(
    session_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthSession],
        Depends(depends_permissions(OAuthSession, Action.DELETE)),
    ],
) -> None:
    service = OAuthSessionService(session, perm_filter)
    try:
        await service.delete(session_id)
    except OAuthSessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
