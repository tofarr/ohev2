"""Tests for the auth dependencies (federated auth + role-based authorization).

These tests exercise the dependency functions directly with a real DB session
and request state, verifying:

* ``depends_access_token`` resolves a bearer token and caches it on the request.
* ``depends_user_id`` reuses the cached token.
* ``depends_roles`` yields the principal's roles and caches small sets.
* ``depends_permissions`` reduces role policies to a SearchFilter and denies
  (403) when no policy applies.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from openhands.ev2.auth.auth_dependencies import (
    _ACCESS_TOKEN_KEY,
    _ROLES_CACHE_THRESHOLD,
    _ROLES_KEY,
    depends_access_token,
    depends_permissions,
    depends_roles,
    depends_user_id,
    register_resource_policy,
)
from openhands.ev2.auth.auth_models import ApiKey, AuthToken, TokenType
from openhands.ev2.auth.auth_tokens import TokenService
from openhands.ev2.config import get_config
from openhands.ev2.role.role_models import Role, UserRole
from openhands.ev2.security.security_models import (
    Action,
    Denied,
    Permitted,
    ReadOnly,
)
from openhands.ev2.user.user_models import User
from openhands.ev2.util.auth_token import create_auth_token
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter


def _make_request() -> Request:
    """A minimal Starlette Request with a writable state."""
    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "cookies": {},
    }
    return Request(scope)


def _auth_token(user_id: uuid.UUID) -> AuthToken:
    return AuthToken(
        id=uuid.uuid4(),
        user_id=user_id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        enabled=True,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        token_type=TokenType.ACCESS_TOKEN,
    )


@pytest.fixture
def other_user_id() -> uuid.UUID:
    return uuid.UUID("99999999-9999-9999-9999-999999999999")


async def _seed_user(session, user_id: uuid.UUID, username: str = "role-user") -> None:
    """Insert a user row (User.id is init=False)."""
    from sqlalchemy import text

    await session.execute(
        text(
            "INSERT INTO users (id, email, username, enabled) "
            "VALUES (:id, :email, :username, true) "
            "ON CONFLICT (id) DO NOTHING"
        ),
        {"id": user_id, "email": f"{username}@example.com", "username": username},
    )
    await session.flush()


async def _seed_idp_rows(session, user_id: uuid.UUID) -> None:
    """Persist a federated IdP refresh + access row so minting can sync to it."""
    from datetime import UTC, datetime, timedelta

    from openhands.ev2.auth.auth_models import IdpAccessToken, IdpRefreshToken
    from openhands.ev2.encryption.encryption_service import get_encryption_service

    enc = get_encryption_service()
    refresh_row = IdpRefreshToken(
        user_id=user_id,
        refresh_token=enc.encrypt_value("idp-refresh"),
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    session.add(refresh_row)
    await session.flush()
    session.add(
        IdpAccessToken(
            refresh_token_id=refresh_row.id,
            access_token=enc.encrypt_value("idp-access"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    await session.flush()


async def _assign_role(
    session,
    *,
    user_id: uuid.UUID,
    name: str,
    **permissions: Any,
) -> Role:
    role = Role(name=name, **permissions)
    session.add(role)
    await session.flush()
    session.add(UserRole(role_id=role.id, user_id=user_id))
    await session.flush()
    return role


# ---------------------------------------------------------------------- #
# depends_access_token / depends_user_id.
# ---------------------------------------------------------------------- #


async def test_depends_access_token_anonymous_caches_sentinel(session, user_id):
    """No bearer + no cookie resolves to None and caches the anonymous sentinel."""
    request = _make_request()

    token = await depends_access_token(
        request, _NoopResponse(), session, x_api_key=None, bearer=None
    )

    assert token is None
    # The anonymous result is cached so a second resolution does no work.
    assert getattr(request.state, _ACCESS_TOKEN_KEY) is not None


async def test_depends_access_token_bearer_resolves_and_caches(session, user_id):
    """A valid bearer access token resolves to an AuthToken and is cached."""
    await _seed_user(session, user_id, "bearer-user")
    await _seed_idp_rows(session, user_id)
    service = TokenService(session)
    access = await service.create_access_token(user_id)
    request = _make_request()

    from fastapi.security import HTTPAuthorizationCredentials

    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access)

    token = await depends_access_token(
        request, _NoopResponse(), session, x_api_key=None, bearer=bearer
    )

    assert token is not None
    assert token.user_id == user_id
    assert token.enabled is True
    # Cached on the request.
    assert getattr(request.state, _ACCESS_TOKEN_KEY) is token


async def test_depends_access_token_invalid_bearer_raises_401(session, user_id):
    """A present-but-invalid bearer token raises 401."""
    request = _make_request()
    from fastapi.security import HTTPAuthorizationCredentials

    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials="not-a-jwe")

    with pytest.raises(HTTPException) as exc:
        await depends_access_token(request, _NoopResponse(), session, x_api_key=None, bearer=bearer)

    assert exc.value.status_code == 401


async def test_depends_access_token_cookie_re_mints_sliding(session, user_id):
    """A legacy cookie token is re-minted (sliding session) and resolves."""
    await _seed_user(session, user_id, "cookie-user")
    cookie_token = create_auth_token(user_id)
    request = _make_request()
    request.cookies["ohesession"] = cookie_token  # type: ignore[index]

    response = _NoopResponse()
    token = await depends_access_token(request, response, session, x_api_key=None, bearer=None)

    assert token is not None
    assert token.user_id == user_id
    # The sliding re-mint sets a fresh cookie on the response.
    assert response.cookies.get("ohesession") is not None


async def test_depends_access_token_reuses_cache(session, user_id):
    """A second call in the same request returns the cached token without re-decrypting."""
    request = _make_request()
    cached = _auth_token(user_id)
    setattr(request.state, _ACCESS_TOKEN_KEY, cached)

    token = await depends_access_token(
        request, _NoopResponse(), session, x_api_key=None, bearer=None
    )

    assert token is cached


async def test_depends_user_id_returns_none_for_anonymous(session, user_id):
    assert await depends_user_id(None) is None


async def test_depends_user_id_returns_token_user_id(session, user_id):
    token = _auth_token(user_id)
    assert await depends_user_id(token) == user_id


# ---------------------------------------------------------------------- #
# depends_roles.
# ---------------------------------------------------------------------- #


async def test_depends_roles_anonymous_yields_nothing(session, user_id):
    request = _make_request()
    roles = [r async for r in depends_roles(request, session, None)]
    assert roles == []


async def test_depends_roles_yields_assigned_roles(session, user_id):
    """Roles assigned via user_roles are yielded in order."""
    await _seed_user(session, user_id, "roles-user")
    await _assign_role(session, user_id=user_id, name="admin", user_permission=Permitted())
    await _assign_role(session, user_id=user_id, name="viewer", user_permission=ReadOnly())

    request = _make_request()
    token = _auth_token(user_id)

    roles = [r async for r in depends_roles(request, session, token)]

    assert {r.name for r in roles} == {"admin", "viewer"}


async def test_depends_roles_caches_small_set_on_request(session, user_id):
    """Fewer than the threshold roles are cached on request.state."""
    await _seed_user(session, user_id, "cache-user")
    await _assign_role(session, user_id=user_id, name="r1", user_permission=Permitted())

    request = _make_request()
    token = _auth_token(user_id)

    roles = [r async for r in depends_roles(request, session, token)]

    cached = getattr(request.state, _ROLES_KEY)
    assert cached == roles
    assert len(cached) == 1


async def test_depends_roles_serves_from_cache_on_second_call(session, user_id):
    """A second iteration reads from the request cache, not the DB."""
    await _seed_user(session, user_id, "cache2-user")
    role = await _assign_role(
        session, user_id=user_id, name="cached-role", user_permission=Permitted()
    )

    request = _make_request()
    setattr(request.state, _ROLES_KEY, [role])
    token = _auth_token(user_id)

    roles = [r async for r in depends_roles(request, session, token)]

    assert roles == [role]


# ---------------------------------------------------------------------- #
# depends_permissions.
# ---------------------------------------------------------------------- #


async def test_depends_permissions_permitted_returns_all_filter(session, user_id):
    """A Permitted policy grants an AllSearchFilter (unrestricted)."""
    await _seed_user(session, user_id, "perm-user")
    await _assign_role(session, user_id=user_id, name="admin", user_permission=Permitted())

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(User, Action.SEARCH)
    filt = await guard(request, session, token)

    assert isinstance(filt, AllSearchFilter)


async def test_depends_permissions_read_only_denies_update(session, user_id):
    """A ReadOnly policy grants read/search but denies update (403)."""
    await _seed_user(session, user_id, "ro-user")
    await _assign_role(session, user_id=user_id, name="viewer", user_permission=ReadOnly())

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(User, Action.UPDATE)
    with pytest.raises(HTTPException) as exc:
        await guard(request, session, token)

    assert exc.value.status_code == 403


async def test_depends_permissions_denied_policy_raises_403(session, user_id):
    """A Denied policy yields a NoneSearchFilter → 403."""
    await _seed_user(session, user_id, "denied-user")
    await _assign_role(session, user_id=user_id, name="blocked", user_permission=Denied())

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(User, Action.SEARCH)
    with pytest.raises(HTTPException) as exc:
        await guard(request, session, token)

    assert exc.value.status_code == 403


async def test_depends_permissions_no_roles_raises_403(session, user_id):
    """A principal with no roles is denied (no policy applied)."""
    await _seed_user(session, user_id, "noroles-user")

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(User, Action.SEARCH)
    with pytest.raises(HTTPException) as exc:
        await guard(request, session, token)

    assert exc.value.status_code == 403


async def test_depends_permissions_anonymous_denied_by_default(session, user_id):
    """An anonymous principal (no token) with no anonymous-granting role is denied."""
    request = _make_request()

    guard = depends_permissions(User, Action.SEARCH)
    with pytest.raises(HTTPException) as exc:
        await guard(request, session, None)

    assert exc.value.status_code == 403


async def test_depends_permissions_combines_roles_with_or(session, user_id):
    """Multiple roles' filters are ORed: a Permitted role overrides a Denied one."""
    await _seed_user(session, user_id, "combo-user")
    await _assign_role(session, user_id=user_id, name="denied", user_permission=Denied())
    await _assign_role(session, user_id=user_id, name="permitted", user_permission=Permitted())

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(User, Action.SEARCH)
    filt = await guard(request, session, token)

    # Or of [NoneSearchFilter, AllSearchFilter] matches everything: the Or
    # contains an All child (None SQL condition) so the disjunction is
    # unrestricted. The combined filter grants access (no 403).
    assert not isinstance(filt, NoneSearchFilter)
    # The effective filter imposes no SQL restriction (an All child makes the
    # whole Or match everything).
    assert filt.sql_condition() is None


async def test_depends_permissions_unregistered_resource_denies(session, user_id):
    """A model with no registered policy attribute is denied (403)."""

    class Unregistered:
        pass

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(Unregistered, Action.SEARCH)
    with pytest.raises(HTTPException) as exc:
        await guard(request, session, token)

    assert exc.value.status_code == 403


async def test_register_resource_policy_adds_mapping(session, user_id):
    """register_resource_policy maps a model to a Role Permission column consulted
    by the policy lookup."""
    await _seed_user(session, user_id, "reg-user")

    class Widget:
        pass

    # Register a model against an existing Role column. The role has no grant
    # on that column (None), so the policy resolves to deny (403), confirming
    # the registered column is consulted.
    register_resource_policy(Widget, "user_permission")
    await _assign_role(session, user_id=user_id, name="widget-admin", role_permission=Permitted())

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(Widget, Action.SEARCH)
    with pytest.raises(HTTPException) as exc:
        await guard(request, session, token)

    assert exc.value.status_code == 403


async def test_depends_access_token_x_api_key_resolves_and_caches(session, user_id):
    """A valid opaque X-API-Key resolves to an AuthToken and is cached."""
    await _seed_user(session, user_id, "apikey-user")
    service = TokenService(session)
    plaintext, _row = await service.create_api_key(user_id, name="ci")
    request = _make_request()

    token = await depends_access_token(
        request, _NoopResponse(), session, x_api_key=plaintext, bearer=None
    )

    assert token is not None
    assert token.user_id == user_id
    assert token.token_type is TokenType.API_KEY
    assert token.enabled is True
    assert getattr(request.state, _ACCESS_TOKEN_KEY) is token


async def test_depends_access_token_invalid_x_api_key_raises_401(session, user_id):
    """A present-but-unrecognized X-API-Key raises 401 (no JWE fallback)."""
    request = _make_request()

    with pytest.raises(HTTPException) as exc:
        await depends_access_token(
            request, _NoopResponse(), session, x_api_key="not-an-api-key", bearer=None
        )

    assert exc.value.status_code == 401


async def test_depends_access_token_x_api_key_takes_priority_over_bearer(session, user_id):
    """When both X-API-Key and Bearer are present, X-API-Key wins."""
    await _seed_user(session, user_id, "prio-user")
    await _seed_idp_rows(session, user_id)
    service = TokenService(session)
    plaintext, _row = await service.create_api_key(user_id)
    # A valid bearer that would resolve to a different token type; ignored.
    bearer = await service.create_access_token(user_id)

    request = _make_request()
    from fastapi.security import HTTPAuthorizationCredentials

    token = await depends_access_token(
        request,
        _NoopResponse(),
        session,
        x_api_key=plaintext,
        bearer=HTTPAuthorizationCredentials(scheme="Bearer", credentials=bearer),
    )

    assert token is not None
    assert token.user_id == user_id
    assert token.token_type is TokenType.API_KEY


async def test_depends_permissions_uses_entity_column(session, user_id):
    """A per-entity Permission column on the role authorizes the matching resource."""
    await _seed_user(session, user_id, "policies-user")
    await _assign_role(
        session,
        user_id=user_id,
        name="policies-admin",
        user_permission=Permitted(),
    )

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(User, Action.SEARCH)
    filt = await guard(request, session, token)

    assert isinstance(filt, AllSearchFilter)


async def test_depends_permissions_entity_column_for_arbitrary_resource(session, user_id):
    """A per-entity column for a non-user resource (e.g. api_key) authorizes."""
    await _seed_user(session, user_id, "apikey-admin-user")
    await _assign_role(
        session,
        user_id=user_id,
        name="apikey-admin",
        api_key_permission=Permitted(),
    )

    request = _make_request()
    token = _auth_token(user_id)

    guard = depends_permissions(ApiKey, Action.SEARCH)
    filt = await guard(request, session, token)

    assert isinstance(filt, AllSearchFilter)


# ---------------------------------------------------------------------- #
# Roles threshold (streaming path).
# ---------------------------------------------------------------------- #


async def test_depends_roles_above_threshold_does_not_cache(session, user_id):
    """When roles >= threshold, the set is not cached on request.state."""
    await _seed_user(session, user_id, "many-user")
    # Create exactly threshold roles so the streaming path is taken.
    for i in range(_ROLES_CACHE_THRESHOLD):
        await _assign_role(session, user_id=user_id, name=f"role-{i}", user_permission=Permitted())

    request = _make_request()
    token = _auth_token(user_id)

    roles = [r async for r in depends_roles(request, session, token)]

    assert len(roles) == _ROLES_CACHE_THRESHOLD
    # Not cached: the streaming path leaves _ROLES_KEY unset.
    from openhands.ev2.auth.auth_dependencies import _ROLES_MISSING

    assert getattr(request.state, _ROLES_KEY, _ROLES_MISSING) is _ROLES_MISSING


# ---------------------------------------------------------------------- #
# Helpers.
# ---------------------------------------------------------------------- #


class _NoopResponse:
    """A stand-in Response that records set_cookie calls without a real Response."""

    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}

    def set_cookie(self, key: str, value: str, **kwargs: Any) -> None:
        self.cookies[key] = value


# ---------------------------------------------------------------------- #
# sync_api_keys — API keys gated by a live federated session.
# ---------------------------------------------------------------------- #


async def test_api_key_sync_rejects_when_no_idp_session(
    session, user_id, monkeypatch: pytest.MonkeyPatch
):
    """With sync_api_keys on, an API key whose user has no IdP row is rejected."""
    get_config.cache_clear()
    monkeypatch.setenv("OHE_IDP_SYNC_API_KEYS", "true")
    await _seed_user(session, user_id, "sync-noidp-user")
    service = TokenService(session)
    plaintext, _row = await service.create_api_key(user_id)

    request = _make_request()
    with pytest.raises(HTTPException) as exc:
        await depends_access_token(
            request, _NoopResponse(), session, x_api_key=plaintext, bearer=None
        )
    assert exc.value.status_code == 401


async def test_api_key_sync_accepts_when_idp_session_live(
    session, user_id, monkeypatch: pytest.MonkeyPatch
):
    """With sync_api_keys on, a live (non-imminent) IdP session admits the key."""
    get_config.cache_clear()
    monkeypatch.setenv("OHE_IDP_SYNC_API_KEYS", "true")
    await _seed_user(session, user_id, "sync-live-user")
    await _seed_idp_rows(session, user_id)
    service = TokenService(session)
    plaintext, _row = await service.create_api_key(user_id)

    request = _make_request()
    token = await depends_access_token(
        request, _NoopResponse(), session, x_api_key=plaintext, bearer=None
    )
    assert token is not None
    assert token.user_id == user_id
    assert token.token_type is TokenType.API_KEY


async def test_api_key_sync_off_allows_no_idp_session(
    session, user_id, monkeypatch: pytest.MonkeyPatch
):
    """With sync_api_keys off (default), no IdP row is required for an API key."""
    get_config.cache_clear()
    monkeypatch.delenv("OHE_IDP_SYNC_API_KEYS", raising=False)
    await _seed_user(session, user_id, "nosync-user")
    service = TokenService(session)
    plaintext, _row = await service.create_api_key(user_id)

    request = _make_request()
    token = await depends_access_token(
        request, _NoopResponse(), session, x_api_key=plaintext, bearer=None
    )
    assert token is not None
    assert token.user_id == user_id
