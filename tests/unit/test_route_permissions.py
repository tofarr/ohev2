"""Every route must be protected by an auth/permission dependency (AGENTS.md §9).

Asserts that each registered API route transitively depends on a protecting
dependency from ``auth_dependencies`` (``depends_access_token``,
``depends_user_id``, ``depends_role_ids``, ``depends_permissions``, or
``depends_permissions_or_none``). Routes that are intentionally public or that
authenticate through a bespoke mechanism are listed in
``PERMISSION_DEPENDENCY_OVERRIDES`` and bypass the check.

This complements ``test_openapi.py`` (which checks the OpenAPI *documentation*
surface) by checking the real FastAPI dependency tree, so a route whose handler
forgets ``Depends(depends_permissions(...))`` is caught even when the OpenAPI
spec is not generated.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from fastapi import FastAPI
from fastapi.routing import APIRoute

from openhands.ev2.app import create_app
from openhands.ev2.auth import auth_dependencies

# The module that owns the protecting dependencies. A dependency callable
# qualifies as "protecting" iff it lives in this module and its qualified name
# is one of the authn resolvers or a ``depends_permissions`` factory/closure.
_PROTECTING_MODULE = auth_dependencies.__name__

# Qualname prefixes for the factory-based guards. ``depends_permissions`` and
# ``depends_permissions_or_none`` both start with ``depends_permissions``; their
# returned closures (``_guard`` / ``_resolve``) carry qualnames like
# ``depends_permissions.<locals>._guard``.
_PROTECTING_QUALNAMES: tuple[str, ...] = (
    "depends_access_token",
    "depends_user_id",
    "depends_role_ids",
)
_PROTECTING_PREFIXES: tuple[str, ...] = ("depends_permissions",)

# Routes that intentionally bypass the permission-dependency requirement.
# Each entry is a (METHOD, PATH) tuple matching a registered APIRoute. Add a
# route here only with a comment explaining why the standard auth dependency
# does not apply; the list is audited in review (AGENTS.md §9).
PERMISSION_DEPENDENCY_OVERRIDES: set[tuple[str, str]] = {
    # Liveness probe — unauthenticated by design.
    ("GET", "/health"),
    # OIDC Discovery (RFC 8414) — public metadata document; clients must be
    # able to auto-configure without authenticating.
    ("GET", "/.well-known/openid-configuration"),
    ("GET", "/.well-known/oauth-authorization-server"),
    # OAuth2 authorization-server flow entry points. These mint or revoke
    # credentials: they authenticate via client credentials in the request
    # body (/auth/token, /auth/refresh) or via the session cookie itself
    # (/auth/logout), not via the permission dependency. /auth/authorize and
    # /auth/callback are browser redirects.
    ("GET", "/auth/authorize"),
    ("GET", "/auth/callback"),
    ("POST", "/auth/token"),
    ("POST", "/auth/refresh"),
    ("POST", "/auth/revoke"),
    ("POST", "/auth/logout"),
    # Built-in dev identity provider (mounted when idp.url == "/auth/dev").
    # It is the credential source, so it cannot require an already-issued
    # credential. Not present in production deployments.
    ("GET", "/auth/dev/authorize"),
    ("POST", "/auth/dev/login"),
    ("POST", "/auth/dev/token"),
    ("POST", "/auth/dev/refresh"),
    # OpenAI-compatible completion passthrough (include_in_schema=False). It is
    # authenticated by the stored LLM's provider API key via a custom proxy
    # auth header (_proxy_auth_matches), not the standard permission system.
    ("POST", "/llm/completion/{llm_id}/chat/completions"),
}


def _collect_api_routes(routes: Sequence[object]) -> Iterator[APIRoute]:
    """Yield every APIRoute, unwrapping FastAPI's included-router nesting.

    FastAPI >=0.115 wraps each included router in an ``_IncludedRouter`` that
    exposes the original via ``original_router``; older versions nest plain
    ``APIRouter`` instances with a ``routes`` attribute. Both are unwrapped so
    the leaf ``APIRoute`` objects (which carry the ``dependant`` tree) are
    reached.
    """
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None and hasattr(original, "routes"):
            yield from _collect_api_routes(original.routes)
        elif hasattr(route, "routes") and not isinstance(route, APIRoute):
            yield from _collect_api_routes(route.routes)
        if isinstance(route, APIRoute):
            yield route


def _is_protecting_dep(call: object) -> bool:
    """True iff *call* is a protecting auth/permission dependency."""
    if getattr(call, "__module__", None) != _PROTECTING_MODULE:
        return False
    qualname = getattr(call, "__qualname__", None) or getattr(call, "__name__", None)
    if not isinstance(qualname, str):
        return False
    return qualname in _PROTECTING_QUALNAMES or qualname.startswith(_PROTECTING_PREFIXES)


def _route_depends_on_protection(route: APIRoute) -> bool:
    """True iff *route* transitively depends on a protecting dependency."""
    seen: set[int] = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if id(dep) in seen:
            continue
        seen.add(id(dep))
        if dep.call is not None and _is_protecting_dep(dep.call):
            return True
        stack.extend(dep.dependencies)
    return False


def _registered_routes(app: FastAPI) -> list[APIRoute]:
    """Deduplicated API routes registered on *app*, keyed by (path, methods)."""
    seen: set[tuple[str, frozenset[str]]] = set()
    out: list[APIRoute] = []
    for route in _collect_api_routes(app.routes):
        assert route.methods is not None  # APIRoute always has methods
        methods = frozenset(route.methods - {"HEAD"})
        key = (route.path, methods)
        if key in seen:
            continue
        seen.add(key)
        out.append(route)
    return out


def test_all_routes_are_protected() -> None:
    """Every non-override route must depend on a protecting auth dependency."""
    app = create_app()
    routes = _registered_routes(app)
    assert routes, "no API routes discovered; route collection is broken"

    unprotected: list[str] = []
    for route in routes:
        assert route.methods is not None  # APIRoute always has methods
        methods = route.methods - {"HEAD"}
        for method in methods:
            key = (method, route.path)
            if key in PERMISSION_DEPENDENCY_OVERRIDES:
                continue
            if not _route_depends_on_protection(route):
                unprotected.append(f"{method} {route.path}")
    assert not unprotected, (
        "Routes missing a protecting auth/permission dependency "
        "(add Depends(depends_permissions(...)) or an authn dependency, or, "
        "if intentionally public/special, add the route to "
        "PERMISSION_DEPENDENCY_OVERRIDES with a comment):\n  " + "\n  ".join(sorted(unprotected))
    )


def test_overrides_match_registered_routes() -> None:
    """Every override must correspond to a real route, so the list stays honest."""
    app = create_app()
    registered: set[tuple[str, str]] = set()
    for route in _registered_routes(app):
        assert route.methods is not None  # APIRoute always has methods
        for method in route.methods - {"HEAD"}:
            registered.add((method, route.path))
    stale = PERMISSION_DEPENDENCY_OVERRIDES - registered
    assert not stale, (
        "PERMISSION_DEPENDENCY_OVERRIDES references routes that are not "
        "registered (remove them or correct the path/method):\n  "
        + "\n  ".join(f"{m} {p}" for m, p in sorted(stale))
    )
