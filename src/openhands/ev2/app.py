"""Minimal FastAPI application entrypoint.

Routes are intentionally stubs at this stage; the REST consistency rules in
AGENTS.md §3 must be applied as resources are added.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI

from openhands.ev2 import __version__
from openhands.ev2.api_key.api_key_router import router as api_key_router
from openhands.ev2.auth.auth_discovery import router as auth_discovery_router
from openhands.ev2.auth.auth_router import clients_router as auth_clients_router
from openhands.ev2.auth.auth_router import router as auth_router
from openhands.ev2.config import get_config
from openhands.ev2.cors.cors_middleware import CorsMiddleware
from openhands.ev2.cors.cors_router import router as cors_router
from openhands.ev2.db import get_session_factory
from openhands.ev2.feature_flag.feature_flag_router import (
    overrides_router as feature_flag_role_assignment_router,
)
from openhands.ev2.feature_flag.feature_flag_router import (
    router as feature_flag_router,
)
from openhands.ev2.feature_flag.feature_flag_router import (
    user_overrides_router as feature_flag_user_assignment_router,
)
from openhands.ev2.group.group_router import members_router as group_members_router
from openhands.ev2.group.group_router import router as group_router
from openhands.ev2.llm.llm_router import router as llm_router
from openhands.ev2.mcp_server_config.mcp_proxy_router import (
    router as mcp_proxy_router,
)
from openhands.ev2.mcp_server_config.mcp_server_config_router import (
    router as mcp_server_config_router,
)
from openhands.ev2.role.role_router import router as role_router
from openhands.ev2.role.user_role_router import router as user_role_router
from openhands.ev2.sandbox.sandbox_config_router import router as sandbox_config_router
from openhands.ev2.sandbox.sandbox_router import router as sandbox_sandbox_router
from openhands.ev2.sandbox.sandbox_snapshot_router import router as sandbox_snapshot_router
from openhands.ev2.sandbox.sandbox_template_router import router as sandbox_template_router
from openhands.ev2.secret.secret_router import router as secret_router
from openhands.ev2.secret.secret_value_router import router as secret_value_router
from openhands.ev2.user.user_router import router as user_router

# Sentinel IdP URL that selects the built-in dev identity provider
# (auth.dev_router). When idp.url == this value the dev IdP router is mounted so
# the system works out of the box without configuring an external IdP.
_DEV_IDP_URL = "/auth/dev"

logger = logging.getLogger(__name__)

# Type for sweep callables: return an optional info message (None = nothing happened).
SweepFn = Callable[[], Awaitable[str | None]]


async def _background_sweep(interval: float, task_name: str, sweep: SweepFn) -> None:
    """Run *sweep* every *interval* seconds until cancelled.

    Failures are logged and the loop continues; the loop is cancelled on
    shutdown.  When *interval* is 0 the loop is not started and the work must
    be driven by an external scheduler — see README.
    """
    while True:
        await asyncio.sleep(interval)
        try:
            message = await sweep()
        except Exception:
            logger.exception("%s sweep failed; will retry next interval", task_name)
        else:
            if message:
                logger.info("%s: %s", task_name, message)


async def _sweep_expired_tokens() -> str | None:
    """Delete expired IdP refresh tokens and return a summary message."""
    from openhands.ev2.auth.auth_service import AuthService

    factory = get_session_factory()
    async with factory() as session:
        service = AuthService(session)
        try:
            deleted = await service.delete_expired_tokens()
        finally:
            await service.aclose()
    return f"deleted {deleted} expired IdP refresh tokens" if deleted else None


async def _sweep_llm_partitions() -> str | None:
    """Manage daily ``llm_usage`` partitions and return a summary message."""
    from openhands.ev2.llm.llm_usage_service import LlmUsageService

    cfg = get_config()
    factory = get_session_factory()
    async with factory() as session:
        service = LlmUsageService(session)
        created, dropped = await service.ensure_partitions(
            preallocate_days=cfg.llm.usage.preallocate_days,
            retention_days=cfg.llm.usage.retention_days,
        )
    return _partition_message(created, dropped)


async def _sweep_llm_aggregate() -> str | None:
    """Roll ``llm_aggregated_usage`` from ``llm_usage`` and return a summary message."""
    from openhands.ev2.llm.llm_usage_service import LlmUsageService

    factory = get_session_factory()
    async with factory() as session:
        service = LlmUsageService(session)
        count = await service.aggregate_behind_now(lag_minutes=1)
    return f"rolled {count} per-user minute rows" if count else None


async def _sweep_mcp_partitions() -> str | None:
    """Manage daily ``mcp_usage`` partitions and return a summary message."""
    from openhands.ev2.mcp_server_config.mcp_usage_service import McpUsageService

    cfg = get_config()
    factory = get_session_factory()
    async with factory() as session:
        service = McpUsageService(session)
        created, dropped = await service.ensure_partitions(
            preallocate_days=cfg.mcp.usage.preallocate_days,
            retention_days=cfg.mcp.usage.retention_days,
        )
    return _partition_message(created, dropped)


async def _sweep_mcp_aggregate() -> str | None:
    """Roll ``mcp_aggregated_usage`` from ``mcp_usage`` and return a summary message."""
    from openhands.ev2.mcp_server_config.mcp_usage_service import McpUsageService

    factory = get_session_factory()
    async with factory() as session:
        service = McpUsageService(session)
        count = await service.aggregate_behind_now(lag_minutes=1)
    return f"rolled {count} per-user minute rows" if count else None


async def _sweep_acl_prune() -> str | None:
    """Remove orphaned item ids from AclPermission policies."""
    from openhands.ev2.security.acl_prune_service import prune_orphaned_acl_ids

    factory = get_session_factory()
    async with factory() as session:
        count = await prune_orphaned_acl_ids(session)
    return f"pruned {count} roles with orphaned ACL ids" if count else None


def _partition_message(created: list[str], dropped: list[str]) -> str | None:
    """Build a log message from partition sweep results."""
    parts: list[str] = []
    if created:
        parts.append(f"created {len(created)} partitions")
    if dropped:
        parts.append(f"dropped {len(dropped)} partitions")
    return "; ".join(parts) if parts else None


async def _cleanup_loop() -> None:
    """Background sweep that deletes expired IdP refresh tokens."""
    cfg = get_config()
    interval = cfg.cleanup_interval
    if interval <= 0:
        return
    await _background_sweep(interval, "auth cleanup", _sweep_expired_tokens)


async def _llm_usage_partition_loop() -> None:
    """Background sweep that manages daily ``llm_usage`` partitions."""
    cfg = get_config()
    interval = cfg.llm.usage.partition_interval
    if interval <= 0:
        return
    await _background_sweep(interval, "llm_usage partition manager", _sweep_llm_partitions)


async def _llm_usage_aggregate_loop() -> None:
    """Background sweep that rolls ``llm_aggregated_usage`` from ``llm_usage``."""
    cfg = get_config()
    interval = cfg.llm.usage.aggregate_interval
    if interval <= 0:
        return
    await _background_sweep(interval, "llm_usage aggregator", _sweep_llm_aggregate)


async def _mcp_usage_partition_loop() -> None:
    """Background sweep that manages daily ``mcp_usage`` partitions."""
    cfg = get_config()
    interval = cfg.mcp.usage.partition_interval
    if interval <= 0:
        return
    await _background_sweep(interval, "mcp_usage partition manager", _sweep_mcp_partitions)


async def _mcp_usage_aggregate_loop() -> None:
    """Background sweep that rolls ``mcp_aggregated_usage`` from ``mcp_usage``."""
    cfg = get_config()
    interval = cfg.mcp.usage.aggregate_interval
    if interval <= 0:
        return
    await _background_sweep(interval, "mcp_usage aggregator", _sweep_mcp_aggregate)


async def _acl_prune_loop() -> None:
    """Background sweep that prunes orphaned ids from AclPermission policies."""
    cfg = get_config()
    interval = cfg.acl_prune_interval
    if interval <= 0:
        return
    await _background_sweep(interval, "acl prune", _sweep_acl_prune)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage the background tasks across the app lifetime.

    Also constructs the configured :class:`SandboxService` (an async context
    manager) and exposes it on ``app.state.sandbox_service`` so the sandbox
    routers can reach it.
    """
    tasks = [
        asyncio.create_task(_cleanup_loop(), name="auth-cleanup"),
        asyncio.create_task(_llm_usage_partition_loop(), name="llm-usage-partition"),
        asyncio.create_task(_llm_usage_aggregate_loop(), name="llm-usage-aggregate"),
        asyncio.create_task(_mcp_usage_partition_loop(), name="mcp-usage-partition"),
        asyncio.create_task(_mcp_usage_aggregate_loop(), name="mcp-usage-aggregate"),
        asyncio.create_task(_acl_prune_loop(), name="acl-prune"),
    ]
    try:
        sandbox_service = get_config().get_sandbox_service()
        async with sandbox_service:
            app.state.sandbox_service = sandbox_service
            yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task


# OpenAPI tag groups, in display order. Each tag carries a short description so
# the rendered docs explain what the group covers. Assignment/permission
# sub-resources are folded into the tag of the entity they relate to
# (AGENTS.md §3), so the group list is the canonical entity surface.
_OPENAPI_TAGS: list[dict[str, str]] = [
    {"name": "auth", "description": "Authentication, sessions, and token minting/refresh."},
    {"name": "auth-clients", "description": "First-party OAuth client registrations."},
    {
        "name": "oidc-discovery",
        "description": "OIDC/OAuth authorization-server discovery metadata.",
    },
    {"name": "auth-dev", "description": "Built-in dev identity provider (non-production only)."},
    {"name": "users", "description": "User accounts and profiles."},
    {"name": "roles", "description": "Roles and their permission configuration."},
    {
        "name": "user-roles",
        "description": "Role-to-user assignments (link table governed by its own permission).",
    },
    {"name": "api-keys", "description": "API keys for programmatic access."},
    {"name": "cors-origins", "description": "CORS allow-list origins."},
    {"name": "secrets", "description": "Secrets and role/user secret-access grants."},
    {
        "name": "secret-values",
        "description": "Read-only reveal of decrypted secret values (requires both read access and value-reveal permission).",
    },
    {"name": "feature-flags", "description": "Feature flags and their role/user assignments."},
    {"name": "llm", "description": "LLM models and usage tracking."},
    {"name": "mcp-server-configs", "description": "MCP server configs and role access grants."},
    {
        "name": "sandbox-templates",
        "description": "DB-backed sandbox templates (mutable, provider-neutral) and role access grants.",
    },
    {
        "name": "sandbox-configs",
        "description": "Durable sandbox intent (DB-backed source of truth) and role access grants.",
    },
    {
        "name": "sandbox-sandboxes",
        "description": "Live sandbox sandboxes (provider-backed reconciler) and role access grants.",
    },
    {
        "name": "sandbox-snapshots",
        "description": "DB-backed sandbox snapshots - create from a sandbox or import a file.",
    },
]


def create_app() -> FastAPI:
    app = FastAPI(
        title="OpenHands Enterprise",
        version=__version__,
        description="OpenHands Enterprise v2",
        openapi_tags=_OPENAPI_TAGS,
        lifespan=lifespan,
    )

    # Global, DB-backed CORS allow-list. Reads the cached allowed-origin set on
    # each cross-origin request; the list is managed via /cors-origins.
    app.add_middleware(CorsMiddleware)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth_router)
    app.include_router(auth_clients_router)
    app.include_router(auth_discovery_router)
    app.include_router(api_key_router)
    app.include_router(cors_router)
    app.include_router(feature_flag_router)
    app.include_router(feature_flag_role_assignment_router)
    app.include_router(feature_flag_user_assignment_router)
    app.include_router(group_router)
    app.include_router(group_members_router)
    app.include_router(llm_router)
    app.include_router(mcp_server_config_router)
    app.include_router(mcp_proxy_router)
    app.include_router(role_router)
    app.include_router(user_role_router)
    app.include_router(secret_router)
    app.include_router(secret_value_router)
    app.include_router(sandbox_template_router)
    app.include_router(sandbox_config_router)
    app.include_router(sandbox_sandbox_router)
    app.include_router(sandbox_snapshot_router)
    app.include_router(user_router)
    # Mount the built-in dev identity provider when the configured IdP URL is the
    # dev sentinel. Read the env var directly (rather than get_config()) so app
    # construction does not require the full AppConfig env to be present at
    # import time; the dev router handlers resolve the full config per request.
    if os.environ.get("OHE_IDP_URL", _DEV_IDP_URL) == _DEV_IDP_URL:
        from openhands.ev2.auth.dev_router import router as dev_router

        app.include_router(dev_router)
    return app


app = create_app()
