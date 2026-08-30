"""Service helpers for recording LLM completion usage."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.llm.llm_models import LlmUsage

logger = logging.getLogger(__name__)

_TOKEN_COLUMNS: tuple[str, ...] = (
    "prompt_tokens",
    "completion_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "context_window",
    "per_turn_token",
)


def _dump_metrics(sdk_metrics: Any) -> dict[str, Any]:
    if sdk_metrics is None:
        return {}
    if hasattr(sdk_metrics, "model_dump"):
        dump = sdk_metrics.model_dump(mode="json")
    else:
        dump = dict(sdk_metrics)
    return dump if isinstance(dump, dict) else {}


def _extract_token_usage(metrics_dump: dict[str, Any]) -> dict[str, int]:
    usage = metrics_dump.get("accumulated_token_usage") or {}
    if not isinstance(usage, dict):
        usage = {}
    return {name: int(usage.get(name, 0) or 0) for name in _TOKEN_COLUMNS}


class LlmUsageService:
    """Append raw LLM usage rows after proxied completions."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_usage(
        self,
        *,
        user_id: uuid.UUID,
        provider_connection_id: uuid.UUID,
        llm_id: uuid.UUID | None,
        response_id: str | None,
        model: str,
        sdk_metrics: Any,
    ) -> LlmUsage | None:
        """Append one usage row; return ``None`` if recording fails."""
        metrics_dump = _dump_metrics(sdk_metrics)
        row = LlmUsage(
            user_id=user_id,
            provider_connection_id=provider_connection_id,
            llm_id=llm_id,
            response_id=response_id,
            model=model,
            accumulated_cost=float(metrics_dump.get("accumulated_cost", 0.0) or 0.0),
            metrics=metrics_dump,
            **_extract_token_usage(metrics_dump),
        )
        try:
            self._session.add(row)
            await self._session.flush()
        except Exception:
            await self._session.rollback()
            logger.exception("failed to record LLM usage")
            return None
        return row


__all__ = ["LlmUsageService"]
