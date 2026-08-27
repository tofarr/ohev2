"""Cross-cutting response schemas shared across resources.

Per AGENTS.md §3 every response is a documented Pydantic schema; these generic
shapes live in `util/` because they are not specific to a single feature.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CountResult(BaseModel):
    """Generic count response for `GET /{resource}/count` endpoints.

    Returns the number of rows the principal is allowed to see, optionally
    narrowed by the same search filter the collection endpoint accepts.
    """

    count: int = Field(ge=0, description="Number of matching rows in scope.")
