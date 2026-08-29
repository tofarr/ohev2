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


class BatchReadResult[T](BaseModel):
    """Generic response for `GET /{resource}/batch?ids=...` endpoints.

    ``items`` is positionally aligned with the requested ``ids`` list: the i-th
    entry is the resource for ``ids[i]`` or ``None`` when that id is missing or
    outside the principal's scope. Duplicates in ``ids`` are preserved (the same
    resource appears at each corresponding position).
    """

    items: list[T | None] = Field(
        description="Resources aligned to the requested ids; null where missing."
    )


class BatchWriteResult[T](BaseModel):
    """Generic response for `POST /{resource}/batch` endpoints.

    ``items`` is positionally aligned with the request's ``operations`` list:
    the i-th entry is the resulting resource ``Read`` for a create/update
    operation or ``None`` for a delete operation. The whole batch is applied in
    a single transaction, so either every entry is present or the request
    failed and no entry is returned.
    """

    items: list[T | None] = Field(
        description="Results aligned to the operations; null for deletes."
    )
