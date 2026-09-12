"""Optional S3-backed :class:`EventBodyStore`.

Selected via ``event.body_store_class``; the constructor argument is the S3
bucket name (``OHE_EVENT_BODY_DIR`` carries the bucket for this backend). Keys
follow the same derivation convention as the filesystem store
(``<event_date>/<event_id[:2]>/<event_id>.json``), so a bucket and a directory
are interchangeable backends.

``boto3`` is an optional dependency (the ``s3`` extra); it is imported lazily
at construction time so the module itself always imports cleanly.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import date
from typing import TYPE_CHECKING, cast

from openhands.ev2.event.event_store import EventBodyStore

if TYPE_CHECKING:  # boto3 is optional; type-checked only when installed
    import boto3  # type: ignore[import-untyped]


class S3EventBodyStore(EventBodyStore):
    """S3-backed store; *bucket* names the S3 bucket holding event bodies."""

    def __init__(self, bucket: str) -> None:
        import boto3 as boto3_module

        self._bucket = bucket
        self._client: boto3.client = boto3_module.client("s3")

    def store_body(self, event_id: uuid.UUID, event_date: date, payload: bytes) -> None:
        self._client.put_object(
            Bucket=self._bucket,
            Key=self.object_key(event_id, event_date),
            Body=payload,
        )

    def load_body(self, event_id: uuid.UUID, event_date: date) -> bytes | None:
        try:
            response = self._client.get_object(
                Bucket=self._bucket,
                Key=self.object_key(event_id, event_date),
            )
        except self._client.exceptions.NoSuchKey:
            return None
        return cast(bytes, response["Body"].read())

    def delete_day(self, event_date: date) -> int:
        # Prefix delete — aligned with the partition drop on the same day.
        prefix = f"{event_date.isoformat()}/"
        paginator = self._client.get_paginator("list_objects_v2")
        removed = 0
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if not keys:
                continue
            self._client.delete_objects(Bucket=self._bucket, Delete={"Objects": keys})
            removed += len(keys)
        return removed

    def iter_envelopes(self) -> Iterator[tuple[uuid.UUID, date, bytes]]:
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket):
            for obj in page.get("Contents", []):
                event_id, event_date = _parse_key(obj["Key"])
                if event_id is None or event_date is None:
                    continue
                downloaded = self._client.get_object(Bucket=self._bucket, Key=obj["Key"])
                yield event_id, event_date, cast(bytes, downloaded["Body"].read())


def _parse_key(key: str) -> tuple[uuid.UUID | None, date | None]:
    """Parse a ``<date>/<prefix>/<id>.json`` key back into its components."""
    date_part, _, rest = key.partition("/")
    try:
        event_date = date.fromisoformat(date_part)
        event_id = uuid.UUID(rest.split("/", 1)[-1].removesuffix(".json"))
    except ValueError:
        return None, None
    return event_id, event_date
