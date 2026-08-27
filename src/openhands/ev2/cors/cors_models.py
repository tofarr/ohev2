"""ORM model for the global CORS allow-list feature.

A single table ``allowed_origins`` holds the serialized browser origins
(``scheme://host[:port]``, per RFC 6454) permitted to make cross-origin
requests to this API. The list is **global** (not linked to an OAuth client):
it is a deployment-level concern, governed by the ``cors_origin`` permission
resource type. The CORS middleware reads this list (cached) to set
``Access-Control-Allow-Origin`` on responses and to answer preflight
``OPTIONS`` requests.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import String, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base


class AllowedOrigin(Base):
    """A globally-permitted browser origin for CORS.

    The ``origin`` is a serialized origin (scheme://host[:port], RFC 6454),
    matched case-sensitively against the request ``Origin`` header. Uniqueness
    is enforced so the same origin cannot be registered twice.
    """

    __tablename__ = "allowed_origins"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    origin: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )
