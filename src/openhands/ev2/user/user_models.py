"""ORM models for the user feature."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import String, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base


class User(Base):
    """A user of the openhands.ev2 system."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(
        default=True,
        server_default="true",
    )
    password: Mapped[str | None] = mapped_column(
        String(2048),
        default=None,
        nullable=True,
    )
    # Stable subject from the federated identity provider (auth2). Nullable: a
    # user created before auth2 or managed locally has no IdP link. Indexed so
    # the callback's lookup-by-subject is O(log n).
    idp_user_id: Mapped[str | None] = mapped_column(
        String(255),
        default=None,
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
