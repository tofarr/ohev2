"""ORM models for the role feature.

Holds the two role-related tables:

* :class:`Role` — a named role bundling per-entity :class:`Permission` policies.
  Each governed entity has its own explicit ``Permission`` JSONB column; a
  ``NULL`` column means "deny" for that entity. Adding a new governed entity is
  a column add (and a matching entry in the resource-policy registry in
  ``auth_dependencies``), not a map key. See AGENTS.md §11.
* :class:`UserRole` — the many-to-many link table ``user_roles`` assigning a
  role to a user. A user's effective permissions are the union of the policies
  on every role assigned to them.

The :class:`Permission` policy types and the :class:`PermissionType` JSONB
column type live in ``security_models``; this module imports them rather than
duplicating the discriminated-union machinery.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.db import Base
from openhands.ev2.security.security_models import Permission, PermissionType
from openhands.ev2.user.user_models import User

# The per-entity ``Permission`` column names on :class:`Role`. Each entry is the
# full column name (``<entity>_permission``). Adding a governed entity is a
# three-step change: append the column name here, add the column to :class:`Role`
# (and the initial migration), and register the resource's ORM model against it
# in ``auth_dependencies.register_resource_policy``. See AGENTS.md §11.
ROLE_ENTITY_COLUMNS: tuple[str, ...] = (
    "user_permission",
    "role_permission",
    "user_role_permission",
    "api_key_permission",
    "oauth_client_permission",
    "cors_origin_permission",
    "secret_permission",
    "provider_connection_permission",
    "llm_permission",
    "feature_flag_permission",
    "feature_flag_role_permission",
)


class Role(Base):
    """A named role bundling per-entity permission policies.

    Each governed entity is its own explicit ``Permission`` JSONB column; a
    ``NULL`` column means "deny" for that entity. This is the canonical store:
    a new resource type is governed by adding a column (and registering it in
    ``auth_dependencies``), not by adding a map key.
    """

    __tablename__ = "roles"
    __table_args__ = {"comment": "Named role bundling per-entity permission policies"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    user_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for user resources; null = deny.",
    )
    role_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for role resources; null = deny.",
    )
    user_role_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for user-role assignment resources; null = deny.",
    )
    api_key_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for api_key resources; null = deny.",
    )
    oauth_client_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for oauth_client resources; null = deny.",
    )
    cors_origin_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for cors_origin resources; null = deny.",
    )
    secret_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for secret resources; null = deny.",
    )
    provider_connection_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for provider_connection resources; null = deny.",
    )
    llm_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for llm resources; null = deny.",
    )
    feature_flag_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for feature_flag resources; null = deny.",
    )
    feature_flag_role_permission: Mapped[Permission | None] = mapped_column(
        PermissionType,
        default=None,
        comment="Permission policy for feature_flag_role resources; null = deny.",
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


class UserRole(Base):
    """Assignment of a :class:`Role` to a :class:`User`.

    Many-to-many link table (``user_roles``). A user's effective permissions are
    the union of the policies on every role assigned to them.
    """

    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint("role_id", "user_id", name="uq_user_roles_role_id_user_id"),
        {"comment": "Role-to-user assignments"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"),
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )

    role: Mapped[Role] = relationship(init=False, lazy="selectin")
    user: Mapped[User] = relationship(init=False, lazy="selectin")
