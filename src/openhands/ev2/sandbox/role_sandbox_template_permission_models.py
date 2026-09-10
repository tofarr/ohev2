"""ORM model for the role-sandbox-template-permission grant link table.

The ``role_sandbox_template_permissions`` table links a :class:`Role` to a
sandbox template id with independent read/update/delete flags. It is the
governed link table for the sandbox template-grant feature
(``sandbox_template_grant_permission`` on :class:`Role` — AGENTS.md §11.1).

sandbox templates are provider-owned (e.g. Docker images), not rows in a
``sandbox_templates`` table, so ``sandbox_template_id`` is a free UUID with
no foreign key: the grant records an opaque template id string-as-uuid. The
unique ``(role_id, sandbox_template_id)`` pair still holds so a role is
granted a template at most once.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)


class RoleSandboxTemplatePermission(Base):
    """Per-role grant of access to a sandbox template.

    Links a :class:`Role` to a sandbox template id with independent
    read/update/delete flags. The ``(role_id, sandbox_template_id)`` pair is
    unique so a role is granted a template at most once.
    """

    __tablename__ = "role_sandbox_template_permissions"
    __table_args__ = (
        UniqueConstraint(
            "role_id",
            "sandbox_template_id",
            name="uq_role_sandbox_tpl_perm_role_sandbox_tpl",
        ),
        {"comment": "Per-role grants of access to sandbox templates"},
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
    sandbox_template_id: Mapped[uuid.UUID] = mapped_column(
        index=True,
    )
    read_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
    )
    update_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
    )
    delete_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
        onupdate=func.now(),
    )


__all__ = ["RoleSandboxTemplatePermission"]
