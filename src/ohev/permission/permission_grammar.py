"""Compact string grammar for round-tripping a Permission to/from a string.

Grammar (URI-path inspired, matches the plural-noun REST resources)::

    <action>:<type>

- ``action`` ∈ {create, read, update, delete, search, use, all}  (all = wildcard / all actions)
- ``type`` is a resource type noun (e.g. ``user``, ``permission``)

A leading principal segment is *not* part of the permission string itself; the
principal (user id) is carried by the enclosing Permission row. Examples::

    read:user
    all:permission
    use:permission

These functions are pure and fully unit-tested. They do not touch the database.
"""

from __future__ import annotations

from dataclasses import dataclass

from ohev.permission.permission_models import Action, Permission, ResourceType

_ACTION_VALUES = {a.value for a in Action}
_SEPARATOR = ":"
_TYPE_VALUES = {t.value for t in ResourceType}


class PermissionParseError(ValueError):
    """Raised when a permission string is malformed."""


@dataclass(frozen=True, slots=True)
class ParsedPermission:
    """Decoded components of a permission string."""

    action: Action
    resource_type: ResourceType


def parse(permission_str: str) -> ParsedPermission:
    """Parse a permission string into its components.

    Raises:
        PermissionParseError: if the string does not conform to the grammar.
    """
    text = permission_str.strip()
    if not text:
        raise PermissionParseError("empty permission string")

    # Split action : type
    parts = text.split(_SEPARATOR)
    if len(parts) != 2:
        raise PermissionParseError(f"expected '<action>:<type>', got {text!r}")

    action_segment = parts[0]
    type_segment = parts[1]

    if not type_segment:
        raise PermissionParseError("type is empty")

    action = _parse_action(action_segment)
    resource_type = _parse_type(type_segment)

    return ParsedPermission(
        action=action,
        resource_type=resource_type,
    )


def _parse_action(segment: str) -> Action:
    """Map an action segment to an Action enum value."""
    if not segment:
        raise PermissionParseError("action segment is empty")
    if segment not in _ACTION_VALUES:
        raise PermissionParseError(
            f"unknown action {segment!r}; expected one of {sorted(_ACTION_VALUES)}"
        )
    return Action(segment)


def _parse_type(type_segment: str) -> ResourceType:
    """Map a type segment to a ResourceType enum value."""
    if type_segment in _TYPE_VALUES:
        return ResourceType(type_segment)
    raise PermissionParseError(
        f"unknown resource type {type_segment!r}; expected one of {sorted(_TYPE_VALUES)}"
    )


def to_string(permission: Permission) -> str:
    """Serialize a Permission model to its canonical string form."""
    return from_components(
        action=permission.action,
        resource_type=permission.resource_type,
    )


def from_components(
    *,
    action: Action,
    resource_type: ResourceType,
) -> str:
    """Build a permission string from explicit components."""
    return _SEPARATOR.join([action.value, resource_type.value])


def parse_many(joined: str) -> list[ParsedPermission]:
    """Parse a whitespace/comma-separated list of permission strings.

    Useful for JWT claim lists or config values.
    """
    tokens = [t.strip() for t in joined.replace(",", " ").split() if t.strip()]
    return [parse(t) for t in tokens]


def is_valid(permission_str: str) -> bool:
    """Whether a permission string conforms to the grammar (never raises)."""
    try:
        parse(permission_str)
    except PermissionParseError:
        return False
    return True
