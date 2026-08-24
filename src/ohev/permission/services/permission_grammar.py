"""Compact string grammar for round-tripping a Permission to/from a string.

Grammar (URI-path inspired, matches the plural-noun REST resources)::

    <action>[.<attr>...]:<type>

- ``action`` ∈ {create, read, update, delete, search, use, all}  (all = wildcard / all actions)
- ``.attr`` suffix, comma-separated, scopes to attributes; absent = all attributes
- ``type`` is a resource type noun (e.g. ``user``, ``permission``)

A leading principal segment is *not* part of the permission string itself; the
principal (user id) is carried by the enclosing Permission row. Examples::

    read:user
    all:permission
    read.email,name:user
    use:permission

These functions are pure and fully unit-tested. They do not touch the database.
"""

from __future__ import annotations

from dataclasses import dataclass

from ohev.permission.models.permission import Action, Permission, ResourceType

_ACTION_VALUES = {a.value for a in Action}
_SEPARATOR = ":"
_ATTR_SEPARATOR = "."
_ATTR_LIST_SEPARATOR = ","
_TYPE_VALUES = {t.value for t in ResourceType}


class PermissionParseError(ValueError):
    """Raised when a permission string is malformed."""


@dataclass(frozen=True, slots=True)
class ParsedPermission:
    """Decoded components of a permission string."""

    action: Action
    resource_type: ResourceType
    attributes: list[str] | None


def parse(permission_str: str) -> ParsedPermission:
    """Parse a permission string into its components.

    Raises:
        PermissionParseError: if the string does not conform to the grammar.
    """
    text = permission_str.strip()
    if not text:
        raise PermissionParseError("empty permission string")

    # Split action[.attrs] : type
    parts = text.split(_SEPARATOR)
    if len(parts) != 2:
        raise PermissionParseError(f"expected '<action>[.attrs]:<type>', got {text!r}")

    action_segment = parts[0]
    type_segment = parts[1]

    if not type_segment:
        raise PermissionParseError("type is empty")

    action, attributes = _parse_action_segment(action_segment)
    resource_type = _parse_type(type_segment)

    return ParsedPermission(
        action=action,
        resource_type=resource_type,
        attributes=attributes,
    )


def _parse_action_segment(segment: str) -> tuple[Action, list[str] | None]:
    """Split '<action>[.<attr>,<attr>]' into (Action, attributes|None)."""
    if not segment:
        raise PermissionParseError("action segment is empty")
    bits = segment.split(_ATTR_SEPARATOR)
    action_token = bits[0]
    if action_token not in _ACTION_VALUES:
        raise PermissionParseError(
            f"unknown action {action_token!r}; expected one of {sorted(_ACTION_VALUES)}"
        )
    action = Action(action_token)
    # Attributes are comma-separated within the first dot-segment after the action.
    attr_bits: list[str] = []
    if len(bits) > 1:
        attr_bits = [b for b in bits[1].split(_ATTR_LIST_SEPARATOR) if b]
    attributes = attr_bits or None
    return action, attributes


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
        resource_type=permission.type,
        attributes=permission.attributes,
    )


def from_components(
    *,
    action: Action,
    resource_type: ResourceType,
    attributes: list[str] | None,
) -> str:
    """Build a permission string from explicit components."""
    action_token = action.value
    if attributes:
        action_token += _ATTR_SEPARATOR + _ATTR_LIST_SEPARATOR.join(attributes)
    return _SEPARATOR.join([action_token, resource_type.value])


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
