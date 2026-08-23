"""Compact string grammar for round-tripping a Permission to/from a string.

Grammar (URI-path inspired, matches the plural-noun REST resources)::

    <action>[.<attr>...]:<resource_type>[:<selector>]

- ``action`` ∈ {create, read, write, delete, use, *}  (* = wildcard / all actions)
- ``.attr`` suffix, comma-separated, scopes to attributes; absent = all attributes
- ``resource_type`` is a plural lowercase noun (e.g. ``users``, ``access-tokens``)
- ``selector``:
    - omitted              -> ALL instances of the type
    - ``id=<uuid|str>``    -> a single entity
    - ``tag=<tag>``        -> all entities tagged <tag>

A leading principal segment is *not* part of the permission string itself; the
principal (user id) is carried by the enclosing Permission row / JWT subject.
Examples::

    read:users
    *:users
    write:conversations:id=123
    read:sandboxes:tag=prod
    read.email,name:users
    use:access-tokens

These functions are pure and fully unit-tested. They do not touch the database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ohev.permission.models.permission import Action, Permission, SelectorKind

_ACTION_VALUES = {a.value for a in Action}
_SEPARATOR = ":"
_ATTR_SEPARATOR = "."
_ATTR_LIST_SEPARATOR = ","
_SELECTOR_KV = re.compile(r"^(id|tag)=(.+)$")


class PermissionParseError(ValueError):
    """Raised when a permission string is malformed."""


@dataclass(frozen=True, slots=True)
class ParsedPermission:
    """Decoded components of a permission string.

    `custom_action` is set only when `action` is `Action.USE` and the source
    string carried a custom verb via ``use(<verb>)``. Otherwise the action's own
    value is the verb.
    """

    action: Action
    custom_action: str | None
    resource_type: str
    selector_kind: SelectorKind
    selector_value: str | None
    attributes: list[str] | None


def parse(permission_str: str) -> ParsedPermission:
    """Parse a permission string into its components.

    Raises:
        PermissionParseError: if the string does not conform to the grammar.
    """
    text = permission_str.strip()
    if not text:
        raise PermissionParseError("empty permission string")

    # Split action[.attrs] : resource_type [: selector]
    parts = text.split(_SEPARATOR)
    if len(parts) < 2 or len(parts) > 3:
        raise PermissionParseError(
            f"expected '<action>[.attrs]:<resource>[:<selector>]', got {text!r}"
        )

    action_segment = parts[0]
    resource_type = parts[1]
    selector_segment = parts[2] if len(parts) == 3 else None

    if not resource_type:
        raise PermissionParseError("resource_type is empty")

    action, attributes, custom_action = _parse_action_segment(action_segment)
    # A present-but-empty selector segment (e.g. "read:users:") is malformed.
    if len(parts) == 3 and selector_segment == "":
        raise PermissionParseError(
            "selector segment is empty; expected 'id=<value>' or 'tag=<value>'"
        )
    selector_kind, selector_value = _parse_selector(selector_segment)

    return ParsedPermission(
        action=action,
        custom_action=custom_action,
        resource_type=resource_type,
        selector_kind=selector_kind,
        selector_value=selector_value,
        attributes=attributes,
    )


def _parse_action_segment(
    segment: str,
) -> tuple[Action, list[str] | None, str | None]:
    """Split '<action>[.<attr>,<attr>]' into (Action, attributes|None, custom|None).

    A known CRUD/wildcard token maps to its enum value. Any other lowercase token
    is treated as a custom (non-CRUD) action verb, stored with `Action.USE` as a
    marker and the literal verb in `custom_action`.
    """
    if not segment:
        raise PermissionParseError("action segment is empty")
    bits = segment.split(_ATTR_SEPARATOR)
    action_token = bits[0]
    if action_token in _ACTION_VALUES:
        action = Action(action_token)
        custom_action: str | None = None
    elif action_token.isidentifier():
        # Non-CRUD verb (e.g. "deploy", "rotate"). Stored under the USE marker.
        action = Action.USE
        custom_action = action_token
    else:
        raise PermissionParseError(
            f"unknown action {action_token!r}; expected one of "
            f"{sorted(_ACTION_VALUES)} or a lowercase custom verb"
        )
    # Attributes are comma-separated within the first dot-segment after the action.
    attr_bits: list[str] = []
    if len(bits) > 1:
        attr_bits = [b for b in bits[1].split(_ATTR_LIST_SEPARATOR) if b]
    attributes = attr_bits or None
    return action, attributes, custom_action


def _parse_selector(
    selector: str | None,
) -> tuple[SelectorKind, str | None]:
    """Map a selector segment to (SelectorKind, value|None)."""
    if selector is None or selector == "":
        return SelectorKind.ALL, None
    match = _SELECTOR_KV.match(selector)
    if match is None:
        raise PermissionParseError(
            f"invalid selector {selector!r}; expected 'id=<value>' or 'tag=<value>'"
        )
    key, value = match.group(1), match.group(2)
    if key == "id":
        return SelectorKind.BY_ID, value
    return SelectorKind.BY_TAG, value


def to_string(permission: Permission) -> str:
    """Serialize a Permission model to its canonical string form."""
    return from_components(
        action=permission.action,
        custom_action=permission.custom_action,
        resource_type=permission.resource_type,
        selector_kind=permission.selector_kind,
        selector_value=permission.selector_value,
        attributes=permission.attributes,
    )


def from_components(
    *,
    action: Action,
    custom_action: str | None,
    resource_type: str,
    selector_kind: SelectorKind,
    selector_value: str | None,
    attributes: list[str] | None,
) -> str:
    """Build a permission string from explicit components."""
    segments: list[str] = []
    action_token = _action_token(action, custom_action)
    if attributes:
        action_token += _ATTR_SEPARATOR + _ATTR_LIST_SEPARATOR.join(attributes)
    segments.append(action_token)
    segments.append(resource_type)
    selector = _selector_segment(selector_kind, selector_value)
    if selector is not None:
        segments.append(selector)
    return _SEPARATOR.join(segments)


def _action_token(action: Action, custom_action: str | None) -> str:
    # A custom non-CRUD verb is serialized as the literal verb itself, so that
    # round-tripping "deploy:sandboxes" yields action=USE, custom_action="deploy".
    if action is Action.USE and custom_action and custom_action != "use":
        return custom_action
    return action.value


def _selector_segment(
    kind: SelectorKind,
    value: str | None,
) -> str | None:
    if kind is SelectorKind.ALL:
        return None
    if value is None:
        raise PermissionParseError(f"selector_kind {kind.value!r} requires a value")
    key = "id" if kind is SelectorKind.BY_ID else "tag"
    return f"{key}={value}"


def parse_many(joined: str) -> list[ParsedPermission]:
    """Parse a whitespace/comma-separated list of permission strings.

    Useful for JWT claim lists or config values.
    """
    tokens = [t.strip() for t in joined.replace(",", " ").split() if t.strip()]
    return [parse(t) for t in tokens]
