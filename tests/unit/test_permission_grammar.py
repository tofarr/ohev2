"""Unit tests for the permission string grammar.

These are pure-function tests — no database required.
"""

from __future__ import annotations

import pytest

from ohev.permission.models.permission import Action, Permission, ResourceType
from ohev.permission.services import (
    PermissionParseError,
    from_components,
    is_valid,
    parse,
    parse_many,
    to_string,
)


class TestParseAction:
    def test_read_user(self) -> None:
        p = parse("read:user")
        assert p.action is Action.READ
        assert p.resource_type is ResourceType.USER
        assert p.attributes is None

    def test_wildcard_action(self) -> None:
        p = parse("all:permission")
        assert p.action is Action.ALL

    def test_all_actions(self) -> None:
        for verb, member in [
            ("create", Action.CREATE),
            ("read", Action.READ),
            ("update", Action.UPDATE),
            ("delete", Action.DELETE),
            ("search", Action.SEARCH),
            ("use", Action.USE),
        ]:
            p = parse(f"{verb}:user")
            assert p.action is member

    def test_unknown_action_rejected(self) -> None:
        with pytest.raises(PermissionParseError, match="unknown action"):
            parse("bogus:user")

    def test_non_identifier_action_rejected(self) -> None:
        with pytest.raises(PermissionParseError, match="unknown action"):
            parse("123:user")


class TestParseType:
    def test_user_type(self) -> None:
        p = parse("read:user")
        assert p.resource_type is ResourceType.USER

    def test_permission_type(self) -> None:
        p = parse("read:permission")
        assert p.resource_type is ResourceType.PERMISSION

    def test_unknown_type_rejected(self) -> None:
        with pytest.raises(PermissionParseError, match="unknown resource type"):
            parse("read:sandboxes")


class TestParseAttributes:
    def test_single_attribute(self) -> None:
        p = parse("read.email:user")
        assert p.attributes == ["email"]

    def test_multiple_attributes(self) -> None:
        p = parse("read.email,name:user")
        assert p.attributes == ["email", "name"]

    def test_no_attributes_means_none(self) -> None:
        p = parse("read:user")
        assert p.attributes is None


class TestParseErrors:
    @pytest.mark.parametrize("s", ["", "  ", "read", "read:user:extra", "read:"])
    def test_malformed(self, s: str) -> None:
        with pytest.raises(PermissionParseError):
            parse(s)

    def test_empty_type(self) -> None:
        with pytest.raises(PermissionParseError, match="type is empty"):
            parse("read:")


class TestIsValid:
    def test_valid_permission(self) -> None:
        assert is_valid("read:user")

    def test_invalid_permission(self) -> None:
        assert not is_valid("bogus:user")

    def test_empty_string(self) -> None:
        assert not is_valid("")


class TestRoundTrip:
    @pytest.mark.parametrize(
        "s",
        [
            "read:user",
            "all:permission",
            "create:user",
            "update:permission",
            "delete:user",
            "search:permission",
            "use:user",
            "read.email,name:user",
            "read.email:permission",
        ],
    )
    def test_roundtrip(self, s: str) -> None:
        p = parse(s)
        rebuilt = from_components(
            action=p.action,
            resource_type=p.resource_type,
            attributes=p.attributes,
        )
        assert rebuilt == s

    def test_to_string_from_model(self) -> None:
        import uuid

        perm = Permission(
            user_id=uuid.uuid4(),
            action=Action.READ,
            resource_type=ResourceType.USER,
            attributes=["email"],
        )
        assert to_string(perm) == "read.email:user"

    def test_to_string_all_selector(self) -> None:
        import uuid

        perm = Permission(
            user_id=uuid.uuid4(),
            action=Action.ALL,
            resource_type=ResourceType.PERMISSION,
        )
        assert to_string(perm) == "all:permission"


class TestParseMany:
    def test_whitespace_separated(self) -> None:
        result = parse_many("read:user create:permission")
        assert len(result) == 2
        assert result[0].resource_type is ResourceType.USER
        assert result[1].action is Action.CREATE

    def test_comma_separated(self) -> None:
        result = parse_many("read:user,create:permission")
        assert len(result) == 2

    def test_empty_returns_empty(self) -> None:
        assert parse_many("") == []

    def test_strips_whitespace(self) -> None:
        result = parse_many("  read:user  ")
        assert len(result) == 1
