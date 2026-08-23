"""Unit tests for the permission string grammar.

These are pure-function tests — no database required.
"""

from __future__ import annotations

import pytest

from ohev.permission.models.permission import Action, Permission, SelectorKind
from ohev.permission.services import (
    PermissionParseError,
    from_components,
    parse,
    parse_many,
    to_string,
)


class TestParseAction:
    def test_read_all_users(self) -> None:
        p = parse("read:users")
        assert p.action is Action.READ
        assert p.resource_type == "users"
        assert p.selector_kind is SelectorKind.ALL
        assert p.selector_value is None
        assert p.attributes is None
        assert p.custom_action is None

    def test_wildcard_action(self) -> None:
        p = parse("*:users")
        assert p.action is Action.ALL

    def test_all_crud_verbs(self) -> None:
        for verb, member in [
            ("create", Action.CREATE),
            ("read", Action.READ),
            ("write", Action.WRITE),
            ("delete", Action.DELETE),
            ("use", Action.USE),
        ]:
            p = parse(f"{verb}:users")
            assert p.action is member

    def test_custom_action_verb(self) -> None:
        p = parse("deploy:sandboxes")
        assert p.action is Action.USE
        assert p.custom_action == "deploy"

    def test_unknown_action_rejected(self) -> None:
        with pytest.raises(PermissionParseError, match="unknown action"):
            parse("123deploy:users")

    def test_non_identifier_action_rejected(self) -> None:
        with pytest.raises(PermissionParseError, match="unknown action"):
            parse("not-valid:users")


class TestParseAttributes:
    def test_single_attribute(self) -> None:
        p = parse("read.email:users")
        assert p.attributes == ["email"]

    def test_multiple_attributes(self) -> None:
        p = parse("read.email,name:users")
        assert p.attributes == ["email", "name"]

    def test_no_attributes_means_none(self) -> None:
        p = parse("read:users")
        assert p.attributes is None


class TestParseSelector:
    def test_by_id(self) -> None:
        p = parse("read:conversations:id=123")
        assert p.selector_kind is SelectorKind.BY_ID
        assert p.selector_value == "123"

    def test_by_id_uuid(self) -> None:
        p = parse("read:users:id=12345678-1234-5678-1234-456789abcdef")
        assert p.selector_kind is SelectorKind.BY_ID
        assert p.selector_value == "12345678-1234-5678-1234-456789abcdef"

    def test_by_tag(self) -> None:
        p = parse("read:sandboxes:tag=prod")
        assert p.selector_kind is SelectorKind.BY_TAG
        assert p.selector_value == "prod"

    def test_omitted_selector_is_all(self) -> None:
        p = parse("read:users")
        assert p.selector_kind is SelectorKind.ALL
        assert p.selector_value is None

    def test_invalid_selector_rejected(self) -> None:
        with pytest.raises(PermissionParseError, match="invalid selector"):
            parse("read:users:bogus")

    def test_invalid_selector_key_rejected(self) -> None:
        with pytest.raises(PermissionParseError, match="invalid selector"):
            parse("read:users:name=foo")


class TestParseErrors:
    @pytest.mark.parametrize(
        "s",
        ["", "  ", "read", "read:users:tag=prod:extra", "read:users:"],
    )
    def test_malformed(self, s: str) -> None:
        with pytest.raises(PermissionParseError):
            parse(s)

    def test_empty_resource_type(self) -> None:
        with pytest.raises(PermissionParseError, match="resource_type is empty"):
            parse("read:")


class TestRoundTrip:
    @pytest.mark.parametrize(
        "s",
        [
            "read:users",
            "*:users",
            "write:conversations:id=123",
            "read:sandboxes:tag=prod",
            "read.email,name:users",
            "use:access-tokens",
            "deploy:sandboxes",
            "read.email:users:id=abc",
        ],
    )
    def test_roundtrip(self, s: str) -> None:
        p = parse(s)
        rebuilt = from_components(
            action=p.action,
            custom_action=p.custom_action,
            resource_type=p.resource_type,
            selector_kind=p.selector_kind,
            selector_value=p.selector_value,
            attributes=p.attributes,
        )
        assert rebuilt == s

    def test_to_string_from_model(self) -> None:
        import uuid

        perm = Permission(
            user_id=uuid.uuid4(),
            action=Action.READ,
            resource_type="users",
            selector_kind=SelectorKind.BY_TAG,
            selector_value="prod",
            attributes=["email"],
        )
        assert to_string(perm) == "read.email:users:tag=prod"

    def test_to_string_all_selector(self) -> None:
        import uuid

        perm = Permission(
            user_id=uuid.uuid4(),
            action=Action.ALL,
            resource_type="users",
        )
        assert to_string(perm) == "*:users"


class TestParseMany:
    def test_whitespace_separated(self) -> None:
        result = parse_many("read:users write:sandboxes:id=1")
        assert len(result) == 2
        assert result[0].resource_type == "users"
        assert result[1].selector_value == "1"

    def test_comma_separated(self) -> None:
        result = parse_many("read:users,write:sandboxes")
        assert len(result) == 2

    def test_empty_returns_empty(self) -> None:
        assert parse_many("") == []

    def test_strips_whitespace(self) -> None:
        result = parse_many("  read:users  ")
        assert len(result) == 1
