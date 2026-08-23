"""Unit tests for the PermissionEvaluator (pure, no database)."""

from __future__ import annotations

import uuid

from ohev.permission.models.permission import Action, Permission, SelectorKind
from ohev.permission.services import PermissionEvaluator


def _perm(
    *,
    action: Action = Action.READ,
    resource_type: str = "users",
    selector_kind: SelectorKind = SelectorKind.ALL,
    selector_value: str | None = None,
    attributes: list[str] | None = None,
    custom_action: str | None = None,
) -> Permission:
    return Permission(
        user_id=uuid.uuid4(),
        action=action,
        resource_type=resource_type,
        selector_kind=selector_kind,
        selector_value=selector_value,
        attributes=attributes,
        custom_action=custom_action,
    )


class TestActionMatching:
    def test_exact_action_match(self) -> None:
        ev = PermissionEvaluator([_perm(action=Action.READ)])
        assert ev.is_allowed(action="read", resource_type="users")

    def test_wrong_action_denied(self) -> None:
        ev = PermissionEvaluator([_perm(action=Action.READ)])
        assert not ev.is_allowed(action="write", resource_type="users")

    def test_wildcard_action_covers_all(self) -> None:
        ev = PermissionEvaluator([_perm(action=Action.ALL)])
        assert ev.is_allowed(action="read", resource_type="users")
        assert ev.is_allowed(action="write", resource_type="users")
        assert ev.is_allowed(action="delete", resource_type="users")

    def test_custom_action_matches_verb(self) -> None:
        ev = PermissionEvaluator(
            [_perm(action=Action.USE, custom_action="deploy", resource_type="sandboxes")]
        )
        assert ev.is_allowed(action="deploy", resource_type="sandboxes")
        assert not ev.is_allowed(action="read", resource_type="sandboxes")

    def test_wrong_resource_type_denied(self) -> None:
        ev = PermissionEvaluator([_perm(resource_type="users")])
        assert not ev.is_allowed(action="read", resource_type="sandboxes")


class TestSelectorMatching:
    def test_all_selector_covers_any_entity(self) -> None:
        ev = PermissionEvaluator([_perm()])
        assert ev.is_allowed(action="read", resource_type="users", resource_id="any-id")

    def test_by_id_matches_specific_entity(self) -> None:
        ev = PermissionEvaluator([_perm(selector_kind=SelectorKind.BY_ID, selector_value="123")])
        assert ev.is_allowed(action="read", resource_type="users", resource_id="123")

    def test_by_id_denies_other_entity(self) -> None:
        ev = PermissionEvaluator([_perm(selector_kind=SelectorKind.BY_ID, selector_value="123")])
        assert not ev.is_allowed(action="read", resource_type="users", resource_id="456")

    def test_by_tag_matches_entity_with_tag(self) -> None:
        ev = PermissionEvaluator([_perm(selector_kind=SelectorKind.BY_TAG, selector_value="prod")])
        assert ev.is_allowed(
            action="read", resource_type="users", resource_tags=("prod", "staging")
        )

    def test_by_tag_denies_entity_without_tag(self) -> None:
        ev = PermissionEvaluator([_perm(selector_kind=SelectorKind.BY_TAG, selector_value="prod")])
        assert not ev.is_allowed(action="read", resource_type="users", resource_tags=("staging",))

    def test_by_tag_denies_no_tags(self) -> None:
        ev = PermissionEvaluator([_perm(selector_kind=SelectorKind.BY_TAG, selector_value="prod")])
        assert not ev.is_allowed(action="read", resource_type="users", resource_tags=())


class TestAttributeMatching:
    def test_no_attribute_restriction_covers_all(self) -> None:
        ev = PermissionEvaluator([_perm()])
        assert ev.is_allowed(action="read", resource_type="users", attributes=("email", "name"))

    def test_attribute_subset_covers_requested(self) -> None:
        ev = PermissionEvaluator([_perm(attributes=["email", "name"])])
        assert ev.is_allowed(action="read", resource_type="users", attributes=("email",))

    def test_attribute_subset_denies_unlisted(self) -> None:
        ev = PermissionEvaluator([_perm(attributes=["email"])])
        assert not ev.is_allowed(
            action="read", resource_type="users", attributes=("email", "password")
        )

    def test_empty_requested_attributes_allowed(self) -> None:
        ev = PermissionEvaluator([_perm(attributes=["email"])])
        assert ev.is_allowed(action="read", resource_type="users", attributes=())


class TestCombined:
    def test_empty_permissions_denies_everything(self) -> None:
        ev = PermissionEvaluator([])
        assert not ev.is_allowed(action="read", resource_type="users")

    def test_multiple_permissions_any_match(self) -> None:
        ev = PermissionEvaluator(
            [
                _perm(action=Action.READ, resource_type="users"),
                _perm(action=Action.WRITE, resource_type="sandboxes"),
            ]
        )
        assert ev.is_allowed(action="read", resource_type="users")
        assert ev.is_allowed(action="write", resource_type="sandboxes")
        assert not ev.is_allowed(action="delete", resource_type="users")

    def test_full_combination(self) -> None:
        ev = PermissionEvaluator(
            [
                _perm(
                    action=Action.ALL,
                    resource_type="sandboxes",
                    selector_kind=SelectorKind.BY_TAG,
                    selector_value="prod",
                    attributes=["name", "status"],
                )
            ]
        )
        assert ev.is_allowed(
            action="read",
            resource_type="sandboxes",
            resource_tags=("prod",),
            attributes=("name",),
        )
        assert not ev.is_allowed(
            action="read",
            resource_type="sandboxes",
            resource_tags=("dev",),
            attributes=("name",),
        )
