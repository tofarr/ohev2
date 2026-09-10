"""Unit tests for the security module (permission policy types).

Pure in-memory tests exercise the :class:`Permission` discriminated-union
round-trip and the ``to_search_filter`` reductions for each implementation.
The :class:`PermissionType` JSONB column type is exercised DB-backed via the
``Role`` model tests in ``test_role_models``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from openhands.ev2.security.security_models import (
    ACL_MAX_IDS,
    AclPermission,
    Action,
    CreatorMatchFilter,
    CreatorPermission,
    Denied,
    GroupPermission,
    Permission,
    PermissionType,
    Permitted,
    ReadOnly,
)
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter

_USER_ID = uuid.uuid4()


class TestPermissionReduction:
    """Each implementation reduces to the correct SearchFilter per action."""

    def test_permitted_always_all(self) -> None:
        policy = Permitted()
        for action in Action:
            assert isinstance(policy.to_search_filter(_USER_ID, action), AllSearchFilter)

    def test_denied_always_none(self) -> None:
        policy = Denied()
        for action in Action:
            assert isinstance(policy.to_search_filter(_USER_ID, action), NoneSearchFilter)

    @pytest.mark.parametrize("action", [Action.READ, Action.SEARCH])
    def test_readonly_allows_read_and_search(self, action: Action) -> None:
        assert isinstance(ReadOnly().to_search_filter(_USER_ID, action), AllSearchFilter)

    @pytest.mark.parametrize("action", [Action.CREATE, Action.UPDATE, Action.DELETE, Action.USE])
    def test_readonly_denies_mutations(self, action: Action) -> None:
        assert isinstance(ReadOnly().to_search_filter(_USER_ID, action), NoneSearchFilter)


class TestPermissionRoundTrip:
    """Serialized policies deserialize back to the concrete subclass."""

    @pytest.mark.parametrize(
        ("policy", "cls"),
        [
            (Permitted(), Permitted),
            (Denied(), Denied),
            (ReadOnly(), ReadOnly),
        ],
    )
    def test_round_trip(self, policy: Permission, cls: type[Permission]) -> None:
        data = policy.model_dump(mode="json")
        restored = Permission.model_validate(data)
        assert isinstance(restored, cls)
        assert restored.kind == cls.__name__

    def test_kind_computed_field(self) -> None:
        assert Permitted().kind == "Permitted"
        assert Denied().kind == "Denied"
        assert ReadOnly().kind == "ReadOnly"


class TestPermissionAbstract:
    def test_base_to_search_filter_not_implemented(self) -> None:
        # The base Permission raises NotImplementedError; concrete subclasses
        # override it. Validating without a kind should fail to resolve a subclass.
        with pytest.raises(ValueError, match="kind"):
            Permission.model_validate({})


class TestPermissionTypeBindProcessor:
    """The JSONB column type serializes Permission models for the driver."""

    def test_none_returns_none(self) -> None:
        assert PermissionType().process_bind_param(None, None) is None

    def test_dict_returned_as_is(self) -> None:
        d = {"kind": "Permitted"}
        assert PermissionType().process_bind_param(d, None) == d

    def test_permission_model_dumped_to_json_dict(self) -> None:
        result = PermissionType().process_bind_param(Permitted(), None)
        assert result == {"kind": "Permitted"}


class TestAclPermissionReduction:
    """AclPermission reduces to the correct SearchFilter per action."""

    def test_create_uses_on_create(self) -> None:
        policy = AclPermission(item_ids=[uuid.uuid4()], on_create=Permitted())
        assert isinstance(policy.to_search_filter(_USER_ID, Action.CREATE), AllSearchFilter)

    def test_create_denied_by_default(self) -> None:
        policy = AclPermission(item_ids=[uuid.uuid4()], on_match=Permitted())
        assert isinstance(policy.to_search_filter(_USER_ID, Action.CREATE), NoneSearchFilter)

    def test_on_match_permitted_admits_only_listed_ids(self) -> None:
        id_in = uuid.uuid4()
        id_out = uuid.uuid4()
        policy = AclPermission(item_ids=[id_in], on_match=Permitted())
        f = policy.to_search_filter(_USER_ID, Action.READ)
        assert f.matches(type("Item", (), {"id": id_in})())
        assert not f.matches(type("Item", (), {"id": id_out})())

    def test_on_match_readonly_admits_read_denies_update_for_listed(self) -> None:
        id_in = uuid.uuid4()
        policy = AclPermission(item_ids=[id_in], on_match=ReadOnly())
        read_f = policy.to_search_filter(_USER_ID, Action.READ)
        update_f = policy.to_search_filter(_USER_ID, Action.UPDATE)
        assert read_f.matches(type("Item", (), {"id": id_in})())
        assert not update_f.matches(type("Item", (), {"id": id_in})())

    def test_on_mismatch_governs_out_of_list_items(self) -> None:
        id_in = uuid.uuid4()
        id_out = uuid.uuid4()
        policy = AclPermission(item_ids=[id_in], on_match=Permitted(), on_mismatch=ReadOnly())
        read_f = policy.to_search_filter(_USER_ID, Action.READ)
        update_f = policy.to_search_filter(_USER_ID, Action.UPDATE)
        # READ: both in-list (Permitted) and out-of-list (ReadOnly) admit → all.
        assert read_f.matches(type("Item", (), {"id": id_in})())
        assert read_f.matches(type("Item", (), {"id": id_out})())
        # UPDATE: in-list admitted (Permitted), out-of-list denied (ReadOnly).
        assert update_f.matches(type("Item", (), {"id": id_in})())
        assert not update_f.matches(type("Item", (), {"id": id_out})())

    def test_empty_item_ids_falls_to_on_mismatch(self) -> None:
        policy = AclPermission(item_ids=[], on_mismatch=ReadOnly())
        assert isinstance(policy.to_search_filter(_USER_ID, Action.READ), AllSearchFilter)
        assert isinstance(policy.to_search_filter(_USER_ID, Action.UPDATE), NoneSearchFilter)

    def test_principal_independent(self) -> None:
        """ACL grants are carried by the role, not tied to the principal."""
        ids = [uuid.uuid4()]
        policy = AclPermission(item_ids=ids, on_match=Permitted())
        f_anon = policy.to_search_filter(None, Action.READ)
        f_user = policy.to_search_filter(_USER_ID, Action.READ)
        assert f_anon.matches(type("Item", (), {"id": ids[0]})())
        assert f_user.matches(type("Item", (), {"id": ids[0]})())

    def test_sql_condition_scopes_in_list_items(self) -> None:
        id_in = uuid.uuid4()
        policy = AclPermission(item_ids=[id_in], on_match=Permitted())
        f = policy.to_search_filter(_USER_ID, Action.UPDATE)
        # Permitted → All for in-list; Denied (default on_mismatch) → None for out.
        # So the SQL admits only id IN (item_ids).
        cond = f.sql_condition()
        assert cond is not None


class TestAclPermissionRoundTrip:
    """Serialized AclPermission deserializes back to the concrete subclass."""

    def test_round_trip_preserves_nested_outcomes(self) -> None:
        ids = [uuid.uuid4(), uuid.uuid4()]
        policy = AclPermission(
            item_ids=ids, on_match=Permitted(), on_mismatch=ReadOnly(), on_create=Permitted()
        )
        data = policy.model_dump(mode="json")
        restored = Permission.model_validate(data)
        assert isinstance(restored, AclPermission)
        assert restored.kind == "AclPermission"
        assert set(restored.item_ids) == set(ids)
        assert isinstance(restored.on_match, Permitted)
        assert isinstance(restored.on_mismatch, ReadOnly)
        assert isinstance(restored.on_create, Permitted)

    def test_kind_computed_field(self) -> None:
        assert AclPermission().kind == "AclPermission"

    def test_defaults_round_trip(self) -> None:
        policy = AclPermission()
        data = policy.model_dump(mode="json")
        restored = Permission.model_validate(data)
        assert isinstance(restored, AclPermission)
        assert restored.item_ids == []
        assert isinstance(restored.on_match, Denied)
        assert isinstance(restored.on_mismatch, Denied)
        assert isinstance(restored.on_create, Denied)


class TestAclPermissionIdCap:
    """The item-id cap forces large grants to custom permission classes."""

    def test_at_cap_allowed(self) -> None:
        ids = [uuid.uuid4() for _ in range(ACL_MAX_IDS)]
        policy = AclPermission(item_ids=ids)
        assert len(policy.item_ids) == ACL_MAX_IDS

    def test_over_cap_rejected(self) -> None:
        ids = [uuid.uuid4() for _ in range(ACL_MAX_IDS + 1)]
        with pytest.raises(ValueError, match="at most"):
            AclPermission(item_ids=ids)


class TestCreatorPermissionReduction:
    """CreatorPermission scopes items by creator_id == user_id."""

    def test_create_uses_on_create(self) -> None:
        policy = CreatorPermission(on_create=Permitted())
        assert isinstance(policy.to_search_filter(_USER_ID, Action.CREATE), AllSearchFilter)

    def test_create_denied_by_default(self) -> None:
        policy = CreatorPermission(on_match=Permitted())
        assert isinstance(policy.to_search_filter(_USER_ID, Action.CREATE), NoneSearchFilter)

    def test_own_items_get_on_match_others_get_on_mismatch(self) -> None:
        other_id = uuid.uuid4()
        policy = CreatorPermission(on_match=Permitted(), on_mismatch=ReadOnly())
        read_f = policy.to_search_filter(_USER_ID, Action.READ)
        update_f = policy.to_search_filter(_USER_ID, Action.UPDATE)
        own = type("Item", (), {"id": uuid.uuid4(), "creator_id": _USER_ID})()
        other = type("Item", (), {"id": uuid.uuid4(), "creator_id": other_id})()
        # READ: own (Permitted) + other (ReadOnly) → all readable.
        assert read_f.matches(own)
        assert read_f.matches(other)
        # UPDATE: own admitted, other denied.
        assert update_f.matches(own)
        assert not update_f.matches(other)

    def test_anonymous_falls_to_on_mismatch(self) -> None:
        policy = CreatorPermission(on_match=Permitted(), on_mismatch=ReadOnly())
        assert isinstance(policy.to_search_filter(None, Action.READ), AllSearchFilter)
        assert isinstance(policy.to_search_filter(None, Action.UPDATE), NoneSearchFilter)

    def test_null_creator_id_falls_to_on_mismatch(self) -> None:
        # An unowned item (NULL creator_id) is not the principal's, so it must
        # fall to on_mismatch (not vanish from both branches). This is the
        # NULL-safe complement (IS DISTINCT FROM) guard.
        policy = CreatorPermission(on_match=Permitted(), on_mismatch=ReadOnly())
        read_f = policy.to_search_filter(_USER_ID, Action.READ)
        unowned = type("Item", (), {"id": uuid.uuid4(), "creator_id": None})()
        assert read_f.matches(unowned)  # ReadOnly → All for READ


class TestCreatorPermissionRoundTrip:
    def test_round_trip_preserves_outcomes(self) -> None:
        policy = CreatorPermission(on_match=Permitted(), on_mismatch=ReadOnly())
        restored = Permission.model_validate(policy.model_dump(mode="json"))
        assert isinstance(restored, CreatorPermission)
        assert restored.kind == "CreatorPermission"
        assert isinstance(restored.on_match, Permitted)
        assert isinstance(restored.on_mismatch, ReadOnly)


class TestGroupPermissionReduction:
    """GroupPermission picks its outcome by principal group membership."""

    def test_member_gets_on_match(self) -> None:
        gid = uuid.uuid4()
        policy = GroupPermission(group_ids=[gid], on_match=Permitted())
        f = policy.to_search_filter(_USER_ID, Action.READ, frozenset({gid}))
        assert isinstance(f, AllSearchFilter)

    def test_non_member_gets_on_mismatch(self) -> None:
        gid = uuid.uuid4()
        policy = GroupPermission(group_ids=[gid], on_match=Permitted(), on_mismatch=Denied())
        f = policy.to_search_filter(_USER_ID, Action.READ, frozenset())
        assert isinstance(f, NoneSearchFilter)

    def test_create_uses_on_create(self) -> None:
        gid = uuid.uuid4()
        policy = GroupPermission(group_ids=[gid], on_create=Permitted())
        f = policy.to_search_filter(_USER_ID, Action.CREATE, frozenset({gid}))
        assert isinstance(f, AllSearchFilter)

    def test_membership_in_one_of_many_groups(self) -> None:
        g1, g2 = uuid.uuid4(), uuid.uuid4()
        policy = GroupPermission(group_ids=[g1, g2], on_match=Permitted())
        f = policy.to_search_filter(_USER_ID, Action.READ, frozenset({g2}))
        assert isinstance(f, AllSearchFilter)

    def test_no_membership_denied_by_default(self) -> None:
        gid = uuid.uuid4()
        policy = GroupPermission(group_ids=[gid])  # all outcomes default Denied
        for action in (Action.READ, Action.UPDATE, Action.CREATE):
            assert isinstance(
                policy.to_search_filter(_USER_ID, action, frozenset()), NoneSearchFilter
            )


class TestGroupPermissionRoundTrip:
    def test_round_trip_preserves_group_ids_and_outcomes(self) -> None:
        g = uuid.uuid4()
        policy = GroupPermission(group_ids=[g], on_match=Permitted())
        restored = Permission.model_validate(policy.model_dump(mode="json"))
        assert isinstance(restored, GroupPermission)
        assert restored.kind == "GroupPermission"
        assert restored.group_ids == [g]
        assert isinstance(restored.on_match, Permitted)


class TestCreatorMatchFilter:
    def test_matches_own_item(self) -> None:
        f = CreatorMatchFilter[Any](creator_id=_USER_ID)
        own = type("Item", (), {"creator_id": _USER_ID})()
        other = type("Item", (), {"creator_id": uuid.uuid4()})()
        assert f.matches(own)
        assert not f.matches(other)

    def test_null_creator_does_not_match(self) -> None:
        f = CreatorMatchFilter[Any](creator_id=_USER_ID)
        unowned = type("Item", (), {"creator_id": None})()
        assert not f.matches(unowned)
