"""Unit tests for the security module (permission policy types).

Pure in-memory tests exercise the :class:`Permission` discriminated-union
round-trip and the ``to_search_filter`` reductions for each implementation.
The :class:`PermissionType` JSONB column type is exercised DB-backed via the
``Role`` model tests in ``test_role_models``.
"""

from __future__ import annotations

import uuid

import pytest

from openhands.ev2.security.security_models import (
    ACL_MAX_IDS,
    AclFilter,
    ACLPermission,
    Action,
    Denied,
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


class TestACLPermissionReduction:
    """ACLPermission reduces to the correct SearchFilter per action."""

    def test_granted_action_admits_listed_ids(self) -> None:
        ids = [uuid.uuid4(), uuid.uuid4()]
        policy = ACLPermission(permitted_ids={Action.READ: ids})
        f = policy.to_search_filter(_USER_ID, Action.READ)
        assert isinstance(f, AclFilter)
        assert set(f.ids) == set(ids)

    def test_missing_action_denies(self) -> None:
        policy = ACLPermission(permitted_ids={Action.READ: [uuid.uuid4()]})
        for action in (Action.CREATE, Action.UPDATE, Action.DELETE, Action.USE):
            assert isinstance(policy.to_search_filter(_USER_ID, action), NoneSearchFilter)

    def test_empty_list_denies(self) -> None:
        policy = ACLPermission(permitted_ids={Action.READ: []})
        assert isinstance(policy.to_search_filter(_USER_ID, Action.READ), NoneSearchFilter)

    def test_principal_independent(self) -> None:
        """ACL grants are carried by the role, not tied to the principal."""
        ids = [uuid.uuid4()]
        policy = ACLPermission(permitted_ids={Action.READ: ids})
        f_anon = policy.to_search_filter(None, Action.READ)
        f_user = policy.to_search_filter(_USER_ID, Action.READ)
        assert isinstance(f_anon, AclFilter)
        assert isinstance(f_user, AclFilter)
        assert set(f_anon.ids) == set(f_user.ids) == set(ids)

    def test_matches_in_memory(self) -> None:
        id_in = uuid.uuid4()
        id_out = uuid.uuid4()
        policy = ACLPermission(permitted_ids={Action.READ: [id_in]})
        f = policy.to_search_filter(_USER_ID, Action.READ)
        item_in = type("Item", (), {"id": id_in})()
        item_out = type("Item", (), {"id": id_out})()
        assert f.matches(item_in)
        assert not f.matches(item_out)


class TestACLPermissionRoundTrip:
    """Serialized ACLPermission deserializes back to the concrete subclass."""

    def test_round_trip(self) -> None:
        ids = [uuid.uuid4(), uuid.uuid4()]
        policy = ACLPermission(permitted_ids={Action.READ: ids, Action.UPDATE: [ids[0]]})
        data = policy.model_dump(mode="json")
        restored = Permission.model_validate(data)
        assert isinstance(restored, ACLPermission)
        assert restored.kind == "ACLPermission"
        assert set(restored.permitted_ids[Action.READ]) == set(ids)
        assert restored.permitted_ids[Action.UPDATE] == [ids[0]]

    def test_kind_computed_field(self) -> None:
        assert ACLPermission(permitted_ids={}).kind == "ACLPermission"

    def test_empty_permitted_ids_round_trip(self) -> None:
        policy = ACLPermission(permitted_ids={})
        data = policy.model_dump(mode="json")
        restored = Permission.model_validate(data)
        assert isinstance(restored, ACLPermission)
        assert restored.permitted_ids == {}


class TestACLPermissionIdCap:
    """The per-action id cap forces large grants to custom permission classes."""

    def test_at_cap_allowed(self) -> None:
        ids = [uuid.uuid4() for _ in range(ACL_MAX_IDS)]
        policy = ACLPermission(permitted_ids={Action.READ: ids})
        assert len(policy.permitted_ids[Action.READ]) == ACL_MAX_IDS

    def test_over_cap_rejected(self) -> None:
        ids = [uuid.uuid4() for _ in range(ACL_MAX_IDS + 1)]
        with pytest.raises(ValueError, match="at most"):
            ACLPermission(permitted_ids={Action.READ: ids})

    def test_cap_is_per_action(self) -> None:
        ids = [uuid.uuid4() for _ in range(ACL_MAX_IDS)]
        # Two actions each at the cap is fine.
        policy = ACLPermission(permitted_ids={Action.READ: ids, Action.UPDATE: list(ids)})
        assert len(policy.permitted_ids[Action.READ]) == ACL_MAX_IDS
        assert len(policy.permitted_ids[Action.UPDATE]) == ACL_MAX_IDS
