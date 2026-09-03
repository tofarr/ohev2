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
