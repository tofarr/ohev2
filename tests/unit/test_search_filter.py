"""Tests for the search filter utilities.

The `matches` path is exercised as pure in-memory logic; `filter_sql` is
exercised both by stringifying the produced `Select` and by executing it
against the embedded PostgreSQL fixture (via the shared `session` fixture),
so the SQL clauses are verified end-to-end.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.user.user_models import User
from openhands.ev2.user.user_schemas import UserCreate, UserSearchFilter
from openhands.ev2.user.user_service import UserService
from openhands.ev2.util.search_filter import (
    ALL,
    NONE,
    AllSearchFilter,
    AndSearchFilter,
    AttributeFilter,
    BaseSearchFilter,
    Condition,
    NoneSearchFilter,
    OrSearchFilter,
    SearchFilter,
    and_filter,
    or_filter,
)


def new_user(email: str, username: str | None = None) -> User:
    """Construct a transient User for in-memory filter tests."""
    return User(email=email, username=username or email.split("@")[0])


class TestAbstractBase:
    def test_search_filter_is_abstract(self) -> None:
        # SearchFilter has abstract methods; it cannot be instantiated directly.
        with pytest.raises(TypeError):
            SearchFilter()  # type: ignore[abstract]

    def test_base_search_filter_concrete_but_requires_entity_for_sql(self) -> None:
        # BaseSearchFilter implements matches/filter_sql, so it is instantiable;
        # but without a concrete entity parametrization, filter_sql raises
        # rather than producing broken SQL.
        class Bare(BaseSearchFilter[User]):
            email__contains: str | None = None

        with pytest.raises(TypeError, match="not parameterized"):
            # Deliberately unparameterized: override the captured entity to
            # simulate a bare BaseSearchFilter subclass with no entity.
            Bare._entity_cls = None
            Bare(email__contains="x").filter_sql(select(User))


class TestEntityResolution:
    def test_entity_resolved_from_generic_parameter(self) -> None:
        assert UserSearchFilter._entity_cls is User

    def test_subclass_of_subclass_inherits_entity(self) -> None:
        class Refined(UserSearchFilter):
            created_at__lt: datetime | None = None

        assert Refined._entity_cls is User

    def test_filter_sql_raises_when_not_parameterized(self) -> None:
        # A filter whose entity was never captured raises clearly.
        class Bare(BaseSearchFilter[User]):
            email__contains: str | None = None

        Bare._entity_cls = None
        with pytest.raises(TypeError, match="not parameterized"):
            Bare(email__contains="x").filter_sql(select(User))


class TestMatchesInMemory:
    def test_empty_filter_matches_everything(self) -> None:
        f = UserSearchFilter()
        user = new_user("alice@example.com")
        assert f.matches(user) is True

    def test_contains_is_case_insensitive(self) -> None:
        f = UserSearchFilter(email__contains="ALICE")
        assert f.matches(new_user("alice@example.com")) is True
        assert f.matches(new_user("bob@example.com")) is False

    def test_contains_partial_substring(self) -> None:
        f = UserSearchFilter(email__contains="alic")
        assert f.matches(new_user("alice@example.com")) is True

    def test_eq(self) -> None:
        f = UserSearchFilter(email__eq="alice@example.com")
        assert f.matches(new_user("alice@example.com")) is True
        assert f.matches(new_user("bob@example.com")) is False

    def test_comparison_operators(self) -> None:
        # Naive datetimes match how the ORM column stores timestamps.
        cutoff = datetime(2024, 1, 1)
        old_user = new_user("old@example.com")
        old_user.created_at = datetime(2023, 1, 1)
        later_user = new_user("new@example.com")
        later_user.created_at = datetime(2025, 1, 1)

        assert UserSearchFilter(created_at__gte=cutoff).matches(later_user) is True
        assert UserSearchFilter(created_at__gte=cutoff).matches(old_user) is False

        assert UserSearchFilter(created_at__lt=cutoff).matches(old_user) is True
        assert UserSearchFilter(created_at__lt=cutoff).matches(later_user) is False

        assert UserSearchFilter(created_at__gt=cutoff).matches(later_user) is True
        assert UserSearchFilter(created_at__gt=cutoff).matches(old_user) is False

        assert UserSearchFilter(created_at__lte=cutoff).matches(old_user) is True
        assert UserSearchFilter(created_at__lte=cutoff).matches(later_user) is False

    def test_multiple_clauses_are_anded(self) -> None:
        f = UserSearchFilter(email__contains="example", email__eq="alice@example.com")
        assert f.matches(new_user("alice@example.com")) is True
        assert f.matches(new_user("bob@example.com")) is False

    def test_none_valued_fields_are_skipped(self) -> None:
        # A field explicitly set to None is treated as "not set".
        f = UserSearchFilter(email__contains=None)
        assert f.matches(new_user("anything@example.com")) is True

    def test_contains_on_none_attribute_returns_false(self) -> None:
        # An entity attribute that is None cannot contain anything.
        f = UserSearchFilter(email__contains="x")
        no_email = new_user("x@example.com")
        no_email.email = None  # type: ignore[assignment]
        assert f.matches(no_email) is False

    def test_contains_falls_back_to_membership_for_sequences(self) -> None:
        # When the attribute is a sequence (not str), contains uses `in`.

        class Tag:
            tags: list[str]

        class TagFilter(BaseSearchFilter[Tag]):
            tags__contains: str | None = None

        item = Tag()
        item.tags = ["alpha", "beta"]
        assert TagFilter(tags__contains="alpha").matches(item) is True
        assert TagFilter(tags__contains="gamma").matches(item) is False

    def test_contains_escapes_like_wildcards_in_value(self) -> None:
        # A literal `%` in the filter value must not act as a SQL wildcard.
        f = UserSearchFilter(email__contains="a%b")
        # The compiled SQL escapes the percent so it matches literally.
        compiled = str(f.filter_sql(select(User)))
        assert "ESCAPE" in compiled


class TestFilterSql:
    def test_filter_sql_returns_select(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        stmt = f.filter_sql(select(User))
        assert stmt is not None
        compiled = str(stmt)
        assert "users" in compiled
        assert "email" in compiled.lower()

    def test_filter_sql_applies_where_clause(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        stmt = f.filter_sql(select(User))
        compiled = str(stmt)
        assert "WHERE" in compiled
        assert "LIKE" in compiled or "like" in compiled

    def test_filter_sql_combines_clauses(self) -> None:
        f = UserSearchFilter(
            email__contains="ali",
            created_at__gte=datetime(2020, 1, 1),
        )
        compiled = str(f.filter_sql(select(User)))
        assert "AND" in compiled

    def test_filter_sql_unknown_attribute_raises(self) -> None:
        class BadFilter(BaseSearchFilter[User]):
            nonexistent__eq: str | None = None

        with pytest.raises(AttributeError, match="nonexistent"):
            BadFilter(nonexistent__eq="x").filter_sql(select(User))


class TestFilterSqlExecuted:
    """Run the produced SQL against the embedded PostgreSQL fixture."""

    # An unrestricted permission filter is used for these filter-mechanics
    # tests; the permission-scoping behavior is covered in the service and
    # route test suites.
    _all = AllSearchFilter[User]()

    async def test_contains_filter_narrows_results(self, session: AsyncSession) -> None:
        service = UserService(session, self._all)
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        await service.create(UserCreate(email="bob@example.com", username="bob"))
        await service.create(UserCreate(email="charlie@other.org", username="charlie"))

        f = UserSearchFilter(email__contains="example")
        stmt = f.filter_sql(select(User).order_by(User.email))
        result = await session.execute(stmt)
        users = list(result.scalars().all())
        emails = {u.email for u in users}
        assert emails == {"alice@example.com", "bob@example.com"}

    async def test_eq_filter_selects_single(self, session: AsyncSession) -> None:
        service = UserService(session, self._all)
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        await service.create(UserCreate(email="bob@example.com", username="bob"))

        f = UserSearchFilter(email__eq="alice@example.com")
        stmt = f.filter_sql(select(User))
        result = await session.execute(stmt)
        users = list(result.scalars().all())
        assert len(users) == 1
        assert users[0].email == "alice@example.com"

    async def test_empty_filter_returns_all(self, session: AsyncSession) -> None:
        service = UserService(session, self._all)
        await service.create(UserCreate(email="a@example.com", username="a"))
        await service.create(UserCreate(email="b@example.com", username="b"))

        f = UserSearchFilter()
        stmt = f.filter_sql(select(User))
        result = await session.execute(stmt)
        users = list(result.scalars().all())
        assert len(users) == 2

    async def test_combined_filters_with_pagination(self, session: AsyncSession) -> None:
        service = UserService(session, self._all)
        for i in range(5):
            await service.create(UserCreate(email=f"user{i}@example.com", username=f"user{i}"))

        f = UserSearchFilter(email__contains="example")
        stmt = f.filter_sql(select(User).order_by(User.id).limit(2))
        result = await session.execute(stmt)
        page = list(result.scalars().all())
        assert len(page) == 2


class TestCompositeFilters:
    """All, None, And, Or composite search filters."""

    def test_all_matches_everything(self) -> None:
        f = AllSearchFilter[User]()
        assert f.matches(new_user("a@x.com")) is True
        assert f.sql_condition() is None

    def test_none_matches_nothing(self) -> None:
        f = NoneSearchFilter[User]()
        assert f.matches(new_user("a@x.com")) is False
        assert f.sql_condition() is not None

    def test_and_requires_all_children_match(self) -> None:
        user = new_user("alice@example.com")
        f = AndSearchFilter[User](
            filters=[
                UserSearchFilter(email__contains="alice"),
                UserSearchFilter(email__contains="example"),
            ]
        )
        assert f.matches(user) is True
        f2 = AndSearchFilter[User](
            filters=[
                UserSearchFilter(email__contains="alice"),
                UserSearchFilter(email__contains="bob"),
            ]
        )
        assert f2.matches(user) is False

    def test_or_requires_any_child_match(self) -> None:
        user = new_user("alice@example.com")
        f = OrSearchFilter[User](
            filters=[
                UserSearchFilter(email__contains="bob"),
                UserSearchFilter(email__contains="alice"),
            ]
        )
        assert f.matches(user) is True
        f2 = OrSearchFilter[User](
            filters=[
                UserSearchFilter(email__contains="bob"),
                UserSearchFilter(email__contains="carol"),
            ]
        )
        assert f2.matches(user) is False

    def test_and_empty_matches_everything(self) -> None:
        f = AndSearchFilter[User](filters=[])
        assert f.matches(new_user("a@x.com")) is True
        assert f.sql_condition() is None

    def test_or_empty_matches_nothing(self) -> None:
        f = OrSearchFilter[User](filters=[])
        assert f.matches(new_user("a@x.com")) is False
        assert f.sql_condition() is not None

    def test_or_with_all_child_matches_everything(self) -> None:
        f = OrSearchFilter[User](
            filters=[UserSearchFilter(email__contains="bob"), AllSearchFilter[User]()]
        )
        assert f.matches(new_user("alice@x.com")) is True
        assert f.sql_condition() is None

    async def test_none_filter_sql_returns_no_rows(self, session: AsyncSession) -> None:
        service = UserService(session, AllSearchFilter[User]())
        await service.create(UserCreate(email="a@x.com", username="a"))
        f = NoneSearchFilter[User]()
        stmt = f.filter_sql(select(User))
        result = await session.execute(stmt)
        assert list(result.scalars().all()) == []

    async def test_and_filter_sql_narrows_results(self, session: AsyncSession) -> None:
        service = UserService(session, AllSearchFilter[User]())
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        await service.create(UserCreate(email="bob@example.com", username="bob"))
        f = AndSearchFilter[User](
            filters=[
                UserSearchFilter(email__contains="example"),
                UserSearchFilter(email__contains="alice"),
            ]
        )
        stmt = f.filter_sql(select(User))
        result = await session.execute(stmt)
        rows = list(result.scalars().all())
        assert len(rows) == 1
        assert rows[0].email == "alice@example.com"

    async def test_or_filter_sql_unions_results(self, session: AsyncSession) -> None:
        service = UserService(session, AllSearchFilter[User]())
        await service.create(UserCreate(email="alice@example.com", username="alice"))
        await service.create(UserCreate(email="bob@other.org", username="bob"))
        f = OrSearchFilter[User](
            filters=[
                UserSearchFilter(email__contains="example"),
                UserSearchFilter(email__contains="other"),
            ]
        )
        stmt = f.filter_sql(select(User))
        result = await session.execute(stmt)
        rows = list(result.scalars().all())
        assert len(rows) == 2


class TestSingletons:
    """ALL and NONE are module-level singletons."""

    def test_all_is_singleton(self) -> None:
        assert ALL is ALL
        assert isinstance(ALL, AllSearchFilter)

    def test_none_is_singleton(self) -> None:
        assert NONE is NONE
        assert isinstance(NONE, NoneSearchFilter)

    def test_all_matches_everything(self) -> None:
        assert ALL.matches(new_user("a@x.com")) is True

    def test_none_matches_nothing(self) -> None:
        assert NONE.matches(new_user("a@x.com")) is False


class TestAttributeFilter:
    """Generic runtime-specified attribute filter."""

    def test_eq_condition(self) -> None:
        f = AttributeFilter[User](attribute="email", value="alice@x.com", condition=Condition.EQ)
        assert f.matches(new_user("alice@x.com")) is True
        assert f.matches(new_user("bob@x.com")) is False

    def test_ne_condition(self) -> None:
        f = AttributeFilter[User](attribute="email", value="alice@x.com", condition=Condition.NE)
        assert f.matches(new_user("alice@x.com")) is False
        assert f.matches(new_user("bob@x.com")) is True

    def test_contains_condition(self) -> None:
        f = AttributeFilter[User](attribute="email", value="alice", condition=Condition.CONTAINS)
        assert f.matches(new_user("alice@x.com")) is True
        assert f.matches(new_user("bob@x.com")) is False

    def test_comparison_conditions(self) -> None:
        user_old = new_user("old@x.com")
        user_old.created_at = datetime(2020, 1, 1)
        user_new = new_user("new@x.com")
        user_new.created_at = datetime(2025, 1, 1)
        cutoff = datetime(2023, 1, 1)

        f_lt = AttributeFilter[User](attribute="created_at", value=cutoff, condition=Condition.LT)
        assert f_lt.matches(user_old) is True
        assert f_lt.matches(user_new) is False

        f_gt = AttributeFilter[User](attribute="created_at", value=cutoff, condition=Condition.GT)
        assert f_gt.matches(user_old) is False
        assert f_gt.matches(user_new) is True

        f_lte = AttributeFilter[User](
            attribute="created_at", value=cutoff, condition=Condition.LTE
        )
        assert f_lte.matches(user_old) is True

        f_gte = AttributeFilter[User](
            attribute="created_at", value=cutoff, condition=Condition.GTE
        )
        assert f_gte.matches(user_new) is True

    def test_sql_condition_requires_entity(self) -> None:
        # Unparameterized AttributeFilter cannot produce SQL.
        f = AttributeFilter(attribute="email", value="x", condition=Condition.EQ)
        with pytest.raises(TypeError, match="not parameterized"):
            f.sql_condition()

    def test_sql_condition_for_parameterized_filter(self) -> None:
        f = AttributeFilter[User](attribute="email", value="alice@x.com", condition=Condition.EQ)
        cond = f.sql_condition()
        assert cond is not None
        compiled = str(cond)
        assert "email" in compiled.lower()


class TestNeOperator:
    """Tests for the ne (not equals) operator in BaseSearchFilter."""

    def test_ne_in_base_filter(self) -> None:
        # Add an ne field dynamically for testing.
        class UserFilterWithNe(BaseSearchFilter[User]):
            enabled__ne: bool | None = None

        user_enabled = new_user("a@x.com")
        user_enabled.enabled = True
        user_disabled = new_user("b@x.com")
        user_disabled.enabled = False

        f = UserFilterWithNe(enabled__ne=True)
        assert f.matches(user_enabled) is False
        assert f.matches(user_disabled) is True

    def test_ne_sql_condition(self) -> None:
        class UserFilterWithNe(BaseSearchFilter[User]):
            enabled__ne: bool | None = None

        f = UserFilterWithNe(enabled__ne=True)
        cond = f.sql_condition()
        assert cond is not None
        compiled = str(cond)
        assert "!=" in compiled or "<>" in compiled or "NOT" in compiled.upper()


class TestFactoryFunctions:
    """and_filter() and or_filter() normalize composite filters."""

    # --- and_filter tests ---

    def test_and_filter_empty_returns_all(self) -> None:
        result = and_filter()
        assert result is ALL

    def test_and_filter_single_returns_unwrapped(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        result = and_filter(f)
        assert result is f

    def test_and_filter_with_none_returns_none(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        result = and_filter(f, NONE)
        assert result is NONE

    def test_and_filter_with_all_skips_all(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        result = and_filter(f, ALL)
        assert result is f  # Unwrapped singleton

    def test_and_filter_flattens_nested_and(self) -> None:
        f1 = UserSearchFilter(email__contains="alice")
        f2 = UserSearchFilter(email__contains="example")
        nested = AndSearchFilter[User](filters=[f1, f2])
        f3 = UserSearchFilter(email__contains="com")
        result = and_filter(nested, f3)
        assert isinstance(result, AndSearchFilter)
        # Should be flattened to 3 children, not nested.
        assert len(result.filters) == 3

    def test_and_filter_with_none_in_nested_returns_none(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        nested = AndSearchFilter[User](filters=[f, NONE])
        result = and_filter(nested)
        assert result is NONE

    # --- or_filter tests ---

    def test_or_filter_empty_returns_none(self) -> None:
        result = or_filter()
        assert result is NONE

    def test_or_filter_single_returns_unwrapped(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        result = or_filter(f)
        assert result is f

    def test_or_filter_with_all_returns_all(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        result = or_filter(f, ALL)
        assert result is ALL

    def test_or_filter_with_none_skips_none(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        result = or_filter(f, NONE)
        assert result is f  # Unwrapped singleton

    def test_or_filter_flattens_nested_or(self) -> None:
        f1 = UserSearchFilter(email__contains="alice")
        f2 = UserSearchFilter(email__contains="bob")
        nested = OrSearchFilter[User](filters=[f1, f2])
        f3 = UserSearchFilter(email__contains="carol")
        result = or_filter(nested, f3)
        assert isinstance(result, OrSearchFilter)
        # Should be flattened to 3 children, not nested.
        assert len(result.filters) == 3

    def test_or_filter_with_all_in_nested_returns_all(self) -> None:
        f = UserSearchFilter(email__contains="alice")
        nested = OrSearchFilter[User](filters=[f, ALL])
        result = or_filter(nested)
        assert result is ALL

    # --- Semantic correctness ---

    def test_and_filter_semantics_match(self) -> None:
        f1 = UserSearchFilter(email__contains="alice")
        f2 = UserSearchFilter(email__contains="example")
        combined = and_filter(f1, f2)
        user = new_user("alice@example.com")
        assert combined.matches(user) is True
        assert combined.matches(new_user("bob@example.com")) is False

    def test_or_filter_semantics_match(self) -> None:
        f1 = UserSearchFilter(email__contains="alice")
        f2 = UserSearchFilter(email__contains="bob")
        combined = or_filter(f1, f2)
        assert combined.matches(new_user("alice@x.com")) is True
        assert combined.matches(new_user("bob@x.com")) is True
        assert combined.matches(new_user("carol@x.com")) is False
