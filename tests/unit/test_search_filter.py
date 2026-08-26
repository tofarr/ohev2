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

from ohev.user.user_models import User
from ohev.user.user_schemas import UserCreate
from ohev.user.user_service import UserService
from ohev.util.search_filter import BaseSearchFilter, SearchFilter


class UserSearchFilter(BaseSearchFilter[User]):
    email__contains: str | None = None
    email__eq: str | None = None
    created_at__gte: datetime | None = None
    created_at__lt: datetime | None = None
    created_at__gt: datetime | None = None
    created_at__lte: datetime | None = None


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
        user = User(email="alice@example.com")
        assert f.matches(user) is True

    def test_contains_is_case_insensitive(self) -> None:
        f = UserSearchFilter(email__contains="ALICE")
        assert f.matches(User(email="alice@example.com")) is True
        assert f.matches(User(email="bob@example.com")) is False

    def test_contains_partial_substring(self) -> None:
        f = UserSearchFilter(email__contains="alic")
        assert f.matches(User(email="alice@example.com")) is True

    def test_eq(self) -> None:
        f = UserSearchFilter(email__eq="alice@example.com")
        assert f.matches(User(email="alice@example.com")) is True
        assert f.matches(User(email="bob@example.com")) is False

    def test_comparison_operators(self) -> None:
        # Naive datetimes match how the ORM column stores timestamps.
        cutoff = datetime(2024, 1, 1)
        old_user = User(email="old@example.com")
        old_user.created_at = datetime(2023, 1, 1)
        new_user = User(email="new@example.com")
        new_user.created_at = datetime(2025, 1, 1)

        assert UserSearchFilter(created_at__gte=cutoff).matches(new_user) is True
        assert UserSearchFilter(created_at__gte=cutoff).matches(old_user) is False

        assert UserSearchFilter(created_at__lt=cutoff).matches(old_user) is True
        assert UserSearchFilter(created_at__lt=cutoff).matches(new_user) is False

        assert UserSearchFilter(created_at__gt=cutoff).matches(new_user) is True
        assert UserSearchFilter(created_at__gt=cutoff).matches(old_user) is False

        assert UserSearchFilter(created_at__lte=cutoff).matches(old_user) is True
        assert UserSearchFilter(created_at__lte=cutoff).matches(new_user) is False

    def test_multiple_clauses_are_anded(self) -> None:
        f = UserSearchFilter(email__contains="example", email__eq="alice@example.com")
        assert f.matches(User(email="alice@example.com")) is True
        assert f.matches(User(email="bob@example.com")) is False

    def test_none_valued_fields_are_skipped(self) -> None:
        # A field explicitly set to None is treated as "not set".
        f = UserSearchFilter(email__contains=None)
        assert f.matches(User(email="anything@example.com")) is True

    def test_contains_on_none_attribute_returns_false(self) -> None:
        # An entity attribute that is None cannot contain anything.
        f = UserSearchFilter(email__contains="x")
        no_email = User(email="x@example.com")
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

    async def test_contains_filter_narrows_results(self, session: AsyncSession) -> None:
        service = UserService(session)
        await service.create(UserCreate(email="alice@example.com"))
        await service.create(UserCreate(email="bob@example.com"))
        await service.create(UserCreate(email="charlie@other.org"))

        f = UserSearchFilter(email__contains="example")
        stmt = f.filter_sql(select(User).order_by(User.email))
        result = await session.execute(stmt)
        users = list(result.scalars().all())
        emails = {u.email for u in users}
        assert emails == {"alice@example.com", "bob@example.com"}

    async def test_eq_filter_selects_single(self, session: AsyncSession) -> None:
        service = UserService(session)
        await service.create(UserCreate(email="alice@example.com"))
        await service.create(UserCreate(email="bob@example.com"))

        f = UserSearchFilter(email__eq="alice@example.com")
        stmt = f.filter_sql(select(User))
        result = await session.execute(stmt)
        users = list(result.scalars().all())
        assert len(users) == 1
        assert users[0].email == "alice@example.com"

    async def test_empty_filter_returns_all(self, session: AsyncSession) -> None:
        service = UserService(session)
        await service.create(UserCreate(email="a@example.com"))
        await service.create(UserCreate(email="b@example.com"))

        f = UserSearchFilter()
        stmt = f.filter_sql(select(User))
        result = await session.execute(stmt)
        users = list(result.scalars().all())
        assert len(users) == 2

    async def test_combined_filters_with_pagination(self, session: AsyncSession) -> None:
        service = UserService(session)
        for i in range(5):
            await service.create(UserCreate(email=f"user{i}@example.com"))

        f = UserSearchFilter(email__contains="example")
        stmt = f.filter_sql(select(User).order_by(User.id).limit(2))
        result = await session.execute(stmt)
        page = list(result.scalars().all())
        assert len(page) == 2
