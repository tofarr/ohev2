"""Tests for the shared random-id minting helper."""

from __future__ import annotations

from openhands.ev2.util.random_id import generate_random_id


def test_generate_random_id_shape() -> None:
    value = generate_random_id()
    assert len(value) == 22
    assert value.islower()
    assert value.isalnum()
    # [a-z0-9] only — no separators that would clash with the Docker ``OHE_``
    # name grammar (``_``) or the K8s derived names (``-``).
    assert "_" not in value and "-" not in value


def test_generate_random_id_is_unique() -> None:
    values = {generate_random_id() for _ in range(1000)}
    assert len(values) == 1000
