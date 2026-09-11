"""Tests for the Aggregator: running, pivoting, error isolation, deduplication."""

from __future__ import annotations

from typing import Callable

from footprint_recon.aggregator import Aggregator
from footprint_recon.collectors.base import Collector
from footprint_recon.models import Finding, Identifier, IdentifierType, RiskLevel, Target


class _FakeCollector(Collector):
    """Test double: delegates to a handler, records every target it was called with."""

    def __init__(self, name: str, handler: Callable[[Target], list[Finding]]) -> None:
        self._name = name
        self._handler = handler
        self.calls: list[Target] = []

    @property
    def name(self) -> str:
        return self._name

    async def collect(self, target: Target) -> list[Finding]:
        self.calls.append(target)
        return self._handler(target)


def _finding(collector: str, *identifiers: Identifier, title: str = "Found something") -> Finding:
    return Finding(
        collector=collector,
        identifiers=list(identifiers),
        title=title,
        detail="detail",
        confidence=1.0,
        risk=RiskLevel.LOW,
    )


async def test_runs_all_enabled_collectors_and_consolidates() -> None:
    a = _FakeCollector("a", lambda t: [_finding("a", title="A found")])
    b = _FakeCollector("b", lambda t: [_finding("b", title="B found")])

    findings = await Aggregator([a, b], max_pivot_iterations=0).run(Target())

    assert {f.title for f in findings} == {"A found", "B found"}


async def test_disabled_collector_is_skipped() -> None:
    a = _FakeCollector("a", lambda t: [_finding("a", title="A found")])
    a.enabled = False
    b = _FakeCollector("b", lambda t: [_finding("b", title="B found")])

    findings = await Aggregator([a, b], max_pivot_iterations=0).run(Target())

    assert a.calls == []
    assert [f.title for f in findings] == ["B found"]


async def test_one_failing_collector_does_not_break_the_others() -> None:
    def boom(_: Target) -> list[Finding]:
        raise RuntimeError("simulated failure")

    a = _FakeCollector("a", boom)
    b = _FakeCollector("b", lambda t: [_finding("b", title="B found")])

    aggregator = Aggregator([a, b], max_pivot_iterations=0)
    findings = await aggregator.run(Target())

    assert [f.title for f in findings] == ["B found"]
    assert aggregator.errors == [("a", "simulated failure")]


async def test_pivot_feeds_new_username_into_next_round() -> None:
    def discover_username(target: Target) -> list[Finding]:
        if target.email and not target.usernames:
            username = Identifier(type=IdentifierType.USERNAME, value="alice")
            return [_finding("email_breach", username)]
        return []

    def check_username(target: Target) -> list[Finding]:
        return [_finding("username", title=f"seen {u}") for u in target.usernames]

    a = _FakeCollector("email_breach", discover_username)
    b = _FakeCollector("username", check_username)

    aggregator = Aggregator([a, b], max_pivot_iterations=1)
    findings = await aggregator.run(Target(email="me@example.com"))

    assert "seen alice" in {f.title for f in findings}
    assert b.calls[-1].usernames == ["alice"]


async def test_max_pivot_iterations_zero_means_no_pivoting() -> None:
    def discover_username(target: Target) -> list[Finding]:
        return [_finding("a", Identifier(type=IdentifierType.USERNAME, value="alice"))]

    a = _FakeCollector("a", discover_username)
    b = _FakeCollector("b", lambda t: [])

    await Aggregator([a, b], max_pivot_iterations=0).run(Target())

    assert len(b.calls) == 1
    assert b.calls[0].usernames == []


async def test_pivot_stops_early_when_nothing_new_is_discovered() -> None:
    calls = {"a": 0, "b": 0}

    def a_handler(target: Target) -> list[Finding]:
        calls["a"] += 1
        return []  # never discovers anything new

    def b_handler(target: Target) -> list[Finding]:
        calls["b"] += 1
        return []

    a = _FakeCollector("a", a_handler)
    b = _FakeCollector("b", b_handler)

    await Aggregator([a, b], max_pivot_iterations=5).run(Target())

    # No new identifiers ever surface, so pivoting should stop after round 1
    # instead of running all 6 allowed rounds.
    assert calls == {"a": 1, "b": 1}


async def test_duplicate_findings_across_rounds_are_deduplicated() -> None:
    def a_handler(target: Target) -> list[Finding]:
        # Always emits the same finding, regardless of target changes.
        return [_finding("a", title="Stable finding")]

    def discover_username(target: Target) -> list[Finding]:
        if not target.usernames:
            return [_finding("b", Identifier(type=IdentifierType.USERNAME, value="alice"))]
        return []

    a = _FakeCollector("a", a_handler)
    b = _FakeCollector("b", discover_username)

    findings = await Aggregator([a, b], max_pivot_iterations=2).run(Target())

    assert [f.title for f in findings].count("Stable finding") == 1
