"""Runs enabled collectors, pivots on newly discovered identifiers, consolidates.

Every enabled collector runs concurrently against the current target. Any
USERNAME/DOMAIN identifiers a collector discovers (plus a FULL_NAME/LOCATION
if the target didn't already have one) are folded back into the target for up
to `max_pivot_iterations` extra rounds — e.g. gravatar finds a username, so
the next round also runs the username collector against it.

Collectors are deterministic given the same target, so a pivot round
naturally re-emits findings already seen for identifiers that didn't change.
Rather than track, per collector, exactly which target fields it cares about
(special-casing every collector here defeats the point of the plugin
interface), findings are simply deduplicated by
`(collector, title, source_url)` before being returned.
"""

from __future__ import annotations

import asyncio

from footprint_recon.collectors.base import Collector
from footprint_recon.models import Finding, IdentifierType, Target


class Aggregator:
    """Runs a set of collectors against a target, pivoting on new identifiers."""

    def __init__(self, collectors: list[Collector], max_pivot_iterations: int = 1) -> None:
        self._collectors = [c for c in collectors if c.enabled]
        self._max_pivot_iterations = max_pivot_iterations
        self.errors: list[tuple[str, str]] = []
        """(collector name, error message) pairs from collectors that raised, most recent run."""

    async def run(self, target: Target) -> list[Finding]:
        self.errors = []
        seen_values = {(i.type, i.value.lower()) for i in target.identifiers()}
        current_target = target
        all_findings: list[Finding] = []

        for round_number in range(self._max_pivot_iterations + 1):
            round_findings = await self._run_round(current_target)
            all_findings.extend(round_findings)

            if round_number == self._max_pivot_iterations:
                break

            next_target, seen_values = self._pivot(current_target, round_findings, seen_values)
            if next_target == current_target:
                break  # nothing new was discovered; further rounds would just repeat this one
            current_target = next_target

        return self._deduplicate(all_findings)

    async def _run_round(self, target: Target) -> list[Finding]:
        results = await asyncio.gather(
            *(self._run_one(collector, target) for collector in self._collectors)
        )
        return [finding for findings in results for finding in findings]

    async def _run_one(self, collector: Collector, target: Target) -> list[Finding]:
        try:
            return await collector.collect(target)
        except Exception as exc:  # noqa: BLE001 - one broken source must not sink the whole run
            self.errors.append((collector.name, str(exc)))
            return []

    def _pivot(
        self,
        target: Target,
        findings: list[Finding],
        seen_values: set[tuple[IdentifierType, str]],
    ) -> tuple[Target, set[tuple[IdentifierType, str]]]:
        new_usernames = list(target.usernames)
        new_domains = list(target.domains)
        full_name = target.full_name
        location = target.location
        seen_values = set(seen_values)

        for identifier in (i for finding in findings for i in finding.identifiers):
            key = (identifier.type, identifier.value.lower())
            if key in seen_values:
                continue
            seen_values.add(key)

            if identifier.type == IdentifierType.USERNAME:
                new_usernames.append(identifier.value)
            elif identifier.type == IdentifierType.DOMAIN:
                new_domains.append(identifier.value)
            elif identifier.type == IdentifierType.FULL_NAME and not full_name:
                full_name = identifier.value
            elif identifier.type == IdentifierType.LOCATION and not location:
                location = identifier.value

        next_target = target.model_copy(
            update={
                "usernames": new_usernames,
                "domains": new_domains,
                "full_name": full_name,
                "location": location,
            }
        )
        return next_target, seen_values

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, str | None]] = set()
        deduplicated = []
        for finding in findings:
            key = (finding.collector, finding.title, finding.source_url)
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(finding)
        return deduplicated
