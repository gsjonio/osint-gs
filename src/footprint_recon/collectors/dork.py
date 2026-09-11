"""Dork collector: generates ready-to-run search-engine queries, no automation.

Unlike the other collectors, this one never makes an HTTP request — the rule
in §1.3 (be a lightweight, passive collector) is moot here since there is
nothing to rate-limit. The user runs each query by hand (or clicks the
generated search link); this collector's job is just building well-formed
`"{value}"` queries from whatever identifiers the target actually has.
"""

from __future__ import annotations

from urllib.parse import quote

from footprint_recon.collectors.base import Collector
from footprint_recon.models import Finding, Identifier, IdentifierType, RiskLevel, Target

_SEARCH_URL = "https://www.google.com/search?q={query}"


class DorkCollector(Collector):
    """Builds Google/Bing-style dork queries for the target's identifiers."""

    @property
    def name(self) -> str:
        return "dork"

    async def collect(self, target: Target) -> list[Finding]:
        queries: list[tuple[str, RiskLevel, list[Identifier]]] = []

        if target.email:
            email_id = Identifier(type=IdentifierType.EMAIL, value=target.email)
            queries += [
                (f'"{target.email}"', RiskLevel.LOW, [email_id]),
                (
                    f'intext:"{target.email}" -site:linkedin.com',
                    RiskLevel.LOW,
                    [email_id],
                ),
                (f'site:pastebin.com "{target.email}"', RiskLevel.MEDIUM, [email_id]),
            ]

        if target.full_name:
            name_id = Identifier(type=IdentifierType.FULL_NAME, value=target.full_name)
            queries.append((f'"{target.full_name}" filetype:pdf', RiskLevel.MEDIUM, [name_id]))
            if target.location:
                location_id = Identifier(type=IdentifierType.LOCATION, value=target.location)
                queries.append(
                    (
                        f'"{target.full_name}" "{target.location}"',
                        RiskLevel.MEDIUM,
                        [name_id, location_id],
                    )
                )

        for username in target.usernames:
            queries.append(
                (
                    f'"{username}" site:github.com',
                    RiskLevel.LOW,
                    [Identifier(type=IdentifierType.USERNAME, value=username)],
                )
            )

        return [self._finding(query, risk, ids) for query, risk, ids in queries]

    def _finding(self, query: str, risk: RiskLevel, identifiers: list[Identifier]) -> Finding:
        return Finding(
            collector=self.name,
            identifiers=identifiers,
            title=f"Dork: {query}",
            detail="Run this search manually; the tool does not execute it for you.",
            source_url=_SEARCH_URL.format(query=quote(query, safe="")),
            confidence=1.0,
            risk=risk,
            raw={"query": query},
        )
