"""Tests for the dork collector. Pure string generation, no HTTP involved."""

from __future__ import annotations

from urllib.parse import quote

from footprint_recon.collectors.dork import DorkCollector
from footprint_recon.models import RiskLevel, Target


async def test_empty_target_yields_nothing() -> None:
    assert await DorkCollector().collect(Target()) == []


async def test_email_yields_three_dorks() -> None:
    findings = await DorkCollector().collect(Target(email="me@example.com"))

    queries = {f.raw["query"] for f in findings}
    assert queries == {
        '"me@example.com"',
        'intext:"me@example.com" -site:linkedin.com',
        'site:pastebin.com "me@example.com"',
    }
    by_query = {f.raw["query"]: f for f in findings}
    assert by_query['site:pastebin.com "me@example.com"'].risk == RiskLevel.MEDIUM
    assert by_query['"me@example.com"'].risk == RiskLevel.LOW


async def test_full_name_without_location_yields_one_dork() -> None:
    findings = await DorkCollector().collect(Target(full_name="Jane Doe"))
    assert [f.raw["query"] for f in findings] == ['"Jane Doe" filetype:pdf']


async def test_full_name_with_location_adds_second_dork() -> None:
    findings = await DorkCollector().collect(Target(full_name="Jane Doe", location="Sao Paulo"))
    queries = {f.raw["query"] for f in findings}
    assert queries == {
        '"Jane Doe" filetype:pdf',
        '"Jane Doe" "Sao Paulo"',
    }


async def test_location_alone_without_full_name_yields_nothing() -> None:
    findings = await DorkCollector().collect(Target(location="Sao Paulo"))
    assert findings == []


async def test_one_dork_per_username() -> None:
    findings = await DorkCollector().collect(Target(usernames=["alice", "bob"]))
    queries = {f.raw["query"] for f in findings}
    assert queries == {'"alice" site:github.com', '"bob" site:github.com'}


async def test_source_url_is_a_clickable_encoded_search_link() -> None:
    findings = await DorkCollector().collect(Target(email="me@example.com"))
    query = findings[0].raw["query"]
    assert findings[0].source_url == f"https://www.google.com/search?q={quote(query, safe='')}"
