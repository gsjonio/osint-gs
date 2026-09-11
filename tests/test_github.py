"""Tests for the GitHub commit-email-leak collector. All HTTP calls are mocked."""

from __future__ import annotations

import httpx

from footprint_recon.collectors.github import GithubCollector
from footprint_recon.config import Config
from footprint_recon.models import RiskLevel, Target

_NO_TOKEN_CONFIG = Config(hibp_api_key=None, github_token=None, user_agent="test-agent")
_WITH_TOKEN_CONFIG = Config(hibp_api_key=None, github_token="fake-token", user_agent="test-agent")


def _events(*heads: str) -> list[dict]:
    return [
        {
            "type": "PushEvent",
            "repo": {"name": "alice/project"},
            "payload": {"head": head},
        }
        for head in heads
    ]


def _patch(email: str, name: str = "Alice Example") -> str:
    return (
        f"From abc123 Mon Sep 17 00:00:00 2001\n"
        f"From: {name} <{email}>\n"
        f"Date: Thu, 1 Jan 2026 00:00:00 -0700\n"
        f"Subject: [PATCH] test commit\n"
    )


async def test_no_usernames_returns_nothing() -> None:
    collector = GithubCollector(config=_NO_TOKEN_CONFIG)
    assert await collector.collect(Target()) == []


async def test_user_not_found_returns_nothing(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    patch_client(handler)

    collector = GithubCollector(config=_NO_TOKEN_CONFIG)
    findings = await collector.collect(Target(usernames=["ghost"]))

    assert findings == []


async def test_leaked_email_matching_target_is_high_risk(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "events/public" in str(request.url):
            return httpx.Response(200, json=_events("a" * 40))
        return httpx.Response(200, text=_patch("me@example.com"))

    patch_client(handler)

    collector = GithubCollector(config=_NO_TOKEN_CONFIG)
    findings = await collector.collect(Target(email="me@example.com", usernames=["alice"]))

    assert len(findings) == 1
    assert findings[0].risk == RiskLevel.HIGH
    assert findings[0].raw["email"] == "me@example.com"
    assert findings[0].source_url == f"https://github.com/alice/project/commit/{'a' * 40}"


async def test_leaked_email_not_matching_target_is_medium_risk(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "events/public" in str(request.url):
            return httpx.Response(200, json=_events("b" * 40))
        return httpx.Response(200, text=_patch("old-personal@example.com"))

    patch_client(handler)

    collector = GithubCollector(config=_NO_TOKEN_CONFIG)
    findings = await collector.collect(Target(email="me@example.com", usernames=["alice"]))

    assert len(findings) == 1
    assert findings[0].risk == RiskLevel.MEDIUM


async def test_duplicate_emails_across_commits_are_deduplicated(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "events/public" in str(request.url):
            return httpx.Response(200, json=_events("c" * 40, "d" * 40))
        return httpx.Response(200, text=_patch("me@example.com"))

    patch_client(handler)

    collector = GithubCollector(config=_NO_TOKEN_CONFIG)
    findings = await collector.collect(Target(email="me@example.com", usernames=["alice"]))

    assert len(findings) == 1


async def test_one_bad_patch_does_not_break_the_others(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "events/public" in url:
            return httpx.Response(200, json=_events("e" * 40, "f" * 40))
        if "e" * 40 in url:
            return httpx.Response(500)
        return httpx.Response(200, text=_patch("me@example.com"))

    patch_client(handler)

    collector = GithubCollector(config=_NO_TOKEN_CONFIG)
    findings = await collector.collect(Target(email="me@example.com", usernames=["alice"]))

    assert len(findings) == 1


async def test_github_token_sent_as_bearer_header(patch_client) -> None:
    seen_auth = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("authorization"))
        if "events/public" in str(request.url):
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    patch_client(handler)

    collector = GithubCollector(config=_WITH_TOKEN_CONFIG)
    await collector.collect(Target(usernames=["alice"]))

    assert seen_auth == ["Bearer fake-token"]


async def test_github_token_is_not_sent_to_patch_requests(patch_client) -> None:
    """The token is only needed (and only sent) for api.github.com, never for the
    unauthenticated github.com/.../commit/{sha}.patch fetches."""
    seen_auth = []

    def handler(request: httpx.Request) -> httpx.Response:
        if "events/public" in str(request.url):
            return httpx.Response(200, json=_events("a" * 40))
        seen_auth.append(request.headers.get("authorization"))
        return httpx.Response(200, text=_patch("me@example.com"))

    patch_client(handler)

    collector = GithubCollector(config=_WITH_TOKEN_CONFIG)
    await collector.collect(Target(usernames=["alice"]))

    assert seen_auth == [None]
