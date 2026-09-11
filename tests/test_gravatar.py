"""Tests for the Gravatar collector. All HTTP calls are mocked — no network access."""

from __future__ import annotations

import hashlib

import httpx

from footprint_recon.collectors.gravatar import GravatarCollector
from footprint_recon.config import Config
from footprint_recon.models import IdentifierType, RiskLevel, Target

_CONFIG = Config(hibp_api_key=None, github_token=None, user_agent="test-agent")
_EMAIL = "me@example.com"
_HASH = hashlib.md5(_EMAIL.encode()).hexdigest()

_PROFILE_RESPONSE = {
    "entry": [
        {
            "profileUrl": "https://gravatar.com/me",
            "preferredUsername": "me_handle",
            "displayName": "Me Example",
            "aboutMe": "Just a person.",
            "currentLocation": "Sao Paulo",
            "company": "Acme",
            "job_title": "Engineer",
            "accounts": [
                {
                    "name": "X",
                    "domain": "x.com",
                    "url": "https://x.com/me_handle",
                    "username": "me_handle",
                    "display": "@me_handle",
                }
            ],
        }
    ]
}


async def test_no_email_returns_nothing() -> None:
    collector = GravatarCollector(config=_CONFIG)
    assert await collector.collect(Target()) == []


async def test_full_profile_yields_profile_and_linked_account_findings(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert f"/{_HASH}.json" in str(request.url)
        return httpx.Response(200, json=_PROFILE_RESPONSE)

    patch_client(handler)

    collector = GravatarCollector(config=_CONFIG)
    findings = await collector.collect(Target(email=_EMAIL))

    assert len(findings) == 2
    profile_finding, account_finding = findings
    assert profile_finding.title == "Public Gravatar profile"
    assert profile_finding.risk == RiskLevel.MEDIUM  # has bio/location/company
    assert any(
        i.type == IdentifierType.USERNAME and i.value == "me_handle"
        for i in profile_finding.identifiers
    )
    assert account_finding.title == "Linked account: X"
    assert account_finding.source_url == "https://x.com/me_handle"


async def test_no_profile_but_public_avatar(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".json"):
            return httpx.Response(404)
        assert request.method == "HEAD"
        return httpx.Response(200)

    patch_client(handler)

    collector = GravatarCollector(config=_CONFIG)
    findings = await collector.collect(Target(email=_EMAIL))

    assert len(findings) == 1
    assert findings[0].title == "Public Gravatar avatar (no public profile)"
    assert findings[0].risk == RiskLevel.LOW


async def test_no_profile_and_no_avatar_yields_nothing(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    patch_client(handler)

    collector = GravatarCollector(config=_CONFIG)
    findings = await collector.collect(Target(email=_EMAIL))

    assert findings == []
