"""Tests for the username (WhatsMyName) collector. All HTTP calls are mocked."""

from __future__ import annotations

import json
import time

import httpx

from footprint_recon.collectors import username as username_module
from footprint_recon.collectors.username import UsernameCollector
from footprint_recon.config import Config
from footprint_recon.models import RiskLevel, Target

_CONFIG = Config(hibp_api_key=None, github_token=None, user_agent="test-agent")

_EXISTS_SITE = {
    "name": "ExampleSite",
    "uri_check": "https://example.com/{account}",
    "e_code": 200,
    "e_string": "profile-header",
    "m_code": 404,
    "m_string": "",
    "cat": "tech",
}

_STATUS_ONLY_SITE = {
    "name": "StatusOnlySite",
    "uri_check": "https://status-only.example/{account}",
    "e_code": 200,
    "e_string": "",
    "m_code": 404,
    "m_string": "",
    "cat": "hobby",
}


async def test_no_usernames_returns_nothing() -> None:
    collector = UsernameCollector(config=_CONFIG, sites=[_EXISTS_SITE])
    assert await collector.collect(Target()) == []


async def test_matching_site_yields_finding(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://example.com/alice"
        return httpx.Response(200, text="<div class='profile-header'>Alice</div>")

    patch_client(handler)

    collector = UsernameCollector(config=_CONFIG, sites=[_EXISTS_SITE])
    findings = await collector.collect(Target(usernames=["alice"]))

    assert len(findings) == 1
    assert findings[0].title == "Username found: ExampleSite"
    assert findings[0].risk == RiskLevel.LOW
    assert findings[0].source_url == "https://example.com/alice"


async def test_missing_account_yields_nothing(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    patch_client(handler)

    collector = UsernameCollector(config=_CONFIG, sites=[_EXISTS_SITE])
    findings = await collector.collect(Target(usernames=["nobody"]))

    assert findings == []


async def test_ambiguous_response_yields_nothing(patch_client) -> None:
    """Neither e_code/e_string nor m_code/m_string matches (e.g. a captcha wall) -> skip."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="captcha required")

    patch_client(handler)

    collector = UsernameCollector(config=_CONFIG, sites=[_EXISTS_SITE])
    findings = await collector.collect(Target(usernames=["alice"]))

    assert findings == []


async def test_status_only_match_needs_no_body_string(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="")

    patch_client(handler)

    collector = UsernameCollector(config=_CONFIG, sites=[_STATUS_ONLY_SITE])
    findings = await collector.collect(Target(usernames=["alice"]))

    assert len(findings) == 1


async def test_username_is_url_encoded(patch_client) -> None:
    seen_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(404)

    patch_client(handler)

    collector = UsernameCollector(config=_CONFIG, sites=[_EXISTS_SITE])
    await collector.collect(Target(usernames=["a b/c"]))

    assert seen_urls == ["https://example.com/a%20b%2Fc"]


async def test_multiple_usernames_and_sites_checked_independently(patch_client) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "alice" in str(request.url):
            return httpx.Response(200, text="profile-header")
        return httpx.Response(404)

    patch_client(handler)

    collector = UsernameCollector(config=_CONFIG, sites=[_EXISTS_SITE, _STATUS_ONLY_SITE])
    findings = await collector.collect(Target(usernames=["alice", "bob"]))

    # alice matches on both sites (status-only site has no body check); bob matches none.
    assert len(findings) == 2
    assert {f.identifiers[0].value for f in findings} == {"alice"}


async def test_load_sites_downloads_and_caches(monkeypatch, tmp_path, patch_client) -> None:
    cache_path = tmp_path / "wmn-data.json"
    monkeypatch.setattr(username_module, "_CACHE_PATH", cache_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == username_module._WMN_DATA_URL:
            return httpx.Response(200, json={"sites": [_EXISTS_SITE]})
        return httpx.Response(200, text="profile-header")

    patch_client(handler)

    collector = UsernameCollector(config=_CONFIG)
    findings = await collector.collect(Target(usernames=["alice"]))

    assert len(findings) == 1
    assert json.loads(cache_path.read_text())["sites"] == [_EXISTS_SITE]


async def test_load_sites_falls_back_to_stale_cache_on_download_failure(
    monkeypatch, tmp_path, patch_client
) -> None:
    cache_path = tmp_path / "wmn-data.json"
    cache_path.write_text(json.dumps({"sites": [_EXISTS_SITE]}), encoding="utf-8")
    stale_time = time.time() - username_module._CACHE_TTL_SECONDS - 3600
    import os

    os.utime(cache_path, (stale_time, stale_time))
    monkeypatch.setattr(username_module, "_CACHE_PATH", cache_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == username_module._WMN_DATA_URL:
            return httpx.Response(500)
        return httpx.Response(200, text="profile-header")

    patch_client(handler)

    collector = UsernameCollector(config=_CONFIG)
    findings = await collector.collect(Target(usernames=["alice"]))

    assert len(findings) == 1
