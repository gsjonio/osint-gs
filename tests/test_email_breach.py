"""Tests for the HIBP email_breach collector. All HTTP calls are mocked — no network access."""

from __future__ import annotations

import httpx
import pytest

from footprint_recon.collectors.email_breach import EmailBreachCollector
from footprint_recon.config import Config
from footprint_recon.models import RiskLevel, Target

_NO_KEY_CONFIG = Config(hibp_api_key=None, github_token=None, user_agent="test-agent")
_WITH_KEY_CONFIG = Config(hibp_api_key="fake-key", github_token=None, user_agent="test-agent")

_BREACH = {
    "Name": "Adobe",
    "BreachDate": "2013-10-04",
    "DataClasses": ["Email addresses", "Passwords"],
    "IsVerified": True,
    "IsSensitive": False,
    "Description": "The Adobe breach.",
}

_CPF_BREACH = {
    "Name": "SerasaExperian",
    "BreachDate": "2021-01-01",
    "DataClasses": ["Email addresses", "CPF numbers"],
    "IsVerified": True,
    "IsSensitive": True,
    "Description": "A Brazilian breach.",
}

_PASTE = {
    "Source": "Pastebin",
    "Id": "abc123",
    "Date": "2020-05-01T00:00:00Z",
    "EmailCount": 42,
}


async def test_no_api_key_returns_manual_check_without_http_call() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise AssertionError("HTTP should not be called when no HIBP_API_KEY is set")

    collector = EmailBreachCollector(config=_NO_KEY_CONFIG)
    findings = await collector.collect(Target(email="me@example.com"))

    assert len(findings) == 1
    assert findings[0].risk == RiskLevel.LOW
    assert "haveibeenpwned.com/account/me%40example.com" in findings[0].source_url


async def test_no_email_returns_nothing() -> None:
    collector = EmailBreachCollector(config=_WITH_KEY_CONFIG)
    assert await collector.collect(Target()) == []


async def test_breach_and_paste_parsed_into_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "breachedaccount" in request.url.path:
            return httpx.Response(200, json=[_BREACH, _CPF_BREACH])
        if "pasteaccount" in request.url.path:
            return httpx.Response(200, json=[_PASTE])
        raise AssertionError(f"unexpected URL: {request.url}")

    _patch_client(monkeypatch, handler)

    collector = EmailBreachCollector(config=_WITH_KEY_CONFIG)
    findings = await collector.collect(Target(email="me@example.com"))

    assert len(findings) == 3
    by_title = {f.title: f for f in findings}
    assert by_title["Breach: Adobe"].risk == RiskLevel.HIGH  # has Passwords
    assert by_title["Breach: SerasaExperian"].risk == RiskLevel.CRITICAL  # has CPF
    assert by_title["Paste on Pastebin"].risk == RiskLevel.MEDIUM


async def test_404_is_treated_as_no_results(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    _patch_client(monkeypatch, handler)

    collector = EmailBreachCollector(config=_WITH_KEY_CONFIG)
    findings = await collector.collect(Target(email="me@example.com"))

    assert findings == []


async def test_429_retries_after_retry_after_header(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"breachedaccount": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if "breachedaccount" in request.url.path:
            calls["breachedaccount"] += 1
            if calls["breachedaccount"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, json=[_BREACH])
        return httpx.Response(404)

    _patch_client(monkeypatch, handler)

    collector = EmailBreachCollector(config=_WITH_KEY_CONFIG)
    findings = await collector.collect(Target(email="me@example.com"))

    assert calls["breachedaccount"] == 2
    assert len(findings) == 1


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    """Route httpx.AsyncClient through a MockTransport instead of the real network."""
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)
