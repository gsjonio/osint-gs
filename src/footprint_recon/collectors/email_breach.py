"""HIBP (Have I Been Pwned) v3 collector: breaches and pastes for the target's email.

The `breachedaccount`/`pasteaccount` endpoints require a paid HIBP API key
(https://haveibeenpwned.com/API/Key, ~US$3.95/mo). There is no legitimate free
equivalent: every "free breach lookup" alternative out there is a leaked-data
broker, which this project's scope rules forbid integrating with. So this
collector runs in two modes:

- With `HIBP_API_KEY` set: full automated breach + paste lookup.
- Without it: emits a single Finding pointing at HIBP's free, human-interactive
  web check instead of silently doing nothing.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from footprint_recon.collectors.base import Collector
from footprint_recon.config import Config, load_config
from footprint_recon.models import Finding, Identifier, IdentifierType, RiskLevel, Target

_API_BASE = "https://haveibeenpwned.com/api/v3"
_REQUEST_TIMEOUT = 10.0
_MIN_REQUEST_INTERVAL = 1.6  # seconds between calls, to stay under HIBP's rate limit.


class EmailBreachCollector(Collector):
    """Looks up the target's email in HIBP breaches and pastes."""

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or load_config()

    @property
    def name(self) -> str:
        return "email_breach"

    async def collect(self, target: Target) -> list[Finding]:
        if not target.email:
            return []
        if not self._config.hibp_api_key:
            return [self._manual_check_finding(target.email)]

        headers = {
            "hibp-api-key": self._config.hibp_api_key,
            "user-agent": self._config.user_agent,
        }
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT, headers=headers) as client:
            breaches = await self._get_json(
                client, f"{_API_BASE}/breachedaccount/{target.email}?truncateResponse=false"
            )
            await asyncio.sleep(_MIN_REQUEST_INTERVAL)
            pastes = await self._get_json(client, f"{_API_BASE}/pasteaccount/{target.email}")

        findings = [self._breach_finding(target.email, b) for b in breaches or []]
        findings += [self._paste_finding(target.email, p) for p in pastes or []]
        return findings

    async def _get_json(self, client: httpx.AsyncClient, url: str) -> list[dict[str, Any]] | None:
        """GET `url`, honoring HIBP's rate limit and treating 404 as "no results"."""
        response = await client.get(url)
        if response.status_code == 429:
            retry_after = float(response.headers.get("Retry-After", 2))
            await asyncio.sleep(retry_after)
            response = await client.get(url)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def _manual_check_finding(self, email: str) -> Finding:
        return Finding(
            collector=self.name,
            identifiers=[Identifier(type=IdentifierType.EMAIL, value=email)],
            title="Manual check recommended: HIBP account lookup",
            detail=(
                "No HIBP_API_KEY configured, so automated breach lookup was skipped "
                "(the HIBP API is a paid feature). Free alternative: check this email "
                "manually on HIBP's public web form."
            ),
            source_url=f"https://haveibeenpwned.com/account/{email}",
            confidence=1.0,
            risk=RiskLevel.LOW,
            raw={},
        )

    def _breach_finding(self, email: str, breach: dict[str, Any]) -> Finding:
        data_classes = breach.get("DataClasses", [])
        risk = RiskLevel.MEDIUM
        if any("cpf" in c.lower() or "national id" in c.lower() for c in data_classes):
            risk = RiskLevel.CRITICAL
        elif breach.get("IsSensitive") or "Passwords" in data_classes:
            risk = RiskLevel.HIGH

        return Finding(
            collector=self.name,
            identifiers=[Identifier(type=IdentifierType.EMAIL, value=email)],
            title=f"Breach: {breach['Name']}",
            detail=(
                f"{breach.get('BreachDate', 'unknown date')} — exposed: "
                f"{', '.join(data_classes) or 'unknown data'}. {breach.get('Description', '')}"
            ),
            source_url=f"https://haveibeenpwned.com/PwnedWebsites#{breach['Name']}",
            confidence=0.95 if breach.get("IsVerified") else 0.6,
            risk=risk,
            raw=breach,
        )

    def _paste_finding(self, email: str, paste: dict[str, Any]) -> Finding:
        return Finding(
            collector=self.name,
            identifiers=[Identifier(type=IdentifierType.EMAIL, value=email)],
            title=f"Paste on {paste.get('Source', 'unknown source')}",
            detail=(
                f"Dated {paste.get('Date', 'unknown date')}, "
                f"{paste.get('EmailCount', '?')} emails included."
            ),
            source_url=None,
            confidence=0.8,
            risk=RiskLevel.MEDIUM,
            raw=paste,
        )
