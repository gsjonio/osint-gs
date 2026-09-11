"""Username collector: multi-platform enumeration via the WhatsMyName dataset.

No hardcoded per-site signatures. Site patterns (URL template, "exists" vs.
"missing" HTTP status/body markers) are reused from the community-maintained
WhatsMyName project (https://github.com/WebBreacher/WhatsMyName), fetched once
and cached locally instead of vendored, so it stays current without us
maintaining ~700 site definitions by hand.

Known limitation: unlike the other collectors (2-3 requests each), this one
issues one lightweight GET per (username, site) pair against ~700 third-party
sites — the same single-profile-URL check a human does by hand, and how
WhatsMyName/Sherlock themselves operate. We do not fetch each site's
robots.txt before that single request (~700 extra requests for one field
check each felt disproportionate); concurrency is capped and every request
has a timeout to stay a lightweight, one-shot lookup rather than a crawl.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from footprint_recon.collectors.base import Collector
from footprint_recon.config import Config, load_config
from footprint_recon.models import Finding, Identifier, IdentifierType, RiskLevel, Target

_WMN_DATA_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_CACHE_PATH = Path.home() / ".cache" / "footprint_recon" / "wmn-data.json"
_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
_REQUEST_TIMEOUT = 8.0
_MAX_CONCURRENCY = 30


class UsernameCollector(Collector):
    """Checks whether the target's usernames exist across the WhatsMyName site list."""

    def __init__(
        self, config: Config | None = None, sites: list[dict[str, Any]] | None = None
    ) -> None:
        """Args:
            config: Settings (only `user_agent` is used). Loaded from `.env` if omitted.
            sites: Inject a WhatsMyName-shaped site list directly (used by tests) instead
                of downloading/caching the real dataset.
        """
        self._config = config or load_config()
        self._preloaded_sites = sites

    @property
    def name(self) -> str:
        return "username"

    async def collect(self, target: Target) -> list[Finding]:
        if not target.usernames:
            return []

        headers = {"user-agent": self._config.user_agent}
        async with httpx.AsyncClient(
            timeout=_REQUEST_TIMEOUT, headers=headers, follow_redirects=True
        ) as client:
            sites = await self._load_sites(client)
            semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)
            results = await asyncio.gather(
                *(
                    self._check_site(client, semaphore, username, site)
                    for username in target.usernames
                    for site in sites
                    if "{account}" in site.get("uri_check", "")
                )
            )
        return [finding for finding in results if finding is not None]

    async def _load_sites(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        """Return the WhatsMyName site list, from the injected override, a fresh local
        cache, or a freshly downloaded copy (falling back to a stale cache on failure).
        """
        if self._preloaded_sites is not None:
            return self._preloaded_sites

        if self._is_cache_fresh():
            return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))["sites"]

        try:
            response = await client.get(_WMN_DATA_URL)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError:
            if _CACHE_PATH.is_file():
                return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))["sites"]
            raise

        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(json.dumps(data), encoding="utf-8")
        return data["sites"]

    def _is_cache_fresh(self) -> bool:
        return (
            _CACHE_PATH.is_file()
            and (time.time() - _CACHE_PATH.stat().st_mtime) < _CACHE_TTL_SECONDS
        )

    async def _check_site(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        username: str,
        site: dict[str, Any],
    ) -> Finding | None:
        url = site["uri_check"].format(account=quote(username, safe=""))
        async with semaphore:
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                return None

        exists = response.status_code == site.get("e_code") and (
            not site.get("e_string") or site["e_string"] in response.text
        )
        if not exists:
            return None
        return self._found_finding(username, site, url)

    def _found_finding(self, username: str, site: dict[str, Any], url: str) -> Finding:
        site_name = site.get("name", "unknown site")
        return Finding(
            collector=self.name,
            identifiers=[
                Identifier(type=IdentifierType.USERNAME, value=username),
                Identifier(type=IdentifierType.URL, value=url),
            ],
            title=f"Username found: {site_name}",
            detail=(
                f"Account '{username}' exists on {site_name} "
                f"({site.get('cat', 'uncategorized')})."
            ),
            source_url=url,
            confidence=0.85,
            risk=RiskLevel.LOW,
            raw=site,
        )
