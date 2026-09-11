"""Gravatar collector: public profile and avatar derived from the target's email.

Fully free — Gravatar's legacy JSON profile endpoint and avatar check require no
API key (verified live against `https://www.gravatar.com` before writing this;
Gravatar's newer v3 API exists too but returns less without an API key, so we
stick with the classic endpoint the spec calls for).

MD5 is Gravatar's own hashing spec for building profile/avatar URLs, not a
choice made here — it is not used for anything security-sensitive.
"""

from __future__ import annotations

import hashlib
from typing import Any

import httpx

from footprint_recon.collectors.base import Collector
from footprint_recon.config import Config, load_config
from footprint_recon.models import Finding, Identifier, IdentifierType, RiskLevel, Target

_PROFILE_URL = "https://www.gravatar.com/{hash}.json"
_AVATAR_URL = "https://www.gravatar.com/avatar/{hash}?d=404"
_REQUEST_TIMEOUT = 10.0


class GravatarCollector(Collector):
    """Looks up the public Gravatar profile and avatar tied to the target's email."""

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or load_config()

    @property
    def name(self) -> str:
        return "gravatar"

    async def collect(self, target: Target) -> list[Finding]:
        if not target.email:
            return []

        email_hash = hashlib.md5(target.email.strip().lower().encode()).hexdigest()
        headers = {"user-agent": self._config.user_agent}
        async with httpx.AsyncClient(
            timeout=_REQUEST_TIMEOUT, headers=headers, follow_redirects=True
        ) as client:
            profile = await self._get_profile(client, email_hash)
            if profile is not None:
                return self._profile_findings(target.email, profile)

            has_avatar = await self._has_public_avatar(client, email_hash)

        if has_avatar:
            return [self._avatar_only_finding(target.email, email_hash)]
        return []

    async def _get_profile(
        self, client: httpx.AsyncClient, email_hash: str
    ) -> dict[str, Any] | None:
        """Fetch the public profile, or None if there isn't one."""
        response = await client.get(_PROFILE_URL.format(hash=email_hash))
        if response.status_code == 404:
            return None
        response.raise_for_status()
        entries = response.json().get("entry", [])
        return entries[0] if entries else None

    async def _has_public_avatar(self, client: httpx.AsyncClient, email_hash: str) -> bool:
        """HEAD-check the avatar so we don't download image bytes just to see if it exists."""
        response = await client.head(_AVATAR_URL.format(hash=email_hash))
        return response.status_code == 200

    def _profile_findings(self, email: str, profile: dict[str, Any]) -> list[Finding]:
        identifiers = [Identifier(type=IdentifierType.EMAIL, value=email)]
        if username := profile.get("preferredUsername"):
            identifiers.append(Identifier(type=IdentifierType.USERNAME, value=username))
        if display_name := profile.get("displayName"):
            identifiers.append(Identifier(type=IdentifierType.FULL_NAME, value=display_name))
        if location := profile.get("currentLocation"):
            identifiers.append(Identifier(type=IdentifierType.LOCATION, value=location))

        pii_fields = ("aboutMe", "currentLocation", "company", "job_title", "pronouns")
        has_pii = any(profile.get(field) for field in pii_fields)

        findings = [
            Finding(
                collector=self.name,
                identifiers=identifiers,
                title="Public Gravatar profile",
                detail=(
                    f"Display name: {profile.get('displayName', '?')}. "
                    f"Bio: {profile.get('aboutMe') or '(none)'}. "
                    f"Location: {profile.get('currentLocation') or '(none)'}. "
                    f"Company/role: {profile.get('company') or '?'} / "
                    f"{profile.get('job_title') or '?'}."
                ),
                source_url=profile.get("profileUrl"),
                confidence=1.0,
                risk=RiskLevel.MEDIUM if has_pii else RiskLevel.LOW,
                raw=profile,
            )
        ]

        for account in profile.get("accounts", []):
            findings.append(self._linked_account_finding(email, account))
        return findings

    def _linked_account_finding(self, email: str, account: dict[str, Any]) -> Finding:
        identifiers = [Identifier(type=IdentifierType.EMAIL, value=email)]
        if url := account.get("url"):
            identifiers.append(Identifier(type=IdentifierType.URL, value=url))
        if username := account.get("username"):
            identifiers.append(Identifier(type=IdentifierType.USERNAME, value=username))

        service = account.get("name") or account.get("domain") or "unknown service"
        return Finding(
            collector=self.name,
            identifiers=identifiers,
            title=f"Linked account: {service}",
            detail=f"Publicly linked on Gravatar as {account.get('display', '?')} on {service}.",
            source_url=account.get("url"),
            confidence=0.9,
            risk=RiskLevel.LOW,
            raw=account,
        )

    def _avatar_only_finding(self, email: str, email_hash: str) -> Finding:
        return Finding(
            collector=self.name,
            identifiers=[Identifier(type=IdentifierType.EMAIL, value=email)],
            title="Public Gravatar avatar (no public profile)",
            detail="An avatar image is registered for this email, but no public profile page.",
            source_url=_AVATAR_URL.format(hash=email_hash).replace("?d=404", ""),
            confidence=1.0,
            risk=RiskLevel.LOW,
            raw={},
        )
