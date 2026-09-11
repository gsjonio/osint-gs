"""GitHub collector: emails leaked through the git author line of public commits.

A very common, underestimated exposure vector: `git commit` embeds whatever
`user.email` is locally configured into every commit's `From:` header, and
that's visible on any public repo regardless of what email is shown on the
GitHub profile itself. Fully free, no token required — `GITHUB_TOKEN` (if set)
only raises the API rate limit.

Note: GitHub's `/users/{user}/events/public` API used to embed a full
`commits` array per push (sha + author) directly in the payload; that field
was removed at some point and only `payload.head` (the push's latest commit
SHA) remains — verified live against the real API before writing this. So we
only check each push's head commit, not every commit within it. That is
enough to detect a leaking email in practice, and keeps this a lightweight,
one-commit-per-push check rather than a full history crawl.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from footprint_recon.collectors.base import Collector
from footprint_recon.config import Config, load_config
from footprint_recon.models import Finding, Identifier, IdentifierType, RiskLevel, Target

_EVENTS_URL = "https://api.github.com/users/{username}/events/public"
_PATCH_URL = "https://github.com/{repo}/commit/{sha}.patch"
_REQUEST_TIMEOUT = 10.0
_MAX_COMMITS_PER_USER = 15
_MAX_CONCURRENCY = 5
_FROM_LINE = re.compile(r"^From:.*<([^>]+)>", re.MULTILINE)


class GithubCollector(Collector):
    """Finds emails leaked via public GitHub commit authorship."""

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or load_config()

    @property
    def name(self) -> str:
        return "github"

    async def collect(self, target: Target) -> list[Finding]:
        if not target.usernames:
            return []

        api_headers = {"accept": "application/vnd.github+json"}
        if self._config.github_token:
            api_headers["authorization"] = f"Bearer {self._config.github_token}"

        # Base client headers apply to every request, including the plain github.com
        # .patch fetches below — so the token/accept header only go on the explicit
        # api.github.com call via `headers=api_headers`, not to every host we touch.
        base_headers = {"user-agent": self._config.user_agent}
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT, headers=base_headers) as client:
            findings: list[Finding] = []
            for username in target.usernames:
                findings += await self._collect_for_username(
                    client, api_headers, target.email, username
                )
            return findings

    async def _collect_for_username(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        target_email: str | None,
        username: str,
    ) -> list[Finding]:
        commits = await self._recent_push_commits(client, api_headers, username)
        if not commits:
            return []

        semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)
        results = await asyncio.gather(
            *(self._fetch_author_email(client, semaphore, repo, sha) for repo, sha in commits)
        )

        seen_emails: dict[str, tuple[str, str, str]] = {}  # email -> (repo, sha, name)
        for result in results:
            if result is None:
                continue
            email, repo, sha, name = result
            seen_emails.setdefault(email, (repo, sha, name))

        return [
            self._leak_finding(username, email, repo, sha, name, is_target=email == target_email)
            for email, (repo, sha, name) in seen_emails.items()
        ]

    async def _recent_push_commits(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], username: str
    ) -> list[tuple[str, str]]:
        """Return up to `_MAX_COMMITS_PER_USER` (repo, sha) pairs from recent public pushes."""
        response = await client.get(_EVENTS_URL.format(username=username), headers=api_headers)
        if response.status_code in (404, 403):
            return []
        response.raise_for_status()

        commits: list[tuple[str, str]] = []
        for event in response.json():
            if event.get("type") != "PushEvent":
                continue
            repo = event.get("repo", {}).get("name")
            sha = event.get("payload", {}).get("head")
            if repo and sha:
                commits.append((repo, sha))
            if len(commits) >= _MAX_COMMITS_PER_USER:
                break
        return commits

    async def _fetch_author_email(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        repo: str,
        sha: str,
    ) -> tuple[str, str, str, str] | None:
        """Return (email, repo, sha, author_name) parsed from the commit's `From:` line."""
        async with semaphore:
            try:
                response = await client.get(_PATCH_URL.format(repo=repo, sha=sha))
            except httpx.HTTPError:
                return None
        if response.status_code != 200:
            return None
        match = _FROM_LINE.search(response.text)
        if not match:
            return None
        name_line = response.text.splitlines()[1] if len(response.text.splitlines()) > 1 else ""
        name = name_line.split("<")[0].removeprefix("From:").strip()
        return match.group(1), repo, sha, name

    def _leak_finding(
        self, username: str, email: str, repo: str, sha: str, name: str, *, is_target: bool
    ) -> Finding:
        return Finding(
            collector=self.name,
            identifiers=[
                Identifier(type=IdentifierType.USERNAME, value=username),
                Identifier(type=IdentifierType.EMAIL, value=email),
            ],
            title=f"Email exposed in GitHub commits: {email}",
            detail=(
                f"Commit author '{name} <{email}>' found in {repo}@{sha[:10]}. "
                "Fix: set a private GitHub no-reply address as `git config user.email` "
                "for future commits (past commits stay exposed unless history is rewritten)."
            ),
            source_url=f"https://github.com/{repo}/commit/{sha}",
            confidence=1.0,
            risk=RiskLevel.HIGH if is_target else RiskLevel.MEDIUM,
            raw={"repo": repo, "sha": sha, "name": name, "email": email},
        )
