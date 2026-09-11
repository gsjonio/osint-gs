"""Loads credentials and settings from a `.env` file (see `.env.example`) plus the environment.

No third-party dotenv library: the format is trivial (`KEY=VALUE` lines) and a
real exported environment variable should always win over the file, which
`os.environ.setdefault` gives us for free.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def _load_dotenv(path: Path = _ENV_FILE) -> None:
    """Populate `os.environ` from a `KEY=VALUE` file without overriding real env vars."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


@dataclass(frozen=True)
class Config:
    """Resolved settings for the current run."""

    hibp_api_key: str | None
    github_token: str | None
    user_agent: str


def load_config() -> Config:
    """Load `.env` (if present) and return the resolved configuration."""
    _load_dotenv()
    return Config(
        hibp_api_key=os.environ.get("HIBP_API_KEY") or None,
        github_token=os.environ.get("GITHUB_TOKEN") or None,
        user_agent=os.environ.get(
            "FOOTPRINT_RECON_USER_AGENT", "footprint-recon/0.1 (self-osint tool)"
        ),
    )
