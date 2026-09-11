"""Common interface every OSINT collector implements.

Collectors are plugged into the :class:`~footprint_recon.aggregator.Aggregator`
one at a time (SRP: one source per collector) and can be toggled off without
touching the others (OCP: new sources are added, existing ones untouched).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from footprint_recon.models import Finding, Target


class Collector(ABC):
    """Base class for a single OSINT source.

    Attributes:
        enabled: Whether the aggregator should run this collector. Defaults
            to ``True``; set to ``False`` (e.g. from config) to skip a source
            without removing it from the pipeline.
    """

    enabled: bool = True

    @property
    @abstractmethod
    def name(self) -> str:
        """Short, stable identifier for this collector (used in `Finding.collector`)."""

    @abstractmethod
    async def collect(self, target: Target) -> list[Finding]:
        """Query this source for everything it knows about `target`.

        Args:
            target: The identifiers to look up. Implementations should only
                use the fields relevant to them (e.g. `email_breach` ignores
                `target.usernames`).

        Returns:
            Findings gathered from this source. Empty list if nothing was
            found — never raises on a plain "no results".
        """
