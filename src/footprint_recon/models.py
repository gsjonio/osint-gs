"""Core data contracts shared by every collector, the aggregator, and the report.

All identifiers the tool ever produces or consumes funnel through
:class:`Identifier`, so the identity graph in ``correlate.py`` can treat any
two :class:`Finding` objects as linked whenever they share one.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class IdentifierType(StrEnum):
    """Kind of a real-world identifier that can be pivoted on."""

    EMAIL = "email"
    USERNAME = "username"
    FULL_NAME = "full_name"
    PHONE = "phone"
    CPF = "cpf"
    DOMAIN = "domain"
    URL = "url"
    LOCATION = "location"
    DEVICE = "device"


class RiskLevel(StrEnum):
    """Severity of a finding, low to critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Identifier(BaseModel):
    """A single real-world identifier (an email, a username, a domain...).

    Frozen and hashable so it can be used as a node key in the identity
    graph built by ``correlate.py``.
    """

    model_config = ConfigDict(frozen=True)

    type: IdentifierType
    value: str

    def __hash__(self) -> int:
        return hash((self.type, self.value.lower()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Identifier):
            return NotImplemented
        return self.type == other.type and self.value.lower() == other.value.lower()


class Finding(BaseModel):
    """One piece of evidence produced by a collector."""

    collector: str
    identifiers: list[Identifier] = Field(default_factory=list)
    title: str
    detail: str
    source_url: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    risk: RiskLevel
    raw: dict = Field(default_factory=dict)


class Target(BaseModel):
    """The user's own identifiers, declared as input for a self-assessment run."""

    email: str | None = None
    full_name: str | None = None
    usernames: list[str] = Field(default_factory=list)
    phone: str | None = None
    cpf: str | None = None
    domains: list[str] = Field(default_factory=list)
    location: str | None = None
    """Home city/region, e.g. for the `"{full_name}" "{location}"` dork."""
    file_paths: list[Path] = Field(default_factory=list)
    """Image files to scan for EXIF leaks (metadata collector). Not an identifier."""

    def identifiers(self) -> list[Identifier]:
        """Flatten the populated fields into :class:`Identifier` objects."""
        result: list[Identifier] = []
        if self.email:
            result.append(Identifier(type=IdentifierType.EMAIL, value=self.email))
        if self.full_name:
            result.append(Identifier(type=IdentifierType.FULL_NAME, value=self.full_name))
        result.extend(
            Identifier(type=IdentifierType.USERNAME, value=username)
            for username in self.usernames
        )
        if self.phone:
            result.append(Identifier(type=IdentifierType.PHONE, value=self.phone))
        if self.cpf:
            result.append(Identifier(type=IdentifierType.CPF, value=self.cpf))
        result.extend(
            Identifier(type=IdentifierType.DOMAIN, value=domain) for domain in self.domains
        )
        if self.location:
            result.append(Identifier(type=IdentifierType.LOCATION, value=self.location))
        return result
