"""CPF collector: defensive context only, never a "consulta CPF" lookup.

Deliberately does not query any third-party "CPF lookup" service — those are
fed by leaked-data brokers, which this project's scope rules (see the top-level
prompt, §1.2) forbid integrating with. What this collector does instead:

1. Documents what a leaked CPF enables in Brazil: combined with full name and
   date of birth, it is enough for identity fraud (opening accounts, credit
   applications in the victim's name) — the actual point of this Finding.
2. Points at the cross-reference to make manually: if `email_breach` reports a
   breach whose `DataClasses` include CPF, that breach is far more dangerous
   than an average credential leak (email_breach already flags that case as
   CRITICAL on its own — this Finding is what explains why).
3. Cites Receita Federal's own public "situação cadastral" lookup
   (https://servicos.receita.fazenda.gov.br) as the one legitimate,
   first-party channel for the CPF's owner to check it — a citation only,
   never fetched or automated here (it's captcha-protected by design).
"""

from __future__ import annotations

from footprint_recon.collectors.base import Collector
from footprint_recon.models import Finding, Identifier, IdentifierType, RiskLevel, Target

_RECEITA_URL = (
    "https://servicos.receita.fazenda.gov.br/servicos/cpf/consultasituacao/consultapublica.asp"
)


class CpfCollector(Collector):
    """Documents CPF exposure risk; never queries a third-party CPF lookup service."""

    @property
    def name(self) -> str:
        return "cpf"

    async def collect(self, target: Target) -> list[Finding]:
        if not target.cpf:
            return []

        identifiers = [Identifier(type=IdentifierType.CPF, value=target.cpf)]
        if target.full_name:
            identifiers.append(Identifier(type=IdentifierType.FULL_NAME, value=target.full_name))

        return [
            Finding(
                collector=self.name,
                identifiers=identifiers,
                title="CPF exposure risk context",
                detail=(
                    "A CPF combined with full name and date of birth is enough for "
                    "identity fraud in Brazil (account opening, credit applications in "
                    "your name). Cross-check manually: if any email_breach finding lists "
                    "CPF/national ID among its DataClasses, that breach is CRITICAL — an "
                    "attacker likely has your CPF tied to your email already. To check "
                    "your own CPF's registration status, use Receita Federal's official, "
                    "free public lookup (linked below) — never a third-party 'consulta "
                    "CPF' site, which is almost always a leaked-data broker."
                ),
                source_url=_RECEITA_URL,
                confidence=1.0,
                risk=RiskLevel.MEDIUM,
                raw={},
            )
        ]
