"""Tests for the CPF collector. No HTTP, no third-party lookup — pure context generation."""

from __future__ import annotations

from footprint_recon.collectors.cpf import CpfCollector
from footprint_recon.models import IdentifierType, RiskLevel, Target


async def test_no_cpf_returns_nothing() -> None:
    assert await CpfCollector().collect(Target()) == []


async def test_cpf_yields_one_context_finding() -> None:
    findings = await CpfCollector().collect(Target(cpf="123.456.789-00"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.risk == RiskLevel.MEDIUM
    assert finding.source_url == (
        "https://servicos.receita.fazenda.gov.br/servicos/cpf/consultasituacao/consultapublica.asp"
    )
    assert any(
        i.type == IdentifierType.CPF and i.value == "123.456.789-00" for i in finding.identifiers
    )


async def test_full_name_is_included_when_present() -> None:
    findings = await CpfCollector().collect(Target(cpf="123.456.789-00", full_name="Jane Doe"))

    ids = findings[0].identifiers
    assert any(i.type == IdentifierType.FULL_NAME and i.value == "Jane Doe" for i in ids)


async def test_no_full_name_means_only_cpf_identifier() -> None:
    findings = await CpfCollector().collect(Target(cpf="123.456.789-00"))
    assert len(findings[0].identifiers) == 1
