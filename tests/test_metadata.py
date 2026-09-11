"""Tests for the EXIF metadata collector. Fully offline: builds real image files."""

from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image
from PIL.TiffImagePlugin import IFDRational

from footprint_recon.collectors.metadata import MetadataCollector
from footprint_recon.models import IdentifierType, RiskLevel, Target

# ExifTags.IFD constants, inlined to avoid importing Pillow internals in tests.
_EXIF_IFD = 0x8769
_GPS_IFD = 0x8825
_MAKE, _MODEL, _SOFTWARE = 0x010F, 0x0110, 0x0131
_DATE_TIME_ORIGINAL = 0x9003


def _make_image(path: Path, *, with_gps: bool = False, with_device: bool = False) -> None:
    img = Image.new("RGB", (4, 4), color="blue")
    exif = img.getexif()
    if with_device:
        exif[_MAKE] = "TestMake"
        exif[_MODEL] = "TestModel"
        exif[_SOFTWARE] = "TestSoftware"
        exif[_EXIF_IFD] = {_DATE_TIME_ORIGINAL: "2024:01:02 03:04:05"}
    if with_gps:
        exif[_GPS_IFD] = {
            1: "N",
            2: (IFDRational(37, 1), IFDRational(46, 1), IFDRational(30, 1)),
            3: "W",
            4: (IFDRational(122, 1), IFDRational(25, 1), IFDRational(10, 1)),
        }
    if with_gps or with_device:
        img.save(path, exif=exif)
    else:
        img.save(path)


async def test_no_files_returns_nothing() -> None:
    assert await MetadataCollector().collect(Target()) == []


async def test_image_without_exif_yields_nothing(tmp_path: Path) -> None:
    path = tmp_path / "clean.jpg"
    _make_image(path)

    findings = await MetadataCollector().collect(Target(file_paths=[path]))
    assert findings == []


async def test_gps_yields_high_risk_location_finding(tmp_path: Path) -> None:
    path = tmp_path / "with_gps.jpg"
    _make_image(path, with_gps=True)

    findings = await MetadataCollector().collect(Target(file_paths=[path]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.risk == RiskLevel.HIGH
    location = next(i for i in finding.identifiers if i.type == IdentifierType.LOCATION)
    lat, lon = (float(v) for v in location.value.split(","))
    assert lat == pytest.approx(37 + 46 / 60 + 30 / 3600)
    assert lon == pytest.approx(-(122 + 25 / 60 + 10 / 3600))


async def test_device_without_gps_yields_low_risk_finding(tmp_path: Path) -> None:
    path = tmp_path / "with_device.jpg"
    _make_image(path, with_device=True)

    findings = await MetadataCollector().collect(Target(file_paths=[path]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.risk == RiskLevel.LOW
    device = next(i for i in finding.identifiers if i.type == IdentifierType.DEVICE)
    assert device.value == "TestMake TestModel"
    assert "Captured: 2024:01:02 03:04:05" in finding.detail


async def test_nonexistent_or_non_image_file_is_skipped(tmp_path: Path) -> None:
    bogus = tmp_path / "not_an_image.txt"
    bogus.write_text("hello")

    findings = await MetadataCollector().collect(
        Target(file_paths=[bogus, tmp_path / "missing.jpg"])
    )
    assert findings == []
