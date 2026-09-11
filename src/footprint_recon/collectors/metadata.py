"""Metadata (EXIF) collector: what your own photos leak about you.

Runs entirely offline against files listed in `Target.file_paths` — no
network calls, no third-party service. Extracts GPS coordinates, capture
timestamp, and camera/software info via Pillow.

Verified live (by round-tripping a synthetic image) that `DateTimeOriginal`
lives in the Exif sub-IFD (tag 0x8769), not the base IFD0 that `Image.getexif()`
returns directly — a naive `getexif()`-only read would silently miss it on
real camera photos, so GPS and Exif sub-IFDs are both fetched explicitly via
`get_ifd()`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError

from footprint_recon.collectors.base import Collector
from footprint_recon.models import Finding, Identifier, IdentifierType, RiskLevel, Target


class MetadataCollector(Collector):
    """Extracts EXIF metadata from image files the user points it at."""

    @property
    def name(self) -> str:
        return "metadata"

    async def collect(self, target: Target) -> list[Finding]:
        findings = []
        for path in target.file_paths:
            finding = self._scan_file(Path(path))
            if finding is not None:
                findings.append(finding)
        return findings

    def _scan_file(self, path: Path) -> Finding | None:
        try:
            with Image.open(path) as img:
                base = img.getexif()
                exif_sub = base.get_ifd(ExifTags.IFD.Exif)
                gps_raw = base.get_ifd(ExifTags.IFD.GPSInfo)
        except (OSError, UnidentifiedImageError):
            return None  # not a readable image

        if not base:
            return None

        tags: dict[str, Any] = {ExifTags.TAGS.get(k, k): v for k, v in base.items()}
        tags.update({ExifTags.TAGS.get(k, k): v for k, v in exif_sub.items()})
        gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_raw.items()}

        identifiers: list[Identifier] = []
        detail_parts: list[str] = []
        risk = RiskLevel.LOW

        try:
            coords = self._decimal_coords(gps)
        except (TypeError, ValueError, ZeroDivisionError):
            # Malformed GPS fields in a corrupted/edge-case file; keep the non-GPS tags.
            coords = None
        if coords is not None:
            lat, lon = coords
            identifiers.append(
                Identifier(type=IdentifierType.LOCATION, value=f"{lat:.6f},{lon:.6f}")
            )
            detail_parts.append(f"GPS coordinates: {lat:.6f}, {lon:.6f}")
            risk = RiskLevel.HIGH

        if date_original := tags.get("DateTimeOriginal"):
            detail_parts.append(f"Captured: {date_original}")

        device = " ".join(str(tags[k]) for k in ("Make", "Model") if tags.get(k)).strip()
        if device:
            identifiers.append(Identifier(type=IdentifierType.DEVICE, value=device))
            detail_parts.append(f"Device: {device}")

        if software := tags.get("Software"):
            detail_parts.append(f"Software: {software}")

        if not detail_parts:
            return None

        raw = {k: str(v) for k, v in tags.items()}
        if gps:
            raw["GPSInfo"] = {k: str(v) for k, v in gps.items()}

        return Finding(
            collector=self.name,
            identifiers=identifiers,
            title=f"EXIF metadata found in {path.name}",
            detail="; ".join(detail_parts),
            source_url=None,
            confidence=1.0,
            risk=risk,
            raw=raw,
        )

    @staticmethod
    def _decimal_coords(gps: dict[str, Any]) -> tuple[float, float] | None:
        lat, lat_ref = gps.get("GPSLatitude"), gps.get("GPSLatitudeRef")
        lon, lon_ref = gps.get("GPSLongitude"), gps.get("GPSLongitudeRef")
        if not (lat and lat_ref and lon and lon_ref):
            return None
        return _dms_to_decimal(lat, lat_ref), _dms_to_decimal(lon, lon_ref)


def _dms_to_decimal(dms: tuple[Any, Any, Any], ref: str) -> float:
    degrees, minutes, seconds = (float(v) for v in dms)
    decimal = degrees + minutes / 60 + seconds / 3600
    return -decimal if ref in ("S", "W") else decimal
