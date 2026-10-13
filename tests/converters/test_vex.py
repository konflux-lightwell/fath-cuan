"""Tests for the CycloneDX 1.7 VEX converter."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from fath_cuan.converters.vex import VEXResult, convert, convert_build_index
from fath_cuan.models.build_index import BuildIndex
from fath_cuan.models.input import InputDocument
from tests.conftest import SAMPLE_INPUT_DATA


SAMPLE_BUILD_INDEX = {
    "ecosystem": "maven",
    "version": {"upstream": "6.0.3", "full": "6.0.3.rhlw-00001", "b": 1, "n": 0},
    "primaryPurl": "pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.3.rhlw-00001",
    "purls": ["pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.3.rhlw-00001"],
    "vulns": ["CVE-2022-40152"],
    "created": "2026-08-06T16:00:00+00:00",
}

SAMPLE_SBOM_SERIAL_NUMBERS = {
    "pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.3.rhlw-00001": "urn:uuid:4048efaf-e166-4041-b19f-6a1b2fec9293",
}


def _mock_no_enrichment(cve_id, osidb_client=None):
    """Return empty enrichment data (no network calls)."""
    return {"osidb_meta": None, "upstream": None, "nvd": None}


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_convert_build_index_produces_vex(mock_prefetch) -> None:
    """VEX converter produces per-CVE and multi-CVE documents."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    assert isinstance(result, VEXResult)
    assert len(result.per_cve) == 1
    assert result.multi_cve is not None

    cve_id, doc = result.per_cve[0]
    assert cve_id == "CVE-2022-40152"
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["version"] == 1
    assert len(doc["vulnerabilities"]) == 1

    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2022-40152"
    assert vuln["analysis"]["state"] == "resolved"
    assert vuln["analysis"]["response"] == ["update"]
    assert "recommendation" in vuln
    assert vuln["published"] == "2026-08-06T16:00:00Z"

    # Affects cross-references SBOM serial number
    assert len(vuln["affects"]) == 1
    ref = vuln["affects"][0]["ref"]
    assert "4048efaf-e166-4041-b19f-6a1b2fec9293" in ref
    assert vuln["affects"][0]["versions"][0]["status"] == "unaffected"

    # CWEs must NOT appear in output (LWLP-2370)
    assert "cwes" not in vuln


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_convert_build_index_no_vulns(mock_prefetch) -> None:
    """Build-index with no vulns produces empty VEX result."""
    data = {**SAMPLE_BUILD_INDEX, "vulns": []}
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(bi, sbom_serial_numbers={})

    assert result.per_cve == []
    assert result.multi_cve is None


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_convert_build_index_multi_cve(mock_prefetch) -> None:
    """Multi-CVE build-index produces multiple per-CVE docs and one aggregate."""
    data = {
        **SAMPLE_BUILD_INDEX,
        "vulns": ["CVE-2022-45688", "CVE-2023-5072"],
    }
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    assert len(result.per_cve) == 2
    assert result.per_cve[0][0] == "CVE-2022-45688"
    assert result.per_cve[1][0] == "CVE-2023-5072"

    assert result.multi_cve is not None
    assert len(result.multi_cve["vulnerabilities"]) == 2


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_convert_legacy_input(mock_prefetch) -> None:
    """Legacy InputDocument produces VEX result."""
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)

    assert isinstance(result, VEXResult)
    assert len(result.per_cve) == 1
    cve_id, vex_doc = result.per_cve[0]
    assert cve_id == "CVE-2024-25710"
    assert vex_doc["bomFormat"] == "CycloneDX"
    assert vex_doc["specVersion"] == "1.7"


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_no_metadata_section(mock_prefetch) -> None:
    """VEX documents must not contain a metadata section."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    _, doc = result.per_cve[0]
    assert "metadata" not in doc
    assert "components" not in doc

    if result.multi_cve:
        assert "metadata" not in result.multi_cve
        assert "components" not in result.multi_cve


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_references_structure(mock_prefetch) -> None:
    """Each vulnerability has a references entry with id and source."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    vuln = result.per_cve[0][1]["vulnerabilities"][0]
    assert len(vuln["references"]) >= 1
    ref = vuln["references"][0]
    assert ref["id"] == "CVE-2022-40152"
    assert "NVD" in ref["source"]["name"]
    assert "nvd.nist.gov" in ref["source"]["url"]


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_advisories_always_include_nvd(mock_prefetch) -> None:
    """Advisories always include at least the NVD entry."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers={})

    vuln = result.per_cve[0][1]["vulnerabilities"][0]
    assert any("nvd.nist.gov" in a["url"] for a in vuln["advisories"])
