from unittest.mock import patch

import pytest

from fath_cuan.converters.osv import _base_version, _parse_gav, convert
from fath_cuan.models.input import InputDocument
from tests.conftest import (
    SAMPLE_DUPLICATE_CVE_DATA,
    SAMPLE_INPUT_DATA,
    SAMPLE_MULTI_CVE_DATA,
)


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_returns_one_record_per_cve(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_MULTI_CVE_DATA)
    results = convert(doc)
    assert len(results) == 2
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.0.0"
    assert results[1].id == "x_RHLW-CVE-2024-26308-1.0.0"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_deduplicates_cves(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_DUPLICATE_CVE_DATA)
    results = convert(doc)
    assert len(results) == 2


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_id_format_matches_reference(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.0.0"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_schema_version(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].schema_version == "1.6.8"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_affected_package(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    pkg = results[0].affected[0].package
    assert pkg.ecosystem == "Maven"
    assert pkg.name == "org.example:artifact"
    assert pkg.purl == "pkg:maven/org.example/artifact"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_fixed_version_is_full_gav_version(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    events = results[0].affected[0].ranges[0].events
    assert events[0].introduced == "0"
    assert events[1].fixed == "1.0.0.rhlw-00001"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_base_version_stripped_in_metadata(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    lw = results[0].database_specific.lightwell
    assert lw.backport_base_version == "1.0.0"
    assert lw.build_id == "BQA6SUOGYCIAA"
    assert lw.source == "pnc-build"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_credits(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert len(results[0].credits) == 1
    assert results[0].credits[0].name == "Red Hat Lightwell"
    assert results[0].credits[0].type == "REMEDIATION_DEVELOPER"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_modified_from_created(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].modified == "2026-07-15T14:02:27Z"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_nvd_reference_added_when_no_upstream(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    refs = results[0].references
    assert len(refs) == 1
    assert refs[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2024-25710"


@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_upstream_severity_populated(mock_fetch: object) -> None:
    mock_fetch.return_value = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        "aliases": ["GHSA-xxxx-yyyy-zzzz", "CVE-2024-25710"],
        "summary": "Test summary",
        "details": "Test details",
        "references": [
            {"url": "https://github.com/example/commit/abc123", "type": "WEB"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-25710", "type": "WEB"},
        ],
    }
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    r = results[0]
    assert len(r.severity) == 1
    assert r.severity[0].type == "CVSS_V3"
    assert r.summary == "Test summary"
    assert r.details == "Test details"
    assert "GHSA-xxxx-yyyy-zzzz" in r.aliases
    assert "CVE-2024-25710" in r.aliases


@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_commit_urls_become_fix_type(mock_fetch: object) -> None:
    mock_fetch.return_value = {
        "references": [
            {"url": "https://github.com/example/repo/commit/abc123", "type": "WEB"},
        ],
    }
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    commit_ref = [r for r in results[0].references if "/commit/" in r.url]
    assert commit_ref[0].type == "FIX"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_model_dump_excludes_none(mock_fetch: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    dumped = results[0].model_dump(exclude_none=True)
    intro_event = dumped["affected"][0]["ranges"][0]["events"][0]
    assert "introduced" in intro_event
    assert "fixed" not in intro_event
    fix_event = dumped["affected"][0]["ranges"][0]["events"][1]
    assert "fixed" in fix_event
    assert "introduced" not in fix_event


def test_parse_gav_valid() -> None:
    g, a, v = _parse_gav("org.example:artifact:1.0.0")
    assert g == "org.example"
    assert a == "artifact"
    assert v == "1.0.0"


def test_parse_gav_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid GAV format"):
        _parse_gav("invalid-gav")


def test_base_version_strips_rhlw() -> None:
    assert _base_version("2.4.8.rhlw-00001") == "2.4.8"


def test_base_version_strips_rhlw_dp() -> None:
    assert _base_version("4.0.4.rhlw-dp-00002") == "4.0.4"


def test_base_version_unchanged_without_qualifier() -> None:
    assert _base_version("5.3.18") == "5.3.18"
