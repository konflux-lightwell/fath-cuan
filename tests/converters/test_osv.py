from unittest.mock import patch

import pytest

from fath_cuan.converters.osv import _base_version, _classify_reference_type, _parse_gav, convert
from fath_cuan.models.input import InputDocument
from tests.conftest import (
    SAMPLE_DUPLICATE_CVE_DATA,
    SAMPLE_INPUT_DATA,
    SAMPLE_MULTI_CVE_DATA,
)


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_returns_one_record_per_cve(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_MULTI_CVE_DATA)
    results = convert(doc)
    assert len(results) == 2
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.0.0"
    assert results[1].id == "x_RHLW-CVE-2024-26308-1.0.0"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_deduplicates_cves(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_DUPLICATE_CVE_DATA)
    results = convert(doc)
    assert len(results) == 2


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_id_prefix_is_x_rhlw(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].id.startswith("x_RHLW-")
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.0.0"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_published_field_set(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].published == "2026-07-15T14:02:27Z"
    assert results[0].modified == "2026-07-15T14:02:27Z"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_withdrawn_is_none(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].withdrawn is None


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_versions_array_populated(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].affected[0].versions == ["1.0.0"]


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_affected_package(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    pkg = results[0].affected[0].package
    assert pkg.ecosystem == "Maven"
    assert pkg.name == "org.example:artifact"
    assert pkg.purl == "pkg:maven/org.example/artifact"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_fixed_version_is_full_gav_version(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    events = results[0].affected[0].ranges[0].events
    assert events[0].introduced == "0"
    assert events[1].fixed == "1.0.0.rhlw-00001"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_base_version_stripped_in_metadata(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    lw = results[0].database_specific.lightwell
    assert lw.backport_base_version == "1.0.0"
    assert lw.build_id == "BQA6SUOGYCIAA"
    assert lw.source == "pnc-build"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_credits(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert len(results[0].credits) == 1
    assert results[0].credits[0].name == "Red Hat Lightwell"
    assert results[0].credits[0].type == "REMEDIATION_DEVELOPER"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_nvd_reference_typed_as_advisory(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    refs = results[0].references
    nvd_ref = [r for r in refs if "nvd.nist.gov" in r.url]
    assert nvd_ref[0].type == "ADVISORY"


@patch("fath_cuan.converters.osv._fetch_upstream_osv")
@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
def test_upstream_severity_populated(mock_nvd: object, mock_osv: object) -> None:
    mock_osv.return_value = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
        ],
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
    assert len(r.severity) >= 1
    assert r.severity[0].type == "CVSS_V3"
    assert r.summary == "Test summary"
    assert r.details == "Test details"
    assert "GHSA-xxxx-yyyy-zzzz" in r.aliases
    assert "CVE-2024-25710" in r.aliases


@patch("fath_cuan.converters.osv._fetch_upstream_osv")
@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
def test_commit_urls_typed_as_fix(mock_nvd: object, mock_osv: object) -> None:
    mock_osv.return_value = {
        "references": [
            {"url": "https://github.com/example/repo/commit/abc123", "type": "WEB"},
        ],
    }
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    commit_ref = [r for r in results[0].references if "/commit/" in r.url]
    assert commit_ref[0].type == "FIX"


@patch("fath_cuan.converters.osv._fetch_upstream_osv")
@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
def test_advisory_urls_typed_as_advisory(mock_nvd: object, mock_osv: object) -> None:
    mock_osv.return_value = {
        "references": [
            {"url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz", "type": "WEB"},
            {"url": "https://access.redhat.com/errata/RHSA-2026:1234", "type": "WEB"},
        ],
    }
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    ghsa_ref = [r for r in results[0].references if "advisories" in r.url]
    assert ghsa_ref[0].type == "ADVISORY"
    rh_ref = [r for r in results[0].references if "errata" in r.url]
    assert rh_ref[0].type == "ADVISORY"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
@patch("fath_cuan.converters.osv._fetch_nvd")
def test_nvd_fallback_for_summary(mock_nvd: object, mock_osv: object) -> None:
    mock_nvd.return_value = {
        "descriptions": [{"lang": "en", "value": "NVD description fallback"}],
        "metrics": {},
    }
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].summary == "NVD description fallback"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
@patch("fath_cuan.converters.osv._fetch_nvd")
def test_nvd_fallback_for_cvss(mock_nvd: object, mock_osv: object) -> None:
    mock_nvd.return_value = {
        "descriptions": [{"lang": "en", "value": "test"}],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
            ],
        },
    }
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert len(results[0].severity) >= 1
    assert results[0].severity[0].type == "CVSS_V3"


@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
@patch("fath_cuan.converters.osv._fetch_nvd")
def test_cvss_v4_from_nvd(mock_nvd: object, mock_osv: object) -> None:
    mock_nvd.return_value = {
        "descriptions": [{"lang": "en", "value": "test"}],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
            ],
            "cvssMetricV40": [
                {"cvssData": {"vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}}
            ],
        },
    }
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    types = [s.type for s in results[0].severity]
    assert "CVSS_V3" in types
    assert "CVSS_V4" in types


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_embargo_mode(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc, embargo=True)
    r = results[0]
    assert r.id == "x_RHLW-CVE-2024-25710-1.0.0"
    assert r.published is not None
    assert r.aliases == []
    assert r.affected[0].package.name == ""
    assert r.database_specific.lightwell.embargo_status == "pre-disclosure"
    mock_osv.assert_not_called()
    mock_nvd.assert_not_called()


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_model_dump_excludes_none(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    dumped = results[0].model_dump(exclude_none=True)
    assert "withdrawn" not in dumped
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


def test_classify_reference_type_commit() -> None:
    assert _classify_reference_type("https://github.com/foo/commit/abc", "WEB") == "FIX"


def test_classify_reference_type_advisory() -> None:
    assert (
        _classify_reference_type("https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "WEB")
        == "ADVISORY"
    )
    assert _classify_reference_type("https://github.com/advisories/GHSA-xxxx", "WEB") == "ADVISORY"
    assert (
        _classify_reference_type("https://access.redhat.com/errata/RHSA-2026:1234", "WEB")
        == "ADVISORY"
    )


def test_classify_reference_type_web() -> None:
    assert _classify_reference_type("https://example.com/blog/post", "WEB") == "WEB"
