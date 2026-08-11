from unittest.mock import patch

import pytest

from fath_cuan.converters.osv import (
    _base_version,
    _classify_reference_type,
    _extract_introduced,
    _jira_severity,
    _parse_gav,
    convert,
    refresh,
)
from fath_cuan.jira.models import VulnerabilityData
from fath_cuan.models.input import InputDocument
from fath_cuan.models.osv import OSVDocument
from fath_cuan.osidb import OsidbClient
from tests.conftest import (
    SAMPLE_DUPLICATE_CVE_DATA,
    SAMPLE_INPUT_DATA,
    SAMPLE_LW_VULN_DATA,
    SAMPLE_MIXED_VULN_DATA,
    SAMPLE_MULTI_CVE_DATA,
    SAMPLE_NOVEL_INPUT,
    SAMPLE_NOVEL_OSV_RECORD,
    SAMPLE_OSV_RECORD,
    SAMPLE_WITH_UPSTREAM_VERSION,
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
    assert pkg.purl == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"


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
    assert lw.source == "pnc-build"
    assert lw.lw_id is None


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


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_upstream_version_used_for_versions_array(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_WITH_UPSTREAM_VERSION)
    results = convert(doc)
    assert results[0].affected[0].versions == ["1.33"]


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_upstream_version_used_for_id(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_WITH_UPSTREAM_VERSION)
    results = convert(doc)
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.33"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_upstream_version_used_for_base_version_meta(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_WITH_UPSTREAM_VERSION)
    results = convert(doc)
    assert results[0].database_specific.lightwell.backport_base_version == "1.33"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_falls_back_to_base_version_without_upstream(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert results[0].affected[0].versions == ["1.0.0"]
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.0.0"


def test_extract_introduced_from_ecosystem_range() -> None:
    upstream = {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.springframework:spring-webmvc"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "6.1.0"}, {"fixed": "6.1.13"}],
                    }
                ],
            }
        ]
    }
    assert _extract_introduced(upstream, "org.springframework:spring-webmvc") == "6.1.0"


def test_extract_introduced_falls_back_to_zero() -> None:
    upstream = {
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "golang.org/x/crypto"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }
        ]
    }
    assert _extract_introduced(upstream, "org.example:artifact") == "0"


def test_extract_introduced_no_matching_package() -> None:
    upstream = {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.other:other"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0"}, {"fixed": "1.5"}],
                    }
                ],
            }
        ]
    }
    assert _extract_introduced(upstream, "org.example:artifact") == "0"


def test_extract_introduced_zero_in_upstream() -> None:
    upstream = {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.yaml:snakeyaml"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.0"}],
                    }
                ],
            }
        ]
    }
    assert _extract_introduced(upstream, "org.yaml:snakeyaml") == "0"


@patch("fath_cuan.converters.osv._fetch_upstream_osv")
@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
def test_introduced_from_upstream_in_full_record(mock_nvd: object, mock_osv: object) -> None:
    mock_osv.return_value = {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.example:artifact"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0.9.0"}, {"fixed": "1.2.0"}],
                    }
                ],
            }
        ],
    }
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    events = results[0].affected[0].ranges[0].events
    assert events[0].introduced == "0.9.0"
    assert events[1].fixed == "1.0.0.rhlw-00001"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_introduced_defaults_to_zero_without_upstream(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    events = results[0].affected[0].ranges[0].events
    assert events[0].introduced == "0"


# ---------------------------------------------------------------------------
# OSIDB integration
# ---------------------------------------------------------------------------

OSIDB_FLAW_RESPONSE = {
    "count": 1,
    "results": [
        {
            "uuid": "33501a2f-eb62-4aaa-9815-36c9832afcee",
            "vulnerability_id": "LW-2026-0468",
            "cve_id": None,
            "title": "Unclosed '[' in LDAP URL host spins thread forever",
            "impact": "CRITICAL",
            "source": "CUSTOMER",
            "cwe_id": "CWE-835",
            "cvss_scores": [
                {
                    "cvss_version": "V3",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "score": 7.5,
                }
            ],
            "cve_description": "parseHost dispatches any host beginning with '['.",
            "comment_zero": "",
            "references": [
                {
                    "url": "https://gitlab.cee.redhat.com/duffy/bananach/-/work_items/468",
                    "type": "SOURCE",
                }
            ],
            "affects": [],
            "components": ["api-ldap-model"],
            "embargoed": False,
            "visibility": "PUBLIC",
        }
    ],
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_osidb_enriches_novel_record(mock_osv: object, mock_nvd: object) -> None:
    client = OsidbClient(base_url="https://example.com", token="fake")
    with patch.object(client, "_get", return_value=OSIDB_FLAW_RESPONSE):
        doc = InputDocument.from_dict(SAMPLE_NOVEL_INPUT)
        results = convert(doc, osidb_client=client)

    r = results[0]
    assert r.summary == "Unclosed '[' in LDAP URL host spins thread forever"
    assert r.severity[0].score == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert r.severity[0].type == "CVSS_V3"
    assert len(r.references) >= 1
    assert r.database_specific.lightwell.lw_id == "LW-2026-0468"
    assert r.database_specific.lightwell.vulnerability_class == "CWE-835"
    assert r.database_specific.lightwell.source == "novel-pipeline"
    expected_purl = "pkg:maven/org.apache.directory.api/api-ldap-model@2.1.2.rhlw-00006"
    assert r.affected[0].package.purl == expected_purl
    mock_osv.assert_not_called()


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_osidb_unavailable_falls_back(mock_osv: object, mock_nvd: object) -> None:
    with patch("fath_cuan.osidb._obtain_token", return_value=None):
        client = OsidbClient(base_url="https://example.com")
        doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
        results = convert(doc, osidb_client=client)
    assert len(results) == 1
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.0.0"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_convert_without_osidb_still_works(mock_osv: object, mock_nvd: object) -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    results = convert(doc)
    assert len(results) == 1
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.0.0"


OSIDB_EMBARGOED_FLAW = {
    "count": 1,
    "results": [
        {
            **OSIDB_FLAW_RESPONSE["results"][0],
            "embargoed": True,
            "visibility": "EMBARGOED",
        }
    ],
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_embargoed_flaw_redacted_when_opted_in(mock_osv: object, mock_nvd: object) -> None:
    client = OsidbClient(base_url="https://example.com", token="fake")
    with patch.object(client, "_get", return_value=OSIDB_EMBARGOED_FLAW):
        doc = InputDocument.from_dict(SAMPLE_NOVEL_INPUT)
        results = convert(doc, osidb_client=client, redact_embargoed=True)

    r = results[0]
    assert r.database_specific.lightwell.embargo_status == "pre-disclosure"
    assert r.affected[0].package.name == ""
    assert r.affected[0].package.purl is None
    assert r.aliases == []
    assert r.summary == ""
    assert r.severity == []


# --- LW- identifier tests ---


SAMPLE_JIRA_VULN_DATA = VulnerabilityData(
    key="VULN-1234",
    summary="Buffer overflow in libfoo",
    details="A buffer overflow vulnerability exists in libfoo allowing remote code execution.",
    severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cve_id="LW-2026-0468",
)


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_uses_jira(mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert len(results) == 1
    mock_jira.assert_called_once_with("LW-2026-0468", None)


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_summary_from_jira(mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert results[0].summary == "Buffer overflow in libfoo"
    assert "remote code execution" in results[0].details


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_severity_cvss_v3(mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert len(results[0].severity) == 1
    assert results[0].severity[0].type == "CVSS_V3"
    assert results[0].severity[0].score == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_severity_cvss_v4(mock_jira: object) -> None:
    jira_data = VulnerabilityData(
        key="VULN-1234",
        summary="Test",
        details="Test",
        severity="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
        cve_id="LW-2026-0468",
    )
    mock_jira.return_value = jira_data
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert results[0].severity[0].type == "CVSS_V4"


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_non_cvss_severity_excluded(mock_jira: object) -> None:
    jira_data = VulnerabilityData(
        key="VULN-1234",
        summary="Test",
        details="Test",
        severity="Critical",
        cve_id="LW-2026-0468",
    )
    mock_jira.return_value = jira_data
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert results[0].severity == []


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_aliases_contain_only_lw_id(mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert results[0].aliases == ["LW-2026-0468"]


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_no_references(mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert results[0].references == []


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_osv_id_format(mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert results[0].id == "x_RHLW-LW-2026-0468-1.0.0"


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_affected_package(mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    pkg = results[0].affected[0].package
    assert pkg.name == "org.example:artifact"
    assert pkg.purl == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"
    events = results[0].affected[0].ranges[0].events
    assert events[0].introduced == "0"
    assert events[1].fixed == "1.0.0.rhlw-00001"


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_database_specific(mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    lw = results[0].database_specific.lightwell
    assert lw.source == "novel-pipeline"
    assert lw.backport_base_version == "1.0.0"
    assert lw.lw_id == "LW-2026-0468"


@patch("fath_cuan.converters.osv._fetch_jira")
def test_lw_id_jira_returns_none(mock_jira: object) -> None:
    mock_jira.return_value = None
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    results = convert(doc)
    assert len(results) == 1
    assert results[0].summary == ""
    assert results[0].details == ""
    assert results[0].severity == []


@patch("fath_cuan.converters.osv._fetch_jira")
@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_mixed_cve_and_lw_ids(mock_osv: object, mock_nvd: object, mock_jira: object) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_MIXED_VULN_DATA)
    results = convert(doc)
    assert len(results) == 2
    assert results[0].id == "x_RHLW-CVE-2024-25710-1.0.0"
    assert results[1].id == "x_RHLW-LW-2026-0468-1.0.0"
    assert results[1].summary == "Buffer overflow in libfoo"


@patch("fath_cuan.converters.osv._fetch_jira")
@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_lw_id_does_not_call_upstream(
    mock_osv: object, mock_nvd: object, mock_jira: object
) -> None:
    mock_jira.return_value = SAMPLE_JIRA_VULN_DATA
    doc = InputDocument.from_dict(SAMPLE_LW_VULN_DATA)
    convert(doc)
    mock_osv.assert_not_called()
    mock_nvd.assert_not_called()


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_embargoed_flaw_full_record_by_default(mock_osv: object, mock_nvd: object) -> None:
    """Without redact_embargoed, embargoed flaws produce full records.

    The Pulp OSV repo is protected by a content guard — all consumers
    are authenticated, so full records are safe within the protected feed.
    """
    client = OsidbClient(base_url="https://example.com", token="fake")
    with patch.object(client, "_get", return_value=OSIDB_EMBARGOED_FLAW):
        doc = InputDocument.from_dict(SAMPLE_NOVEL_INPUT)
        results = convert(doc, osidb_client=client)

    r = results[0]
    assert r.summary == "Unclosed '[' in LDAP URL host spins thread forever"
    assert len(r.severity) >= 1
    assert r.affected[0].package.name != ""


def test_jira_severity_cvss_v3() -> None:
    result = _jira_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert len(result) == 1
    assert result[0].type == "CVSS_V3"


def test_jira_severity_cvss_v4() -> None:
    result = _jira_severity("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
    assert len(result) == 1
    assert result[0].type == "CVSS_V4"


def test_jira_severity_cvss_v2() -> None:
    result = _jira_severity("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")
    assert len(result) == 1
    assert result[0].type == "CVSS_V2"


def test_jira_severity_non_cvss_returns_empty() -> None:
    assert _jira_severity("Critical") == []


def test_jira_severity_empty_returns_empty() -> None:
    assert _jira_severity("") == []


# ---------------------------------------------------------------------------
# refresh()
# ---------------------------------------------------------------------------


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_refresh_preserves_identity(mock_osv: object, mock_nvd: object) -> None:
    record = OSVDocument.model_validate(SAMPLE_OSV_RECORD)
    result = refresh(record)
    assert result.id == "x_RHLW-CVE-2024-25710-1.0.0"
    assert result.affected[0].package.name == "org.example:artifact"
    events = result.affected[0].ranges[0].events
    assert events[1].fixed == "1.0.0.rhlw-00001"
    assert result.published == "2026-07-15T14:02:27Z"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_refresh_fixes_purl(mock_osv: object, mock_nvd: object) -> None:
    record = OSVDocument.model_validate(SAMPLE_OSV_RECORD)
    assert "@" not in (record.affected[0].package.purl or "")
    result = refresh(record)
    assert "@1.0.0.rhlw-00001" in (result.affected[0].package.purl or "")


@patch("fath_cuan.converters.osv._fetch_upstream_osv")
@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
def test_refresh_enriches_from_upstream(mock_nvd: object, mock_osv: object) -> None:
    mock_osv.return_value = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
        ],
        "summary": "Refreshed summary from upstream",
        "details": "Refreshed details",
        "aliases": ["GHSA-test", "CVE-2024-25710"],
        "references": [
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-25710", "type": "WEB"},
        ],
    }
    record = OSVDocument.model_validate(SAMPLE_OSV_RECORD)
    result = refresh(record)
    assert result.summary == "Refreshed summary from upstream"
    assert result.details == "Refreshed details"
    assert len(result.severity) >= 1
    assert "GHSA-test" in result.aliases


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_refresh_novel_with_osidb(mock_osv: object, mock_nvd: object) -> None:
    osidb_response = {
        "count": 1,
        "results": [
            {
                "uuid": "test-uuid",
                "vulnerability_id": "LW-2026-0468",
                "cve_id": None,
                "title": "OSIDB refreshed title",
                "impact": "CRITICAL",
                "source": "CUSTOMER",
                "cwe_id": "CWE-835",
                "cvss_scores": [
                    {
                        "cvss_version": "V3",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        "score": 7.5,
                    }
                ],
                "cve_description": "OSIDB description",
                "comment_zero": "",
                "references": [],
                "affects": [],
                "components": ["api-ldap-model"],
                "embargoed": False,
                "visibility": "PUBLIC",
            }
        ],
    }
    client = OsidbClient(base_url="https://example.com", token="fake")
    with patch.object(client, "_get", return_value=osidb_response):
        record = OSVDocument.model_validate(SAMPLE_NOVEL_OSV_RECORD)
        result = refresh(record, osidb_client=client)

    assert result.summary == "OSIDB refreshed title"
    assert result.severity[0].score == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert result.database_specific.lightwell.lw_id == "LW-2026-0468"
    assert result.database_specific.lightwell.vulnerability_class == "CWE-835"
    assert result.database_specific.lightwell.source == "novel-pipeline"
    mock_osv.assert_not_called()


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_refresh_corrects_sub_artifact_from_osidb(mock_osv: object, mock_nvd: object) -> None:
    """OSIDB components[] overrides wrong sub-artifact attribution."""
    osidb_response = {
        "count": 1,
        "results": [
            {
                "uuid": "test-uuid",
                "vulnerability_id": "CVE-2023-20861",
                "cve_id": "CVE-2023-20861",
                "title": "SpEL DoS",
                "impact": "MODERATE",
                "source": "CVE",
                "cwe_id": "CWE-400",
                "cvss_scores": [],
                "cve_description": "Spring Expression Language DoS",
                "comment_zero": "",
                "references": [],
                "affects": [
                    {"ps_module": "LTWL", "ps_component": "spring-expression"},
                ],
                "components": ["spring-expression"],
                "embargoed": False,
                "visibility": "PUBLIC",
            }
        ],
    }
    # Record incorrectly says spring-core
    wrong_record = {
        **SAMPLE_OSV_RECORD,
        "id": "x_RHLW-CVE-2023-20861-5.3.18",
        "aliases": ["CVE-2023-20861"],
        "affected": [
            {
                "package": {
                    "ecosystem": "Maven",
                    "name": "org.springframework:spring-core",
                    "purl": "pkg:maven/org.springframework/spring-core",
                },
                "versions": ["5.3.18"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "5.3.18.rhlw-00010"},
                        ],
                    }
                ],
            }
        ],
        "database_specific": {
            "lightwell": {
                "source": "pnc-build",
                "backport_base_version": "5.3.18",
            }
        },
    }
    client = OsidbClient(base_url="https://example.com", token="fake")
    with patch.object(client, "_get", return_value=osidb_response):
        record = OSVDocument.model_validate(wrong_record)
        result = refresh(record, osidb_client=client)

    assert result.affected[0].package.name == "org.springframework:spring-expression"
    assert "spring-expression" in (result.affected[0].package.purl or "")
