from unittest.mock import patch

from fath_cuan.osidb import OsidbClient, extract_osidb_metadata

SAMPLE_FLAW = {
    "uuid": "33501a2f-eb62-4aaa-9815-36c9832afcee",
    "vulnerability_id": "LW-2026-0468",
    "cve_id": None,
    "title": "Unclosed '[' in LDAP URL host spins thread forever",
    "impact": "CRITICAL",
    "source": "CUSTOMER",
    "cwe_id": "CWE-835",
    "cvss_scores": [
        {
            "flaw": "33501a2f-eb62-4aaa-9815-36c9832afcee",
            "cvss_version": "V3",
            "issuer": "RH",
            "score": 4.5,
            "vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
        }
    ],
    "cve_description": "parseHost dispatches any host beginning with '[' to parseIpLiteral.",
    "comment_zero": "",
    "references": [
        {
            "description": "GitLab Issue",
            "type": "SOURCE",
            "url": "https://gitlab.cee.redhat.com/duffy/bananach/-/work_items/468",
        },
        {
            "description": "Jira ticket",
            "type": "SOURCE",
            "url": "https://redhat.atlassian.net/browse/LTWL-2560",
        },
    ],
    "affects": [
        {
            "uuid": "8599d3c6-c1a4-4ef8-b6c9-402dd6215b65",
            "affectedness": "AFFECTED",
            "ps_module": "LTWL",
        }
    ],
    "components": ["api-ldap-model"],
    "embargoed": True,
    "visibility": "EMBARGOED",
}

SAMPLE_FLAW_WITH_CVE = {
    "uuid": "0befba31-f0fd-40b8-8dce-3acfa4e34e88",
    "vulnerability_id": "LW-2026-0093",
    "cve_id": "CVE-2025-48924",
    "title": "ClassUtils.getClass uncontrolled recursion",
    "impact": "MODERATE",
    "source": "CUSTOMER",
    "cwe_id": "CWE-674",
    "cvss_scores": [],
    "cve_description": "",
    "comment_zero": (
        "## Vulnerability Details\n\n## Description\n\nThe class-not-found handler recurses."
    ),
    "references": [],
    "affects": [],
    "components": ["commons-lang3"],
    "embargoed": False,
    "visibility": "PUBLIC",
}


def test_extract_metadata_basic() -> None:
    meta = extract_osidb_metadata(SAMPLE_FLAW)
    assert meta["title"] == "Unclosed '[' in LDAP URL host spins thread forever"
    assert meta["vulnerability_id"] == "LW-2026-0468"
    assert meta["cve_id"] is None
    assert meta["impact"] == "CRITICAL"
    assert meta["cwe_id"] == "CWE-835"
    assert meta["embargoed"] is True


def test_extract_metadata_cvss_vectors() -> None:
    meta = extract_osidb_metadata(SAMPLE_FLAW)
    assert len(meta["cvss_vectors"]) == 1
    assert meta["cvss_vectors"][0]["type"] == "CVSS_V3"
    assert meta["cvss_vectors"][0]["score"] == "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"


def test_extract_metadata_references() -> None:
    meta = extract_osidb_metadata(SAMPLE_FLAW)
    assert len(meta["references"]) == 2
    assert meta["references"][0]["type"] == "WEB"
    assert "bananach" in meta["references"][0]["url"]


def test_extract_metadata_description_from_cve_description() -> None:
    meta = extract_osidb_metadata(SAMPLE_FLAW)
    assert "parseHost" in meta["description"]


def test_extract_metadata_description_from_comment_zero() -> None:
    meta = extract_osidb_metadata(SAMPLE_FLAW_WITH_CVE)
    assert "class-not-found handler recurses" in meta["description"]


def test_extract_metadata_cve_id_present() -> None:
    meta = extract_osidb_metadata(SAMPLE_FLAW_WITH_CVE)
    assert meta["cve_id"] == "CVE-2025-48924"


def test_extract_metadata_no_cvss_scores() -> None:
    meta = extract_osidb_metadata(SAMPLE_FLAW_WITH_CVE)
    assert meta["cvss_vectors"] == []


def test_client_available_with_token() -> None:
    client = OsidbClient(base_url="https://example.com", token="fake-token")
    assert client.available is True


def test_client_unavailable_without_token() -> None:
    with patch("fath_cuan.osidb._obtain_token", return_value=None):
        client = OsidbClient(base_url="https://example.com")
        assert client.available is False


def test_client_get_flaw_returns_match() -> None:
    client = OsidbClient(base_url="https://example.com", token="fake")

    mock_response = {
        "count": 1,
        "results": [SAMPLE_FLAW],
    }

    with patch.object(client, "_get", return_value=mock_response):
        result = client.get_flaw("LW-2026-0468")
        assert result is not None
        assert result["vulnerability_id"] == "LW-2026-0468"


def test_client_get_flaw_returns_none_when_unavailable() -> None:
    with patch("fath_cuan.osidb._obtain_token", return_value=None):
        client = OsidbClient(base_url="https://example.com")
        result = client.get_flaw("LW-2026-0468")
        assert result is None


def test_customer_report_refs_filtered_out() -> None:
    flaw = {
        **SAMPLE_FLAW,
        "references": [
            {"url": "https://gitlab.cee.redhat.com/work_items/468", "type": "SOURCE"},
            {"url": "https://support.redhat.com/case/123", "type": "CUSTOMER_REPORT"},
        ],
    }
    meta = extract_osidb_metadata(flaw)
    urls = [r["url"] for r in meta["references"]]
    assert "https://support.redhat.com/case/123" not in urls
    assert "https://gitlab.cee.redhat.com/work_items/468" in urls


def test_upstream_ref_typed_as_fix_with_commit_url() -> None:
    flaw = {
        **SAMPLE_FLAW,
        "references": [
            {"url": "https://github.com/apache/project/commit/abc123", "type": "UPSTREAM"},
        ],
    }
    meta = extract_osidb_metadata(flaw)
    assert meta["references"][0]["type"] == "FIX"


def test_upstream_ref_without_commit_falls_back_to_web() -> None:
    flaw = {
        **SAMPLE_FLAW,
        "references": [
            {"url": "https://github.com/apache/project/pull/42", "type": "UPSTREAM"},
        ],
    }
    meta = extract_osidb_metadata(flaw)
    assert meta["references"][0]["type"] == "WEB"


def test_external_nvd_ref_typed_as_advisory() -> None:
    flaw = {
        **SAMPLE_FLAW,
        "references": [
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2025-48924", "type": "EXTERNAL"},
        ],
    }
    meta = extract_osidb_metadata(flaw)
    assert meta["references"][0]["type"] == "ADVISORY"
