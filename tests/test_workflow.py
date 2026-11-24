from unittest.mock import MagicMock, patch

from fath_cuan.jira.client import JiraClient
from fath_cuan.workflow import process_osv, process_vex, resolve_module_vulns
from tests.conftest import SAMPLE_INPUT_DATA, SAMPLE_LW_VULN_DATA


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_returns_list(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert isinstance(result, list)
    assert len(result) == 1


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_has_correct_id(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result[0]["id"] == "x_RHLW-CVE-2024-25710-1.0.0"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_has_schema_version(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result[0]["schema_version"] == "1.9.2"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_has_aliases(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result[0]["aliases"] == ["CVE-2024-25710"]


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_excludes_none_values(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    for event in result[0]["affected"][0]["ranges"][0]["events"]:
        assert None not in event.values()


@patch("fath_cuan.converters.osv._fetch_jira")
def test_process_osv_passes_jira_client(mock_jira: MagicMock) -> None:
    mock_jira.return_value = None
    client = JiraClient()
    process_osv(SAMPLE_LW_VULN_DATA, jira_client=client)
    mock_jira.assert_called_once_with("LW-2026-0468", client)


_NO_ENRICHMENT = {
    "osidb_meta": None,
    "upstream": None,
    "nvd": None,
}


@patch(
    "fath_cuan.converters.vex._prefetch_enrichment",
    return_value=_NO_ENRICHMENT,
)
def test_process_vex_returns_vex_result(mock_enrich: object) -> None:
    from fath_cuan.converters.vex import VEXResult

    result = process_vex(SAMPLE_INPUT_DATA)
    assert isinstance(result, VEXResult)
    assert len(result.per_cve) == 1


PYPI_BUILD_INDEX = {
    "buildId": "pipeline-1",
    "ecosystem": "pypi",
    "version": {"upstream": "7.6.12", "full": "7.6.12+rhlw.1", "b": 1, "n": 0},
    "purls": ["pkg:pypi/coverage@7.6.12%2Brhlw.1"],
    "vulns": ["CVE-2024-25710"],
    "created": "2026-07-15T14:02:27+00:00",
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_dispatches_to_build_index(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(PYPI_BUILD_INDEX)
    assert len(result) == 1
    assert result[0]["id"] == "x_RHLW-CVE-2024-25710-7.6.12"
    assert result[0]["affected"][0]["package"]["ecosystem"] == "PyPI"
    assert result[0]["affected"][0]["package"]["purl"] == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


@patch(
    "fath_cuan.converters.vex._prefetch_enrichment",
    return_value=_NO_ENRICHMENT,
)
def test_process_vex_build_index_returns_vex_result(
    mock_enrich: object,
) -> None:
    from fath_cuan.converters.vex import VEXResult

    result = process_vex(PYPI_BUILD_INDEX)
    assert isinstance(result, VEXResult)
    assert len(result.per_cve) == 1


# ── LWLP-5917: one placement for OSV, SBOM and VEX ───────────────────────────

_LOGBACK_GAV_INDEX = {
    "buildId": "BSO7LXV6QPQAA",
    "created": "2026-11-13T18:59:33+00:00",
    "primaryGav": "ch.qos.logback:logback-classic:1.5.9.rhlw-00034",
    "gavs": [
        "ch.qos.logback:logback-classic:1.5.9.rhlw-00034",
        "ch.qos.logback:logback-access:1.5.9.rhlw-00034",
        "ch.qos.logback:logback-core:1.5.9.rhlw-00034",
        "ch.qos.logback:logback-parent:1.5.9.rhlw-00034",
    ],
    "vulns": ["CVE-2024-12798", "CVE-2024-12801", "CVE-2026-10532", "CVE-2026-19880"],
}


def _logback_upstream(vuln_id: str) -> dict | None:
    """Upstream data as on osv.dev: three logback-core CVEs, one without package data."""
    if vuln_id == "CVE-2026-19880":
        return None
    return {
        "affected": [{"package": {"ecosystem": "Maven", "name": "ch.qos.logback:logback-core"}}]
    }


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", side_effect=_logback_upstream)
def test_resolve_module_vulns_logback_1_5_9(mock_osv: MagicMock, mock_nvd: MagicMock) -> None:
    """The logback 1.5.9.rhlw-00034 build: two modules, two advisories (LWLP-5917)."""
    placement = resolve_module_vulns(_LOGBACK_GAV_INDEX)
    records = process_osv(
        {**_LOGBACK_GAV_INDEX, "advisoryId": "RHLW-2026-33400e52ea4f277c"},
        module_vulns=placement,
    )

    assert placement == {
        "ch.qos.logback:logback-classic": ["CVE-2026-19880"],
        "ch.qos.logback:logback-core": ["CVE-2024-12798", "CVE-2024-12801", "CVE-2026-10532"],
    }
    summary = [(r["affected"][0]["package"]["name"], r["upstream"]) for r in records]
    assert summary == [
        ("ch.qos.logback:logback-classic", ["CVE-2026-19880"]),
        ("ch.qos.logback:logback-core", ["CVE-2024-12798", "CVE-2024-12801", "CVE-2026-10532"]),
    ]
    assert records[0]["id"] == "RHLW-2026-33400e52ea4f277c"
    assert records[1]["id"] != records[0]["id"]
    assert all(len(r["affected"]) == 1 for r in records)


def test_resolve_module_vulns_without_vulns() -> None:
    assert resolve_module_vulns({**_LOGBACK_GAV_INDEX, "vulns": []}) == {}


def test_resolve_module_vulns_starts_with_empty_caches() -> None:
    """A second build in the same process doesn't reuse the first build's answers."""
    client = MagicMock()
    with patch("fath_cuan.converters.osv.clear_caches") as clear:
        resolve_module_vulns({**_LOGBACK_GAV_INDEX, "vulns": []}, osidb_client=client)
    clear.assert_called_once_with()
    client.clear_cache.assert_called_once_with()


@patch("fath_cuan.converters.osv._fetch_nvd")
@patch("fath_cuan.converters.osv._fetch_upstream_osv", side_effect=_logback_upstream)
def test_resolve_module_vulns_skips_nvd(mock_osv: MagicMock, mock_nvd: MagicMock) -> None:
    """Placement needs no NVD data (slow, rate-limited)."""
    resolve_module_vulns(_LOGBACK_GAV_INDEX)
    mock_nvd.assert_not_called()
