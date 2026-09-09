"""OSV generation for the PyPI ecosystem via the unified build-index path.

These tests exercise ``convert_build_index`` for Python packages and confirm
the shared core produces correct pkg:pypi PURLs, PEP 503 names, PEP 440 base
versions, and the "PyPI" OSV ecosystem — while reusing the same enrichment,
embargo, and id logic as the Maven path.
"""

from unittest.mock import patch

from fath_cuan.converters.osv import _extract_introduced, convert_build_index
from fath_cuan.models.build_index import BuildIndex
from fath_cuan.osidb import OsidbClient

PYPI_BUILD_INDEX = {
    "buildId": "pipeline-17388121",
    "ecosystem": "pypi",
    "version": {"upstream": "7.6.12", "full": "7.6.12+rhlw.1", "b": 1, "n": 0},
    "purls": ["pkg:pypi/coverage@7.6.12%2Brhlw.1"],
    "vulns": ["CVE-2024-25710"],
    "created": "2026-07-15T14:02:27+00:00",
}

MAVEN_BUILD_INDEX = {
    "buildId": "pipeline-1",
    "ecosystem": "maven",
    "version": {"upstream": "1.0.0", "full": "1.0.0.rhlw-00001", "b": 1, "n": 0},
    "purls": ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"],
    "vulns": ["CVE-2024-25710"],
    "created": "2026-07-15T14:02:27+00:00",
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_pypi_affected_package(mock_osv: object, mock_nvd: object) -> None:
    bi = BuildIndex.from_dict(PYPI_BUILD_INDEX)
    results = convert_build_index(bi)
    pkg = results[0].affected[0].package
    assert pkg.ecosystem == "PyPI"
    assert pkg.name == "coverage"
    assert pkg.purl == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_pypi_id_and_versions_use_upstream(mock_osv: object, mock_nvd: object) -> None:
    bi = BuildIndex.from_dict(PYPI_BUILD_INDEX)
    results = convert_build_index(bi)
    assert results[0].id == "x_RHLW-CVE-2024-25710-7.6.12"
    assert results[0].affected[0].versions == ["7.6.12"]
    assert results[0].database_specific.lightwell.backport_base_version == "7.6.12"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_pypi_fixed_version_is_full_local_version(mock_osv: object, mock_nvd: object) -> None:
    bi = BuildIndex.from_dict(PYPI_BUILD_INDEX)
    results = convert_build_index(bi)
    events = results[0].affected[0].ranges[0].events
    assert events[0].introduced == "0"
    assert events[1].fixed == "7.6.12+rhlw.1"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_pypi_name_pep503_normalized(mock_osv: object, mock_nvd: object) -> None:
    bi = BuildIndex.from_dict(
        {
            **PYPI_BUILD_INDEX,
            "purls": ["pkg:pypi/HuggingFace_Hub@1.0.0+rhlw.1"],
            "version": {"upstream": "1.0.0", "full": "1.0.0+rhlw.1"},
        }
    )
    results = convert_build_index(bi)
    pkg = results[0].affected[0].package
    assert pkg.name == "huggingface-hub"
    assert pkg.purl == "pkg:pypi/huggingface-hub@1.0.0%2Brhlw.1"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_pypi_published_from_created(mock_osv: object, mock_nvd: object) -> None:
    bi = BuildIndex.from_dict(PYPI_BUILD_INDEX)
    results = convert_build_index(bi)
    assert results[0].published == "2026-07-15T14:02:27Z"
    assert results[0].modified == "2026-07-15T14:02:27Z"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_pypi_embargo_stub(mock_osv: object, mock_nvd: object) -> None:
    bi = BuildIndex.from_dict(PYPI_BUILD_INDEX)
    results = convert_build_index(bi, embargo=True)
    r = results[0]
    assert r.affected[0].package.name == ""
    assert r.affected[0].package.ecosystem == "PyPI"
    assert r.database_specific.lightwell.embargo_status == "pre-disclosure"
    mock_osv.assert_not_called()


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_maven_build_index_matches_gav_index_output(mock_osv: object, mock_nvd: object) -> None:
    """A Maven build-index must produce the same OSV as the legacy gav-index."""
    bi = BuildIndex.from_dict(MAVEN_BUILD_INDEX)
    results = convert_build_index(bi)
    r = results[0]
    assert r.id == "x_RHLW-CVE-2024-25710-1.0.0"
    pkg = r.affected[0].package
    assert pkg.ecosystem == "Maven"
    assert pkg.name == "org.example:artifact"
    assert pkg.purl == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"
    assert r.affected[0].versions == ["1.0.0"]
    assert r.affected[0].ranges[0].events[1].fixed == "1.0.0.rhlw-00001"


# --- PyPI upstream introduced extraction ---


def test_extract_introduced_pypi() -> None:
    upstream = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "coverage"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "7.0.0"}, {"fixed": "7.6.12"}]}
                ],
            }
        ]
    }
    assert _extract_introduced(upstream, "coverage", "PyPI") == "7.0.0"


def test_extract_introduced_pypi_ignores_maven_entry() -> None:
    upstream = {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "coverage"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}
                ],
            }
        ]
    }
    assert _extract_introduced(upstream, "coverage", "PyPI") == "0"


# --- OSIDB enrichment on a Python novel ---

OSIDB_NOVEL = {
    "count": 1,
    "results": [
        {
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "vulnerability_id": "LW-2099-0001",
            "cve_id": None,
            "title": "Example novel flaw in a Python package",
            "impact": "HIGH",
            "cwe_id": "CWE-79",
            "cvss_scores": [
                {
                    "cvss_version": "V3",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "score": 7.5,
                }
            ],
            "cve_description": "Example description.",
            "comment_zero": "",
            "references": [],
            "affects": [],
            "components": ["coverage"],
            "embargoed": False,
            "visibility": "PUBLIC",
        }
    ],
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_pypi_novel_enriched_from_osidb(mock_osv: object, mock_nvd: object) -> None:
    client = OsidbClient(base_url="https://example.com", token="fake")
    bi = BuildIndex.from_dict({**PYPI_BUILD_INDEX, "vulns": ["LW-2099-0001"]})
    with patch.object(client, "_get", return_value=OSIDB_NOVEL):
        results = convert_build_index(bi, osidb_client=client)
    r = results[0]
    assert r.summary == "Example novel flaw in a Python package"
    assert r.severity[0].type == "CVSS_V3"
    assert r.database_specific.lightwell.lw_id == "LW-2099-0001"
    assert r.database_specific.lightwell.source == "novel-pipeline"
    assert r.affected[0].package.purl == "pkg:pypi/coverage@7.6.12%2Brhlw.1"
    assert r.affected[0].package.ecosystem == "PyPI"
    mock_osv.assert_not_called()


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_convert_uses_primary_purl_not_first_of_purls(mock_osv: object, mock_nvd: object) -> None:
    """The affected package is taken from primaryPurl, even if purls[0] differs."""
    bi = BuildIndex.from_dict(
        {
            **PYPI_BUILD_INDEX,
            "primaryPurl": "pkg:pypi/coverage@7.6.12%2Brhlw.1",
            "purls": [
                "pkg:pypi/other@9.9.9%2Brhlw.1",
                "pkg:pypi/coverage@7.6.12%2Brhlw.1",
            ],
        }
    )
    results = convert_build_index(bi)
    assert results[0].affected[0].package.purl == "pkg:pypi/coverage@7.6.12%2Brhlw.1"
    assert results[0].affected[0].package.name == "coverage"
