from unittest.mock import patch

import pytest

from fath_cuan.gittrailers import ResolvedVulns
from fath_cuan.index_builder import build_index_document, migrate_document
from fath_cuan.workflow import process_osv
from tests.conftest import (
    SAMPLE_INPUT_DATA,
    SAMPLE_MULTI_CVE_DATA,
    SAMPLE_WITH_UPSTREAM_VERSION,
)


def _no_vulns(*args: object, **kwargs: object) -> ResolvedVulns:
    return ResolvedVulns([], "clean")


def _fixed_vulns(*args: object, **kwargs: object) -> ResolvedVulns:
    return ResolvedVulns(["CVE-2024-1234"], "cli")


def test_pypi_from_purl() -> None:
    doc = build_index_document(
        version_local="7.6.12+rhlw.1",
        purl="pkg:pypi/HuggingFace_Hub@7.6.12",
        version_upstream="7.6.12",
        b=1,
        vulns=["CVE-2024-1234"],
        vuln_resolver=_fixed_vulns,
    )
    assert doc["ecosystem"] == "pypi"
    assert doc["purls"] == ["pkg:pypi/huggingface-hub@7.6.12%2Brhlw.1"]
    assert doc["version"] == {"upstream": "7.6.12", "full": "7.6.12+rhlw.1", "b": 1, "n": 0}
    assert doc["vulns"] == ["CVE-2024-1234"]
    assert "buildId" not in doc


def test_maven_from_gav() -> None:
    doc = build_index_document(
        version_local="1.0.0.rhlw-00001",
        gav="org.example:artifact:1.0.0",
        build_id="pipeline-9",
        vuln_resolver=_fixed_vulns,
    )
    assert doc["ecosystem"] == "maven"
    assert doc["purls"] == ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"]
    assert doc["version"]["upstream"] == "1.0.0"
    assert doc["version"]["full"] == "1.0.0.rhlw-00001"
    assert doc["buildId"] == "pipeline-9"


def test_maven_from_purl() -> None:
    doc = build_index_document(
        version_local="1.0.0.rhlw-00001",
        purl="pkg:maven/org.example/artifact@1.0.0",
        vuln_resolver=_no_vulns,
    )
    assert doc["purls"] == ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"]


def test_upstream_derived_when_omitted() -> None:
    doc = build_index_document(
        version_local="7.6.12+rhlw.2",
        purl="pkg:pypi/coverage@7.6.12",
        vuln_resolver=_no_vulns,
    )
    assert doc["version"]["upstream"] == "7.6.12"


def test_clean_build_has_empty_vulns() -> None:
    doc = build_index_document(
        version_local="7.6.12+rhlw.1",
        purl="pkg:pypi/coverage@7.6.12",
        vuln_resolver=_no_vulns,
    )
    assert doc["vulns"] == []


def test_both_purl_and_gav_rejected() -> None:
    with pytest.raises(ValueError, match="exactly one of"):
        build_index_document(
            version_local="1.0.0",
            purl="pkg:pypi/coverage@7.6.12",
            gav="org.example:artifact:1.0.0",
            vuln_resolver=_no_vulns,
        )


def test_neither_purl_nor_gav_rejected() -> None:
    with pytest.raises(ValueError, match="exactly one of"):
        build_index_document(version_local="1.0.0", vuln_resolver=_no_vulns)


def test_ecosystem_mismatch_rejected() -> None:
    with pytest.raises(ValueError, match="does not match"):
        build_index_document(
            version_local="7.6.12+rhlw.1",
            ecosystem="maven",
            purl="pkg:pypi/coverage@7.6.12",
            vuln_resolver=_no_vulns,
        )


def test_gav_with_nonmaven_ecosystem_rejected() -> None:
    with pytest.raises(ValueError, match="only valid for the maven"):
        build_index_document(
            version_local="1.0.0",
            ecosystem="pypi",
            gav="org.example:artifact:1.0.0",
            vuln_resolver=_no_vulns,
        )


def test_maven_plus_local_rejected_for_remediation() -> None:
    # b=1 -> caught by the schema-level guard on BuildIndex (upstream == full).
    with pytest.raises(ValueError, match=r"version\.full distinct"):
        build_index_document(
            version_local="1.0.0+rhlw.1",  # PyPI-shaped '+' form on a Maven GAV
            gav="org.example:artifact:1.0.0",
            b=1,
            vuln_resolver=_fixed_vulns,
        )


def test_require_vuln_rejects_upstream_equals_full() -> None:
    # --require-vuln without b/n -> caught in build_index_document.
    with pytest.raises(ValueError, match="upstream base equals"):
        build_index_document(
            version_local="1.0.0+rhlw.1",
            gav="org.example:artifact:1.0.0",
            require_vuln=True,
            vuln_resolver=_fixed_vulns,
        )


def test_require_vuln_rejects_tier4_regex() -> None:
    def _regex(*a: object, **k: object) -> ResolvedVulns:
        return ResolvedVulns(["CVE-2019-0001"], "regex")

    with pytest.raises(ValueError, match="tier-4"):
        build_index_document(
            version_local="7.6.12+rhlw.1",
            purl="pkg:pypi/coverage",  # versionless coordinate (item 18)
            require_vuln=True,
            vuln_resolver=_regex,
        )


def test_versionless_purl_accepted() -> None:
    doc = build_index_document(
        version_local="7.6.12+rhlw.1",
        purl="pkg:pypi/coverage",  # no @version
        vuln_resolver=_no_vulns,
    )
    assert doc["purls"] == ["pkg:pypi/coverage@7.6.12%2Brhlw.1"]


def test_versionless_gav_accepted() -> None:
    doc = build_index_document(
        version_local="1.0.0.rhlw-00001",
        gav="org.example:artifact",  # no version
        vuln_resolver=_no_vulns,
    )
    assert doc["purls"] == ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"]


def test_clean_build_allows_equal_upstream_and_full() -> None:
    # No b/n/require -> not a remediation, so the upstream==full guard is skipped.
    doc = build_index_document(
        version_local="1.0.0+rhlw.1",
        gav="org.example:artifact:1.0.0",
        vuln_resolver=_no_vulns,
    )
    assert doc["version"]["upstream"] == doc["version"]["full"]


# ---------------------------------------------------------------------------
# index migrate: legacy gav-index -> unified build-index
# ---------------------------------------------------------------------------

MULTI_GAV_INDEX = {
    **SAMPLE_INPUT_DATA,
    "primaryGav": "org.example:artifact:1.0.0.rhlw-00001",
    "gavs": [
        "org.example:artifact:1.0.0.rhlw-00001",
        "org.example:dep:2.5.0.rhlw-00001",
        "org.example:artifact:1.0.0.rhlw-00001",  # duplicate of primary
    ],
}


def test_migrate_basic() -> None:
    doc = migrate_document(SAMPLE_INPUT_DATA)
    assert doc["ecosystem"] == "maven"
    assert doc["purls"][0] == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"
    # b/n derived from vuln IDs (1 CVE backport, 0 novel).
    assert doc["version"] == {"upstream": "1.0.0", "full": "1.0.0.rhlw-00001", "b": 1, "n": 0}
    assert doc["vulns"] == ["CVE-2024-25710"]


def test_migrate_derives_b_n_from_vuln_prefixes() -> None:
    src = {**SAMPLE_INPUT_DATA, "vulns": ["CVE-2024-1", "CVE-2024-2", "LW-2026-0001"]}
    doc = migrate_document(src)
    assert doc["version"]["b"] == 2
    assert doc["version"]["n"] == 1


def test_migrate_rejects_non_rhlw_primary_gav() -> None:
    # primaryGav lacks the .rhlw- qualifier -> upstream == full with vulns present
    # -> the BuildIndex remediation guard fires (item 21).
    src = {**SAMPLE_INPUT_DATA, "primaryGav": "org.example:artifact:1.0.0", "gavs": []}
    with pytest.raises(ValueError, match=r"version\.full distinct"):
        migrate_document(src)


def test_migrate_trimmed_index_without_optional_fields() -> None:
    # A trimmed legacy index (no evidence/gavCount/gavIndexTag/gavs) still migrates.
    trimmed = {
        "buildId": "B1",
        "created": "2026-07-15T14:02:27+00:00",
        "vulns": ["CVE-2024-25710"],
        "primaryGav": "org.example:artifact:1.0.0.rhlw-00001",
    }
    doc = migrate_document(trimmed)
    assert doc["purls"] == ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"]


def test_migrate_preserves_build_id_and_created() -> None:
    doc = migrate_document(SAMPLE_INPUT_DATA)
    assert doc["buildId"] == "BQA6SUOGYCIAA"
    assert doc["created"].startswith("2026-07-15T14:02:27")


def test_migrate_converts_all_gavs_dedup_primary_first() -> None:
    doc = migrate_document(MULTI_GAV_INDEX)
    assert doc["purls"] == [
        "pkg:maven/org.example/artifact@1.0.0.rhlw-00001",
        "pkg:maven/org.example/dep@2.5.0.rhlw-00001",
    ]


def test_migrate_uses_upstream_version_field() -> None:
    doc = migrate_document(SAMPLE_WITH_UPSTREAM_VERSION)
    assert doc["version"]["upstream"] == "1.33"


@patch("fath_cuan.converters.osv._fetch_jira", return_value=None)
@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_migrated_build_index_yields_identical_osv(
    mock_osv: object, mock_nvd: object, mock_jira: object
) -> None:
    """Migration must be OSV-lossless: same records as the original gav-index."""
    for gav_index in (SAMPLE_INPUT_DATA, SAMPLE_MULTI_CVE_DATA, SAMPLE_WITH_UPSTREAM_VERSION):
        direct = process_osv(gav_index)
        migrated = process_osv(migrate_document(gav_index))
        assert migrated == direct


# --- primaryPurl emission ---


def test_build_index_emits_primary_purl() -> None:
    doc = build_index_document(
        version_local="7.6.12+rhlw.1",
        purl="pkg:pypi/coverage@7.6.12",
        vuln_resolver=_no_vulns,
    )
    assert doc["primaryPurl"] == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


def test_migrate_emits_primary_purl() -> None:
    doc = migrate_document(MULTI_GAV_INDEX)
    assert doc["primaryPurl"] == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"


# --- fail-not-empty on remediation builds (change #3) ---


def test_require_vuln_fails_when_empty() -> None:
    with pytest.raises(ValueError, match="no vulnerability IDs resolved"):
        build_index_document(
            version_local="7.6.12+rhlw.1",
            purl="pkg:pypi/coverage@7.6.12",
            require_vuln=True,
            vuln_resolver=_no_vulns,
        )


def test_b_count_implies_required_vuln() -> None:
    with pytest.raises(ValueError, match="no vulnerability IDs resolved"):
        build_index_document(
            version_local="7.6.12+rhlw.1",
            purl="pkg:pypi/coverage@7.6.12",
            b=1,
            vuln_resolver=_no_vulns,
        )


def test_n_count_implies_required_vuln() -> None:
    with pytest.raises(ValueError, match="no vulnerability IDs resolved"):
        build_index_document(
            version_local="7.6.12+rhlw.1",
            purl="pkg:pypi/coverage@7.6.12",
            n=1,
            vuln_resolver=_no_vulns,
        )


def test_clean_build_allows_empty_vulns() -> None:
    doc = build_index_document(
        version_local="7.6.12+rhlw.1",
        purl="pkg:pypi/coverage@7.6.12",
        vuln_resolver=_no_vulns,
    )
    assert doc["vulns"] == []
