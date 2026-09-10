import pytest

from fath_cuan.gittrailers import ResolvedVulns
from fath_cuan.index_builder import build_index_document


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
    with pytest.raises(ValueError, match="upstream base equals"):
        build_index_document(
            version_local="1.0.0+rhlw.1",  # PyPI-shaped '+' form on a Maven GAV
            gav="org.example:artifact:1.0.0",
            b=1,
            vuln_resolver=_fixed_vulns,
        )


def test_clean_build_allows_equal_upstream_and_full() -> None:
    # No b/n/require -> not a remediation, so the upstream==full guard is skipped.
    doc = build_index_document(
        version_local="1.0.0+rhlw.1",
        gav="org.example:artifact:1.0.0",
        vuln_resolver=_no_vulns,
    )
    assert doc["version"]["upstream"] == doc["version"]["full"]
