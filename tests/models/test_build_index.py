from datetime import datetime

import pytest

from fath_cuan.models.build_index import BuildIndex

VALID_PYPI = {
    "buildId": "pipeline-17388121",
    "ecosystem": "pypi",
    "version": {"upstream": "7.6.12", "full": "7.6.12+rhlw.1", "b": 1, "n": 0},
    "purls": ["pkg:pypi/coverage@7.6.12%2Brhlw.1"],
    "vulns": ["CVE-2026-12345"],
}

VALID_MAVEN = {
    "buildId": "pipeline-1",
    "ecosystem": "maven",
    "version": {"upstream": "1.0.0", "full": "1.0.0.rhlw-00001", "b": 1, "n": 0},
    "purls": ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"],
    "vulns": ["CVE-2024-25710"],
}


def test_parses_pypi() -> None:
    bi = BuildIndex.from_dict(VALID_PYPI)
    assert bi.build_id == "pipeline-17388121"
    assert bi.ecosystem == "pypi"
    assert bi.version.upstream == "7.6.12"
    assert bi.version.full == "7.6.12+rhlw.1"
    assert bi.version.b == 1
    assert bi.version.n == 0
    assert bi.purls == ["pkg:pypi/coverage@7.6.12%2Brhlw.1"]
    assert bi.vulns == ["CVE-2026-12345"]


def test_parses_maven() -> None:
    bi = BuildIndex.from_dict(VALID_MAVEN)
    assert bi.ecosystem == "maven"


def test_ecosystem_normalized_to_lowercase() -> None:
    bi = BuildIndex.from_dict({**VALID_PYPI, "ecosystem": "PyPI"})
    assert bi.ecosystem == "pypi"


def test_unsupported_ecosystem_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported ecosystem"):
        BuildIndex.from_dict({**VALID_PYPI, "ecosystem": "npm"})


def test_empty_purls_rejected() -> None:
    with pytest.raises(ValueError, match="at least one purl"):
        BuildIndex.from_dict({**VALID_PYPI, "purls": []})


def test_vulns_default_empty_for_clean_build() -> None:
    payload = {k: v for k, v in VALID_PYPI.items() if k != "vulns"}
    bi = BuildIndex.from_dict(payload)
    assert bi.vulns == []


def test_created_optional() -> None:
    assert BuildIndex.from_dict(VALID_PYPI).created is None
    bi = BuildIndex.from_dict({**VALID_PYPI, "created": "2026-07-15T14:02:27+00:00"})
    assert isinstance(bi.created, datetime)


def test_version_counters_default_zero() -> None:
    bi = BuildIndex.from_dict({**VALID_PYPI, "version": {"upstream": "7.6.12"}})
    assert bi.version.b == 0
    assert bi.version.n == 0
    assert bi.version.full is None


def test_primary_purl_backfilled_from_first() -> None:
    bi = BuildIndex.from_dict(VALID_PYPI)  # no primaryPurl in fixture
    assert bi.primary_purl == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


def test_primary_purl_explicit_preserved() -> None:
    payload = {
        **VALID_PYPI,
        "primaryPurl": "pkg:pypi/coverage@7.6.12%2Brhlw.1",
        "purls": ["pkg:pypi/other@1.0.0", "pkg:pypi/coverage@7.6.12%2Brhlw.1"],
    }
    assert BuildIndex.from_dict(payload).primary_purl == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


def test_model_dump_includes_primary_purl() -> None:
    data = BuildIndex.from_dict(VALID_PYPI).model_dump(by_alias=True)
    assert data["primaryPurl"] == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


def test_primary_purl_must_match_version_full() -> None:
    payload = {
        **VALID_PYPI,
        "version": {"upstream": "7.6.12", "full": "7.6.12+rhlw.1"},
        "primaryPurl": "pkg:pypi/coverage@7.6.12",  # base, not the full remediated version
        "purls": ["pkg:pypi/coverage@7.6.12"],
    }
    with pytest.raises(ValueError, match="does not match"):
        BuildIndex.from_dict(payload)


def test_primary_purl_matching_full_ok() -> None:
    bi = BuildIndex.from_dict(VALID_PYPI)  # full 7.6.12+rhlw.1, purl %2Brhlw.1
    assert bi.version.full == "7.6.12+rhlw.1"


def test_no_full_skips_match_check() -> None:
    payload = {
        **VALID_PYPI,
        "version": {"upstream": "7.6.12"},
        "primaryPurl": "pkg:pypi/coverage@7.6.12",
        "purls": ["pkg:pypi/coverage@7.6.12"],
    }
    assert BuildIndex.from_dict(payload).version.full is None
