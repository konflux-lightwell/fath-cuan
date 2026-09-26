"""Tests for affected-module resolution: the OSV affected package must be the
CVE's actually-vulnerable module (from upstream / OSIDB), matched to what the
build produced — NOT the build's arbitrary primary coordinate (primaryGav)."""

from unittest.mock import patch

from fath_cuan.converters.osv import convert
from fath_cuan.models.input import InputDocument
from fath_cuan.osidb import OsidbClient

# primaryGav is spring-aop (the arbitrary alphabetical pick); the real vuln is
# in spring-core, and spring-core WAS built (present in gavs[]).
SPRING_GAV_INDEX = {
    "buildId": "B1",
    "created": "2026-07-15T14:02:27+00:00",
    "vulns": ["CVE-2025-41249"],
    "primaryGav": "org.springframework:spring-aop:5.3.18.rhlw-00010",
    "gavs": [
        "org.springframework:spring-aop:5.3.18.rhlw-00010",
        "org.springframework:spring-core:5.3.18.rhlw-00010",
        "org.springframework:spring-web:5.3.18.rhlw-00010",
    ],
}

_SPRING_CORE_UPSTREAM = {
    "affected": [
        {
            "package": {"ecosystem": "Maven", "name": "org.springframework:spring-core"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.3.45"}]}],
        }
    ],
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_cve_resolves_to_real_module_not_primary_gav(mock_osv: object, mock_nvd: object) -> None:
    mock_osv.return_value = _SPRING_CORE_UPSTREAM
    results = convert(InputDocument.from_dict(SPRING_GAV_INDEX))
    assert len(results) == 1
    aff = results[0].affected
    assert len(aff) == 1
    assert aff[0].package.name == "org.springframework:spring-core"
    assert aff[0].package.purl == "pkg:maven/org.springframework/spring-core@5.3.18.rhlw-00010"
    # introduced comes from the upstream range for spring-core; fixed is the rhlw build.
    assert aff[0].ranges[0].events[0].introduced == "0"
    assert aff[0].ranges[0].events[1].fixed == "5.3.18.rhlw-00010"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_cve_dropped_when_affected_module_not_built(mock_osv: object, mock_nvd: object) -> None:
    mock_osv.return_value = _SPRING_CORE_UPSTREAM
    # spring-core is NOT in this build -> refuse to mis-attribute, drop the record.
    data = {
        **SPRING_GAV_INDEX,
        "gavs": [
            "org.springframework:spring-aop:5.3.18.rhlw-00010",
            "org.springframework:spring-web:5.3.18.rhlw-00010",
        ],
    }
    results = convert(InputDocument.from_dict(data))
    assert results == []


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_multi_affected_emits_one_entry_per_built_module(
    mock_osv: object, mock_nvd: object
) -> None:
    mock_osv.return_value = {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "ch.qos.logback:logback-classic"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
            {
                "package": {"ecosystem": "Maven", "name": "ch.qos.logback:logback-core"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
        ]
    }
    data = {
        "buildId": "B2",
        "created": "2026-07-15T14:02:27+00:00",
        "vulns": ["CVE-2023-6378"],
        "primaryGav": "ch.qos.logback:logback-access:1.2.11.rhlw-00001",
        "gavs": [
            "ch.qos.logback:logback-access:1.2.11.rhlw-00001",
            "ch.qos.logback:logback-classic:1.2.11.rhlw-00001",
            "ch.qos.logback:logback-core:1.2.11.rhlw-00001",
        ],
    }
    results = convert(InputDocument.from_dict(data))
    names = {a.package.name for a in results[0].affected}
    assert names == {"ch.qos.logback:logback-classic", "ch.qos.logback:logback-core"}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_no_authoritative_data_falls_back_to_primary(mock_osv: object, mock_nvd: object) -> None:
    # No upstream, no OSIDB -> preserve prior behaviour (attribute to primaryGav).
    results = convert(InputDocument.from_dict(SPRING_GAV_INDEX))
    assert results[0].affected[0].package.name == "org.springframework:spring-aop"


_OSIDB_NOVEL = {
    "count": 1,
    "results": [
        {
            "vulnerability_id": "LW-2099-0001",
            "cve_id": None,
            "title": "Novel flaw in okio core",
            "impact": "HIGH",
            "cwe_id": "CWE-400",
            "cvss_scores": [],
            "cve_description": "desc",
            "comment_zero": "",
            "references": [],
            "affects": [],
            "components": ["okio"],
            "embargoed": False,
            "visibility": "PUBLIC",
        }
    ],
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_novel_resolves_from_osidb_components(mock_osv: object, mock_nvd: object) -> None:
    client = OsidbClient(base_url="https://example.com", token="fake")
    data = {
        "buildId": "B3",
        "created": "2026-07-15T14:02:27+00:00",
        "vulns": ["LW-2099-0001"],
        "primaryGav": "com.squareup.okio:benchmarks:1.17.2.rhlw-00001",
        "gavs": [
            "com.squareup.okio:benchmarks:1.17.2.rhlw-00001",
            "com.squareup.okio:okio:1.17.2.rhlw-00001",
        ],
    }
    with patch.object(client, "_get", return_value=_OSIDB_NOVEL):
        results = convert(InputDocument.from_dict(data), osidb_client=client)
    assert results[0].affected[0].package.name == "com.squareup.okio:okio"
    assert results[0].database_specific.lightwell.source == "novel-pipeline"


def _osidb_cve(cve_id: str, components: list[str]) -> dict[str, object]:
    """Build a minimal OSIDB `_get` payload for a CVE naming built components."""
    return {
        "count": 1,
        "results": [
            {
                "vulnerability_id": "",
                "cve_id": cve_id,
                "title": "Flaw",
                "impact": "HIGH",
                "cwe_id": "CWE-79",
                "cvss_scores": [],
                "cve_description": "desc",
                "comment_zero": "",
                "references": [],
                "affects": [],
                "components": components,
                "embargoed": False,
                "visibility": "PUBLIC",
            }
        ],
    }


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_cve_upstream_match_is_case_insensitive(mock_osv: object, mock_nvd: object) -> None:
    # Upstream names the module with divergent casing; it must still resolve to
    # the (lowercase) built coordinate rather than fall through to a strict drop.
    mock_osv.return_value = {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.SpringFramework:Spring-Core"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    results = convert(InputDocument.from_dict(SPRING_GAV_INDEX))
    assert len(results) == 1
    assert results[0].affected[0].package.name == "org.springframework:spring-core"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_affected_versions_respect_upstream_version(mock_osv: object, mock_nvd: object) -> None:
    # With an explicit upstreamVersion, the affected entry's versions[] must
    # match the record id / backport_base_version, not the per-gav base.
    mock_osv.return_value = _SPRING_CORE_UPSTREAM
    data = {
        "buildId": "B4",
        "created": "2026-07-15T14:02:27+00:00",
        "vulns": ["CVE-2025-41249"],
        "upstreamVersion": "5.3.18",
        "primaryGav": "org.springframework:spring-aop:5.3.18.RELEASE.rhlw-00010",
        "gavs": [
            "org.springframework:spring-aop:5.3.18.RELEASE.rhlw-00010",
            "org.springframework:spring-core:5.3.18.RELEASE.rhlw-00010",
        ],
    }
    results = convert(InputDocument.from_dict(data))
    aff = results[0].affected[0]
    assert aff.package.name == "org.springframework:spring-core"
    assert aff.versions == ["5.3.18"]
    assert results[0].database_specific.lightwell.backport_base_version == "5.3.18"
    assert results[0].id.endswith("-5.3.18")


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_falls_through_to_osidb_when_upstream_names_unbuilt_module(
    mock_osv: object, mock_nvd: object
) -> None:
    # Upstream names spring-core (not built here), but OSIDB names spring-web
    # (which IS built). The record must be rescued via OSIDB, not dropped.
    mock_osv.return_value = _SPRING_CORE_UPSTREAM
    client = OsidbClient(base_url="https://example.com", token="fake")
    data = {
        **SPRING_GAV_INDEX,
        "gavs": [
            "org.springframework:spring-aop:5.3.18.rhlw-00010",
            "org.springframework:spring-web:5.3.18.rhlw-00010",
        ],
    }
    with patch.object(client, "_get", return_value=_osidb_cve("CVE-2025-41249", ["spring-web"])):
        results = convert(InputDocument.from_dict(data), osidb_client=client)
    assert len(results) == 1
    assert results[0].affected[0].package.name == "org.springframework:spring-web"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_ambiguous_bare_artifactid_fails_closed(mock_osv: object, mock_nvd: object) -> None:
    # A bare OSIDB component 'widget' matches two built modules across different
    # groups; the fuzzy fallback must NOT arbitrarily bind one. With no
    # unambiguous match it falls back to the primary coordinate.
    client = OsidbClient(base_url="https://example.com", token="fake")
    data = {
        "buildId": "B5",
        "created": "2026-07-15T14:02:27+00:00",
        "vulns": ["LW-2099-0002"],
        "primaryGav": "org.example:app:1.0.0.rhlw-00001",
        "gavs": [
            "org.example:app:1.0.0.rhlw-00001",
            "org.a:widget:1.0.0.rhlw-00001",
            "org.b:widget:1.0.0.rhlw-00001",
        ],
    }
    novel = _osidb_cve("", ["widget"])
    novel["results"][0]["vulnerability_id"] = "LW-2099-0002"  # type: ignore[index]
    novel["results"][0]["cve_id"] = None  # type: ignore[index]
    with patch.object(client, "_get", return_value=novel):
        results = convert(InputDocument.from_dict(data), osidb_client=client)
    names = {a.package.name for a in results[0].affected}
    assert names == {"org.example:app"}  # fell back to primary, bound neither widget


# ---------------------------------------------------------------------------
# New advisory path — multiple CVEs affecting different modules
# ---------------------------------------------------------------------------

MULTI_MODULE_ADVISORY = {
    "buildId": "B6",
    "created": "2026-07-15T14:02:27+00:00",
    "vulns": ["CVE-2025-00001", "CVE-2025-00002"],
    "primaryGav": "ch.qos.logback:logback-access:1.2.11.rhlw-00001",
    "gavs": [
        "ch.qos.logback:logback-access:1.2.11.rhlw-00001",
        "ch.qos.logback:logback-classic:1.2.11.rhlw-00001",
        "ch.qos.logback:logback-core:1.2.11.rhlw-00001",
    ],
    "advisoryId": "RHLW-2026-00050",
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv")
def test_multi_cve_different_modules(mock_osv: object, mock_nvd: object) -> None:
    mock_osv.side_effect = [
        {
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "ch.qos.logback:logback-classic"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                }
            ],
            "summary": "Classic vuln",
        },
        {
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "ch.qos.logback:logback-core"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                }
            ],
            "summary": "Core vuln",
        },
    ]
    results = convert(InputDocument.from_dict(MULTI_MODULE_ADVISORY))
    assert len(results) == 1
    names = [a.package.name for a in results[0].affected]
    assert "ch.qos.logback:logback-classic" in names
    assert "ch.qos.logback:logback-core" in names
    # 2 modules * 2 ecosystem entries each = 4
    assert len(results[0].affected) == 4
