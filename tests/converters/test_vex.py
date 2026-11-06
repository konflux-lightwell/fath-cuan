"""Tests for the CycloneDX 1.7 VEX converter."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from fath_cuan.converters.vex import VEXResult, convert, convert_build_index
from fath_cuan.models.build_index import BuildIndex
from fath_cuan.models.input import InputDocument
from tests.conftest import SAMPLE_INPUT_DATA

SAMPLE_BUILD_INDEX = {
    "ecosystem": "maven",
    "version": {"upstream": "6.0.3", "full": "6.0.3.rhlw-00001", "b": 1, "n": 0},
    "primaryPurl": "pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.3.rhlw-00001",
    "purls": ["pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.3.rhlw-00001"],
    "vulns": ["CVE-2022-40152"],
    "created": "2026-08-06T16:00:00+00:00",
}

_WOODSTOX_PURL = "pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.3.rhlw-00001"

SAMPLE_SBOM_SERIAL_NUMBERS = {
    _WOODSTOX_PURL: "urn:uuid:4048efaf-e166-4041-b19f-6a1b2fec9293",
}


def _mock_no_enrichment(cve_id, osidb_client=None):
    """Return empty enrichment data (no network calls)."""
    return {"osidb_meta": None, "upstream": None, "nvd": None}


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_convert_build_index_produces_vex(mock_prefetch) -> None:
    """A single-CVE build produces one per-CVE document and no multi-CVE one."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    assert isinstance(result, VEXResult)
    assert len(result.per_cve) == 1
    # LWLP-4254: a one-statement multi-CVE doc would duplicate the per-CVE doc.
    assert result.multi_cve is None

    cve_id, doc = result.per_cve[0]
    assert cve_id == "CVE-2022-40152"
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["version"] == 1
    assert len(doc["vulnerabilities"]) == 1

    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2022-40152"
    assert vuln["analysis"]["state"] == "resolved"
    assert vuln["analysis"]["response"] == ["update"]
    assert "recommendation" in vuln
    assert vuln["published"] == "2026-08-06T16:00:00Z"

    # Affects cross-references SBOM serial number
    assert len(vuln["affects"]) == 1
    ref = vuln["affects"][0]["ref"]
    assert "4048efaf-e166-4041-b19f-6a1b2fec9293" in ref
    assert vuln["affects"][0]["versions"][0]["status"] == "unaffected"

    # CWEs must NOT appear in output (LWLP-2370)
    assert "cwes" not in vuln


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_convert_build_index_no_vulns(mock_prefetch) -> None:
    """Build-index with no vulns produces empty VEX result."""
    data = {**SAMPLE_BUILD_INDEX, "vulns": []}
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(bi, sbom_serial_numbers={})

    assert result.per_cve == []
    assert result.multi_cve is None


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_convert_build_index_multi_cve(mock_prefetch) -> None:
    """Multi-CVE build-index produces multiple per-CVE docs and one aggregate."""
    data = {
        **SAMPLE_BUILD_INDEX,
        "vulns": ["CVE-2022-45688", "CVE-2023-5072"],
    }
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    assert len(result.per_cve) == 2
    assert result.per_cve[0][0] == "CVE-2022-45688"
    assert result.per_cve[1][0] == "CVE-2023-5072"

    assert result.multi_cve is not None
    assert len(result.multi_cve["vulnerabilities"]) == 2


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_convert_legacy_input(mock_prefetch) -> None:
    """Legacy InputDocument produces VEX result."""
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)

    assert isinstance(result, VEXResult)
    assert len(result.per_cve) == 1
    cve_id, vex_doc = result.per_cve[0]
    assert cve_id == "CVE-2024-25710"
    assert vex_doc["bomFormat"] == "CycloneDX"
    assert vex_doc["specVersion"] == "1.7"


_SERIAL_CORE = "urn:uuid:4048efaf-e166-4041-b19f-6a1b2fec9293"
_SERIAL_EXTRA = "urn:uuid:9c1d2f3e-0000-4000-8000-000000000002"
_EXTRA_PURL = "pkg:maven/com.fasterxml.woodstox/woodstox-extra@6.0.3.rhlw-00001"

MULTI_MODULE_BUILD_INDEX = {
    **SAMPLE_BUILD_INDEX,
    "purls": [_WOODSTOX_PURL, _EXTRA_PURL],
}


def _affects_serials(doc: dict) -> set[str]:
    return {a["ref"].split("/", 1)[0] for v in doc["vulnerabilities"] for a in v["affects"]}


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_metadata_component_single_module(mock_prefetch) -> None:
    """A VEX names its module in metadata.component; timestamp matches updated."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    _, doc = result.per_cve[0]
    assert "components" not in doc
    assert doc["metadata"]["timestamp"] == doc["vulnerabilities"][0]["updated"]
    assert doc["metadata"]["component"] == {
        "type": "library",
        "bom-ref": _WOODSTOX_PURL,
        "group": "com.fasterxml.woodstox",
        "name": "woodstox-core",
        "version": "6.0.3.rhlw-00001",
        "purl": _WOODSTOX_PURL,
    }
    # Single-module build: the legacy fields are that module's documents.
    assert len(result.modules) == 1
    assert result.modules[0].purl == _WOODSTOX_PURL
    assert result.modules[0].per_cve == result.per_cve
    assert result.modules[0].multi_cve is None


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_metadata_component_uses_sbom_identity(mock_prefetch) -> None:
    """With the SBOM subject passed in, the VEX purl is byte-identical to it."""
    full_purl = (
        f"{_WOODSTOX_PURL}?type=jar"
        "&repository_url=https://packages.redhat.com/lightwell/java/remediated/"
    )
    sbom_component = {
        "type": "library",
        "bom-ref": _WOODSTOX_PURL,
        "group": "com.fasterxml.woodstox",
        "name": "woodstox-core",
        "version": "6.0.3.rhlw-00001",
        "purl": full_purl,
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "hashes": [{"alg": "SHA-256", "content": "00" * 32}],
        "pedigree": {"ancestors": []},
    }
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(
        bi,
        sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS,
        sbom_components={_WOODSTOX_PURL: sbom_component},
    )

    component = result.per_cve[0][1]["metadata"]["component"]
    assert component["purl"] == full_purl
    assert component["bom-ref"] == _WOODSTOX_PURL
    # Identity only: SBOM content never leaks into the VEX.
    assert set(component) == {"type", "bom-ref", "group", "name", "version", "purl"}
    assert result.modules[0].purl == full_purl


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_matches_pnc_sbom_components0(mock_prefetch) -> None:
    """PNC SBOMs carry the subject in components[0] with a ?type=jar bom-ref.

    The BOM-Link uses that exact bom-ref and the VEX metadata.component copies
    the canonical purl (qualifiers sorted: repository_url before type).
    """
    purl = "pkg:maven/org.jsoup/jsoup@1.22.1.rhlw-00002"
    bom_ref = f"{purl}?type=jar"
    canonical = (
        f"{purl}?repository_url=https://packages.redhat.com/lightwell/java/remediated/&type=jar"
    )
    pnc_components0 = {
        "bom-ref": bom_ref,
        "group": "org.jsoup",
        "name": "jsoup",
        "purl": canonical,
        "type": "library",
        "version": "1.22.1.rhlw-00002",
        "hashes": [{"alg": "SHA-256", "content": "c8" * 32}],
        "licenses": [{"license": {"id": "MIT"}}],
    }
    serial = "urn:uuid:c1573583-6884-55df-b85f-b2691dcd2ec4"
    data = {
        **SAMPLE_BUILD_INDEX,
        "version": {"upstream": "1.22.1", "full": "1.22.1.rhlw-00002", "b": 1, "n": 0},
        "primaryPurl": purl,
        "purls": [purl],
    }
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(
        bi,
        sbom_serial_numbers={bom_ref: serial},
        sbom_components={bom_ref: pnc_components0},
    )

    _, doc = result.modules[0].per_cve[0]
    assert doc["vulnerabilities"][0]["affects"][0]["ref"] == (
        "urn:cdx:c1573583-6884-55df-b85f-b2691dcd2ec4/1#"
        "pkg%3Amaven%2Forg.jsoup%2Fjsoup%401.22.1.rhlw-00002%3Ftype%3Djar"
    )
    assert doc["metadata"]["component"] == {
        "type": "library",
        "bom-ref": bom_ref,
        "group": "org.jsoup",
        "name": "jsoup",
        "version": "1.22.1.rhlw-00002",
        "purl": canonical,
    }


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_one_document_set_per_module(mock_prefetch) -> None:
    """Each module gets its own VEX referencing only its own SBOM."""
    bi = BuildIndex.from_dict(MULTI_MODULE_BUILD_INDEX)
    result = convert_build_index(
        bi,
        sbom_serial_numbers={_WOODSTOX_PURL: _SERIAL_CORE, _EXTRA_PURL: _SERIAL_EXTRA},
    )

    assert [m.purl for m in result.modules] == [_WOODSTOX_PURL, _EXTRA_PURL]
    for module, serial, name in (
        (result.modules[0], _SERIAL_CORE, "woodstox-core"),
        (result.modules[1], _SERIAL_EXTRA, "woodstox-extra"),
    ):
        assert len(module.per_cve) == 1
        assert module.multi_cve is None
        _, doc = module.per_cve[0]
        assert _affects_serials(doc) == {f"urn:cdx:{serial.removeprefix('urn:uuid:')}"}
        assert doc["metadata"]["component"]["name"] == name
        assert doc["metadata"]["component"]["purl"] == module.purl
        assert f"Update to {name} 6.0.3.rhlw-00001" in doc["vulnerabilities"][0]["recommendation"]

    # Legacy fields keep the build-wide shape for existing callers.
    _, legacy = result.per_cve[0]
    assert len(legacy["vulnerabilities"][0]["affects"]) == 2
    assert "component" not in legacy["metadata"]
    assert legacy["metadata"]["timestamp"] == "2026-08-06T16:00:00Z"


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_module_without_sbom_serial_is_skipped(mock_prefetch) -> None:
    """A module with no SBOM to reference gets no per-module VEX."""
    bi = BuildIndex.from_dict(MULTI_MODULE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers={_WOODSTOX_PURL: _SERIAL_CORE})

    assert [m.purl for m in result.modules] == [_WOODSTOX_PURL]


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_per_module_multi_cve_document(mock_prefetch) -> None:
    """A module fixing two CVEs gets a multi-CVE document with its metadata."""
    data = {**MULTI_MODULE_BUILD_INDEX, "vulns": ["CVE-2022-45688", "CVE-2023-5072"]}
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(
        bi,
        sbom_serial_numbers={_WOODSTOX_PURL: _SERIAL_CORE, _EXTRA_PURL: _SERIAL_EXTRA},
    )

    for module in result.modules:
        assert [cve for cve, _ in module.per_cve] == ["CVE-2022-45688", "CVE-2023-5072"]
        assert module.multi_cve is not None
        assert len(module.multi_cve["vulnerabilities"]) == 2
        assert module.multi_cve["metadata"]["component"]["purl"] == module.purl
        assert len(_affects_serials(module.multi_cve)) == 1


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_embargo_stub_has_no_metadata(mock_prefetch) -> None:
    """Embargo stubs stay minimal: no metadata, no affects."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS, embargo=True)

    for docs in (result.per_cve, result.modules[0].per_cve):
        _, doc = docs[0]
        assert "metadata" not in doc
        assert doc["vulnerabilities"][0]["analysis"]["state"] == "in_triage"
        assert (
            "affects" not in doc["vulnerabilities"][0] or not doc["vulnerabilities"][0]["affects"]
        )


def _mock_one_osidb_embargoed(cve_id, osidb_client=None):
    embargoed = cve_id == "CVE-2023-5072"
    return {"osidb_meta": {"embargoed": embargoed}, "upstream": None, "nvd": None}


@pytest.mark.parametrize(
    ("side_effect", "kwargs"),
    [
        (_mock_no_enrichment, {"embargo": True}),  # all stubs
        (_mock_one_osidb_embargoed, {"redact_embargoed": True}),  # stub + full entry
    ],
    ids=["embargo", "redact-mixed"],
)
def test_vex_multi_cve_with_stub_has_no_metadata(side_effect, kwargs) -> None:
    """A multi-CVE document holding an embargo stub never names the module."""
    data = {**SAMPLE_BUILD_INDEX, "vulns": ["CVE-2022-45688", "CVE-2023-5072"]}
    bi = BuildIndex.from_dict(data)
    with patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=side_effect):
        result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS, **kwargs)

    for multi in (result.multi_cve, result.modules[0].multi_cve):
        assert multi is not None
        assert len(multi["vulnerabilities"]) == 2
        assert "metadata" not in multi


_LW_ID = "LW-2026-0042"


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_keeps_lw_ids_with_public_cves(mock_prefetch) -> None:
    """A build fixing an LW- issue and a CVE states both: no silent fix."""
    data = {**SAMPLE_BUILD_INDEX, "vulns": [_LW_ID, "CVE-2022-40152"]}
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    assert [cve for cve, _ in result.per_cve] == [_LW_ID, "CVE-2022-40152"]
    assert result.multi_cve is not None
    assert {v["id"] for v in result.multi_cve["vulnerabilities"]} == {_LW_ID, "CVE-2022-40152"}
    assert result.modules[0].per_cve == result.per_cve

    _, lw_doc = result.per_cve[0]
    lw = lw_doc["vulnerabilities"][0]
    assert lw["source"] == {"name": "Red Hat Lightwell"}
    assert lw["analysis"]["state"] == "resolved"
    assert lw["affects"][0]["ref"].startswith("urn:cdx:4048efaf-")
    assert f"Red Hat Lightwell fix for {_LW_ID}" in lw["recommendation"]
    assert "backports" not in lw["recommendation"]
    # No NVD record exists for an LW- ID.
    assert "nvd.nist.gov" not in json.dumps(lw_doc)


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_lw_only_build_produces_vex(mock_prefetch) -> None:
    """A build with only LW- fixes still produces VEX for them."""
    data = {**SAMPLE_BUILD_INDEX, "vulns": [_LW_ID]}
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    assert [cve for cve, _ in result.per_cve] == [_LW_ID]
    assert result.multi_cve is None


def _mock_osidb_embargoed(cve_id, osidb_client=None):
    return {"osidb_meta": {"embargoed": True}, "upstream": None, "nvd": None}


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_osidb_embargoed)
def test_vex_lw_not_dropped_when_osidb_embargoed(mock_prefetch) -> None:
    """LW- statements are never dropped because OSIDB marks them embargoed."""
    data = {**SAMPLE_BUILD_INDEX, "vulns": [_LW_ID]}
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    assert [cve for cve, _ in result.per_cve] == [_LW_ID]


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_lw_embargo_stub_uses_lightwell_source(mock_prefetch) -> None:
    """An LW- embargo stub names Red Hat Lightwell, not NVD."""
    data = {**SAMPLE_BUILD_INDEX, "vulns": [_LW_ID]}
    bi = BuildIndex.from_dict(data)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS, embargo=True)

    stub = result.per_cve[0][1]["vulnerabilities"][0]
    assert stub["id"] == _LW_ID
    assert stub["source"] == {"name": "Red Hat Lightwell"}
    assert stub["analysis"]["state"] == "in_triage"


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_references_structure(mock_prefetch) -> None:
    """Each vulnerability has a references entry with id and source."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    vuln = result.per_cve[0][1]["vulnerabilities"][0]
    assert len(vuln["references"]) >= 1
    ref = vuln["references"][0]
    assert ref["id"] == "CVE-2022-40152"
    assert "NVD" in ref["source"]["name"]
    assert "nvd.nist.gov" in ref["source"]["url"]


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_vex_advisories_always_include_nvd(mock_prefetch) -> None:
    """Advisories always include at least the NVD entry."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers={})

    vuln = result.per_cve[0][1]["vulnerabilities"][0]
    assert any("nvd.nist.gov" in a["url"] for a in vuln["advisories"])


# ---------------------------------------------------------------------------
# LWLP-4254: upstream fix via GHSA aliases, no placeholder, CVSS method
# ---------------------------------------------------------------------------

# Shapes taken from live osv.dev data for CVE-2022-40152: the CVE record
# has only GIT ranges; the GHSA alias carries the Maven ECOSYSTEM ranges
# for two upstream branches.
_CVE_RECORD = {
    "id": "CVE-2022-40152",
    "aliases": ["GHSA-3f7h-mf4q-vrm4"],
    "affected": [{"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}],
}
_GHSA_RECORD = {
    "id": "GHSA-3f7h-mf4q-vrm4",
    "aliases": ["CVE-2022-40152"],
    "affected": [
        {
            "package": {"ecosystem": "Maven", "name": "com.fasterxml.woodstox:woodstox-core"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "6.0.0"}, {"fixed": "6.4.0"}]}
            ],
        },
        {
            "package": {"ecosystem": "Maven", "name": "com.fasterxml.woodstox:woodstox-core"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4.0"}]}],
        },
    ],
}


def _fake_fetch(osv_id: str):
    return {"CVE-2022-40152": _CVE_RECORD, "GHSA-3f7h-mf4q-vrm4": _GHSA_RECORD}.get(osv_id)


@patch("fath_cuan.converters.vex._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.vex._fetch_upstream_osv", side_effect=_fake_fetch)
def test_upstream_fix_follows_ghsa_alias(mock_osv, mock_nvd) -> None:
    """The fix version comes from the GHSA alias, on the build's branch."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    vuln = result.per_cve[0][1]["vulnerabilities"][0]
    expected = (
        "Update to woodstox-core 6.0.3.rhlw-00001 from Red Hat Lightwell "
        "remediated repository. This version backports the upstream fix "
        "from woodstox-core 6.4.0."
    )
    assert vuln["recommendation"] == expected
    assert vuln["analysis"]["detail"] == expected
    fetched = [c.args[0] for c in mock_osv.call_args_list]
    assert fetched == ["CVE-2022-40152", "GHSA-3f7h-mf4q-vrm4"]


def test_extract_upstream_fix_picks_range_containing_base_version() -> None:
    """Each upstream branch reports its own fix version."""
    from fath_cuan.converters.vex import _extract_upstream_fix

    name = "com.fasterxml.woodstox:woodstox-core"
    records = [_CVE_RECORD, _GHSA_RECORD]
    assert _extract_upstream_fix(records, "Maven", name, "6.0.3") == (name, "6.4.0")
    assert _extract_upstream_fix(records, "Maven", name, "5.1.0") == (name, "5.4.0")
    # Not affected on any listed branch -> no (wrong) fix version.
    assert _extract_upstream_fix(records, "Maven", name, "7.0.0") == ("", "")
    # CVE record alone has no ECOSYSTEM ranges.
    assert _extract_upstream_fix([_CVE_RECORD], "Maven", name, "6.0.3") == ("", "")


def test_extract_upstream_fix_prefers_matching_package() -> None:
    """Ranges for the build's own package win over other packages."""
    from fath_cuan.converters.vex import _extract_upstream_fix

    record = {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.other:lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}
                ],
            },
            {
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5"}]}
                ],
            },
        ]
    }
    assert _extract_upstream_fix([record], "Maven", "org.example:lib", "1.0") == (
        "org.example:lib",
        "1.5",
    )


def _single_package_record(name: str, fixed: str) -> dict:
    return {
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": name},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}
                ],
            }
        ]
    }


def test_extract_upstream_fix_ignores_other_projects() -> None:
    """Another project's range is never used (CVE-2023-38286 on thymeleaf).

    The GHSA lists only de.codecentric:spring-boot-admin-server; comparing
    thymeleaf 3.0.15 against its numbering would name the wrong fix.
    """
    from fath_cuan.converters.vex import _extract_upstream_fix

    record = _single_package_record("de.codecentric:spring-boot-admin-server", "3.1.2")
    assert _extract_upstream_fix([record], "Maven", "org.thymeleaf:thymeleaf", "3.0.15") == (
        "",
        "",
    )


@pytest.mark.parametrize(
    "listed",
    [
        "dom4j:dom4j",  # same artifactId, related groupId (project rename)
        "org.dom4j:dom4j-core",  # same groupId
        "Org.Dom4j:Dom4j",  # exact match up to case
    ],
)
def test_extract_upstream_fix_falls_back_within_same_project(listed: str) -> None:
    """Fallback is allowed when groupId or artifactId matches."""
    from fath_cuan.converters.vex import _extract_upstream_fix

    record = _single_package_record(listed, "2.1.3")
    assert _extract_upstream_fix([record], "Maven", "org.dom4j:dom4j", "2.1.1") == (
        listed,
        "2.1.3",
    )


@patch("fath_cuan.converters.vex._prefetch_enrichment", side_effect=_mock_no_enrichment)
def test_no_newer_release_placeholder(mock_prefetch) -> None:
    """Without an upstream fix version the text is neutral, never a placeholder."""
    bi = BuildIndex.from_dict(SAMPLE_BUILD_INDEX)
    result = convert_build_index(bi, sbom_serial_numbers=SAMPLE_SBOM_SERIAL_NUMBERS)

    vuln = result.per_cve[0][1]["vulnerabilities"][0]
    assert "a newer release" not in vuln["recommendation"]
    assert "a newer release" not in vuln["analysis"]["detail"]
    assert vuln["recommendation"].endswith("This version backports the upstream fix.")


@pytest.mark.parametrize(
    ("vector", "method"),
    [
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSSv3"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSSv31"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSSv4"),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSSv2"),
    ],
)
def test_cvss_method_matches_vector_version(vector: str, method: str) -> None:
    """Rating method is derived from the vector version, for OSIDB and NVD."""
    from fath_cuan.converters.vex import _extract_nvd_score, _extract_osidb_score

    osidb = {"cvss_vectors": [{"type": "CVSS_V3", "score": vector, "numeric_score": 9.8}]}
    assert _extract_osidb_score(osidb) == (vector, 9.8, method)

    nvd_key = {"CVSSv3": "cvssMetricV30", "CVSSv4": "cvssMetricV40"}.get(method, "cvssMetricV31")
    nvd = {"metrics": {nvd_key: [{"cvssData": {"vectorString": vector, "baseScore": 9.8}}]}}
    assert _extract_nvd_score(nvd) == (vector, 9.8, method)


def test_extract_upstream_fix_ignores_unrelated_same_artifact() -> None:
    """A shared generic artifactId alone does not make the same project."""
    from fath_cuan.converters.vex import _extract_upstream_fix

    record = _single_package_record("org.bar:core", "9.0")
    assert _extract_upstream_fix([record], "Maven", "com.foo:core", "1.0") == ("", "")


def test_extract_upstream_fix_normalizes_pypi_names() -> None:
    """PyPI names match after PEP 503 normalization (GHSA spells ``PyYAML``)."""
    from fath_cuan.converters.vex import _extract_upstream_fix

    record = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "PyYAML"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}
                ],
            }
        ]
    }
    assert _extract_upstream_fix([record], "PyPI", "pyyaml", "5.3.1") == ("PyYAML", "5.4")
