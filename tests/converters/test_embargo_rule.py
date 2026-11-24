"""One embargo rule for OSV and VEX (ADR-0055 §3, LWLP-6111).

Release tooling decides embargo by the ``LW-`` ID: a build with an ``LW-`` ID is
predisclosure content, so ``LW-`` IDs are never left out of OSV or VEX, embargoed
or not. A CVE that OSIDB marks as embargoed is left out of both.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from fath_cuan.converters import osv as osv_converter
from fath_cuan.converters import vex as vex_converter
from fath_cuan.converters.osv import is_embargo_excluded
from fath_cuan.models.input import InputDocument
from fath_cuan.osidb import OsidbClient
from tests.conftest import SAMPLE_INPUT_DATA

# commons-io 2.11.0.rhlw-00011-n-00001 (2026-11-22): OSIDB marked four of the five
# LW- IDs as embargoed, so the OSV advisory listed only LW-2026-10181 while the VEX
# listed all five.
_COMMONS_IO_VULNS = [
    "LW-2026-0023",
    "LW-2026-0024",
    "LW-2026-0026",
    "LW-2026-10181",
    "LW-2026-4255",
]
_EMBARGOED = {"LW-2026-0023", "LW-2026-0024", "LW-2026-0026", "LW-2026-4255"}


def _flaw(vuln_id: str, embargoed: bool) -> dict[str, Any]:
    key = "vulnerability_id" if vuln_id.startswith("LW-") else "cve_id"
    return {
        "uuid": f"uuid-{vuln_id}",
        key: vuln_id,
        "title": f"Flaw {vuln_id}",
        "impact": "MODERATE",
        "cvss_scores": [],
        "embargoed": embargoed,
        "visibility": "EMBARGOED" if embargoed else "PUBLIC",
        "components": [],
        "affects": [],
        "references": [],
    }


def _osidb(embargoed: set[str]) -> OsidbClient:
    """An OSIDB client whose flaw lookups mark the IDs in *embargoed* as embargoed."""
    client = OsidbClient(base_url="https://example.com", token="fake")

    def _get(path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        # The ID asked for, whether by an exact-ID filter or the text search.
        params = params or {}
        vuln_id = params.get("search") or params.get("vulnerability_id") or params["cve_id"]
        return {"count": 1, "results": [_flaw(vuln_id, vuln_id in embargoed)]}

    client._get = _get  # type: ignore[method-assign]
    return client


def _index(vulns: list[str]) -> InputDocument:
    return InputDocument.from_dict(
        {
            **SAMPLE_INPUT_DATA,
            "vulns": vulns,
            "primaryGav": "commons-io:commons-io:2.11.0.rhlw-00011-n-00001",
            "gavs": ["commons-io:commons-io:2.11.0.rhlw-00011-n-00001"],
            "advisoryId": "RHLW-2026-8206ff06612aa71b",
        }
    )


@pytest.fixture
def no_upstream():
    with (
        patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None),
        patch("fath_cuan.converters.osv._fetch_nvd", return_value=None),
        patch("fath_cuan.converters.vex._fetch_upstream_osv", return_value=None),
        patch("fath_cuan.converters.vex._fetch_nvd", return_value=None),
    ):
        yield


@pytest.mark.parametrize(
    ("vuln_id", "embargoed", "excluded"),
    [
        ("LW-2026-0023", True, False),
        ("LW-2026-10181", False, False),
        ("CVE-2026-0001", True, True),
        ("CVE-2026-0001", False, False),
        ("CVE-2026-0001", None, False),
    ],
)
def test_is_embargo_excluded(vuln_id: str, embargoed: bool | None, excluded: bool) -> None:
    meta = None if embargoed is None else {"embargoed": embargoed}
    assert is_embargo_excluded(vuln_id, meta) is excluded


def test_embargoed_lw_ids_stay_in_the_advisory(no_upstream: None) -> None:
    """The commons-io case: the advisory lists all five LW- IDs."""
    records = osv_converter.convert(_index(_COMMONS_IO_VULNS), osidb_client=_osidb(_EMBARGOED))

    assert [r.id for r in records] == ["RHLW-2026-8206ff06612aa71b"]
    assert records[0].upstream == _COMMONS_IO_VULNS


def test_all_embargoed_lw_build_still_gets_an_advisory(no_upstream: None) -> None:
    """The netty case: every LW- ID embargoed used to drop the advisory entirely."""
    vulns = ["LW-2026-0568", "LW-2026-0570"]
    records = osv_converter.convert(_index(vulns), osidb_client=_osidb(set(vulns)))

    assert len(records) == 1
    assert records[0].upstream == vulns
    meta = records[0].affected[0].database_specific.lightwell
    assert meta.repository_url == "https://packages.redhat.com/lightwell/java/predisclosure/"


def test_osv_and_vex_name_the_same_ids(no_upstream: None) -> None:
    """Both formats keep LW- IDs and drop an embargoed CVE (one rule)."""
    vulns = ["LW-2026-0023", "LW-2026-10181", "CVE-2026-0002", "CVE-2026-0003"]
    embargoed = {"LW-2026-0023", "CVE-2026-0002"}
    doc = _index(vulns)

    records = osv_converter.convert(doc, osidb_client=_osidb(embargoed))
    vex = vex_converter.convert(
        doc,
        osidb_client=_osidb(embargoed),
        sbom_serial_numbers={
            "pkg:maven/commons-io/commons-io@2.11.0.rhlw-00011-n-00001": (
                "urn:uuid:00000000-0000-4000-8000-000000000001"
            )
        },
    )

    expected = ["LW-2026-0023", "LW-2026-10181", "CVE-2026-0003"]
    assert [u for u in records[0].upstream if not u.startswith("GHSA-")] == expected
    assert [v["id"] for v in vex.modules[0].multi_cve["vulnerabilities"]] == expected
