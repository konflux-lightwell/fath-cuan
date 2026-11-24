from __future__ import annotations

import logging
from typing import Any

from fath_cuan.converters import osv as osv_converter
from fath_cuan.converters import vex as vex_converter
from fath_cuan.converters.vex import VEXResult
from fath_cuan.ecosystems import Coordinate, coordinate_from_purl, maven_coordinate
from fath_cuan.jira.client import JiraClient
from fath_cuan.models.build_index import BuildIndex
from fath_cuan.models.input import InputDocument
from fath_cuan.osidb import OsidbClient

logger = logging.getLogger(__name__)


def _start_build(osidb_client: OsidbClient | None) -> None:
    """Empty the lookup caches before a build (see ``osv.clear_caches``).

    A process that handles more than one build must never reuse an earlier
    answer, such as an osv.dev 404 for a CVE that wasn't imported yet.
    """
    osv_converter.clear_caches()
    clear_osidb = getattr(osidb_client, "clear_cache", None)
    if clear_osidb is not None:
        clear_osidb()


def _is_build_index(input_json: dict[str, Any]) -> bool:
    """Distinguish a unified build-index from a legacy PNC gav-index.

    A build-index carries ``purls``/``ecosystem``; the legacy gav-index
    is keyed by ``primaryGav`` and has neither.
    """
    return "purls" in input_json or "ecosystem" in input_json


def _index_coordinates(input_json: dict[str, Any]) -> tuple[Coordinate, list[Coordinate]]:
    """Return the primary coordinate and the built module coordinates of an index."""
    if _is_build_index(input_json):
        bi = BuildIndex.from_dict(input_json)
        upstream = bi.version.upstream
        coord = coordinate_from_purl(
            bi.primary_purl, ecosystem=bi.ecosystem, upstream_version=upstream
        )
        built = osv_converter._purl_built_coords(bi.purls, bi.ecosystem, upstream)
        return coord, built
    doc = InputDocument.from_dict(input_json)
    coord = maven_coordinate(doc.primary_gav, doc.upstream_version)
    built = osv_converter._maven_built_coords(doc.gavs, doc.upstream_version)
    return coord, built


def resolve_module_vulns(
    input_json: dict[str, Any],
    osidb_client: OsidbClient | None = None,
) -> dict[str, list[str]]:
    """Place the build's vulnerabilities on the modules that fix them (LWLP-5917).

    Returns ``{module name: [vuln IDs]}`` (Maven ``group:artifact``), the
    primary module first, one entry per module that has a fix. Pass the
    result to :func:`process_osv` and :func:`process_vex` (and use it to
    choose the SBOMs to enrich) so the OSV advisories, SBOMs and VEX
    documents name exactly the same modules. See
    :func:`fath_cuan.converters.osv.place_vulnerabilities` for the rules.

    This is the first step for a build, so it starts with empty lookup
    caches (osv.dev, NVD and *osidb_client*'s flaws; LWLP-6012).
    """
    _start_build(osidb_client)
    vulns = list(input_json.get("vulns") or [])
    if not vulns:
        return {}
    coord, built = _index_coordinates(input_json)
    # Placement needs package names only: skip NVD (CVSS comes later, in
    # process_osv / process_vex).
    prefetched = osv_converter._prefetch_all(vulns, osidb_client, with_nvd=False)
    placement = osv_converter.place_vulnerabilities(vulns, coord, built, prefetched)
    logger.info(
        "Placed %d vulnerabilities on %d module(s): %s",
        len(vulns),
        len(placement),
        "; ".join(f"{m}: {', '.join(ids)}" for m, ids in placement.items()),
    )
    return placement


def process_osv(
    input_json: dict[str, Any],
    embargo: bool = False,
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
    module_vulns: dict[str, list[str]] | None = None,
    repository_url: str | None = None,
) -> list[dict[str, Any]]:
    """Convert input JSON into OSV records.

    Dispatches to build-index or legacy gav-index path. With an advisory ID,
    one advisory per module that has a fix (*module_vulns* from
    :func:`resolve_module_vulns`, or computed). *repository_url* overrides
    the repository recorded in the advisories (default: predisclosure for a
    build with ``LW-`` IDs, remediated otherwise).

    Without *module_vulns* this is the build's first step, so it starts with
    empty lookup caches; with them, it reuses the answers of
    :func:`resolve_module_vulns`. :func:`process_vex` follows on the same build.
    """
    if module_vulns is None:
        _start_build(osidb_client)
    if _is_build_index(input_json):
        logger.info(
            "Processing OSV from build-index (%s)",
            input_json.get("ecosystem", ""),
        )
        bi = BuildIndex.from_dict(input_json)
        osv_docs = osv_converter.convert_build_index(
            bi,
            embargo=embargo,
            osidb_client=osidb_client,
            jira_client=jira_client,
            redact_embargoed=redact_embargoed,
            module_vulns=module_vulns,
            repository_url=repository_url,
        )
    else:
        logger.info(
            "Processing OSV for %s",
            input_json.get("primaryGav", ""),
        )
        doc = InputDocument.from_dict(input_json)
        osv_docs = osv_converter.convert(
            doc,
            embargo=embargo,
            osidb_client=osidb_client,
            jira_client=jira_client,
            redact_embargoed=redact_embargoed,
            module_vulns=module_vulns,
            repository_url=repository_url,
        )
    logger.info("Converted %d OSV records", len(osv_docs))
    return [d.model_dump(exclude_none=True) for d in osv_docs]


def process_vex(
    input_json: dict[str, Any],
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
    embargo: bool = False,
    redact_embargoed: bool = False,
    sbom_components: dict[str, dict[str, Any]] | None = None,
    module_vulns: dict[str, list[str]] | None = None,
) -> VEXResult:
    """Generate CycloneDX 1.7 VEX documents from input JSON.

    Dispatches to build-index or legacy gav-index path. Returns a
    VEXResult with per-CVE and multi-CVE documents.

    Production SBOM cross-referencing (sbom_serial_numbers, and
    optionally sbom_components for the VEX metadata.component) is wired
    by slan-cuan, not the CLI.
    """
    if _is_build_index(input_json):
        logger.info(
            "Processing VEX from build-index (%s)",
            input_json.get("ecosystem", ""),
        )
        bi = BuildIndex.from_dict(input_json)
        return vex_converter.convert_build_index(
            bi,
            osidb_client=osidb_client,
            sbom_serial_numbers=sbom_serial_numbers,
            embargo=embargo,
            redact_embargoed=redact_embargoed,
            sbom_components=sbom_components,
            module_vulns=module_vulns,
        )

    logger.info(
        "Processing VEX for %s",
        input_json.get("primaryGav", ""),
    )
    doc = InputDocument.from_dict(input_json)
    return vex_converter.convert(
        doc,
        osidb_client=osidb_client,
        sbom_serial_numbers=sbom_serial_numbers,
        embargo=embargo,
        redact_embargoed=redact_embargoed,
        sbom_components=sbom_components,
        module_vulns=module_vulns,
    )
