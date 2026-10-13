from __future__ import annotations

import logging
from typing import Any

from fath_cuan.converters import osv as osv_converter
from fath_cuan.converters import vex as vex_converter
from fath_cuan.converters.vex import VEXResult
from fath_cuan.jira.client import JiraClient
from fath_cuan.models.build_index import BuildIndex
from fath_cuan.models.input import InputDocument
from fath_cuan.osidb import OsidbClient

logger = logging.getLogger(__name__)


def _is_build_index(input_json: dict[str, Any]) -> bool:
    """Distinguish a unified build-index from a legacy PNC gav-index.

    A build-index carries ``purls``/``ecosystem``; the legacy gav-index is
    keyed by ``primaryGav`` and has neither.
    """
    return "purls" in input_json or "ecosystem" in input_json


def process_osv(
    input_json: dict[str, Any],
    embargo: bool = False,
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
) -> list[dict[str, Any]]:
    """Convert input JSON into a list of OSV records (one per vulnerability).

    Accepts either the unified build-index (Maven or PyPI) or the legacy
    Maven-only PNC gav-index, dispatching on the input shape.
    """
    if _is_build_index(input_json):
        logger.info("Processing OSV records from build-index (%s)", input_json.get("ecosystem", ""))
        bi = BuildIndex.from_dict(input_json)
        osv_docs = osv_converter.convert_build_index(
            bi,
            embargo=embargo,
            osidb_client=osidb_client,
            jira_client=jira_client,
            redact_embargoed=redact_embargoed,
        )
    else:
        logger.info("Processing OSV records for %s", input_json.get("primaryGav", ""))
        doc = InputDocument.from_dict(input_json)
        osv_docs = osv_converter.convert(
            doc,
            embargo=embargo,
            osidb_client=osidb_client,
            jira_client=jira_client,
            redact_embargoed=redact_embargoed,
        )
    logger.info("Converted %d OSV records", len(osv_docs))
    return [d.model_dump(exclude_none=True) for d in osv_docs]


def process_vex(
    input_json: dict[str, Any],
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
) -> VEXResult:
    """Generate CycloneDX 1.7 VEX documents from input JSON.

    Accepts either the unified build-index or the legacy PNC gav-index,
    dispatching on the input shape. Returns a VEXResult containing per-CVE
    documents and a multi-CVE aggregate document.

    Args:
        input_json: Build-index or gav-index dict.
        osidb_client: Optional OSIDB client for enrichment data.
        sbom_serial_numbers: Map of PURL -> SBOM serialNumber for
            cross-referencing VEX affects[].ref to SBOMs.

    Returns:
        VEXResult with per_cve and multi_cve documents.
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
        )

    logger.info(
        "Processing VEX for %s", input_json.get("primaryGav", "")
    )
    doc = InputDocument.from_dict(input_json)
    return vex_converter.convert(
        doc,
        osidb_client=osidb_client,
        sbom_serial_numbers=sbom_serial_numbers,
    )
