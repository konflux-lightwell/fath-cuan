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

    A build-index carries ``purls``/``ecosystem``; the legacy gav-index
    is keyed by ``primaryGav`` and has neither.
    """
    return "purls" in input_json or "ecosystem" in input_json


def process_osv(
    input_json: dict[str, Any],
    embargo: bool = False,
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
) -> list[dict[str, Any]]:
    """Convert input JSON into OSV records (one per vulnerability).

    Dispatches to build-index or legacy gav-index path.
    """
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
        )
    logger.info("Converted %d OSV records", len(osv_docs))
    return [d.model_dump(exclude_none=True) for d in osv_docs]


def process_vex(
    input_json: dict[str, Any],
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
    embargo: bool = False,
    redact_embargoed: bool = False,
) -> VEXResult:
    """Generate CycloneDX 1.7 VEX documents from input JSON.

    Dispatches to build-index or legacy gav-index path. Returns a
    VEXResult with per-CVE and multi-CVE documents.

    Production SBOM cross-referencing (sbom_serial_numbers) is wired
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
    )
