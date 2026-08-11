from __future__ import annotations

import logging
from typing import Any

from fath_cuan.converters import osv as osv_converter
from fath_cuan.converters import vex as vex_converter
from fath_cuan.jira.client import JiraClient
from fath_cuan.models.input import InputDocument
from fath_cuan.osidb import OsidbClient

logger = logging.getLogger(__name__)


def process_osv(
    input_json: dict[str, Any],
    embargo: bool = False,
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
) -> list[dict[str, Any]]:
    """Convert input JSON into a list of OSV records (one per CVE)."""
    logger.info("Processing OSV records for %s", input_json.get("primaryGav", ""))
    doc = InputDocument.from_dict(input_json)
    logger.info("Converting to OSV records")
    osv_docs = osv_converter.convert(
        doc,
        embargo=embargo,
        osidb_client=osidb_client,
        jira_client=jira_client,
        redact_embargoed=redact_embargoed,
    )
    logger.info("Converted %d OSV records", len(osv_docs))
    return [d.model_dump(exclude_none=True) for d in osv_docs]


def refresh_osv(
    osv_json: dict[str, Any],
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
) -> dict[str, Any]:
    """Fully regenerate an existing OSV record from authoritative sources."""
    from fath_cuan.models.osv import OSVDocument

    logger.info("Refreshing OSV record %s", osv_json.get("id", "?"))
    record = OSVDocument.model_validate(osv_json)
    refreshed = osv_converter.refresh(
        record,
        osidb_client=osidb_client,
        jira_client=jira_client,
        redact_embargoed=redact_embargoed,
    )
    logger.info("Refreshed %s", refreshed.id)
    return refreshed.model_dump(exclude_none=True)


def process_vex(input_json: dict[str, Any]) -> dict[str, Any]:
    logger.info("Processing VEX records for %s", input_json.get("primaryGav", ""))
    doc = InputDocument.from_dict(input_json)
    logger.info("Converting to VEX record")
    vex_doc = vex_converter.convert(doc)
    logger.info("Converted VEX record")
    return vex_doc.model_dump(exclude_none=True)
