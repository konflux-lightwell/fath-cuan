from __future__ import annotations

from typing import Any

from fath_cuan.converters import osv as osv_converter
from fath_cuan.converters import vex as vex_converter
from fath_cuan.models.input import InputDocument


def process_osv(input_json: dict[str, Any], embargo: bool = False) -> list[dict[str, Any]]:
    """Convert input JSON into a list of OSV records (one per CVE)."""
    doc = InputDocument.from_dict(input_json)
    osv_docs = osv_converter.convert(doc, embargo=embargo)
    return [d.model_dump(exclude_none=True) for d in osv_docs]


def process_vex(input_json: dict[str, Any]) -> dict[str, Any]:
    doc = InputDocument.from_dict(input_json)
    vex_doc = vex_converter.convert(doc)
    return vex_doc.model_dump(exclude_none=True)
