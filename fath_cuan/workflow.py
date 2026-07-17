from __future__ import annotations

from typing import Any

from fath_cuan.converters import osv as osv_converter
from fath_cuan.converters import vex as vex_converter
from fath_cuan.models.input import InputDocument


def process_osv(input_json: dict[str, Any]) -> dict[str, Any]:
    doc = InputDocument.from_dict(input_json)
    osv_doc = osv_converter.convert(doc)
    return osv_doc.model_dump(exclude_none=True)


def process_vex(input_json: dict[str, Any]) -> dict[str, Any]:
    doc = InputDocument.from_dict(input_json)
    vex_doc = vex_converter.convert(doc)
    return vex_doc.model_dump(exclude_none=True)


def process_all(input_json: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        "osv": process_osv(input_json),
        "vex": process_vex(input_json),
    }
