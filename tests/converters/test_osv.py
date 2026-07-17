import pytest

from fath_cuan.converters.osv import _parse_gav, convert
from fath_cuan.models.input import InputDocument
from tests.conftest import SAMPLE_INPUT_DATA


def test_osv_convert_returns_correct_id() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    assert result.id == "x_RHLW-BQA6SUOGYCIAA"


def test_osv_convert_schema_version() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    assert result.schema_version == "1.6.8"


def test_osv_convert_aliases_match_cves() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    assert result.aliases == ["CVE-A"]


def test_osv_convert_deduplicates_aliases() -> None:
    data = {**SAMPLE_INPUT_DATA, "cves": ["CVE-A", "CVE-A", "CVE-B"]}
    doc = InputDocument.from_dict(data)
    result = convert(doc)
    assert result.aliases == ["CVE-A", "CVE-B"]


def test_osv_convert_affected_package() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    assert len(result.affected) == 1
    pkg = result.affected[0].package
    assert pkg.ecosystem == "Maven"
    assert pkg.name == "org.example:artifact"
    assert pkg.purl == "pkg:maven/org.example/artifact"


def test_osv_convert_affected_ranges() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    ranges = result.affected[0].ranges
    assert len(ranges) == 1
    assert ranges[0].type == "ECOSYSTEM"
    events = ranges[0].events
    assert len(events) == 2
    assert events[0].introduced == "0"
    assert events[1].fixed == "1.0.0"


def test_osv_convert_credits() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    assert len(result.credits) == 1
    assert result.credits[0].name == "Red Hat Lightwell"
    assert result.credits[0].type == "REMEDIATION_DEVELOPER"


def test_osv_convert_database_specific() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    lw = result.database_specific.lightwell
    assert lw.source == "lightwell-pipeline"
    assert lw.backport_base_version == "1.0.0"
    assert lw.build_id == "BQA6SUOGYCIAA"


def test_osv_convert_modified_timestamp() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    assert result.modified == "2026-07-15T14:02:27Z"


def test_osv_convert_model_dump_excludes_none() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    result = convert(doc)
    dumped = result.model_dump(exclude_none=True)
    intro_event = dumped["affected"][0]["ranges"][0]["events"][0]
    assert "introduced" in intro_event
    assert "fixed" not in intro_event
    fix_event = dumped["affected"][0]["ranges"][0]["events"][1]
    assert "fixed" in fix_event
    assert "introduced" not in fix_event


def test_parse_gav_valid() -> None:
    g, a, v = _parse_gav("org.example:artifact:1.0.0")
    assert g == "org.example"
    assert a == "artifact"
    assert v == "1.0.0"


def test_parse_gav_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid GAV format"):
        _parse_gav("invalid-gav")
