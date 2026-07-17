import pytest

from fath_cuan.workflow import process_all, process_osv, process_vex
from tests.conftest import SAMPLE_INPUT_DATA


def test_process_osv_returns_dict() -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert isinstance(result, dict)


def test_process_osv_has_correct_id() -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result["id"] == "x_RHLW-BQA6SUOGYCIAA"


def test_process_osv_has_schema_version() -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result["schema_version"] == "1.6.8"


def test_process_osv_has_aliases() -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result["aliases"] == ["CVE-A"]


def test_process_osv_excludes_none_values() -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    for event in result["affected"][0]["ranges"][0]["events"]:
        assert None not in event.values()


def test_process_vex_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        process_vex(SAMPLE_INPUT_DATA)


def test_process_all_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        process_all(SAMPLE_INPUT_DATA)
