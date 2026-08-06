from unittest.mock import MagicMock, patch

import pytest

from fath_cuan.jira.client import JiraClient
from fath_cuan.workflow import process_osv, process_vex
from tests.conftest import SAMPLE_INPUT_DATA, SAMPLE_LW_VULN_DATA


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_returns_list(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert isinstance(result, list)
    assert len(result) == 1


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_has_correct_id(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result[0]["id"] == "x_RHLW-CVE-2024-25710-1.0.0"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_has_schema_version(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result[0]["schema_version"] == "1.6.8"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_has_aliases(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    assert result[0]["aliases"] == ["CVE-2024-25710"]


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_process_osv_excludes_none_values(mock_osv: object, mock_nvd: object) -> None:
    result = process_osv(SAMPLE_INPUT_DATA)
    for event in result[0]["affected"][0]["ranges"][0]["events"]:
        assert None not in event.values()


@patch("fath_cuan.converters.osv._fetch_jira")
def test_process_osv_passes_jira_client(mock_jira: MagicMock) -> None:
    mock_jira.return_value = None
    client = JiraClient()
    process_osv(SAMPLE_LW_VULN_DATA, jira_client=client)
    mock_jira.assert_called_once_with("LW-2026-0468", client)


def test_process_vex_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        process_vex(SAMPLE_INPUT_DATA)
