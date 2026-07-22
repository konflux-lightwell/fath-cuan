import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from fath_cuan.cli import main
from tests.conftest import SAMPLE_INPUT_DATA


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_cli_process_osv_to_stdout(mock_osv: object, mock_nvd: object) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--stdout", "--format", "osv", "-"],
        input=json.dumps(SAMPLE_INPUT_DATA),
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "1.6.8"
    assert data["id"] == "x_RHLW-CVE-2024-25710-1.0.0"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_cli_process_osv_to_file(mock_osv: object, mock_nvd: object, tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--output-dir", str(tmp_path), "--format", "osv", "-"],
        input=json.dumps(SAMPLE_INPUT_DATA),
    )
    assert result.exit_code == 0
    output_file = tmp_path / "x_RHLW-CVE-2024-25710-1.0.0.json"
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert data["id"] == "x_RHLW-CVE-2024-25710-1.0.0"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_cli_process_from_file(
    mock_osv: object, mock_nvd: object, sample_json_file: Path, tmp_path: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--output-dir", str(tmp_path), "--format", "osv", str(sample_json_file)],
    )
    assert result.exit_code == 0


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_cli_process_from_stdin(mock_osv: object, mock_nvd: object) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--stdout", "--format", "osv", "-"],
        input=json.dumps(SAMPLE_INPUT_DATA),
    )
    assert result.exit_code == 0


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["process", "--help"])
    assert result.exit_code == 0
    assert "--output-dir" in result.output
    assert "--stdout" in result.output
    assert "--format" in result.output
