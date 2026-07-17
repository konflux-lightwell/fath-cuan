import json
from pathlib import Path

from click.testing import CliRunner

from fath_cuan.cli import main
from tests.conftest import SAMPLE_INPUT_DATA


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_process_osv_to_stdout() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--stdout", "--format", "osv", "-"],
        input=json.dumps(SAMPLE_INPUT_DATA),
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "1.6.8"
    assert data["id"] == "x_RHLW-BQA6SUOGYCIAA"


def test_cli_process_osv_to_file(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--output-dir", str(tmp_path), "--format", "osv", "-"],
        input=json.dumps(SAMPLE_INPUT_DATA),
    )
    assert result.exit_code == 0
    output_file = tmp_path / "x_RHLW-BQA6SUOGYCIAA.json"
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert data["id"] == "x_RHLW-BQA6SUOGYCIAA"


def test_cli_process_from_file(sample_json_file: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--output-dir", str(tmp_path), "--format", "osv", str(sample_json_file)],
    )
    assert result.exit_code == 0


def test_cli_process_from_stdin() -> None:
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
