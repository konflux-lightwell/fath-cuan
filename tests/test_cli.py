from pathlib import Path

from click.testing import CliRunner

from fath_cuan.cli import main


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_process_from_file(sample_json_file: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["process", str(sample_json_file)])
    assert result.exit_code != 0
    assert "NotImplementedError" in result.output or result.exit_code != 0


def test_cli_process_from_stdin() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "-"],
        input='{"id": "CVE-2024-1234", "description": "test"}',
    )
    assert result.exit_code != 0


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["process", "--help"])
    assert result.exit_code == 0
    assert "--output-dir" in result.output
    assert "--stdout" in result.output
    assert "--format" in result.output
