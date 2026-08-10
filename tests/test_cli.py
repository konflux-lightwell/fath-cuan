import json
import logging
import os
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from fath_cuan.cli import _build_jira_client, main
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


class TestBuildJiraClient:
    def test_returns_none_without_token(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "JIRA_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            assert _build_jira_client() is None

    def test_returns_client_with_token(self) -> None:
        with patch.dict(os.environ, {"JIRA_TOKEN": "secret"}, clear=True):
            client = _build_jira_client()
            assert client is not None
            assert client.server == "https://redhat.atlassian.net"

    def test_uses_email_from_env(self) -> None:
        env = {"JIRA_TOKEN": "secret", "JIRA_EMAIL": "user@example.com"}
        with patch.dict(os.environ, env, clear=True):
            client = _build_jira_client()
            assert client is not None
            assert client._email == "user@example.com"

    def test_uses_server_from_env(self) -> None:
        env = {"JIRA_TOKEN": "secret", "JIRA_SERVER": "https://custom.atlassian.net/"}
        with patch.dict(os.environ, env, clear=True):
            client = _build_jira_client()
            assert client is not None
            assert client.server == "https://custom.atlassian.net"

    def test_empty_token_returns_none(self) -> None:
        with patch.dict(os.environ, {"JIRA_TOKEN": ""}, clear=True):
            assert _build_jira_client() is None


class TestJiraFlag:
    @patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
    @patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
    def test_jira_not_called_without_flag(self, mock_osv: object, mock_nvd: object) -> None:
        runner = CliRunner()
        with (
            patch.dict(os.environ, {"JIRA_TOKEN": "secret"}, clear=True),
            patch("fath_cuan.cli._build_jira_client") as mock_build,
        ):
            result = runner.invoke(
                main,
                ["process", "--stdout", "--format", "osv", "-"],
                input=json.dumps(SAMPLE_INPUT_DATA),
            )
            mock_build.assert_not_called()
        assert result.exit_code == 0

    @patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
    @patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
    def test_jira_enabled_with_flag(self, mock_osv: object, mock_nvd: object) -> None:
        runner = CliRunner()
        with patch.dict(os.environ, {"JIRA_TOKEN": "secret"}, clear=True):
            result = runner.invoke(
                main,
                ["process", "--jira", "--stdout", "--format", "osv", "-"],
                input=json.dumps(SAMPLE_INPUT_DATA),
            )
        assert result.exit_code == 0
        assert "JIRA enrichment enabled" in result.output

    @patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
    @patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
    @patch("fath_cuan.cli._build_jira_client", return_value=None)
    def test_jira_warns_without_token(
        self, mock_build: object, mock_osv: object, mock_nvd: object
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["process", "--jira", "--stdout", "--format", "osv", "-"],
            input=json.dumps(SAMPLE_INPUT_DATA),
        )
        assert result.exit_code == 0
        mock_build.assert_called_once()


class TestVerbosity:
    def _invoke_with_verbosity(self, flags: list[str]) -> None:
        runner = CliRunner()
        runner.invoke(main, [*flags, "process", "--help"])

    def test_default_is_warning(self) -> None:
        self._invoke_with_verbosity([])
        assert logging.root.level == logging.WARNING

    def test_v_sets_info(self) -> None:
        self._invoke_with_verbosity(["-v"])
        assert logging.root.level == logging.INFO

    def test_vv_sets_debug(self) -> None:
        self._invoke_with_verbosity(["-vv"])
        assert logging.root.level == logging.DEBUG

    def test_vvvvv_stays_debug(self) -> None:
        self._invoke_with_verbosity(["-vvvvv"])
        assert logging.root.level == logging.DEBUG
