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


PYPI_BUILD_INDEX = {
    "buildId": "pipeline-1",
    "ecosystem": "pypi",
    "version": {"upstream": "7.6.12", "full": "7.6.12+rhlw.1", "b": 1, "n": 0},
    "purls": ["pkg:pypi/coverage@7.6.12%2Brhlw.1"],
    "vulns": ["CVE-2024-25710"],
    "created": "2026-07-15T14:02:27+00:00",
}


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_cli_process_pypi_build_index_to_stdout(mock_osv: object, mock_nvd: object) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--stdout", "--format", "osv", "-"],
        input=json.dumps(PYPI_BUILD_INDEX),
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["id"] == "x_RHLW-CVE-2024-25710-7.6.12"
    assert data["affected"][0]["package"]["ecosystem"] == "PyPI"
    assert data["affected"][0]["package"]["purl"] == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_cli_process_all_skips_vex_with_warning(
    mock_osv: object, mock_nvd: object, tmp_path: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["process", "--output-dir", str(tmp_path), "-"],  # default --format all
        input=json.dumps(SAMPLE_INPUT_DATA),
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "x_RHLW-CVE-2024-25710-1.0.0.json").exists()
    assert not (tmp_path / "vex.json").exists()
    assert "skipping VEX" in result.output


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_cli_process_format_vex_fails_cleanly(mock_osv: object, mock_nvd: object) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["process", "--format", "vex", "--stdout", "-"], input=json.dumps(SAMPLE_INPUT_DATA)
    )
    assert result.exit_code != 0
    assert "not yet implemented" in result.output.lower()


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["process", "--help"])
    assert result.exit_code == 0
    assert "--output-dir" in result.output
    assert "--stdout" in result.output
    assert "--format" in result.output


class TestIndexCreate:
    def test_pypi_to_stdout(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "index",
                "create",
                "--purl",
                "pkg:pypi/HuggingFace_Hub@7.6.12",
                "--version-upstream",
                "7.6.12",
                "--version-local",
                "7.6.12+rhlw.1",
                "--b",
                "1",
                "--vuln",
                "CVE-2024-1234",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ecosystem"] == "pypi"
        assert data["purls"] == ["pkg:pypi/huggingface-hub@7.6.12%2Brhlw.1"]
        assert data["version"] == {"upstream": "7.6.12", "full": "7.6.12+rhlw.1", "b": 1, "n": 0}
        assert data["vulns"] == ["CVE-2024-1234"]

    def test_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "build-index.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "index",
                "create",
                "--gav",
                "org.example:artifact:1.0.0",
                "--version-local",
                "1.0.0.rhlw-00001",
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["purls"] == ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"]
        assert data["vulns"] == []

    def test_both_purl_and_gav_errors(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "index",
                "create",
                "--purl",
                "pkg:pypi/coverage@7.6.12",
                "--gav",
                "org.example:artifact:1.0.0",
                "--version-local",
                "7.6.12+rhlw.1",
            ],
        )
        assert result.exit_code != 0
        assert "exactly one of" in result.output

    def test_require_vuln_fails_when_empty(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "index",
                "create",
                "--purl",
                "pkg:pypi/coverage@7.6.12",
                "--version-local",
                "7.6.12+rhlw.1",
                "--require-vuln",
            ],
        )
        assert result.exit_code != 0
        assert "no vulnerability IDs resolved" in result.output

    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["index", "create", "--help"])
        assert result.exit_code == 0
        assert "--version-local" in result.output
        assert "--purl" in result.output
        assert "--require-vuln" in result.output


class TestIndexMigrate:
    def test_from_stdin_to_stdout(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["index", "migrate", "--source-legacy-index", "-"],
            input=json.dumps(SAMPLE_INPUT_DATA),
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ecosystem"] == "maven"
        assert data["purls"] == ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"]
        assert data["vulns"] == ["CVE-2024-25710"]

    def test_to_file(self, tmp_path: Path) -> None:
        src = tmp_path / "gav-index.json"
        src.write_text(json.dumps(SAMPLE_INPUT_DATA))
        out = tmp_path / "build-index.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["index", "migrate", "--source-legacy-index", str(src), "--output", str(out)],
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["purls"][0] == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"

    def test_rejects_non_gav_index(self) -> None:
        # a build-index (no primaryGav) fed to migrate -> clean error, no pydantic dump
        runner = CliRunner()
        bi = {
            "ecosystem": "maven",
            "version": {"upstream": "1.0.0"},
            "purls": ["pkg:maven/g/a@1.0.0"],
        }
        result = runner.invoke(
            main, ["index", "migrate", "--source-legacy-index", "-"], input=json.dumps(bi)
        )
        assert result.exit_code != 0
        assert "not a legacy PNC gav-index" in result.output

    def test_invalid_gav_errors(self) -> None:
        bad = {**SAMPLE_INPUT_DATA, "primaryGav": "notagav"}
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["index", "migrate", "--source-legacy-index", "-"],
            input=json.dumps(bad),
        )
        assert result.exit_code != 0
        assert "Invalid GAV" in result.output


class TestIndexCreateAttach:
    def test_attach_pushes(self) -> None:
        from tests.test_oci import FakeRegistry

        reg = FakeRegistry()
        runner = CliRunner()
        with patch("fath_cuan.cli._build_registry", return_value=reg):
            result = runner.invoke(
                main,
                [
                    "index",
                    "create",
                    "--purl",
                    "pkg:pypi/coverage@7.6.12",
                    "--version-local",
                    "7.6.12+rhlw.1",
                    "--vuln",
                    "CVE-2099-1",
                    "--attach-to",
                    "quay.io/example/img:tag",
                ],
            )
        assert result.exit_code == 0, result.output
        assert reg.push_count == 1
        assert "Attached build-index" in result.output

    def test_attach_deduplicates_on_second_run(self) -> None:
        from tests.test_oci import FakeRegistry

        reg = FakeRegistry()
        runner = CliRunner()
        args = [
            "index",
            "create",
            "--purl",
            "pkg:pypi/coverage@7.6.12",
            "--version-local",
            "7.6.12+rhlw.1",
            "--vuln",
            "CVE-2099-1",
            "--attach-to",
            "quay.io/example/img:tag",
        ]
        with patch("fath_cuan.cli._build_registry", return_value=reg):
            first = runner.invoke(main, args)
            second = runner.invoke(main, args)
        assert first.exit_code == 0
        assert second.exit_code == 0
        assert reg.push_count == 1
        assert "deduplicated" in second.output

    def test_attach_conflict_fails(self) -> None:
        from tests.test_oci import FakeRegistry

        reg = FakeRegistry(
            {("quay.io/example/img:tag", "application/vnd.lightwell.build-index.v1+json"): [b"{}"]}
        )
        runner = CliRunner()
        with patch("fath_cuan.cli._build_registry", return_value=reg):
            result = runner.invoke(
                main,
                [
                    "index",
                    "create",
                    "--purl",
                    "pkg:pypi/coverage@7.6.12",
                    "--version-local",
                    "7.6.12+rhlw.1",
                    "--vuln",
                    "CVE-2099-1",
                    "--attach-to",
                    "quay.io/example/img:tag",
                ],
            )
        assert result.exit_code != 0
        assert "divergent" in result.output


class TestRefresh:
    def _seed(self, build_index: dict) -> "object":
        from tests.test_oci import FakeRegistry

        return FakeRegistry(
            {
                ("quay.io/example/img:tag", "application/vnd.lightwell.build-index.v1+json"): [
                    json.dumps(build_index).encode()
                ]
            }
        )

    @patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
    @patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
    def test_refresh_generates_osv(self, mock_osv: object, mock_nvd: object) -> None:
        reg = self._seed(
            {
                "ecosystem": "maven",
                "version": {"upstream": "1.0.0", "full": "1.0.0.rhlw-00001"},
                "primaryPurl": "pkg:maven/org.example/artifact@1.0.0.rhlw-00001",
                "purls": ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"],
                "vulns": ["CVE-2024-25710"],
                "created": "2026-07-15T14:02:27+00:00",
            }
        )
        runner = CliRunner()
        with patch("fath_cuan.cli._build_registry", return_value=reg):
            result = runner.invoke(main, ["refresh", "quay.io/example/img:tag", "--stdout"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["id"] == "x_RHLW-CVE-2024-25710-1.0.0"
        assert data["affected"][0]["package"]["purl"] == (
            "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"
        )

    def test_refresh_no_referrer_fails(self) -> None:
        from tests.test_oci import FakeRegistry

        runner = CliRunner()
        with patch("fath_cuan.cli._build_registry", return_value=FakeRegistry()):
            result = runner.invoke(main, ["refresh", "quay.io/example/img:tag", "--stdout"])
        assert result.exit_code != 0
        assert "no build-index referrer" in result.output


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
