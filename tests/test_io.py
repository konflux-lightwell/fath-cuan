import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from fath_cuan.io.reader import read_input
from fath_cuan.io.writer import write_to_file, write_to_stdout


def test_read_input_from_file(sample_json_file: Path) -> None:
    data = read_input(str(sample_json_file))
    assert data["id"] == "CVE-2024-1234"


def test_read_input_from_stdin() -> None:
    fake_stdin = StringIO('{"id": "stdin-test", "description": "from stdin"}')
    with patch("sys.stdin", fake_stdin):
        data = read_input(None)
    assert data["id"] == "stdin-test"


def test_read_input_dash_means_stdin() -> None:
    fake_stdin = StringIO('{"id": "dash-test", "description": "from dash"}')
    with patch("sys.stdin", fake_stdin):
        data = read_input("-")
    assert data["id"] == "dash-test"


def test_write_to_file(tmp_path: Path) -> None:
    data = {"id": "CVE-2024-1234"}
    result = write_to_file(data, tmp_path, "output.json")
    assert result == tmp_path / "output.json"
    written = json.loads(result.read_text())
    assert written["id"] == "CVE-2024-1234"


def test_write_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    data = {"id": "CVE-2024-1234"}
    write_to_stdout(data)
    captured = capsys.readouterr()
    assert '"id"' in captured.out
