from pathlib import Path

import pytest


@pytest.fixture
def sample_json_file(tmp_path: Path) -> Path:
    p = tmp_path / "input.json"
    p.write_text('{"id": "CVE-2024-1234", "description": "test"}')
    return p
