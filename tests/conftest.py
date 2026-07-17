import json
from pathlib import Path

import pytest

SAMPLE_INPUT_DATA = {
    "buildId": "BQA6SUOGYCIAA",
    "created": "2026-07-15T14:02:27+00:00",
    "cves": ["CVE-A"],
    "evidence": {
        "additionalTags": ["tag-1"],
        "digestRef": "quay.io/example@sha256:abc123",
        "ref": "quay.io/example:lw-BQA6SUOGYCIAA",
    },
    "gavCount": 1,
    "gavIndexTag": "idx-BQA6SUOGYCIAA",
    "gavs": ["org.example:artifact:1.0.0"],
    "primaryGav": "org.example:artifact:1.0.0",
}


@pytest.fixture
def sample_json_file(tmp_path: Path) -> Path:
    p = tmp_path / "input.json"
    p.write_text(json.dumps(SAMPLE_INPUT_DATA))
    return p
