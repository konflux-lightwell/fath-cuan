import json
from pathlib import Path

import pytest

SAMPLE_INPUT_DATA = {
    "buildId": "BQA6SUOGYCIAA",
    "created": "2026-07-15T14:02:27+00:00",
    "cves": ["CVE-2024-25710"],
    "evidence": {
        "additionalTags": ["tag-1"],
        "digestRef": "quay.io/example@sha256:abc123",
        "ref": "quay.io/example:lw-BQA6SUOGYCIAA",
    },
    "gavCount": 1,
    "gavIndexTag": "idx-BQA6SUOGYCIAA",
    "gavs": ["org.example:artifact:1.0.0.rhlw-00001"],
    "primaryGav": "org.example:artifact:1.0.0.rhlw-00001",
}

SAMPLE_MULTI_CVE_DATA = {
    **SAMPLE_INPUT_DATA,
    "cves": ["CVE-2024-25710", "CVE-2024-26308"],
}

SAMPLE_DUPLICATE_CVE_DATA = {
    **SAMPLE_INPUT_DATA,
    "cves": ["CVE-2024-25710", "CVE-2024-25710", "CVE-2024-26308"],
}

SAMPLE_WITH_UPSTREAM_VERSION = {
    **SAMPLE_INPUT_DATA,
    "primaryGav": "org.yaml:snakeyaml:1.33.0.rhlw-00001",
    "gavs": ["org.yaml:snakeyaml:1.33.0.rhlw-00001"],
    "upstreamVersion": "1.33",
}


@pytest.fixture
def sample_json_file(tmp_path: Path) -> Path:
    p = tmp_path / "input.json"
    p.write_text(json.dumps(SAMPLE_INPUT_DATA))
    return p


SAMPLE_NOVEL_DATA = {
    "buildId": "novel-pipeline-123",
    "created": "2026-07-24T12:00:00+00:00",
    "cves": ["LW-2026-000203"],
    "evidence": {
        "additionalTags": [],
        "digestRef": "",
        "ref": "",
    },
    "gavCount": 1,
    "gavIndexTag": "",
    "gavs": ["org.glassfish.jaxb:jaxb-core:4.0.4.rhlw-00001"],
    "primaryGav": "org.glassfish.jaxb:jaxb-core:4.0.4.rhlw-00001",
    "upstreamVersion": "4.0.4",
    "lwId": "LW-2026-000203",
    "vulnerabilityClass": "XML External Entity (XXE)",
    "findingId": "019dac2e-bc0b-79a1-a5bd-53d65777b1fc",
    "severityScore": 5.9,
    "description": "Incomplete XXE hardening in XML parser factories",
}
