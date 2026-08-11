import json
from pathlib import Path

import pytest

SAMPLE_INPUT_DATA = {
    "buildId": "BQA6SUOGYCIAA",
    "created": "2026-07-15T14:02:27+00:00",
    "vulns": ["CVE-2024-25710"],
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
    "vulns": ["CVE-2024-25710", "CVE-2024-26308"],
}

SAMPLE_DUPLICATE_CVE_DATA = {
    **SAMPLE_INPUT_DATA,
    "vulns": ["CVE-2024-25710", "CVE-2024-25710", "CVE-2024-26308"],
}

SAMPLE_WITH_UPSTREAM_VERSION = {
    **SAMPLE_INPUT_DATA,
    "primaryGav": "org.yaml:snakeyaml:1.33.0.rhlw-00001",
    "gavs": ["org.yaml:snakeyaml:1.33.0.rhlw-00001"],
    "upstreamVersion": "1.33",
}

SAMPLE_NOVEL_INPUT = {
    **SAMPLE_INPUT_DATA,
    "vulns": ["LW-2026-0468"],
    "primaryGav": "org.apache.directory.api:api-ldap-model:2.1.2.rhlw-00006",
}

SAMPLE_LW_VULN_DATA = {
    **SAMPLE_INPUT_DATA,
    "vulns": ["LW-2026-0468"],
}

SAMPLE_MIXED_VULN_DATA = {
    **SAMPLE_INPUT_DATA,
    "vulns": ["CVE-2024-25710", "LW-2026-0468"],
}


SAMPLE_OSV_RECORD = {
    "schema_version": "1.6.8",
    "id": "x_RHLW-CVE-2024-25710-1.0.0",
    "published": "2026-07-15T14:02:27Z",
    "modified": "2026-07-15T14:02:27Z",
    "summary": "",
    "details": "",
    "severity": [],
    "references": [],
    "aliases": ["CVE-2024-25710"],
    "affected": [
        {
            "package": {
                "ecosystem": "Maven",
                "name": "org.example:artifact",
                "purl": "pkg:maven/org.example/artifact",
            },
            "versions": ["1.0.0"],
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.0.0.rhlw-00001"},
                    ],
                }
            ],
        }
    ],
    "credits": [{"name": "Red Hat Lightwell", "type": "REMEDIATION_DEVELOPER"}],
    "database_specific": {
        "lightwell": {
            "source": "pnc-build",
            "backport_base_version": "1.0.0",
        }
    },
}

SAMPLE_NOVEL_OSV_RECORD = {
    **SAMPLE_OSV_RECORD,
    "id": "x_RHLW-LW-2026-0468-2.1.2",
    "aliases": [],
    "affected": [
        {
            "package": {
                "ecosystem": "Maven",
                "name": "org.apache.directory.api:api-ldap-model",
                "purl": "pkg:maven/org.apache.directory.api/api-ldap-model",
            },
            "versions": ["2.1.2"],
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.1.2.rhlw-00006"},
                    ],
                }
            ],
        }
    ],
    "database_specific": {
        "lightwell": {
            "source": "novel-pipeline",
            "backport_base_version": "2.1.2",
        }
    },
}


@pytest.fixture
def sample_json_file(tmp_path: Path) -> Path:
    p = tmp_path / "input.json"
    p.write_text(json.dumps(SAMPLE_INPUT_DATA))
    return p
