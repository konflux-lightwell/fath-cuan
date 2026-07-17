import pytest
from pydantic import ValidationError

from fath_cuan.models.input import Evidence, InputDocument

SAMPLE_INPUT = {
    "buildId": "BQA6SUOGYCIAA",
    "created": "2026-07-15T14:02:27+00:00",
    "cves": ["CVE-A", "CVE-A"],
    "evidence": {
        "additionalTags": ["com.sun.xml.bind.external_relaxng-datatype_4.0.4.rhlw-dp-00002"],
        "digestRef": (
            "quay.io/light-castle/secure-pnc"
            "@sha256:2c511de7d9aab696e5dd6de8710b1b2de70f3cfee81625aaecd762d76c13e8e5"
        ),
        "ref": "quay.io/light-castle/secure-pnc:lw-BQA6SUOGYCIAA",
    },
    "gavCount": 17,
    "gavIndexTag": "idx-BQA6SUOGYCIAA",
    "gavs": [
        "com.sun.xml.bind.external:relaxng-datatype:4.0.4.rhlw-dp-00002",
        "com.sun.xml.bind.external:rngom:4.0.4.rhlw-dp-00002",
    ],
    "primaryGav": "com.sun.xml.bind.external:relaxng-datatype:4.0.4.rhlw-dp-00002",
}


def test_input_document_from_dict() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT)
    assert doc.build_id == "BQA6SUOGYCIAA"
    assert doc.cves == ["CVE-A", "CVE-A"]
    assert doc.gav_count == 17
    assert doc.gav_index_tag == "idx-BQA6SUOGYCIAA"
    assert doc.primary_gav == "com.sun.xml.bind.external:relaxng-datatype:4.0.4.rhlw-dp-00002"
    assert len(doc.gavs) == 2


def test_input_document_evidence() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT)
    assert isinstance(doc.evidence, Evidence)
    assert doc.evidence.ref == "quay.io/light-castle/secure-pnc:lw-BQA6SUOGYCIAA"
    assert doc.evidence.digest_ref.startswith("quay.io/light-castle/secure-pnc@sha256:")
    assert len(doc.evidence.additional_tags) == 1


def test_input_document_created_parsed() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT)
    assert doc.created.year == 2026
    assert doc.created.month == 7
    assert doc.created.day == 15


def test_input_document_validates_required_fields() -> None:
    with pytest.raises(ValidationError):
        InputDocument.from_dict({})
