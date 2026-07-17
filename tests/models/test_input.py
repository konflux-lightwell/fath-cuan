import pytest
from pydantic import ValidationError

from fath_cuan.models.input import InputDocument


def test_input_document_from_dict() -> None:
    data = {"id": "CVE-2024-1234", "description": "A test vulnerability"}
    doc = InputDocument.from_dict(data)
    assert doc.id == "CVE-2024-1234"
    assert doc.description == "A test vulnerability"


def test_input_document_validates_required_fields() -> None:
    with pytest.raises(ValidationError):
        InputDocument.from_dict({})
