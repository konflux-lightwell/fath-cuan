import pytest

from fath_cuan.converters.vex import convert
from fath_cuan.models.input import InputDocument


def test_vex_convert_raises_not_implemented() -> None:
    doc = InputDocument(id="CVE-2024-1234", description="test")
    with pytest.raises(NotImplementedError):
        convert(doc)
