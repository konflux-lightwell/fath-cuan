import pytest

from fath_cuan.converters.vex import convert
from fath_cuan.models.input import InputDocument
from tests.conftest import SAMPLE_INPUT_DATA


def test_vex_convert_raises_not_implemented() -> None:
    doc = InputDocument.from_dict(SAMPLE_INPUT_DATA)
    with pytest.raises(NotImplementedError):
        convert(doc)
