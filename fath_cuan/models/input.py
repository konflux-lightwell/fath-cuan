from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel


class InputDocument(BaseModel):
    id: str
    description: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InputDocument:
        return cls.model_validate(data)
