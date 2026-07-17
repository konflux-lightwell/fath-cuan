from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Evidence(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    additional_tags: list[str] = Field(alias="additionalTags")
    digest_ref: str = Field(alias="digestRef")
    ref: str


class InputDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    build_id: str = Field(alias="buildId")
    created: datetime
    cves: list[str]
    evidence: Evidence
    gav_count: int = Field(alias="gavCount")
    gav_index_tag: str = Field(alias="gavIndexTag")
    gavs: list[str]
    primary_gav: str = Field(alias="primaryGav")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InputDocument:
        return cls.model_validate(data)
