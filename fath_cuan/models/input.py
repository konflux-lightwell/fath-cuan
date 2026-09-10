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
    vulns: list[str]
    primary_gav: str = Field(alias="primaryGav")
    upstream_version: str | None = Field(default=None, alias="upstreamVersion")
    # Optional: consumed by neither the OSV converter nor `index migrate`, so a
    # trimmed legacy index (lacking these) still migrates rather than failing
    # validation on fields the code is about to discard.
    evidence: Evidence | None = None
    gav_count: int = Field(default=0, alias="gavCount")
    gav_index_tag: str = Field(default="", alias="gavIndexTag")
    gavs: list[str] = Field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InputDocument:
        return cls.model_validate(data)
