from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_VULN_ID_PATTERNS = [
    re.compile(r"^CVE-\d{4}-\d{4,}$"),
    re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$"),
    re.compile(r"^LW-\d{4}-\d{4,}$"),
]


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
    advisory_id: str | None = Field(default=None, alias="advisoryId")

    @field_validator("vulns")
    @classmethod
    def _valid_vuln_ids(cls, value: list[str]) -> list[str]:
        for v in value:
            if not any(p.fullmatch(v) for p in _VULN_ID_PATTERNS):
                raise ValueError(
                    f"vuln id '{v}' must match CVE-YYYY-NNNN+, "
                    f"GHSA-xxxx-xxxx-xxxx, or LW-YYYY-NNNN+"
                )
        return value

    @field_validator("advisory_id")
    @classmethod
    def _valid_advisory_id(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"RHLW-\d{4}-\d{5}", value):
            raise ValueError(f"advisory_id must match RHLW-YYYY-NNNNN, got '{value}'")
        return value

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InputDocument:
        return cls.model_validate(data)
