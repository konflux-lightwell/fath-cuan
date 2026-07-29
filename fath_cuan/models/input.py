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
    upstream_version: str | None = Field(default=None, alias="upstreamVersion")
    lw_id: str | None = Field(default=None, alias="lwId")
    vulnerability_class: str | None = Field(default=None, alias="vulnerabilityClass")
    finding_id: str | None = Field(default=None, alias="findingId")
    severity_score: float | None = Field(default=None, alias="severityScore")
    description: str | None = Field(default=None, alias="description")

    @property
    def is_novel(self) -> bool:
        """True if this is a novel vulnerability (has LW ID, no CVE)."""
        return bool(self.lw_id) and not any(c.startswith("CVE-") for c in self.cves)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InputDocument:
        return cls.model_validate(data)
