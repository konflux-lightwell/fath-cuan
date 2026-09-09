"""The unified ``build-index.json`` input model.

Media type: ``application/vnd.lightwell.build-index.v1+json``.

This is the ecosystem-neutral successor to the Maven-only PNC ``gav-index``
(see :class:`fath_cuan.models.input.InputDocument`). It carries Package URLs
(``purls``) instead of Maven GAVs and decomposes the version into upstream /
full / backport-count (``b``) / novel-count (``n``) so OSV and policy tooling
need not regex-split version strings.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fath_cuan.ecosystems import SUPPORTED_ECOSYSTEMS


class VersionInfo(BaseModel):
    """Decomposed version metadata for a remediated build."""

    model_config = ConfigDict(populate_by_name=True)

    upstream: str
    full: str | None = None
    b: int = 0
    n: int = 0


class BuildIndex(BaseModel):
    """A ``build-index.json`` document: build -> package(s) -> vulnerabilities."""

    model_config = ConfigDict(populate_by_name=True)

    build_id: str = Field(default="", alias="buildId")
    ecosystem: str
    version: VersionInfo
    primary_purl: str = Field(alias="primaryPurl")
    purls: list[str]
    vulns: list[str] = Field(default_factory=list)
    # Not part of the minimal proposal schema, but OSV records need a
    # published/modified timestamp. Optional; the converter defaults to the
    # current UTC time when absent.
    created: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def _backfill_primary_purl(cls, data: Any) -> Any:
        """Default primaryPurl to the first purl when absent.

        The revised contract makes ``primaryPurl`` a required field; producers
        always emit it. This keeps consumption forgiving for indexes that carry
        only ``purls[]`` by promoting the first entry.
        """
        if isinstance(data, dict) and not data.get("primaryPurl") and not data.get("primary_purl"):
            purls = data.get("purls")
            if isinstance(purls, list) and purls:
                data = {**data, "primaryPurl": purls[0]}
        return data

    @field_validator("ecosystem")
    @classmethod
    def _known_ecosystem(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in SUPPORTED_ECOSYSTEMS:
            raise ValueError(
                f"Unsupported ecosystem '{value}'; expected one of {sorted(SUPPORTED_ECOSYSTEMS)}"
            )
        return normalized

    @field_validator("purls")
    @classmethod
    def _at_least_one_purl(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("build-index must contain at least one purl")
        return value

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BuildIndex:
        return cls.model_validate(data)
