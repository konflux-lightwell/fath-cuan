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

from fath_cuan.ecosystems import SUPPORTED_ECOSYSTEMS, parse_purl


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
    # primaryPurl is authoritative for the remediated coordinate: OSV generation
    # takes the affected package (name + fixed version) from it, so its version
    # MUST equal version.full when that is set (validated below).
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

    @model_validator(mode="after")
    def _primary_purl_matches_full(self) -> BuildIndex:
        """primaryPurl must carry the remediated (full) version.

        OSV generation reads the fixed version from primaryPurl, so a producer
        that points primaryPurl at the upstream coordinate while carrying the
        remediated version in version.full would silently emit an advisory whose
        fix is the base version. Fail loudly instead.
        """
        if self.version.full:
            try:
                _, _, purl_version = parse_purl(self.primary_purl)
            except ValueError:
                return self  # malformed PURL surfaces where it's resolved
            if purl_version != self.version.full:
                raise ValueError(
                    f"primaryPurl version '{purl_version}' does not match "
                    f"version.full '{self.version.full}'"
                )
        return self

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BuildIndex:
        return cls.model_validate(data)
