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
    b: int = Field(default=0, ge=0)
    n: int = Field(default=0, ge=0)


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
    advisory_id: str | None = Field(default=None, alias="advisoryId")

    @model_validator(mode="before")
    @classmethod
    def _backfill_primary_purl(cls, data: Any) -> Any:
        """Default primaryPurl to the sole purl, only when there is exactly one.

        ``primaryPurl`` is a required field; producers always emit it. As a
        convenience we backfill it ONLY for a single-purl index, where the
        primary is unambiguous. A multi-purl index with no primaryPurl is left
        unset so the required-field validation fails — promoting ``purls[0]``
        there could silently pick a secondary/transitive package as the affected
        artifact, which is exactly what making primaryPurl required prevents.
        """
        if isinstance(data, dict) and not data.get("primaryPurl") and not data.get("primary_purl"):
            purls = data.get("purls")
            if isinstance(purls, list) and len(purls) == 1:
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

    @model_validator(mode="after")
    def _remediation_carries_remediated_version(self) -> BuildIndex:
        """A remediation build must carry a full version distinct from upstream.

        Enforced at the schema boundary so every ecosystem and every producer
        (index create, index migrate, external tools) is covered at once. A build
        is a remediation if it declares backport/novel counts (``b`` or ``n`` > 0)
        **or** simply carries ``vulns`` — a migrated index writes ``b=0, n=0`` yet
        still lists the CVEs it fixed. Either way it must have a ``version.full``
        that differs from ``version.upstream``; otherwise the OSV ``fixed`` event
        equals the vulnerable version, which a scanner reads as "no fix exists".
        """
        remediation = bool(self.version.b or self.version.n or self.vulns)
        if remediation and (not self.version.full or self.version.full == self.version.upstream):
            raise ValueError(
                f"remediation build (b={self.version.b}, n={self.version.n}, "
                f"vulns={len(self.vulns)}) must carry a version.full distinct from "
                f"version.upstream ('{self.version.upstream}')"
            )
        return self

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BuildIndex:
        return cls.model_validate(data)
