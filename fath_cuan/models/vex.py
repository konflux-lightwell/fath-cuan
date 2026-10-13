"""CycloneDX 1.7 VEX document models.

Pydantic models matching the gold-standard VEX schema. These are built
directly (no cyclonedx-python-lib dependency) and serialized via
``model_dump(by_alias=True, exclude_none=True)``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CdxSource(BaseModel):
    """CycloneDX source reference (NVD, Red Hat Lightwell, etc.)."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    url: str | None = None


class CdxAnalysis(BaseModel):
    """Vulnerability analysis with resolution state."""

    model_config = ConfigDict(populate_by_name=True)

    state: str
    response: list[str] = Field(default_factory=list)
    detail: str = ""


class CdxVersion(BaseModel):
    """Affected version with status."""

    model_config = ConfigDict(populate_by_name=True)

    version: str
    status: str


class CdxAffects(BaseModel):
    """Cross-reference to SBOM component via URN."""

    model_config = ConfigDict(populate_by_name=True)

    ref: str
    versions: list[CdxVersion] = Field(default_factory=list)


class CdxReference(BaseModel):
    """Vulnerability reference (e.g. NVD entry)."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    source: CdxSource


class CdxRating(BaseModel):
    """CVSS rating entry."""

    model_config = ConfigDict(populate_by_name=True)

    source: CdxSource
    method: str
    score: float
    severity: str
    vector: str


class CdxAdvisory(BaseModel):
    """Advisory link (NVD page, upstream issue, upstream fix commit)."""

    model_config = ConfigDict(populate_by_name=True)

    url: str
    title: str


class CdxVulnerability(BaseModel):
    """Single CycloneDX vulnerability entry."""

    model_config = ConfigDict(populate_by_name=True)

    bom_ref: str = Field(alias="bom-ref")
    id: str
    source: CdxSource
    analysis: CdxAnalysis
    affects: list[CdxAffects] = Field(default_factory=list)
    references: list[CdxReference] = Field(default_factory=list)
    ratings: list[CdxRating] = Field(default_factory=list)
    # LWLP-2370: CWE enrichment code collects CWE IDs but output omits them
    # until CWE + CSAF enrichment are confirmed ready together.
    cwes: list[int] | None = Field(default=None, exclude=True)
    recommendation: str = ""
    advisories: list[CdxAdvisory] = Field(default_factory=list)
    published: str = ""
    updated: str = ""


class CdxVEXDocument(BaseModel):
    """CycloneDX 1.7 VEX document (vulnerabilities only, no components)."""

    model_config = ConfigDict(populate_by_name=True)

    bom_format: str = Field(default="CycloneDX", alias="bomFormat")
    spec_version: str = Field(default="1.7", alias="specVersion")
    serial_number: str = Field(alias="serialNumber")
    version: int = 1
    vulnerabilities: list[CdxVulnerability] = Field(default_factory=list)
