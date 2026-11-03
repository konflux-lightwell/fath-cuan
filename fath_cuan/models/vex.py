"""CycloneDX 1.7 VEX document models.

Pydantic models matching the gold-standard VEX schema. These are built
directly (no cyclonedx-python-lib dependency) and serialized via
``model_dump(by_alias=True, exclude_none=True)``.

Uses ``serialization_alias`` so Python code constructs models with
normal field names while JSON output uses CycloneDX keys.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CdxSource(BaseModel):
    """CycloneDX source reference."""

    name: str
    url: str | None = None


class CdxAnalysis(BaseModel):
    """Vulnerability analysis with resolution state."""

    state: str
    response: list[str] = Field(default_factory=list)
    detail: str = ""


class CdxVersion(BaseModel):
    """Affected version with status."""

    version: str
    status: str


class CdxAffects(BaseModel):
    """Cross-reference to SBOM component via URN."""

    ref: str
    versions: list[CdxVersion] = Field(default_factory=list)


class CdxReference(BaseModel):
    """Vulnerability reference (e.g. NVD entry)."""

    id: str
    source: CdxSource


class CdxRating(BaseModel):
    """CVSS rating entry."""

    source: CdxSource
    method: str
    score: float
    severity: str
    vector: str


class CdxAdvisory(BaseModel):
    """Advisory link (NVD, upstream issue, fix commit)."""

    url: str
    title: str


class CdxVulnerability(BaseModel):
    """Single CycloneDX vulnerability entry."""

    bom_ref: str = Field(serialization_alias="bom-ref")
    id: str
    source: CdxSource
    analysis: CdxAnalysis
    affects: list[CdxAffects] = Field(default_factory=list)
    references: list[CdxReference] = Field(
        default_factory=list,
    )
    ratings: list[CdxRating] = Field(default_factory=list)
    # LWLP-2370: CWE IDs collected but excluded from output
    # until CWE + CSAF enrichment are ready together.
    cwes: list[int] | None = Field(default=None, exclude=True)
    recommendation: str = ""
    advisories: list[CdxAdvisory] = Field(
        default_factory=list,
    )
    published: str = ""
    updated: str = ""


class CdxMetadataComponent(BaseModel):
    """Identity of the module a VEX document is about (``metadata.component``).

    Identity fields only, mirroring the SBOM subject so the purl is
    byte-identical; licenses, hashes and pedigree stay in the SBOM.
    """

    type: str = "library"
    bom_ref: str = Field(serialization_alias="bom-ref")
    group: str | None = None
    name: str
    version: str
    purl: str


class CdxVEXMetadata(BaseModel):
    """VEX ``metadata``: release timestamp and the module described."""

    timestamp: str
    component: CdxMetadataComponent | None = None


class CdxVEXDocument(BaseModel):
    """CycloneDX 1.7 VEX document (no components; ``metadata.component`` names the module)."""

    bom_format: str = Field(
        default="CycloneDX",
        serialization_alias="bomFormat",
    )
    spec_version: str = Field(
        default="1.7",
        serialization_alias="specVersion",
    )
    serial_number: str = Field(
        serialization_alias="serialNumber",
    )
    version: int = 1
    metadata: CdxVEXMetadata | None = None
    vulnerabilities: list[CdxVulnerability] = Field(
        default_factory=list,
    )
