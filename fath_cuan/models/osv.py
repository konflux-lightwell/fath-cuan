from __future__ import annotations

from pydantic import BaseModel, Field


class Severity(BaseModel):
    type: str
    score: str


class Reference(BaseModel):
    url: str
    type: str


class Event(BaseModel):
    introduced: str | None = None
    fixed: str | None = None


class Range(BaseModel):
    type: str = "ECOSYSTEM"
    events: list[Event]


class Package(BaseModel):
    ecosystem: str = "Maven"
    name: str
    purl: str | None = None


class Credit(BaseModel):
    name: str
    type: str


class LightwellMeta(BaseModel):
    source: str = "pnc-build"
    backport_base_version: str
    lw_id: str | None = None
    embargo_status: str | None = None
    embargo_expires: str | None = None
    vulnerability_class: str | None = None
    remediated_version: str | None = None
    repository_url: str | None = None


class DatabaseSpecific(BaseModel):
    lightwell: LightwellMeta


class AdvisoryLevelMeta(BaseModel):
    csaf_advisory: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)


class AdvisoryDatabaseSpecific(BaseModel):
    lightwell: AdvisoryLevelMeta


class AffectedEntry(BaseModel):
    package: Package
    versions: list[str] = Field(default_factory=list)
    ranges: list[Range]
    database_specific: DatabaseSpecific | None = None


class OSVDocument(BaseModel):
    schema_version: str = "1.9.0"
    id: str
    published: str | None = None
    modified: str
    withdrawn: str | None = None
    severity: list[Severity] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    summary: str = ""
    details: str = ""
    aliases: list[str] | None = None
    upstream: list[str] | None = None
    affected: list[AffectedEntry]
    credits: list[Credit] = Field(default_factory=list)
    database_specific: DatabaseSpecific | AdvisoryDatabaseSpecific
