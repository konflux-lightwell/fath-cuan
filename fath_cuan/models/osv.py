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


class AffectedEntry(BaseModel):
    package: Package
    versions: list[str] = Field(default_factory=list)
    ranges: list[Range]


class Credit(BaseModel):
    name: str
    type: str


class LightwellMeta(BaseModel):
    source: str = "pnc-build"
    backport_base_version: str
    build_id: str
    embargo_status: str | None = None
    embargo_expires: str | None = None


class DatabaseSpecific(BaseModel):
    lightwell: LightwellMeta


class OSVDocument(BaseModel):
    schema_version: str = "1.6.8"
    id: str
    published: str | None = None
    modified: str
    withdrawn: str | None = None
    severity: list[Severity] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    summary: str = ""
    details: str = ""
    aliases: list[str] = Field(default_factory=list)
    affected: list[AffectedEntry]
    credits: list[Credit] = Field(default_factory=list)
    database_specific: DatabaseSpecific
