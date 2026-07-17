from __future__ import annotations

from pydantic import BaseModel


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
    ranges: list[Range]


class Credit(BaseModel):
    name: str
    type: str


class LightwellMeta(BaseModel):
    source: str = "lightwell-pipeline"
    backport_base_version: str
    build_id: str


class DatabaseSpecific(BaseModel):
    lightwell: LightwellMeta


class OSVDocument(BaseModel):
    schema_version: str = "1.6.8"
    id: str
    modified: str
    aliases: list[str]
    affected: list[AffectedEntry]
    credits: list[Credit]
    database_specific: DatabaseSpecific
