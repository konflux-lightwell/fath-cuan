from __future__ import annotations

from fath_cuan.models.input import InputDocument
from fath_cuan.models.osv import (
    AffectedEntry,
    Credit,
    DatabaseSpecific,
    Event,
    LightwellMeta,
    OSVDocument,
    Package,
    Range,
)

_OSV_ID_PREFIX = "x_RHLW-"


def _parse_gav(gav: str) -> tuple[str, str, str]:
    """Split a Maven GAV string ('group:artifact:version') into its parts."""
    parts = gav.split(":")
    if len(parts) != 3:
        raise ValueError(f"Invalid GAV format, expected 'group:artifact:version': {gav}")
    return parts[0], parts[1], parts[2]


def _deduplicate(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def convert(doc: InputDocument) -> OSVDocument:
    group_id, artifact_id, version = _parse_gav(doc.primary_gav)

    coordinates = f"{group_id}:{artifact_id}"
    purl = f"pkg:maven/{group_id}/{artifact_id}"

    affected = AffectedEntry(
        package=Package(name=coordinates, purl=purl),
        ranges=[
            Range(
                events=[
                    Event(introduced="0"),
                    Event(fixed=version),
                ]
            )
        ],
    )

    modified = doc.created.strftime("%Y-%m-%dT%H:%M:%SZ")

    return OSVDocument(
        id=f"{_OSV_ID_PREFIX}{doc.build_id}",
        modified=modified,
        aliases=_deduplicate(doc.cves),
        affected=[affected],
        credits=[Credit(name="Red Hat Lightwell", type="REMEDIATION_DEVELOPER")],
        database_specific=DatabaseSpecific(
            lightwell=LightwellMeta(
                backport_base_version=version,
                build_id=doc.build_id,
            )
        ),
    )
