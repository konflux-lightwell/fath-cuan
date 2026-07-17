from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

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
    Reference,
    Severity,
)

_OSV_ID_PREFIX = "x_RHLW-"
_OSV_API = "https://api.osv.dev/v1/vulns"


def _parse_gav(gav: str) -> tuple[str, str, str]:
    """Split a Maven GAV string ('group:artifact:version') into its parts."""
    parts = gav.split(":")
    if len(parts) != 3:
        raise ValueError(f"Invalid GAV format, expected 'group:artifact:version': {gav}")
    return parts[0], parts[1], parts[2]


def _base_version(version: str) -> str:
    """Strip the rhlw qualifier to get the upstream base version."""
    m = re.match(r"^(.+?)\.rhlw-\w+-\d+$", version)
    if m:
        return m.group(1)
    m = re.match(r"^(.+?)\.rhlw-\d+$", version)
    if m:
        return m.group(1)
    return version


def _fetch_upstream_osv(cve_id: str) -> dict[str, Any] | None:
    """Fetch upstream OSV record for a CVE from osv.dev."""
    url = f"{_OSV_API}/{cve_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())  # type: ignore[no-any-return]
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None


def _extract_severity(upstream: dict[str, Any]) -> list[Severity]:
    """Extract CVSS severity from upstream OSV record."""
    result: list[Severity] = []
    for s in upstream.get("severity", []):
        score_type = s.get("type", "")
        score = s.get("score", "")
        if score_type and score:
            result.append(Severity(type=score_type, score=score))
    return result


def _extract_references(upstream: dict[str, Any], cve_id: str) -> list[Reference]:
    """Extract references from upstream OSV, fix types for commit URLs."""
    refs: list[Reference] = []
    seen: set[str] = set()
    for r in upstream.get("references", []):
        url = r.get("url", "")
        if not url or url in seen:
            continue
        seen.add(url)
        ref_type = r.get("type", "WEB")
        if "/commit/" in url or "/commits/" in url:
            ref_type = "FIX"
        refs.append(Reference(url=url, type=ref_type))

    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    if nvd_url not in seen:
        refs.append(Reference(url=nvd_url, type="WEB"))
    return refs


def _extract_aliases(upstream: dict[str, Any], cve_id: str) -> list[str]:
    """Extract aliases from upstream OSV, ensuring the CVE is included."""
    aliases = list(upstream.get("aliases", []))
    if cve_id not in aliases:
        aliases.append(cve_id)
    return aliases


def convert(doc: InputDocument) -> list[OSVDocument]:
    """Convert a PNC gav-index into one OSV record per CVE.

    Matches the balor-fianna reference format exactly: one file per CVE,
    with upstream severity/summary/details/references from osv.dev.
    """
    group_id, artifact_id, version = _parse_gav(doc.primary_gav)
    base_ver = _base_version(version)
    coordinates = f"{group_id}:{artifact_id}"
    purl = f"pkg:maven/{group_id}/{artifact_id}"

    modified = doc.created.strftime("%Y-%m-%dT%H:%M:%SZ")

    records: list[OSVDocument] = []
    seen_cves: set[str] = set()

    for cve_id in doc.cves:
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        osv_id = f"{_OSV_ID_PREFIX}{cve_id}-{base_ver}"

        upstream = _fetch_upstream_osv(cve_id)

        severity: list[Severity] = []
        references: list[Reference] = [
            Reference(url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", type="WEB")
        ]
        aliases: list[str] = [cve_id]
        summary = ""
        details = ""

        if upstream:
            severity = _extract_severity(upstream)
            references = _extract_references(upstream, cve_id)
            aliases = _extract_aliases(upstream, cve_id)
            summary = upstream.get("summary", "")
            details = upstream.get("details", "")

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

        record = OSVDocument(
            id=osv_id,
            modified=modified,
            severity=severity,
            references=references,
            summary=summary,
            details=details,
            aliases=aliases,
            affected=[affected],
            credits=[Credit(name="Red Hat Lightwell", type="REMEDIATION_DEVELOPER")],
            database_specific=DatabaseSpecific(
                lightwell=LightwellMeta(
                    backport_base_version=base_ver,
                    build_id=doc.build_id,
                )
            ),
        )
        records.append(record)

    return records
