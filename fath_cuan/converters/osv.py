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
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_ADVISORY_PATTERNS = (
    "/advisories/",
    "/advisory/",
    "nvd.nist.gov/vuln/detail/",
    "GHSA-",
    "security.netapp.com/advisory/",
    "access.redhat.com/errata/",
    "access.redhat.com/security/cve/",
)


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


def _fetch_nvd(cve_id: str) -> dict[str, Any] | None:
    """Fetch CVE data from NVD as a fallback for missing summary/severity."""
    url = f"{_NVD_API}?cveId={cve_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve", {})  # type: ignore[no-any-return]
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
        import logging

        logging.warning("NVD fetch failed for %s: %s", cve_id, e)
    return None


def _extract_severity(upstream: dict[str, Any], nvd: dict[str, Any] | None) -> list[Severity]:
    """Extract CVSS severity from upstream OSV and NVD, including v3.1 and v4.0."""
    result: list[Severity] = []
    seen_types: set[str] = set()

    for s in upstream.get("severity", []):
        score_type = s.get("type", "")
        score = s.get("score", "")
        if score_type and score and score_type not in seen_types:
            result.append(Severity(type=score_type, score=score))
            seen_types.add(score_type)

    if nvd and "CVSS_V3" not in seen_types:
        metrics = nvd.get("metrics", {})
        for v31 in metrics.get("cvssMetricV31", []):
            vector = v31.get("cvssData", {}).get("vectorString", "")
            if vector:
                result.append(Severity(type="CVSS_V3", score=vector))
                seen_types.add("CVSS_V3")
                break

    if nvd and "CVSS_V4" not in seen_types:
        metrics = nvd.get("metrics", {})
        for v40 in metrics.get("cvssMetricV40", []):
            vector = v40.get("cvssData", {}).get("vectorString", "")
            if vector:
                result.append(Severity(type="CVSS_V4", score=vector))
                seen_types.add("CVSS_V4")
                break

    return result


def _classify_reference_type(url: str, original_type: str) -> str:
    """Classify a reference URL as FIX, ADVISORY, or pass through the original type."""
    if "/commit/" in url or "/commits/" in url:
        return "FIX"
    for pattern in _ADVISORY_PATTERNS:
        if pattern in url:
            return "ADVISORY"
    return original_type


def _extract_references(upstream: dict[str, Any], cve_id: str) -> list[Reference]:
    """Extract references from upstream OSV with proper type classification."""
    refs: list[Reference] = []
    seen: set[str] = set()
    for r in upstream.get("references", []):
        url = r.get("url", "")
        if not url or url in seen:
            continue
        seen.add(url)
        ref_type = _classify_reference_type(url, r.get("type", "WEB"))
        refs.append(Reference(url=url, type=ref_type))

    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    if nvd_url not in seen:
        refs.append(Reference(url=nvd_url, type="ADVISORY"))
    return refs


def _extract_aliases(upstream: dict[str, Any], cve_id: str) -> list[str]:
    """Extract aliases from upstream OSV, ensuring the CVE is included."""
    aliases = list(upstream.get("aliases", []))
    if cve_id not in aliases:
        aliases.append(cve_id)
    return aliases


def _extract_summary_details(
    upstream: dict[str, Any] | None, nvd: dict[str, Any] | None
) -> tuple[str, str]:
    """Extract summary and details, falling back to NVD if upstream is missing."""
    summary = ""
    details = ""

    if upstream:
        summary = upstream.get("summary", "")
        details = upstream.get("details", "")

    if not summary and nvd:
        descriptions = nvd.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                if not details:
                    details = summary
                break

    return summary, details


def convert(doc: InputDocument, embargo: bool = False) -> list[OSVDocument]:
    """Convert a PNC gav-index into one OSV record per CVE.

    Matches the Lightwell OSV format specification. Fetches upstream CVE
    data from osv.dev with NVD fallback for missing fields.
    """
    group_id, artifact_id, version = _parse_gav(doc.primary_gav)
    base_ver = doc.upstream_version if doc.upstream_version else _base_version(version)
    coordinates = f"{group_id}:{artifact_id}"
    purl = f"pkg:maven/{group_id}/{artifact_id}"

    published = doc.created.strftime("%Y-%m-%dT%H:%M:%SZ")
    modified = published

    records: list[OSVDocument] = []
    seen_cves: set[str] = set()

    for cve_id in doc.cves:
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        osv_id = f"{_OSV_ID_PREFIX}{cve_id}-{base_ver}"

        if embargo:
            record = OSVDocument(
                id=osv_id,
                published=published,
                modified=modified,
                aliases=[],
                affected=[
                    AffectedEntry(
                        package=Package(name="", purl=None),
                        ranges=[],
                    )
                ],
                credits=[Credit(name="Red Hat Lightwell", type="REMEDIATION_DEVELOPER")],
                database_specific=DatabaseSpecific(
                    lightwell=LightwellMeta(
                        backport_base_version=base_ver,
                        build_id=doc.build_id,
                        embargo_status="pre-disclosure",
                    )
                ),
            )
            records.append(record)
            continue

        upstream = _fetch_upstream_osv(cve_id)
        nvd = None

        severity: list[Severity] = []
        references: list[Reference] = [
            Reference(url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", type="ADVISORY")
        ]
        aliases: list[str] = [cve_id]
        summary = ""
        details = ""

        if upstream:
            references = _extract_references(upstream, cve_id)
            aliases = _extract_aliases(upstream, cve_id)
            summary = upstream.get("summary", "")
            details = upstream.get("details", "")

        if not summary or not severity:
            nvd = _fetch_nvd(cve_id)

        severity = _extract_severity(upstream or {}, nvd)
        summary, details = _extract_summary_details(upstream, nvd)

        affected = AffectedEntry(
            package=Package(name=coordinates, purl=purl),
            versions=[base_ver],
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
            published=published,
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
