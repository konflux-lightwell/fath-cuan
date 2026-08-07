from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any

from fath_cuan.jira.client import JiraClient
from fath_cuan.jira.models import VulnerabilityData
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
from fath_cuan.osidb import OsidbClient, extract_osidb_metadata

_OSV_ID_PREFIX = "x_RHLW-"
_OSV_API = "https://api.osv.dev/v1/vulns"
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

logger = logging.getLogger(__name__)

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
    logger.debug("Fetching upstream OSV for %s", cve_id)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.debug("Received upstream OSV response for %s", cve_id)
            return json.loads(resp.read())  # type: ignore[no-any-return]
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        logger.debug("No upstream OSV data found for %s", cve_id)
        return None


def _fetch_nvd(cve_id: str) -> dict[str, Any] | None:
    """Fetch CVE data from NVD as a fallback for missing summary/severity."""
    url = f"{_NVD_API}?cveId={cve_id}"
    logger.debug("Fetching NVD data for %s", cve_id)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            if vulns:
                logger.debug("Received NVD data for %s", cve_id)
                return vulns[0].get("cve", {})  # type: ignore[no-any-return]
            logger.debug("No NVD vulnerabilities found for %s", cve_id)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
        logger.warning("NVD fetch failed for %s: %s", cve_id, e)
    return None


def _fetch_jira(lw_id: str, client: JiraClient | None = None) -> VulnerabilityData | None:
    """Fetch vulnerability data from JIRA for a Lightwell identifier."""
    jira = client or JiraClient()
    logger.debug("Fetching JIRA vulnerability data for %s", lw_id)
    try:
        result = jira.fetch_vulnerability(lw_id)
        if result:
            logger.debug("Found JIRA ticket %s for %s", result.key, lw_id)
        else:
            logger.debug("No matching JIRA ticket found for %s", lw_id)
        return result
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as e:
        logger.warning("JIRA fetch failed for %s: %s", lw_id, e)
        return None


def _jira_severity(severity_value: str) -> list[Severity]:
    """Convert a JIRA severity value to OSV Severity entries."""
    if not severity_value:
        return []
    if severity_value.startswith("CVSS:4"):
        return [Severity(type="CVSS_V4", score=severity_value)]
    if severity_value.startswith("CVSS:3"):
        return [Severity(type="CVSS_V3", score=severity_value)]
    if severity_value.startswith("CVSS:2"):
        return [Severity(type="CVSS_V2", score=severity_value)]
    return []


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


def _extract_introduced(upstream: dict[str, Any], coordinates: str) -> str:
    """Extract the introduced version from upstream OSV ECOSYSTEM range.

    Searches the upstream affected entries for a matching Maven package
    and returns the introduced version from its ECOSYSTEM range.
    Falls back to "0" if no matching range is found.
    """
    for a in upstream.get("affected", []):
        pkg = a.get("package", {})
        if pkg.get("ecosystem") != "Maven":
            continue
        upstream_name = pkg.get("name", "")
        if upstream_name != coordinates and coordinates not in upstream_name:
            continue
        for r in a.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            for e in r.get("events", []):
                if "introduced" in e:
                    return str(e["introduced"])
    return "0"


def _extract_aliases(upstream: dict[str, Any], cve_id: str) -> list[str]:
    """Extract aliases from upstream OSV, ensuring the CVE is included."""
    aliases = list(upstream.get("aliases", []))
    if cve_id not in aliases:
        aliases.append(cve_id)
    return aliases


_USELESS_SUMMARIES = frozenset(
    {
        "fixed",
        "fixed.",
        "update",
        "update.",
        "patch",
        "patch.",
        "security fix",
        "security fix.",
        "bug fix",
        "bug fix.",
    }
)


def _is_useful_summary(text: str) -> bool:
    """Return False for summaries that are too short or generic to be informative."""
    stripped = text.strip()
    if not stripped or len(stripped) < 5:
        return False
    return stripped.lower() not in _USELESS_SUMMARIES


def _extract_summary_details(
    upstream: dict[str, Any] | None, nvd: dict[str, Any] | None
) -> tuple[str, str]:
    """Extract summary and details, falling back to NVD if upstream is missing."""
    summary = ""
    details = ""

    if upstream:
        candidate = upstream.get("summary", "")
        if _is_useful_summary(candidate):
            summary = candidate
        details = upstream.get("details", "")

    if not summary and details and _is_useful_summary(details):
        summary = details.split("\n", 1)[0]

    if not summary and nvd:
        descriptions = nvd.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                if not details:
                    details = summary
                break

    return summary, details


def convert(
    doc: InputDocument,
    embargo: bool = False,
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
) -> list[OSVDocument]:
    """Convert a PNC gav-index into one OSV record per CVE.

    Matches the Lightwell OSV format specification. Data source priority:
    1. OSIDB (structured vulnerability metadata, when available)
    2. Upstream OSV (osv.dev)
    3. NVD (fallback for missing summary/severity)
    4. JIRA (fallback for Lightwell identifiers)

    The Pulp OSV repo is currently protected by a content guard and is
    not public. All novel findings are embargoed by default within the
    protected feed. Set redact_embargoed=True to produce redacted stubs
    for embargoed flaws — use this when generating files destined for a
    public or less-trusted distribution.
    """
    group_id, artifact_id, version = _parse_gav(doc.primary_gav)
    base_ver = doc.upstream_version if doc.upstream_version else _base_version(version)
    coordinates = f"{group_id}:{artifact_id}"
    purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
    logger.debug("Converting %s (%s) with %d vulns", coordinates, version, len(doc.vulns))

    published = doc.created.strftime("%Y-%m-%dT%H:%M:%SZ")
    modified = published

    records: list[OSVDocument] = []
    seen_cves: set[str] = set()

    for cve_id in doc.vulns:
        if cve_id in seen_cves:
            logger.debug("Skipping duplicate %s", cve_id)
            continue
        seen_cves.add(cve_id)

        osv_id = f"{_OSV_ID_PREFIX}{cve_id}-{base_ver}"

        if embargo:
            logger.debug("Generating embargo stub for %s", cve_id)
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
                        embargo_status="pre-disclosure",
                    )
                ),
            )
            records.append(record)
            continue

        osidb_meta: dict[str, Any] | None = None
        if osidb_client and osidb_client.available:
            flaw = osidb_client.get_flaw(cve_id)
            if flaw:
                osidb_meta = extract_osidb_metadata(flaw)

        # Embargo redaction is opt-in. The current Pulp OSV repo is
        # protected by a content guard (not public), so full records are
        # safe for authenticated consumers. Enable redact_embargoed when
        # generating for a public or less-trusted feed.
        if redact_embargoed and osidb_meta and osidb_meta.get("embargoed"):
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
                        source="novel-pipeline",
                        backport_base_version=base_ver,
                        embargo_status="pre-disclosure",
                    )
                ),
            )
            records.append(record)
            continue

        upstream = _fetch_upstream_osv(cve_id) if cve_id.startswith("CVE-") else None
        nvd = None

        severity: list[Severity] = []
        references: list[Reference] = []
        aliases: list[str] = [cve_id]
        summary = ""
        details = ""
        lw_meta_extra: dict[str, str] = {}

        if osidb_meta:
            summary = osidb_meta.get("title", "")
            details = osidb_meta.get("description", "")

            for cv in osidb_meta.get("cvss_vectors", []):
                severity.append(Severity(type=cv["type"], score=cv["score"]))

            for ref in osidb_meta.get("references", []):
                references.append(Reference(url=ref["url"], type=ref["type"]))

            osidb_cve = osidb_meta.get("cve_id")
            if osidb_cve and osidb_cve not in aliases:
                aliases.append(osidb_cve)

            vuln_id = osidb_meta.get("vulnerability_id", "")
            if vuln_id:
                lw_meta_extra["lw_id"] = vuln_id

            cwe = osidb_meta.get("cwe_id", "")
            if cwe:
                lw_meta_extra["vulnerability_class"] = cwe

        if upstream:
            if not references:
                references = _extract_references(upstream, cve_id)
            aliases = _extract_aliases(upstream, cve_id)
            if not summary:
                summary = upstream.get("summary", "")
            if not details:
                details = upstream.get("details", "")

        if not _is_useful_summary(summary) or not severity:
            logger.debug("Missing summary/severity, falling back to NVD for %s", cve_id)
            nvd = _fetch_nvd(cve_id) if cve_id.startswith("CVE-") else None

        if not severity:
            severity = _extract_severity(upstream or {}, nvd)

        summary, details = (
            _extract_summary_details(
                upstream if not osidb_meta else None,
                nvd,
            )
            if not _is_useful_summary(summary)
            else (summary, details)
        )

        if not osidb_meta and cve_id.startswith("LW-"):
            jira_data = _fetch_jira(cve_id, jira_client)
            if jira_data:
                if not _is_useful_summary(summary):
                    summary = jira_data.summary
                if not details:
                    details = jira_data.details
                if not severity:
                    severity = _jira_severity(jira_data.severity)

        if not references and cve_id.startswith("CVE-"):
            references.append(
                Reference(
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    type="ADVISORY",
                )
            )

        introduced = _extract_introduced(upstream, coordinates) if upstream else "0"

        source = "novel-pipeline" if cve_id.startswith("LW-") else "pnc-build"

        if cve_id.startswith("LW-") and "lw_id" not in lw_meta_extra:
            lw_meta_extra["lw_id"] = cve_id

        affected = AffectedEntry(
            package=Package(name=coordinates, purl=purl),
            versions=[base_ver],
            ranges=[
                Range(
                    events=[
                        Event(introduced=introduced),
                        Event(fixed=version),
                    ]
                )
            ],
        )

        lw_meta = LightwellMeta(
            source=source,
            backport_base_version=base_ver,
            **lw_meta_extra,
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
            database_specific=DatabaseSpecific(lightwell=lw_meta),
        )
        records.append(record)

    logger.info("Generated %d OSV records", len(records))
    return records
