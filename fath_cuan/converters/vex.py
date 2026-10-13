"""CycloneDX 1.7 VEX converter.

Generates per-CVE and multi-CVE VEX documents from build-index or
InputDocument data. Reuses the OSIDB/NVD/upstream enrichment chain from
the OSV converter for advisories, ratings, recommendations, and timestamps.

No cyclonedx-python-lib dependency — models are built directly via Pydantic.
"""

from __future__ import annotations

import concurrent.futures
import logging
import urllib.parse
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from fath_cuan.converters.osv import (
    _fetch_nvd,
    _fetch_upstream_osv,
    _is_public_url,
)
from fath_cuan.ecosystems import (
    Coordinate,
    coordinate_from_purl,
    maven_coordinate,
)
from fath_cuan.models.build_index import BuildIndex
from fath_cuan.models.input import InputDocument
from fath_cuan.models.vex import (
    CdxAdvisory,
    CdxAffects,
    CdxAnalysis,
    CdxRating,
    CdxReference,
    CdxSource,
    CdxVersion,
    CdxVEXDocument,
    CdxVulnerability,
)
from fath_cuan.osidb import OsidbClient, extract_osidb_metadata

logger = logging.getLogger(__name__)

_NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"


@dataclass(frozen=True)
class VEXResult:
    """Container for generated VEX documents."""

    per_cve: list[tuple[str, dict[str, Any]]]
    multi_cve: dict[str, Any] | None


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------


def _prefetch_enrichment(cve_id: str, osidb_client: OsidbClient | None) -> dict[str, Any]:
    """Fetch OSIDB, upstream OSV, and NVD data for a single CVE."""
    osidb_meta: dict[str, Any] | None = None
    if osidb_client and osidb_client.available:
        flaw = osidb_client.get_flaw(cve_id)
        if flaw:
            osidb_meta = extract_osidb_metadata(flaw)
    upstream = _fetch_upstream_osv(cve_id) if cve_id.startswith("CVE-") else None
    nvd = _fetch_nvd(cve_id) if cve_id.startswith("CVE-") else None
    return {"osidb_meta": osidb_meta, "upstream": upstream, "nvd": nvd}


# ---------------------------------------------------------------------------
# Advisories
# ---------------------------------------------------------------------------


def _build_advisories(upstream: dict[str, Any] | None, cve_id: str) -> list[CdxAdvisory]:
    """Build advisory links: NVD, upstream issue, fix commit."""
    advisories: list[CdxAdvisory] = [
        CdxAdvisory(
            url=f"{_NVD_DETAIL}{cve_id}",
            title=f"NVD entry for {cve_id}",
        )
    ]
    if not upstream:
        return advisories

    for r in upstream.get("references", []):
        url = r.get("url", "")
        if not url or not _is_public_url(url):
            continue
        if "/issues/" in url or "/issue/" in url:
            advisories.append(CdxAdvisory(url=url, title="Upstream issue report"))
        elif "/commit/" in url or "/commits/" in url:
            advisories.append(CdxAdvisory(url=url, title="Upstream fix commit"))
        elif "/security/" in url or "/advisory/" in url or "/advisories/" in url:
            advisories.append(CdxAdvisory(url=url, title="Upstream security advisory"))
    return advisories


# ---------------------------------------------------------------------------
# Ratings — no local CVSS calculator; scores come from OSIDB or NVD only.
# ---------------------------------------------------------------------------


def _extract_nvd_score(
    nvd: dict[str, Any] | None,
) -> tuple[float, str, str, str]:
    """Extract numeric score + severity + method + vector from NVD.

    Returns (score, severity, method, vector) or (0, "", "", "").
    """
    if not nvd:
        return 0.0, "", "", ""
    metrics = nvd.get("metrics", {})
    for v31 in metrics.get("cvssMetricV31", []):
        data = v31.get("cvssData", {})
        score = data.get("baseScore", 0.0)
        vector = data.get("vectorString", "")
        if score:
            return (
                float(score),
                _score_to_severity(float(score)),
                "CVSSv31",
                vector,
            )
    for v40 in metrics.get("cvssMetricV40", []):
        data = v40.get("cvssData", {})
        score = data.get("baseScore", 0.0)
        vector = data.get("vectorString", "")
        if score:
            return (
                float(score),
                _score_to_severity(float(score)),
                "CVSSv4",
                vector,
            )
    return 0.0, "", "", ""


def _build_ratings(
    osidb_meta: dict[str, Any] | None,
    upstream: dict[str, Any] | None,
    nvd: dict[str, Any] | None,
) -> list[CdxRating]:
    """Build CVSS ratings from OSIDB or NVD (in priority order).

    No local CVSS score calculation — numeric scores come directly from
    the authoritative source or the VEX entry has empty ratings.
    """
    # OSIDB is authoritative
    if osidb_meta:
        for cv in osidb_meta.get("cvss_vectors", []):
            vector = cv.get("score", "")
            numeric = cv.get("numeric_score", 0.0)
            if not vector:
                continue
            if numeric:
                method = "CVSSv4" if cv.get("type") == "CVSS_V4" else "CVSSv31"
                return [
                    CdxRating(
                        source=CdxSource(name="Red Hat Lightwell"),
                        method=method,
                        score=float(numeric),
                        severity=_score_to_severity(float(numeric)),
                        vector=vector,
                    )
                ]

    # NVD fallback (carries baseScore as a float)
    score, severity, method, vector = _extract_nvd_score(nvd)
    if score:
        return [
            CdxRating(
                source=CdxSource(name="Red Hat Lightwell"),
                method=method,
                score=score,
                severity=severity,
                vector=vector,
            )
        ]

    # No authoritative score available
    return []


def _score_to_severity(score: float) -> str:
    """Map CVSS score to severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


# ---------------------------------------------------------------------------
# CWE collection (output disabled per LWLP-2370)
# ---------------------------------------------------------------------------


def _extract_cwe_ids(osidb_meta: dict[str, Any] | None, nvd: dict[str, Any] | None) -> list[int]:
    """Collect CWE IDs from OSIDB and NVD.

    LWLP-2370: collected but excluded from VEX serialization.
    """
    cwe_ids: list[int] = []
    seen: set[int] = set()

    if osidb_meta:
        cwe_str = osidb_meta.get("cwe_id", "")
        if cwe_str:
            for part in cwe_str.replace("->", ",").split(","):
                part = part.strip()
                if part.startswith("CWE-"):
                    try:
                        cwe_num = int(part[4:])
                        if cwe_num not in seen:
                            seen.add(cwe_num)
                            cwe_ids.append(cwe_num)
                    except ValueError:
                        pass

    if nvd:
        for weakness in nvd.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    try:
                        cwe_num = int(val[4:])
                        if cwe_num not in seen:
                            seen.add(cwe_num)
                            cwe_ids.append(cwe_num)
                    except ValueError:
                        pass
    return cwe_ids


# ---------------------------------------------------------------------------
# Upstream fix extraction + recommendation text
# ---------------------------------------------------------------------------


def _extract_upstream_fix(
    upstream: dict[str, Any] | None,
    osv_ecosystem: str = "Maven",
) -> tuple[str, str]:
    """Extract upstream package name and fix version from OSV data.

    Returns (upstream_name, fix_version) or ("", "").
    """
    if not upstream:
        return "", ""
    for affected in upstream.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != osv_ecosystem:
            continue
        name = pkg.get("name", "")
        for r in affected.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            for event in r.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return name, str(fixed)
    return "", ""


def _build_recommendation(
    artifact_name: str,
    version: str,
    upstream_name: str,
    upstream_fix_version: str,
) -> str:
    """Build update recommendation text."""
    fix_name = upstream_name.split(":")[-1] if upstream_name else artifact_name
    fix_ver = upstream_fix_version or "a newer release"
    return (
        f"Update to {artifact_name} {version} from Red Hat Lightwell "
        f"remediated repository. This version backports the upstream "
        f"fix from {fix_name} {fix_ver}."
    )


# ---------------------------------------------------------------------------
# Affects cross-reference
# ---------------------------------------------------------------------------


def _build_affects_ref(sbom_serial_number: str, version: int, purl: str) -> str:
    """Build URN cross-reference to an SBOM component.

    Uses bare PURL (no qualifiers) matching gold standard.
    """
    sbom_uuid = sbom_serial_number
    if sbom_uuid.startswith("urn:uuid:"):
        sbom_uuid = sbom_uuid[len("urn:uuid:") :]
    bare_purl = purl.split("?", 1)[0]
    encoded_purl = urllib.parse.quote(bare_purl, safe="")
    return f"urn:cdx:{sbom_uuid}/{version}#{encoded_purl}"


# ---------------------------------------------------------------------------
# Embargo stub
# ---------------------------------------------------------------------------


def _build_embargo_stub(
    cve_id: str,
    affects_entries: list[CdxAffects],
    timestamp: str,
) -> CdxVulnerability:
    """Build a minimal VEX entry for an embargoed CVE.

    Contains only the CVE ID and analysis state — no enrichment data,
    ratings, advisories, or recommendation text. Safe for accidental
    public exposure: discloses nothing beyond the CVE ID itself.
    """
    return CdxVulnerability(
        bom_ref=str(uuid4()),
        id=cve_id,
        source=CdxSource(name="NVD", url=f"{_NVD_DETAIL}{cve_id}"),
        analysis=CdxAnalysis(state="in_triage"),
        affects=affects_entries,
        published=timestamp,
        updated=timestamp,
    )


# ---------------------------------------------------------------------------
# Per-vulnerability builder
# ---------------------------------------------------------------------------


def _build_vulnerability(
    cve_id: str,
    enrichment: dict[str, Any],
    affects_entries: list[CdxAffects],
    artifact_name: str,
    version: str,
    osv_ecosystem: str,
    timestamp: str,
) -> CdxVulnerability:
    """Build a CycloneDX vulnerability entry from enrichment data."""
    osidb_meta = enrichment.get("osidb_meta")
    upstream = enrichment.get("upstream")
    nvd = enrichment.get("nvd")

    upstream_name, upstream_fix_version = _extract_upstream_fix(upstream, osv_ecosystem)
    recommendation = _build_recommendation(
        artifact_name, version, upstream_name, upstream_fix_version
    )
    advisories = _build_advisories(upstream, cve_id)
    ratings = _build_ratings(osidb_meta, upstream, nvd)
    cwe_ids = _extract_cwe_ids(osidb_meta, nvd)

    if not ratings and not advisories[1:]:
        logger.warning("No enrichment data for %s; ratings/advisories sparse", cve_id)

    return CdxVulnerability(
        bom_ref=str(uuid4()),
        id=cve_id,
        source=CdxSource(name="NVD", url=f"{_NVD_DETAIL}{cve_id}"),
        analysis=CdxAnalysis(
            state="resolved",
            response=["update"],
            detail=recommendation,
        ),
        affects=affects_entries,
        references=[
            CdxReference(
                id=cve_id,
                source=CdxSource(
                    name=f"NVD entry for {cve_id}",
                    url=f"{_NVD_DETAIL}{cve_id}",
                ),
            )
        ],
        ratings=ratings,
        cwes=cwe_ids if cwe_ids else None,
        recommendation=recommendation,
        advisories=advisories,
        published=timestamp,
        updated=timestamp,
    )


# ---------------------------------------------------------------------------
# Shared core for both build-index and legacy InputDocument paths
# ---------------------------------------------------------------------------


def _build_vex_documents(
    vulns: list[str],
    all_coords: list[Coordinate],
    coord: Coordinate,
    timestamp: str,
    osidb_client: OsidbClient | None,
    sbom_serial_numbers: dict[str, str],
) -> VEXResult:
    """Build per-CVE and multi-CVE VEX documents (shared core)."""
    if not vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    sbom_sns = sbom_serial_numbers
    osv_eco = coord.osv_ecosystem
    artifact_name = coord.name.split(":")[-1]

    # Filter out LW- (novel/pre-disclosure) IDs — the identifier itself
    # is embargo-sensitive and must not appear in VEX documents.
    cve_vulns = [v for v in dict.fromkeys(vulns) if not v.startswith("LW-")]
    if not cve_vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    # Prefetch enrichment in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            cve_id: pool.submit(_prefetch_enrichment, cve_id, osidb_client) for cve_id in cve_vulns
        }
        enrichment_data = {cve_id: fut.result() for cve_id, fut in futures.items()}

    per_cve_docs: list[tuple[str, dict[str, Any]]] = []
    all_vuln_entries: list[CdxVulnerability] = []

    for cve_id in cve_vulns:
        enrichment = enrichment_data[cve_id]
        osidb_meta = enrichment.get("osidb_meta")
        is_embargoed = bool(osidb_meta and osidb_meta.get("embargoed"))

        # Build affects entries (link to SBOM serial numbers)
        affects: list[CdxAffects] = []
        for c in all_coords:
            sn = sbom_sns.get(c.purl, "")
            if not sn:
                bare = c.purl.split("?", 1)[0]
                sn = sbom_sns.get(bare, "")
            if sn:
                ref = _build_affects_ref(sn, 1, c.purl)
                affects.append(
                    CdxAffects(
                        ref=ref,
                        versions=[
                            CdxVersion(
                                version=c.version,
                                status="unaffected",
                            )
                        ],
                    )
                )

        if is_embargoed:
            logger.warning("Embargoed %s: emitting stub (no enrichment)", cve_id)
            vuln = _build_embargo_stub(cve_id, affects, timestamp)
        else:
            vuln = _build_vulnerability(
                cve_id,
                enrichment,
                affects,
                artifact_name,
                coord.version,
                osv_eco,
                timestamp,
            )

        all_vuln_entries.append(vuln)

        per_cve_doc = CdxVEXDocument(
            serial_number=f"urn:uuid:{uuid4()}",
            vulnerabilities=[vuln],
        )
        per_cve_docs.append(
            (
                cve_id,
                per_cve_doc.model_dump(by_alias=True, exclude_none=True),
            )
        )

    multi_cve_doc = None
    if all_vuln_entries:
        multi_doc = CdxVEXDocument(
            serial_number=f"urn:uuid:{uuid4()}",
            vulnerabilities=all_vuln_entries,
        )
        multi_cve_doc = multi_doc.model_dump(by_alias=True, exclude_none=True)

    logger.info(
        "Generated %d per-CVE VEX + %d multi-CVE VEX",
        len(per_cve_docs),
        1 if multi_cve_doc else 0,
    )
    return VEXResult(per_cve=per_cve_docs, multi_cve=multi_cve_doc)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def convert_build_index(
    bi: BuildIndex,
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
) -> VEXResult:
    """Generate VEX documents from a build-index."""
    if not bi.vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    coord = coordinate_from_purl(
        bi.primary_purl,
        ecosystem=bi.ecosystem,
        upstream_version=bi.version.upstream,
    )
    if bi.created:
        timestamp = bi.created.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        from datetime import UTC, datetime

        timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    all_coords: list[Coordinate] = []
    for purl in bi.purls:
        try:
            c = coordinate_from_purl(
                purl,
                ecosystem=bi.ecosystem,
                upstream_version=bi.version.upstream,
            )
            all_coords.append(c)
        except ValueError:
            logger.debug("Skipping unparseable purl %r", purl)

    return _build_vex_documents(
        bi.vulns,
        all_coords,
        coord,
        timestamp,
        osidb_client,
        sbom_serial_numbers or {},
    )


def convert(
    doc: InputDocument,
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
) -> VEXResult:
    """Generate VEX documents from a legacy PNC InputDocument."""
    if not doc.vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    coord = maven_coordinate(doc.primary_gav, doc.upstream_version)
    timestamp = doc.created.strftime("%Y-%m-%dT%H:%M:%SZ")

    all_coords: list[Coordinate] = []
    for gav in doc.gavs:
        try:
            all_coords.append(maven_coordinate(gav, doc.upstream_version))
        except ValueError:
            logger.debug("Skipping unparseable gav %r", gav)
    if not all_coords:
        all_coords = [coord]

    return _build_vex_documents(
        doc.vulns,
        all_coords,
        coord,
        timestamp,
        osidb_client,
        sbom_serial_numbers or {},
    )
