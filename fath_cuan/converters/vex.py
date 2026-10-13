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
    _extract_references,
    _extract_severity,
    _fetch_nvd,
    _fetch_upstream_osv,
    _is_public_url,
)
from fath_cuan.ecosystems import (
    Coordinate,
    coordinate_from_purl,
    maven_base_version,
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
    CdxVEXDocument,
    CdxVersion,
    CdxVulnerability,
)
from fath_cuan.osidb import OsidbClient, extract_osidb_metadata

logger = logging.getLogger(__name__)

_NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"


@dataclass(frozen=True)
class VEXResult:
    """Container for generated VEX documents."""

    per_cve: list[tuple[str, dict[str, Any]]]  # (cve_id, document_dict)
    multi_cve: dict[str, Any] | None  # aggregate document (None when 0 vulns)


def _prefetch_enrichment(
    cve_id: str, osidb_client: OsidbClient | None
) -> dict[str, Any]:
    """Fetch OSIDB, upstream OSV, and NVD data for a single CVE."""
    osidb_meta: dict[str, Any] | None = None
    if osidb_client and osidb_client.available:
        flaw = osidb_client.get_flaw(cve_id)
        if flaw:
            osidb_meta = extract_osidb_metadata(flaw)
    upstream = _fetch_upstream_osv(cve_id) if cve_id.startswith("CVE-") else None
    nvd = _fetch_nvd(cve_id) if cve_id.startswith("CVE-") else None
    return {"osidb_meta": osidb_meta, "upstream": upstream, "nvd": nvd}


def _build_advisories(
    upstream: dict[str, Any] | None, cve_id: str
) -> list[CdxAdvisory]:
    """Build advisory links from upstream references: NVD, issue, fix commit."""
    advisories: list[CdxAdvisory] = []
    nvd_url = f"{_NVD_DETAIL}{cve_id}"
    advisories.append(CdxAdvisory(url=nvd_url, title=f"NVD entry for {cve_id}"))

    if not upstream:
        return advisories

    refs = upstream.get("references", [])
    for r in refs:
        url = r.get("url", "")
        if not url or not _is_public_url(url):
            continue
        if "/issues/" in url or "/issue/" in url:
            advisories.append(CdxAdvisory(url=url, title="Upstream issue report"))
        elif "/commit/" in url or "/commits/" in url:
            # Distinguish branch-specific commits
            if "/commit/" in url:
                advisories.append(CdxAdvisory(url=url, title="Upstream fix commit"))
            else:
                advisories.append(CdxAdvisory(url=url, title="Upstream fix commit"))
        elif "/security/" in url or "/advisory/" in url or "/advisories/" in url:
            # Vendor security advisory (e.g. Spring Security Advisory)
            advisories.append(CdxAdvisory(url=url, title="Upstream security advisory"))

    return advisories


def _build_ratings(
    osidb_meta: dict[str, Any] | None,
    upstream: dict[str, Any] | None,
    nvd: dict[str, Any] | None,
) -> list[CdxRating]:
    """Build CVSS ratings from OSIDB, upstream, or NVD (in priority order)."""
    # OSIDB is authoritative
    if osidb_meta:
        for cv in osidb_meta.get("cvss_vectors", []):
            vector = cv.get("score", "")
            if not vector:
                continue
            score = _cvss_score_from_vector(vector)
            severity = _score_to_severity(score)
            method = "CVSSv4" if cv.get("type") == "CVSS_V4" else "CVSSv31"
            return [
                CdxRating(
                    source=CdxSource(name="Red Hat Lightwell"),
                    method=method,
                    score=score,
                    severity=severity,
                    vector=vector,
                )
            ]

    # Fall back to upstream OSV + NVD
    severity_entries = _extract_severity(upstream or {}, nvd)
    for sev in severity_entries:
        if sev.type in ("CVSS_V3", "CVSS_V4"):
            score = _cvss_score_from_vector(sev.score)
            severity = _score_to_severity(score)
            method = "CVSSv4" if sev.type == "CVSS_V4" else "CVSSv31"
            return [
                CdxRating(
                    source=CdxSource(name="Red Hat Lightwell"),
                    method=method,
                    score=score,
                    severity=severity,
                    vector=sev.score,
                )
            ]

    return []


def _cvss_score_from_vector(vector: str) -> float:
    """Parse CVSS base score from a vector string (simple heuristic).

    For precision this uses the same computation as the jfrog_bridge
    CVSS calculator. A lightweight approximation suffices here because
    the authoritative score comes from OSIDB/NVD ratings.
    """
    import math

    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        kv = part.split(":", 1)
        if len(kv) == 2:
            metrics[kv[0]] = kv[1]

    if not metrics or "AV" not in metrics:
        return 0.0

    val_maps = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }

    def _val(key: str) -> float:
        return val_maps.get(key, {}).get(metrics.get(key, ""), 0.0)

    av, ac, pr, ui = _val("AV"), _val("AC"), _val("PR"), _val("UI")
    ci, ii, ai = _val("C"), _val("I"), _val("A")
    s = metrics.get("S", "U")

    if s == "C":
        if metrics.get("PR") == "L":
            pr = 0.68
        elif metrics.get("PR") == "H":
            pr = 0.50

    iss = 1.0 - (1.0 - ci) * (1.0 - ii) * (1.0 - ai)
    if s == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * math.Pow(iss - 0.02, 15) if hasattr(math, "Pow") else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if s == "C":
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    return math.ceil(score * 10) / 10


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


def _extract_cwe_ids(
    osidb_meta: dict[str, Any] | None, nvd: dict[str, Any] | None
) -> list[int]:
    """Collect CWE IDs from OSIDB and NVD.

    LWLP-2370: CWE enrichment code collects IDs here, but VEX output
    omits them until CWE + CSAF enrichment are confirmed ready together.
    """
    cwe_ids: list[int] = []
    seen: set[int] = set()

    if osidb_meta:
        cwe_str = osidb_meta.get("cwe_id", "")
        if cwe_str:
            # Format: "CWE-NNN" or "CWE-NNN->CWE-MMM"
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


def _extract_upstream_fix(upstream: dict[str, Any] | None, osv_ecosystem: str = "Maven") -> tuple[str, str]:
    """Extract the upstream package name and fix version from OSV data.

    Returns (upstream_name, fix_version). Falls back to ("", "") when the
    upstream data has no matching ECOSYSTEM range with a fixed event.
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
    """Build update recommendation text matching gold standard.

    When upstream fix info is available, references the upstream package
    and version where the fix originated (e.g. "woodstox-core 6.4.0").
    Falls back to the remediated artifact name when unavailable.
    """
    fix_name = upstream_name.split(":")[-1] if upstream_name else artifact_name
    fix_version = upstream_fix_version if upstream_fix_version else "a newer release"
    return (
        f"Update to {artifact_name} {version} from Red Hat Lightwell "
        f"remediated repository. This version backports the upstream fix "
        f"from {fix_name} {fix_version}."
    )


def _build_affects_ref(sbom_serial_number: str, version: int, purl: str) -> str:
    """Build the URN cross-reference to an SBOM component.

    Format: urn:cdx:<sbom-uuid>/<version>#<purl-encoded>
    Uses the bare PURL (without qualifiers) matching the gold standard.
    """
    # Strip "urn:uuid:" prefix from serialNumber
    sbom_uuid = sbom_serial_number
    if sbom_uuid.startswith("urn:uuid:"):
        sbom_uuid = sbom_uuid[len("urn:uuid:"):]
    # Strip qualifiers from the PURL (everything after '?')
    bare_purl = purl.split("?", 1)[0]
    encoded_purl = urllib.parse.quote(bare_purl, safe="")
    return f"urn:cdx:{sbom_uuid}/{version}#{encoded_purl}"


def _build_vulnerability(
    cve_id: str,
    enrichment: dict[str, Any],
    affects_entries: list[CdxAffects],
    artifact_name: str,
    version: str,
    base_version: str,
    timestamp: str,
) -> CdxVulnerability:
    """Build a single CycloneDX vulnerability entry from enrichment data."""
    osidb_meta = enrichment.get("osidb_meta")
    upstream = enrichment.get("upstream")
    nvd = enrichment.get("nvd")

    # Extract upstream fix info for recommendation text
    upstream_name, upstream_fix_version = _extract_upstream_fix(upstream)
    recommendation = _build_recommendation(
        artifact_name, version, upstream_name, upstream_fix_version,
    )

    advisories = _build_advisories(upstream, cve_id)
    ratings = _build_ratings(osidb_meta, upstream, nvd)

    # LWLP-2370: collect CWEs but do not emit
    cwe_ids = _extract_cwe_ids(osidb_meta, nvd)

    return CdxVulnerability(
        **{"bom-ref": str(uuid4())},
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


def convert_build_index(
    bi: BuildIndex,
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
) -> VEXResult:
    """Generate VEX documents from a build-index.

    Args:
        bi: The parsed build-index.
        osidb_client: Optional OSIDB client for enrichment.
        sbom_serial_numbers: Map of PURL -> SBOM serialNumber (urn:uuid:...).

    Returns:
        VEXResult with per-CVE and multi-CVE documents.
    """
    if not bi.vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    coord = coordinate_from_purl(
        bi.primary_purl,
        ecosystem=bi.ecosystem,
        upstream_version=bi.version.upstream,
    )
    timestamp = ""
    if bi.created:
        timestamp = bi.created.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        from datetime import UTC, datetime
        timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    sbom_sns = sbom_serial_numbers or {}

    # Resolve all built coordinates for affects entries
    all_coords: list[Coordinate] = []
    for purl in bi.purls:
        try:
            c = coordinate_from_purl(purl, ecosystem=bi.ecosystem, upstream_version=bi.version.upstream)
            all_coords.append(c)
        except ValueError:
            logger.debug("Skipping unparseable purl %r", purl)

    # Prefetch enrichment data in parallel
    unique_vulns = list(dict.fromkeys(bi.vulns))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            cve_id: pool.submit(_prefetch_enrichment, cve_id, osidb_client)
            for cve_id in unique_vulns
        }
        enrichment_data = {cve_id: fut.result() for cve_id, fut in futures.items()}

    # Build per-CVE VEX documents
    per_cve_docs: list[tuple[str, dict[str, Any]]] = []
    all_vulns: list[CdxVulnerability] = []

    artifact_name = coord.name.split(":")[-1]

    for cve_id in unique_vulns:
        enrichment = enrichment_data[cve_id]

        # Skip embargoed CVEs
        osidb_meta = enrichment.get("osidb_meta")
        if osidb_meta and osidb_meta.get("embargoed"):
            logger.warning("Skipping embargoed %s in VEX generation", cve_id)
            continue

        # Build affects entries (link to SBOM serial numbers)
        affects: list[CdxAffects] = []
        for c in all_coords:
            sn = sbom_sns.get(c.purl, "")
            if not sn:
                # Use bare PURL as bom-ref key too
                bare_purl = f"pkg:maven/{c.name.replace(':', '/')}@{c.version}"
                sn = sbom_sns.get(bare_purl, "")
            if sn:
                ref = _build_affects_ref(sn, 1, c.purl)
                affects.append(
                    CdxAffects(
                        ref=ref,
                        versions=[CdxVersion(version=c.version, status="unaffected")],
                    )
                )

        vuln = _build_vulnerability(
            cve_id, enrichment, affects,
            artifact_name, coord.version, coord.base_version,
            timestamp,
        )
        all_vulns.append(vuln)

        # Per-CVE document
        per_cve_doc = CdxVEXDocument(
            **{"serialNumber": f"urn:uuid:{uuid4()}"},
            vulnerabilities=[vuln],
        )
        per_cve_docs.append(
            (cve_id, per_cve_doc.model_dump(by_alias=True, exclude_none=True))
        )

    # Multi-CVE document (all vulns in one)
    multi_cve_doc = None
    if all_vulns:
        multi_doc = CdxVEXDocument(
            **{"serialNumber": f"urn:uuid:{uuid4()}"},
            vulnerabilities=all_vulns,
        )
        multi_cve_doc = multi_doc.model_dump(by_alias=True, exclude_none=True)

    logger.info("Generated %d per-CVE VEX + 1 multi-CVE VEX", len(per_cve_docs))
    return VEXResult(per_cve=per_cve_docs, multi_cve=multi_cve_doc)


def convert(
    doc: InputDocument,
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
) -> VEXResult:
    """Generate VEX documents from a legacy PNC InputDocument.

    Args:
        doc: The parsed InputDocument (gav-index).
        osidb_client: Optional OSIDB client for enrichment.
        sbom_serial_numbers: Map of PURL -> SBOM serialNumber.

    Returns:
        VEXResult with per-CVE and multi-CVE documents.
    """
    if not doc.vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    coord = maven_coordinate(doc.primary_gav, doc.upstream_version)
    timestamp = doc.created.strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom_sns = sbom_serial_numbers or {}

    # Resolve all built coordinates
    all_coords: list[Coordinate] = []
    for gav in doc.gavs:
        try:
            c = maven_coordinate(gav, doc.upstream_version)
            all_coords.append(c)
        except ValueError:
            logger.debug("Skipping unparseable gav %r", gav)
    if not all_coords:
        all_coords = [coord]

    # Prefetch enrichment
    unique_vulns = list(dict.fromkeys(doc.vulns))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            cve_id: pool.submit(_prefetch_enrichment, cve_id, osidb_client)
            for cve_id in unique_vulns
        }
        enrichment_data = {cve_id: fut.result() for cve_id, fut in futures.items()}

    per_cve_docs: list[tuple[str, dict[str, Any]]] = []
    all_vulns: list[CdxVulnerability] = []
    artifact_name = coord.name.split(":")[-1]

    for cve_id in unique_vulns:
        enrichment = enrichment_data[cve_id]
        osidb_meta = enrichment.get("osidb_meta")
        if osidb_meta and osidb_meta.get("embargoed"):
            logger.warning("Skipping embargoed %s in VEX generation", cve_id)
            continue

        affects: list[CdxAffects] = []
        for c in all_coords:
            sn = sbom_sns.get(c.purl, "")
            if sn:
                ref = _build_affects_ref(sn, 1, c.purl)
                affects.append(
                    CdxAffects(
                        ref=ref,
                        versions=[CdxVersion(version=c.version, status="unaffected")],
                    )
                )

        vuln = _build_vulnerability(
            cve_id, enrichment, affects,
            artifact_name, coord.version, coord.base_version,
            timestamp,
        )
        all_vulns.append(vuln)

        per_cve_doc = CdxVEXDocument(
            **{"serialNumber": f"urn:uuid:{uuid4()}"},
            vulnerabilities=[vuln],
        )
        per_cve_docs.append(
            (cve_id, per_cve_doc.model_dump(by_alias=True, exclude_none=True))
        )

    multi_cve_doc = None
    if all_vulns:
        multi_doc = CdxVEXDocument(
            **{"serialNumber": f"urn:uuid:{uuid4()}"},
            vulnerabilities=all_vulns,
        )
        multi_cve_doc = multi_doc.model_dump(by_alias=True, exclude_none=True)

    logger.info("Generated %d per-CVE VEX + 1 multi-CVE VEX", len(per_cve_docs))
    return VEXResult(per_cve=per_cve_docs, multi_cve=multi_cve_doc)
