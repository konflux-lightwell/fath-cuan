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


def _build_advisories(upstream: dict[str, Any] | None, cve_id: str) -> list[CdxAdvisory]:
    """Build advisory links: NVD, issue, fix commit."""
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
            advisories.append(CdxAdvisory(url=url, title="Upstream fix commit"))
        elif "/security/" in url or "/advisory/" in url or "/advisories/" in url:
            advisories.append(CdxAdvisory(url=url, title="Upstream security advisory"))

    return advisories


# ---------------------------------------------------------------------------
# CVSS ratings — no local calculator; scores come from OSIDB or NVD only.
# ---------------------------------------------------------------------------


def _extract_osidb_score(
    osidb_meta: dict[str, Any],
) -> tuple[str, float, str] | None:
    """Extract (vector, numeric_score, method) from OSIDB metadata.

    OSIDB ``cvss_scores`` carries the vector string. The numeric score
    is obtained from the raw flaw's ``cvss_scores[].score`` field when
    ``extract_osidb_metadata`` populates ``numeric_score``.  Falls back
    to NVD if the numeric score is absent.
    """
    for cv in osidb_meta.get("cvss_vectors", []):
        vector = cv.get("score", "")
        if not vector:
            continue
        numeric = cv.get("numeric_score")
        if numeric is None or numeric <= 0:
            return None
        method = "CVSSv4" if cv.get("type") == "CVSS_V4" else "CVSSv31"
        return vector, float(numeric), method
    return None


def _extract_nvd_score(
    nvd: dict[str, Any],
) -> tuple[str, float, str] | None:
    """Extract (vector, baseScore, method) from NVD CVE data."""
    metrics = nvd.get("metrics", {})
    for v31 in metrics.get("cvssMetricV31", []):
        data = v31.get("cvssData", {})
        vector = data.get("vectorString", "")
        base = data.get("baseScore")
        if vector and base is not None:
            return vector, float(base), "CVSSv31"
    for v40 in metrics.get("cvssMetricV40", []):
        data = v40.get("cvssData", {})
        vector = data.get("vectorString", "")
        base = data.get("baseScore")
        if vector and base is not None:
            return vector, float(base), "CVSSv4"
    return None


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


def _build_ratings(
    osidb_meta: dict[str, Any] | None,
    nvd: dict[str, Any] | None,
) -> list[CdxRating]:
    """Build CVSS ratings from OSIDB or NVD. Empty when neither has a score."""
    result = None
    if osidb_meta:
        result = _extract_osidb_score(osidb_meta)
    if result is None and nvd:
        result = _extract_nvd_score(nvd)
    if result is None:
        return []
    vector, score, method = result
    return [
        CdxRating(
            source=CdxSource(name="Red Hat Lightwell"),
            method=method,
            score=score,
            severity=_score_to_severity(score),
            vector=vector,
        )
    ]


# ---------------------------------------------------------------------------
# CWE extraction (collected but not emitted — LWLP-2370)
# ---------------------------------------------------------------------------


def _extract_cwe_ids(osidb_meta: dict[str, Any] | None, nvd: dict[str, Any] | None) -> list[int]:
    """Collect CWE IDs from OSIDB and NVD.

    LWLP-2370: CWE enrichment code collects IDs here, but VEX output
    omits them until CWE + CSAF enrichment are confirmed ready together.
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
    """Build update recommendation text matching gold standard."""
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


def _build_affects_ref(sbom_serial_number: str, version: int, bom_ref: str) -> str:
    """Build the URN cross-reference to an SBOM component.

    Format: urn:cdx:<sbom-uuid>/<version>#<bom-ref-encoded>
    Uses the bom-ref as it appears in the SBOM so the cross-link
    resolves regardless of qualifier form (bare vs ``?type=jar``).
    """
    sbom_uuid = sbom_serial_number
    if sbom_uuid.startswith("urn:uuid:"):
        sbom_uuid = sbom_uuid[len("urn:uuid:") :]
    encoded = urllib.parse.quote(bom_ref, safe="")
    return f"urn:cdx:{sbom_uuid}/{version}#{encoded}"


# ---------------------------------------------------------------------------
# Embargo handling
# ---------------------------------------------------------------------------

_EMBARGO_ANALYSIS = CdxAnalysis(state="in_triage")


def _build_embargo_stub(
    cve_id: str,
    timestamp: str,
) -> CdxVulnerability:
    """Build a minimal VEX entry for an embargoed CVE.

    Contains only the CVE ID and state — no enrichment data, ratings,
    advisories, or recommendation text. Safe for accidental disclosure.
    """
    return CdxVulnerability(
        bom_ref=str(uuid4()),
        id=cve_id,
        source=CdxSource(name="NVD", url=f"{_NVD_DETAIL}{cve_id}"),
        analysis=_EMBARGO_ANALYSIS,
        published=timestamp,
        updated=timestamp,
    )


# ---------------------------------------------------------------------------
# Vulnerability builder
# ---------------------------------------------------------------------------


def _build_vulnerability(
    cve_id: str,
    enrichment: dict[str, Any],
    affects_entries: list[CdxAffects],
    artifact_name: str,
    version: str,
    timestamp: str,
    osv_ecosystem: str = "Maven",
) -> CdxVulnerability:
    """Build a single CycloneDX vulnerability entry."""
    osidb_meta = enrichment.get("osidb_meta")
    upstream = enrichment.get("upstream")
    nvd = enrichment.get("nvd")

    if not osidb_meta and not upstream and not nvd:
        logger.warning(
            "No enrichment data for %s; ratings/advisories sparse",
            cve_id,
        )

    upstream_name, upstream_fix_version = _extract_upstream_fix(upstream, osv_ecosystem)
    recommendation = _build_recommendation(
        artifact_name, version, upstream_name, upstream_fix_version
    )

    advisories = _build_advisories(upstream, cve_id)
    ratings = _build_ratings(osidb_meta, nvd)
    cwe_ids = _extract_cwe_ids(osidb_meta, nvd)

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
# Shared VEX generation core
# ---------------------------------------------------------------------------


def _build_vex_documents(
    vulns: list[str],
    all_coords: list[Coordinate],
    coord: Coordinate,
    timestamp: str,
    osidb_client: OsidbClient | None,
    sbom_serial_numbers: dict[str, str],
    embargo: bool = False,
    redact_embargoed: bool = False,
) -> VEXResult:
    """Shared core for VEX generation (both build-index and legacy paths)."""
    if not vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    sbom_sns = sbom_serial_numbers
    osv_eco = coord.osv_ecosystem

    # Filter out LW- novel-fix identifiers — the identifier itself
    # is embargo-sensitive and must not appear in VEX documents.
    cve_vulns = [v for v in dict.fromkeys(vulns) if not v.startswith("LW-")]
    if len(cve_vulns) < len(set(vulns)):
        skipped = len(set(vulns)) - len(cve_vulns)
        logger.info("Skipping %d LW- identifier(s) from VEX generation", skipped)

    if not cve_vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    # Prefetch enrichment in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            cve_id: pool.submit(_prefetch_enrichment, cve_id, osidb_client) for cve_id in cve_vulns
        }
        enrichment_data = {cve_id: fut.result() for cve_id, fut in futures.items()}

    per_cve_docs: list[tuple[str, dict[str, Any]]] = []
    all_vex_vulns: list[CdxVulnerability] = []
    artifact_name = coord.name.split(":")[-1]

    for cve_id in cve_vulns:
        enrichment = enrichment_data[cve_id]
        osidb_meta = enrichment.get("osidb_meta")

        # Embargo handling: emit stub, never full enrichment data.
        if embargo or (redact_embargoed and osidb_meta and osidb_meta.get("embargoed")):
            stub = _build_embargo_stub(cve_id, timestamp)
            all_vex_vulns.append(stub)
            doc = CdxVEXDocument(
                serial_number=f"urn:uuid:{uuid4()}",
                vulnerabilities=[stub],
            )
            per_cve_docs.append(
                (
                    cve_id,
                    doc.model_dump(by_alias=True, exclude_none=True),
                )
            )
            continue

        # Non-embargoed but OSIDB says embargoed: drop entirely.
        if osidb_meta and osidb_meta.get("embargoed"):
            logger.warning(
                "Dropping embargoed %s from VEX (not in redact mode)",
                cve_id,
            )
            continue

        # Build affects entries. The serial-numbers map may be keyed
        # by a qualified bom-ref (e.g. ?type=jar from PNC) while
        # c.purl is always bare (from PackageURL.to_string()). Try
        # the bare form first, then scan for a qualified key that
        # starts with the bare PURL.
        affects: list[CdxAffects] = []
        for c in all_coords:
            bare = c.purl.split("?", 1)[0]
            sn = sbom_sns.get(c.purl) or sbom_sns.get(bare)
            bom_ref_key = bare
            if not sn:
                # Scan for a qualified key matching this coordinate
                for k, v in sbom_sns.items():
                    if k.split("?", 1)[0] == bare:
                        sn = v
                        bom_ref_key = k
                        break
            if sn:
                ref = _build_affects_ref(sn, 1, bom_ref_key)
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

        vuln = _build_vulnerability(
            cve_id,
            enrichment,
            affects,
            artifact_name,
            coord.version,
            timestamp,
            osv_ecosystem=osv_eco,
        )
        all_vex_vulns.append(vuln)

        doc = CdxVEXDocument(
            serial_number=f"urn:uuid:{uuid4()}",
            vulnerabilities=[vuln],
        )
        per_cve_docs.append((cve_id, doc.model_dump(by_alias=True, exclude_none=True)))

    multi_cve_doc = None
    if all_vex_vulns:
        multi_doc = CdxVEXDocument(
            serial_number=f"urn:uuid:{uuid4()}",
            vulnerabilities=all_vex_vulns,
        )
        multi_cve_doc = multi_doc.model_dump(by_alias=True, exclude_none=True)

    logger.info(
        "Generated %d per-CVE VEX + %s multi-CVE VEX",
        len(per_cve_docs),
        "1" if multi_cve_doc else "0",
    )
    return VEXResult(per_cve=per_cve_docs, multi_cve=multi_cve_doc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def convert_build_index(
    bi: BuildIndex,
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
    embargo: bool = False,
    redact_embargoed: bool = False,
) -> VEXResult:
    """Generate VEX documents from a build-index."""
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
        embargo=embargo,
        redact_embargoed=redact_embargoed,
    )


def convert(
    doc: InputDocument,
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
    embargo: bool = False,
    redact_embargoed: bool = False,
) -> VEXResult:
    """Generate VEX documents from a legacy PNC InputDocument."""
    coord = maven_coordinate(doc.primary_gav, doc.upstream_version)
    timestamp = doc.created.strftime("%Y-%m-%dT%H:%M:%SZ")

    all_coords: list[Coordinate] = []
    for gav in doc.gavs:
        try:
            c = maven_coordinate(gav, doc.upstream_version)
            all_coords.append(c)
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
        embargo=embargo,
        redact_embargoed=redact_embargoed,
    )
