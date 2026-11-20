"""CycloneDX 1.7 VEX converter.

Generates per-CVE and multi-CVE VEX documents from build-index or
InputDocument data. Reuses the OSIDB/NVD/upstream enrichment chain from
the OSV converter for advisories, ratings, recommendations, and timestamps.

No cyclonedx-python-lib dependency — models are built directly via Pydantic.
"""

from __future__ import annotations

import concurrent.futures
import functools
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from fath_cuan.converters.osv import (
    _fetch_nvd,
    _fetch_upstream_osv,
    _is_public_url,
    _norm_name,
    _version_cmp,
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
    CdxMetadataComponent,
    CdxRating,
    CdxReference,
    CdxSource,
    CdxVersion,
    CdxVEXDocument,
    CdxVEXMetadata,
    CdxVulnerability,
)
from fath_cuan.osidb import OsidbClient, extract_osidb_metadata

logger = logging.getLogger(__name__)

_NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"

# Lightwell novel-fix identifiers (embargoed until a CVE is assigned). They
# are kept in VEX so slan-cuan routes the whole build to predisclosure
# repositories (or fails closed); dropping them would publish a silent fix.
_LW_PREFIX = "LW-"
_LIGHTWELL_SOURCE = CdxSource(name="Red Hat Lightwell")


def _is_lw(vuln_id: str) -> bool:
    return vuln_id.startswith(_LW_PREFIX)


# osv.dev CVE records usually carry only GIT ranges; the Maven/PyPI
# ECOSYSTEM ranges (with the upstream fix version) live on the GHSA
# aliases. Cap the alias fan-out per CVE.
_ALIAS_PREFIXES = ("GHSA-",)
_MAX_ALIAS_FETCHES = 5


@dataclass(frozen=True)
class ModuleVEX:
    """VEX documents for ONE built module (one SBOM, one VEX per module).

    Every document references only this module's SBOM in ``affects[]`` and
    names the module in ``metadata.component``. ``multi_cve`` is set only
    when the module has two or more statements.
    """

    purl: str
    per_cve: list[tuple[str, dict[str, Any]]]
    multi_cve: dict[str, Any] | None


@dataclass(frozen=True)
class VEXResult:
    """Container for generated VEX documents.

    ``modules`` holds the per-module documents, one entry per built module
    with an SBOM to reference. ``per_cve``/``multi_cve`` are kept for
    existing callers: for a single-module build they are that module's
    documents; for a multi-module build they keep the build-wide shape
    (``affects[]`` lists every module, no ``metadata.component``).
    """

    per_cve: list[tuple[str, dict[str, Any]]]
    multi_cve: dict[str, Any] | None
    modules: list[ModuleVEX] = field(default_factory=list)


def _prefetch_enrichment(cve_id: str, osidb_client: OsidbClient | None) -> dict[str, Any]:
    """Fetch OSIDB, upstream OSV, and NVD data for a single CVE."""
    osidb_meta: dict[str, Any] | None = None
    if osidb_client and osidb_client.available:
        flaw = osidb_client.get_flaw(cve_id)
        if flaw:
            osidb_meta = extract_osidb_metadata(flaw)
    upstream = _fetch_upstream_osv(cve_id) if cve_id.startswith("CVE-") else None
    upstream_aliases = _fetch_alias_records(upstream)
    nvd = _fetch_nvd(cve_id) if cve_id.startswith("CVE-") else None
    return {
        "osidb_meta": osidb_meta,
        "upstream": upstream,
        "upstream_aliases": upstream_aliases,
        "nvd": nvd,
    }


def _fetch_alias_records(upstream: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Fetch the osv.dev records for an upstream record's GHSA aliases.

    Fetched concurrently (order preserved) so one CVE with several aliases
    does not hold a prefetch worker for several sequential round trips.
    """
    if not upstream:
        return []
    alias_ids = [
        a
        for a in dict.fromkeys(upstream.get("aliases") or [])
        if isinstance(a, str) and a.startswith(_ALIAS_PREFIXES)
    ][:_MAX_ALIAS_FETCHES]
    if not alias_ids:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(alias_ids)) as pool:
        fetched = list(pool.map(_fetch_upstream_osv, alias_ids))
    return [record for record in fetched if record]


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


def _cvss_method(vector: str) -> str:
    """Map a CVSS vector to its CycloneDX rating method by version prefix."""
    if vector.startswith("CVSS:4.0/"):
        return "CVSSv4"
    if vector.startswith("CVSS:3.1/"):
        return "CVSSv31"
    if vector.startswith("CVSS:3.0/"):
        return "CVSSv3"
    if vector.startswith("CVSS:"):
        return "other"
    # CVSS v2 vectors carry no version prefix (e.g. "AV:N/AC:L/Au:N/...").
    return "CVSSv2"


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
        return vector, float(numeric), _cvss_method(vector)
    return None


def _extract_nvd_score(
    nvd: dict[str, Any],
) -> tuple[str, float, str] | None:
    """Extract (vector, baseScore, method) from NVD CVE data."""
    metrics = nvd.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        for metric in metrics.get(key, []):
            data = metric.get("cvssData", {})
            vector = data.get("vectorString", "")
            base = data.get("baseScore")
            if vector and base is not None:
                return vector, float(base), _cvss_method(vector)
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


def _ecosystem_fix_ranges(
    records: list[dict[str, Any]], osv_ecosystem: str
) -> list[tuple[str, str, str]]:
    """Collect ``(package_name, introduced, fixed)`` ECOSYSTEM ranges."""
    out: list[tuple[str, str, str]] = []
    for record in records:
        for affected in record.get("affected") or []:
            pkg = affected.get("package") or {}
            if pkg.get("ecosystem") != osv_ecosystem:
                continue
            name = str(pkg.get("name", ""))
            for r in affected.get("ranges") or []:
                if r.get("type") != "ECOSYSTEM":
                    continue
                introduced = "0"
                for event in r.get("events") or []:
                    if "introduced" in event:
                        introduced = str(event["introduced"])
                    elif event.get("fixed"):
                        out.append((name, introduced, str(event["fixed"])))
    return out


def _in_range(version: str, introduced: str, fixed: str) -> bool:
    """True when ``introduced <= version < fixed`` (``"0"`` = unbounded)."""
    lower_ok = introduced == "0" or _version_cmp(introduced, version) <= 0
    return lower_ok and _version_cmp(version, fixed) < 0


def _related_groups(a: str, b: str) -> bool:
    """True when one groupId is the other or a dotted extension of it."""
    return a == b or a.endswith(f".{b}") or b.endswith(f".{a}")


def _same_project(candidate: str, package_name: str) -> bool:
    """True when *candidate* belongs to the same project as *package_name*.

    Both names must already be normalized (see ``_norm_name``). A shared
    groupId matches. A shared artifactId matches only when the groupIds are
    related (one extends the other), which covers project renames such as
    ``dom4j:dom4j`` -> ``org.dom4j:dom4j`` without matching unrelated
    projects that happen to share a generic artifactId (``org.bar:core``
    vs ``com.foo:core``). Names without a ``:`` (PyPI) only match exactly.
    """
    if ":" not in candidate or ":" not in package_name:
        return candidate == package_name
    c_group, _, c_artifact = candidate.partition(":")
    group, _, artifact = package_name.partition(":")
    return c_group == group or (c_artifact == artifact and _related_groups(c_group, group))


def _cmp_fixed(a: tuple[str, str, str], b: tuple[str, str, str]) -> int:
    return _version_cmp(a[2], b[2])


def _extract_upstream_fix(
    upstream: dict[str, Any] | list[dict[str, Any]] | None,
    osv_ecosystem: str = "Maven",
    package_name: str = "",
    base_version: str = "",
) -> tuple[str, str]:
    """Extract the upstream package name and fix version from OSV data.

    *upstream* is the CVE record and/or its alias (GHSA) records. Package
    names are compared after ecosystem normalization (PEP 503 for PyPI,
    casefold for Maven), since advisories do not always match the build's
    spelling (``PyYAML`` vs ``pyyaml``). Ranges for *package_name* are
    preferred; otherwise only ranges from the same project (see
    ``_same_project``) are considered -- another project's fix version
    must never be named. When *base_version* is
    known, only the range containing it yields a fix version (lowest fix
    wins) -- a CVE fixed on several upstream branches must not report
    another branch's fix.

    Returns (upstream_name, fix_version), or ("", "") when nothing matches.
    """
    if not upstream:
        return "", ""
    records = [upstream] if isinstance(upstream, dict) else upstream
    ranges = _ecosystem_fix_ranges(records, osv_ecosystem)
    if package_name:
        wanted = _norm_name(package_name, osv_ecosystem)
        normed = [(_norm_name(r[0], osv_ecosystem), r) for r in ranges]
        named = [r for n, r in normed if n == wanted]
        ranges = named or [r for n, r in normed if _same_project(n, wanted)]
    if base_version:
        ranges = [r for r in ranges if _in_range(base_version, r[1], r[2])]
    if not ranges:
        return "", ""
    # Lowest fix wins among the ranges containing the base version.
    best = min(ranges, key=functools.cmp_to_key(_cmp_fixed)) if base_version else ranges[0]
    name, _, fixed = best
    return name, fixed


def _build_recommendation(
    artifact_name: str,
    version: str,
    upstream_name: str,
    upstream_fix_version: str,
) -> str:
    """Build update recommendation text matching gold standard.

    Names the upstream fix version only when it is known; never emits a
    placeholder version.
    """
    lead = f"Update to {artifact_name} {version} from Red Hat Lightwell remediated repository."
    if not upstream_fix_version:
        return f"{lead} This version backports the upstream fix."
    fix_name = upstream_name.split(":")[-1] if upstream_name else artifact_name
    return f"{lead} This version backports the upstream fix from {fix_name} {upstream_fix_version}."


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
        source=(
            _LIGHTWELL_SOURCE
            if _is_lw(cve_id)
            else CdxSource(name="NVD", url=f"{_NVD_DETAIL}{cve_id}")
        ),
        analysis=_EMBARGO_ANALYSIS,
        published=timestamp,
        updated=timestamp,
    )


# ---------------------------------------------------------------------------
# Vulnerability builder
# ---------------------------------------------------------------------------


def _build_lw_vulnerability(
    lw_id: str,
    osidb_meta: dict[str, Any] | None,
    affects_entries: list[CdxAffects],
    artifact_name: str,
    version: str,
    timestamp: str,
) -> CdxVulnerability:
    """Build the VEX entry for a Lightwell novel fix (``LW-`` identifier).

    There is no NVD record and no upstream fix to name, so the entry carries
    the Lightwell source, OSIDB ratings when available, and neutral wording.
    """
    recommendation = (
        f"Update to {artifact_name} {version} from Red Hat Lightwell "
        f"remediated repository. This version contains the Red Hat Lightwell "
        f"fix for {lw_id}."
    )
    return CdxVulnerability(
        bom_ref=str(uuid4()),
        id=lw_id,
        source=_LIGHTWELL_SOURCE,
        analysis=CdxAnalysis(
            state="resolved",
            response=["update"],
            detail=recommendation,
        ),
        affects=affects_entries,
        ratings=_build_ratings(osidb_meta, None),
        recommendation=recommendation,
        published=timestamp,
        updated=timestamp,
    )


def _build_vulnerability(
    cve_id: str,
    enrichment: dict[str, Any],
    affects_entries: list[CdxAffects],
    artifact_name: str,
    version: str,
    timestamp: str,
    osv_ecosystem: str = "Maven",
    package_name: str = "",
    base_version: str = "",
) -> CdxVulnerability:
    """Build a single CycloneDX vulnerability entry."""
    osidb_meta = enrichment.get("osidb_meta")
    upstream = enrichment.get("upstream")
    nvd = enrichment.get("nvd")

    if _is_lw(cve_id):
        return _build_lw_vulnerability(
            cve_id, osidb_meta, affects_entries, artifact_name, version, timestamp
        )

    if not osidb_meta and not upstream and not nvd:
        logger.warning(
            "No enrichment data for %s; ratings/advisories sparse",
            cve_id,
        )

    fix_records = [r for r in (upstream, *enrichment.get("upstream_aliases", [])) if r]
    upstream_name, upstream_fix_version = _extract_upstream_fix(
        fix_records, osv_ecosystem, package_name, base_version
    )
    if not upstream_fix_version:
        logger.info("No upstream fix version found for %s; using neutral wording", cve_id)
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


_COMPONENT_IDENTITY_KEYS = ("type", "bom-ref", "group", "name", "version", "purl")


def _resolve_sbom_ref(c: Coordinate, sbom_sns: dict[str, str]) -> tuple[str | None, str]:
    """Find the SBOM serial and bom-ref for a coordinate.

    The serial-numbers map may be keyed by a qualified bom-ref (e.g.
    ?type=jar from PNC) while c.purl is always bare (from
    PackageURL.to_string()). Try the exact and bare forms first, then scan
    for a qualified key that starts with the bare PURL.
    """
    bare = c.purl.split("?", 1)[0]
    sn = sbom_sns.get(c.purl) or sbom_sns.get(bare)
    if sn:
        return sn, bare
    for k, v in sbom_sns.items():
        if k.split("?", 1)[0] == bare:
            return v, k
    return None, bare


def _module_component(
    c: Coordinate,
    bom_ref: str,
    sbom_components: dict[str, dict[str, Any]],
) -> CdxMetadataComponent:
    """Build ``metadata.component`` for a module.

    Prefers the SBOM subject identity passed by the caller (the SBOM's
    ``components[0]``, the shape PNC produces), so the purl is
    byte-identical to the SBOM's (including qualifiers such as
    ``repository_url`` that only the caller knows). Falls back to the
    coordinate.
    """
    bare = c.purl.split("?", 1)[0]
    sbom_comp = next(
        (sbom_components[k] for k in (bom_ref, c.purl, bare) if k in sbom_components),
        None,
    )
    if sbom_comp:
        identity = {k: sbom_comp[k] for k in _COMPONENT_IDENTITY_KEYS if sbom_comp.get(k)}
        # The caller's SBOM component may lack a bom-ref (it is optional in
        # CycloneDX); fall back to the ref used in the affects[] BOM-Link.
        identity.setdefault("bom-ref", bom_ref)
        return CdxMetadataComponent.model_validate(
            {("bom_ref" if k == "bom-ref" else k): v for k, v in identity.items()}
        )
    group, _, name = c.name.rpartition(":")
    return CdxMetadataComponent(
        bom_ref=bom_ref,
        group=group or None,
        name=name,
        version=c.version,
        purl=c.purl,
    )


def _build_doc_set(
    cve_vulns: list[str],
    enrichment_data: dict[str, dict[str, Any]],
    targets: list[tuple[Coordinate, str, str]],
    text_coord: Coordinate,
    timestamp: str,
    component: CdxMetadataComponent | None,
    embargo: bool,
    redact_embargoed: bool,
) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, Any] | None]:
    """Build per-CVE documents and the optional multi-CVE document.

    *targets* are the ``(coordinate, sbom_serial, bom_ref)`` entries listed
    in each statement's ``affects[]``; *text_coord* names the package in
    the recommendation text and drives the upstream-fix lookup.
    """
    metadata = CdxVEXMetadata(timestamp=timestamp, component=component)
    has_stub = False
    per_cve_docs: list[tuple[str, dict[str, Any]]] = []
    all_vex_vulns: list[CdxVulnerability] = []
    artifact_name = text_coord.name.split(":")[-1]

    for cve_id in cve_vulns:
        enrichment = enrichment_data[cve_id]
        osidb_meta = enrichment.get("osidb_meta")

        # Embargo handling: emit stub, never full enrichment data. Stubs
        # carry no metadata, so nothing beyond the CVE ID is disclosed.
        if embargo or (redact_embargoed and osidb_meta and osidb_meta.get("embargoed")):
            stub = _build_embargo_stub(cve_id, timestamp)
            has_stub = True
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

        # Non-embargoed but OSIDB says embargoed: drop entirely. LW- IDs are
        # embargoed by definition and are never dropped (see _LW_PREFIX).
        if osidb_meta and osidb_meta.get("embargoed") and not _is_lw(cve_id):
            logger.warning(
                "Dropping embargoed %s from VEX (not in redact mode)",
                cve_id,
            )
            continue

        affects = [
            CdxAffects(
                ref=_build_affects_ref(sn, 1, bom_ref),
                versions=[CdxVersion(version=c.version, status="unaffected")],
            )
            for c, sn, bom_ref in targets
        ]

        vuln = _build_vulnerability(
            cve_id,
            enrichment,
            affects,
            artifact_name,
            text_coord.version,
            timestamp,
            osv_ecosystem=text_coord.osv_ecosystem,
            package_name=text_coord.name,
            base_version=text_coord.base_version,
        )
        all_vex_vulns.append(vuln)

        doc = CdxVEXDocument(
            serial_number=f"urn:uuid:{uuid4()}",
            metadata=metadata,
            vulnerabilities=[vuln],
        )
        per_cve_docs.append((cve_id, doc.model_dump(by_alias=True, exclude_none=True)))

    # A multi-CVE document is only meaningful for two or more statements;
    # with one it would duplicate the per-CVE document. Like the stub
    # documents, a multi-CVE document holding any embargo stub carries no
    # metadata: it must not tie the embargoed IDs to a named module.
    multi_cve_doc = None
    if len(all_vex_vulns) >= 2:
        multi_doc = CdxVEXDocument(
            serial_number=f"urn:uuid:{uuid4()}",
            metadata=None if has_stub else metadata,
            vulnerabilities=all_vex_vulns,
        )
        multi_cve_doc = multi_doc.model_dump(by_alias=True, exclude_none=True)
    return per_cve_docs, multi_cve_doc


def _build_vex_documents(
    vulns: list[str],
    all_coords: list[Coordinate],
    coord: Coordinate,
    timestamp: str,
    osidb_client: OsidbClient | None,
    sbom_serial_numbers: dict[str, str],
    embargo: bool = False,
    redact_embargoed: bool = False,
    sbom_components: dict[str, dict[str, Any]] | None = None,
) -> VEXResult:
    """Shared core for VEX generation (both build-index and legacy paths)."""
    if not vulns:
        return VEXResult(per_cve=[], multi_cve=None)

    sbom_sns = sbom_serial_numbers
    components = sbom_components or {}

    # LW- novel-fix identifiers stay in the VEX: slan-cuan routes any VEX
    # carrying them to predisclosure repositories, or fails closed. Dropping
    # them would leave a CVE-only VEX for a build that also carries an
    # embargoed fix, i.e. a silent fix.
    cve_vulns = list(dict.fromkeys(vulns))
    lw_count = sum(1 for v in cve_vulns if _is_lw(v))
    if lw_count:
        logger.info("Including %d LW- identifier(s) in VEX (predisclosure only)", lw_count)

    # Prefetch enrichment in parallel (once per CVE, shared by all modules)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            cve_id: pool.submit(_prefetch_enrichment, cve_id, osidb_client) for cve_id in cve_vulns
        }
        enrichment_data = {cve_id: fut.result() for cve_id, fut in futures.items()}

    targets: list[tuple[Coordinate, str, str]] = []
    for c in all_coords:
        sn, bom_ref = _resolve_sbom_ref(c, sbom_sns)
        if sn:
            targets.append((c, sn, bom_ref))
        else:
            logger.info("No SBOM serial number for %s; no per-module VEX", c.purl)

    # One independent VEX document set per module, referencing only that
    # module's SBOM and named in metadata.component.
    modules: list[ModuleVEX] = []
    for c, sn, bom_ref in targets:
        component = _module_component(c, bom_ref, components)
        per_cve, multi = _build_doc_set(
            cve_vulns,
            enrichment_data,
            [(c, sn, bom_ref)],
            c,
            timestamp,
            component,
            embargo,
            redact_embargoed,
        )
        modules.append(ModuleVEX(purl=component.purl, per_cve=per_cve, multi_cve=multi))

    if len(all_coords) == 1 and modules:
        per_cve_docs, multi_cve_doc = modules[0].per_cve, modules[0].multi_cve
    else:
        # Build-wide shape kept for existing callers: affects[] lists every
        # module, so metadata.component is set only for a single-module build
        # (one whose module has no SBOM serial to reference).
        build_component = None
        if len(all_coords) == 1:
            only = all_coords[0]
            build_component = _module_component(only, only.purl.split("?", 1)[0], components)
        per_cve_docs, multi_cve_doc = _build_doc_set(
            cve_vulns,
            enrichment_data,
            targets,
            coord,
            timestamp,
            build_component,
            embargo,
            redact_embargoed,
        )

    logger.info(
        "Generated %d per-CVE VEX + %s multi-CVE VEX; %d module(s)",
        len(per_cve_docs),
        "1" if multi_cve_doc else "0",
        len(modules),
    )
    return VEXResult(per_cve=per_cve_docs, multi_cve=multi_cve_doc, modules=modules)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def convert_build_index(
    bi: BuildIndex,
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
    embargo: bool = False,
    redact_embargoed: bool = False,
    sbom_components: dict[str, dict[str, Any]] | None = None,
) -> VEXResult:
    """Generate VEX documents from a build-index.

    *sbom_components* optionally maps the same keys as
    *sbom_serial_numbers* to each SBOM's subject (its ``components[0]``);
    its identity fields become the VEX ``metadata.component``.
    """
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
        sbom_components=sbom_components,
    )


def convert(
    doc: InputDocument,
    osidb_client: OsidbClient | None = None,
    sbom_serial_numbers: dict[str, str] | None = None,
    embargo: bool = False,
    redact_embargoed: bool = False,
    sbom_components: dict[str, dict[str, Any]] | None = None,
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
        sbom_components=sbom_components,
    )
