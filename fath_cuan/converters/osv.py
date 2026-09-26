from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any

from packageurl import PackageURL

from fath_cuan.ecosystems import (
    Coordinate,
    coordinate_from_purl,
    maven_base_version,
    maven_coordinate,
    parse_gav,
    pep503_normalize,
)
from fath_cuan.jira.client import JiraClient
from fath_cuan.jira.models import VulnerabilityData
from fath_cuan.models.build_index import BuildIndex
from fath_cuan.models.input import InputDocument
from fath_cuan.models.osv import (
    AdvisoryDatabaseSpecific,
    AdvisoryLevelMeta,
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

_ADVISORY_URL_TEMPLATE = "https://packages.redhat.com/lightwell/advisories/{}.json"

_REPOSITORY_URLS: dict[str, str] = {
    "maven": "https://packages.redhat.com/lightwell/java/remediated/",
    "pypi": "https://packages.redhat.com/lightwell/python/remediated/",
}

_REGISTRY_NAMES: dict[str, str] = {
    "maven": "Maven Central",
    "pypi": "PyPI",
}

_INTERNAL_URL_PATTERNS = (
    "gitlab.cee.redhat.com",
    "issues.redhat.com",
    "bugzilla.redhat.com",
    "jira.redhat.com",
)


# Backward-compatible aliases. The canonical implementations now live in
# fath_cuan.ecosystems; these names are kept because tests and the Java OSV
# behaviour they pin import them from this module.
_parse_gav = parse_gav
_base_version = maven_base_version


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


def _introduced_from_entry(affected: dict[str, Any]) -> str | None:
    """Return the introduced version from an affected entry's ECOSYSTEM range."""
    for r in affected.get("ranges", []):
        if r.get("type") != "ECOSYSTEM":
            continue
        for e in r.get("events", []):
            if "introduced" in e:
                return str(e["introduced"])
    return None


def _extract_introduced(
    upstream: dict[str, Any], coordinates: str, osv_ecosystem: str = "Maven"
) -> str:
    """Extract the introduced version from upstream OSV ECOSYSTEM range.

    Searches the upstream affected entries for a package in the given OSV
    ecosystem (e.g. "Maven", "PyPI") whose name matches ``coordinates``. An
    **exact** name match is always preferred. For non-normalized ecosystems a
    substring match is used as a fallback when no exact entry exists; for PyPI
    the substring fallback is **disabled** so a bare ``requests`` cannot bind to
    ``requests-oauthlib`` — exact match is authoritative there.

    For PyPI, both sides are PEP 503-normalized before comparison, so an
    upstream name in any casing/separator form (``Coverage``, ``zope.interface``)
    still matches our already-normalized coordinate — otherwise the lookup would
    silently miss and emit an over-broad ``introduced: "0"``. Falls back to "0"
    if no match yields an introduced version.
    """

    def _norm(name: str) -> str:
        return pep503_normalize(name) if osv_ecosystem == "PyPI" else name

    target = _norm(coordinates)
    entries = [
        a
        for a in upstream.get("affected", [])
        if a.get("package", {}).get("ecosystem") == osv_ecosystem
    ]
    for a in entries:  # exact match first
        if _norm(a.get("package", {}).get("name", "")) == target:
            v = _introduced_from_entry(a)
            if v is not None:
                return v
    # Substring fallback is unsafe for exact-normalized ecosystems (PyPI): a
    # single-token name like 'requests' would bind to any advisory package that
    # merely contains it (e.g. 'requests-oauthlib'). PyPI names are PEP 503-
    # normalized on both sides, so the exact pass above is authoritative — skip
    # the fallback there. Keep it only for ecosystems without such normalization.
    if osv_ecosystem != "PyPI":
        for a in entries:  # substring fallback (non-normalized ecosystems only)
            if target in _norm(a.get("package", {}).get("name", "")):
                v = _introduced_from_entry(a)
                if v is not None:
                    return v
    return "0"


def _norm_name(name: str, osv_ecosystem: str) -> str:
    """Normalize a package name for cross-source matching.

    * **PyPI** — PEP 503 (lowercase + collapse ``-_.`` runs).
    * **Maven** — casefold ``group:artifact``. Maven coordinates are
      conventionally lowercase but not guaranteed to be, and an upstream
      advisory's Maven name isn't guaranteed to use the same casing as our
      gav-index entry. Casefolding both sides before the compare stops a mere
      casing divergence from missing the match (which, for a CVE, would leave
      ``strict`` True and drop an otherwise-correct record).
    """
    return pep503_normalize(name) if osv_ecosystem == "PyPI" else name.casefold()


def _candidate_index(built_coords: list[Coordinate]) -> dict[str, Coordinate]:
    """Map normalized package name -> the Coordinate actually built for it.

    These are the artifacts the build produced (the gav-index ``gavs[]`` /
    build-index ``purls[]``). The affected module resolved from the upstream
    advisory or OSIDB is matched against this set so the OSV names the module
    that was really shipped — not the build's arbitrary primary coordinate.
    """
    index: dict[str, Coordinate] = {}
    for c in built_coords:
        index.setdefault(_norm_name(c.name, c.osv_ecosystem), c)
    return index


def _upstream_affected_names(upstream: dict[str, Any] | None, osv_ecosystem: str) -> list[str]:
    """Affected package names for ``osv_ecosystem`` from an upstream OSV record."""
    if not upstream:
        return []
    names: list[str] = []
    for a in upstream.get("affected", []):
        pkg = a.get("package", {})
        if pkg.get("ecosystem") == osv_ecosystem:
            name = pkg.get("name", "")
            if name:
                names.append(name)
    return names


def _resolve_affected(
    upstream: dict[str, Any] | None,
    osidb_meta: dict[str, Any] | None,
    candidates: dict[str, Coordinate],
    osv_ecosystem: str,
) -> tuple[list[Coordinate], bool]:
    """Resolve a vuln's true affected module(s) to the coordinate(s) actually built.

    Returns ``(matched, strict)``:

    * **CVE (upstream advisory)** is authoritative. When it names affected
      packages in this ecosystem and at least one was built, ``strict`` is True
      and only the matched built modules are emitted. If it names packages but
      none were built, OSIDB ``components`` are consulted as a fallback before
      giving up; only when neither source can place a built module does it
      return ``([], strict=True)`` so the caller DROPS the record rather than
      fall back to the build's arbitrary primary coordinate (the ``primaryGav``
      mis-attribution this fix exists to eliminate). Upstream matching is exact
      (case-normalized per ecosystem).
    * **Novel (OSIDB components)** is advisory but fuzzy (Red Hat component names
      do not always map 1:1 to Maven coordinates), so ``strict`` is False: a
      match is used when found (incl. an unambiguous bare-artifactId), otherwise
      the caller falls back.

    A build with no enumerated modules (empty ``candidates``) is never strict —
    it falls back to the primary coordinate, preserving prior behaviour when the
    build manifest itself is unavailable.
    """
    if not candidates:
        return [], False

    def _collect(names: list[str], fuzzy: bool) -> list[Coordinate]:
        out: list[Coordinate] = []
        seen: set[str] = set()
        for n in names:
            key = _norm_name(str(n), osv_ecosystem)
            cand = candidates.get(key)
            if cand is None and fuzzy:
                # Bare-artifactId fallback (OSIDB component names don't always
                # carry the groupId). Collect ALL built modules whose artifactId
                # matches and fail closed when more than one does: a build
                # producing both org.a:widget and org.b:widget must not silently
                # bind a bare 'widget' component to whichever hashed first.
                artifact_matches = [
                    c
                    for cand_key, c in candidates.items()
                    if key == cand_key.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
                ]
                if len(artifact_matches) == 1:
                    cand = artifact_matches[0]
                elif len(artifact_matches) > 1:
                    logger.warning(
                        "Ambiguous artifactId %r matches multiple built modules %s; "
                        "refusing to bind (failing closed)",
                        n,
                        sorted(c.name for c in artifact_matches),
                    )
            if cand is not None and cand.name not in seen:
                seen.add(cand.name)
                out.append(cand)
        return out

    osidb_comps = [str(c) for c in (osidb_meta.get("components") or [])] if osidb_meta else []

    upstream_names = _upstream_affected_names(upstream, osv_ecosystem)
    if upstream_names:
        matched = _collect(upstream_names, fuzzy=False)
        if matched:
            return matched, True
        # Upstream named affected module(s) but none were built here. Before
        # committing to the strict drop, fall through to OSIDB — it may name the
        # correct, buildable module even when the upstream coordinate doesn't
        # match this build's gavs. Only if OSIDB also can't place it do we drop.
        if osidb_comps:
            osidb_matched = _collect(osidb_comps, fuzzy=True)
            if osidb_matched:
                return osidb_matched, False
        return [], True

    if osidb_comps:
        return _collect(osidb_comps, fuzzy=True), False

    return [], False


def _affected_entry(c: Coordinate, upstream: dict[str, Any] | None) -> AffectedEntry:
    """Build an OSV AffectedEntry for a built coordinate, with the upstream introduced range."""
    introduced = _extract_introduced(upstream, c.name, c.osv_ecosystem) if upstream else "0"
    return AffectedEntry(
        package=Package(name=c.name, purl=c.purl, ecosystem=c.osv_ecosystem),
        versions=[c.base_version],
        ranges=[Range(events=[Event(introduced=introduced), Event(fixed=c.version)])],
    )


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


def _maven_built_coords(gavs: list[str], upstream_version: str | None = None) -> list[Coordinate]:
    """Resolve each gav-index GAV to a Coordinate (skipping unparseable entries).

    ``upstream_version`` is threaded through so every built module derives the
    same ``base_version`` as the primary coordinate (and thus the record id /
    ``backport_base_version``). Without it a module gav like
    ``1.2.3.Final.rhlw-00001`` would yield ``versions=['1.2.3.Final']`` while
    the id used ``upstreamVersion=1.2.3`` — an internally inconsistent document.
    """
    coords: list[Coordinate] = []
    for gav in gavs:
        try:
            coords.append(maven_coordinate(gav, upstream_version))
        except ValueError:
            logger.debug("Skipping unparseable gav %r", gav)
    return coords


def _purl_built_coords(
    purls: list[str], ecosystem: str, upstream_version: str | None = None
) -> list[Coordinate]:
    """Resolve each build-index PURL to a Coordinate (skipping unparseable entries).

    ``upstream_version`` is threaded through for the same reason as
    :func:`_maven_built_coords`: keep each affected entry's ``versions[]`` in
    step with the record's ``backport_base_version``.
    """
    coords: list[Coordinate] = []
    for purl in purls:
        try:
            coords.append(
                coordinate_from_purl(purl, ecosystem=ecosystem, upstream_version=upstream_version)
            )
        except ValueError:
            logger.debug("Skipping unparseable purl %r", purl)
    return coords


def _is_internal_url(url: str) -> bool:
    """Return True for URLs belonging to internal Red Hat infrastructure."""
    return any(p in url for p in _INTERNAL_URL_PATTERNS)


def _classify_advisory_reference(url: str, original_type: str) -> str:
    """Classify a reference URL for the per-release (advisory) path.

    Commits become FIX, issue tracker links become REPORT, everything else
    keeps its original type unless it would be ADVISORY (reserved for the
    advisory's own URL).
    """
    if "/commit/" in url or "/commits/" in url:
        return "FIX"
    if "/issues/" in url:
        return "REPORT"
    if original_type == "ADVISORY":
        return "WEB"
    return original_type


def _versionless_purl(coord: Coordinate) -> str:
    """Construct a versionless Package URL from a Coordinate."""
    if coord.ecosystem == "maven":
        group, artifact = coord.name.split(":")
        return PackageURL(type="maven", namespace=group, name=artifact).to_string()
    if coord.ecosystem == "pypi":
        return PackageURL(type="pypi", name=coord.name).to_string()
    raise ValueError(f"Unsupported ecosystem for versionless PURL: {coord.ecosystem}")


def _synthesize_details(
    coord: Coordinate,
    per_cve_descriptions: list[tuple[str, str]],
) -> str:
    """Build the ``details`` text for a per-release advisory record."""
    name = coord.name
    version = coord.version
    base_version = coord.base_version
    cve_ids = [cid for cid, _ in per_cve_descriptions]

    if len(cve_ids) == 1:
        fix_desc = "a backported security fix"
    elif len(cve_ids) == 2:
        fix_desc = f"backported fixes for {cve_ids[0]} and {cve_ids[1]}"
    else:
        fix_desc = "backported fixes for " + ", ".join(cve_ids[:-1]) + f", and {cve_ids[-1]}"

    lead = f"Red Hat Lightwell has released {name} {version} with {fix_desc}."

    cve_descs = []
    for cve_id, desc in per_cve_descriptions:
        if desc:
            cve_descs.append(f"{cve_id}: {desc}")

    registry = _REGISTRY_NAMES.get(coord.ecosystem, "the upstream registry")
    dropin = (
        f"This patched artifact is a drop-in replacement for {name} {base_version} from {registry}."
    )

    return "\n\n".join([lead, *cve_descs, dropin])


def _build_advisory_record(
    advisory_id: str,
    coord: Coordinate,
    vulns: list[str],
    published: str,
    modified: str,
    candidates: dict[str, Coordinate],
    osidb_client: OsidbClient | None,
) -> list[OSVDocument]:
    """Build a single per-release OSV record for all CVEs (new advisory path)."""
    osv_ecosystem = coord.osv_ecosystem

    cve_ids: list[str] = []
    ghsa_ids: list[str] = []
    all_cwe_ids: list[str] = []
    best_severity: list[Severity] = []
    per_cve_descriptions: list[tuple[str, str]] = []
    all_refs: list[Reference] = []
    resolved_modules: list[Coordinate] = []
    seen_modules: set[str] = set()
    upstream_cache: dict[str, dict[str, Any] | None] = {}

    seen_cves: set[str] = set()
    for cve_id in vulns:
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        cve_ids.append(cve_id)

        osidb_meta: dict[str, Any] | None = None
        if osidb_client and osidb_client.available:
            flaw = osidb_client.get_flaw(cve_id)
            if flaw:
                osidb_meta = extract_osidb_metadata(flaw)

        upstream = _fetch_upstream_osv(cve_id) if cve_id.startswith("CVE-") else None
        upstream_cache[cve_id] = upstream

        nvd: dict[str, Any] | None = None

        # Collect GHSA aliases from upstream
        if upstream:
            for alias in upstream.get("aliases", []):
                if alias.startswith("GHSA-") and alias not in ghsa_ids:
                    ghsa_ids.append(alias)

        # CWE IDs from OSIDB
        if osidb_meta:
            cwe = osidb_meta.get("cwe_id", "")
            if cwe and cwe not in all_cwe_ids:
                all_cwe_ids.append(cwe)

        # Severity: keep the first non-empty set found
        sev: list[Severity] = []
        if osidb_meta:
            for cv in osidb_meta.get("cvss_vectors", []):
                sev.append(Severity(type=cv["type"], score=cv["score"]))
        if not sev:
            nvd = _fetch_nvd(cve_id) if cve_id.startswith("CVE-") else None
            sev = _extract_severity(upstream or {}, nvd)
        if sev and not best_severity:
            best_severity = sev

        # Per-CVE description (best available)
        desc = ""
        if osidb_meta:
            desc = osidb_meta.get("description", "") or osidb_meta.get("title", "")
        if not desc and upstream:
            desc = upstream.get("summary", "") or upstream.get("details", "")
        if not desc:
            if nvd is None and cve_id.startswith("CVE-"):
                nvd = _fetch_nvd(cve_id)
            if nvd:
                for d in nvd.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
        per_cve_descriptions.append((cve_id, desc))

        # Public references from upstream (filtered)
        if upstream:
            for r in upstream.get("references", []):
                url = r.get("url", "")
                if url and not _is_internal_url(url):
                    ref_type = _classify_advisory_reference(url, r.get("type", "WEB"))
                    all_refs.append(Reference(url=url, type=ref_type))
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        all_refs.append(Reference(url=nvd_url, type="WEB"))

        # Module resolution
        matched, strict = _resolve_affected(upstream, osidb_meta, candidates, osv_ecosystem)
        if matched:
            for mc in matched:
                if mc.name not in seen_modules:
                    seen_modules.add(mc.name)
                    resolved_modules.append(mc)
        elif strict:
            logger.warning("Skipping unresolvable %s in advisory %s", cve_id, advisory_id)
        else:
            if coord.name not in seen_modules:
                seen_modules.add(coord.name)
                resolved_modules.append(coord)

    # upstream IDs: CVEs first, then GHSAs, deduplicated
    all_upstream_ids = list(dict.fromkeys(cve_ids + ghsa_ids))

    # Affected entries: 2 per resolved module (plain + Lightwell ecosystem)
    affected: list[AffectedEntry] = []
    for mc in resolved_modules:
        vl_purl = _versionless_purl(mc)
        repo_url = _REPOSITORY_URLS.get(mc.ecosystem, "")

        introduced = "0"
        for _cve_id, ups in upstream_cache.items():
            if ups:
                v = _extract_introduced(ups, mc.name, mc.osv_ecosystem)
                if v != "0":
                    introduced = v
                    break

        affected.append(
            AffectedEntry(
                package=Package(ecosystem=mc.osv_ecosystem, name=mc.name, purl=vl_purl),
                versions=[mc.base_version],
                ranges=[Range(events=[Event(introduced=introduced), Event(fixed=mc.version)])],
                database_specific=DatabaseSpecific(
                    lightwell=LightwellMeta(
                        source="pnc-build",
                        backport_base_version=mc.base_version,
                        remediated_version=mc.version,
                        repository_url=repo_url,
                    )
                ),
            )
        )
        affected.append(
            AffectedEntry(
                package=Package(ecosystem=f"Red Hat Lightwell:{mc.osv_ecosystem}", name=mc.name),
                ranges=[Range(events=[Event(introduced=introduced), Event(fixed=mc.version)])],
            )
        )

    # References: ADVISORY first, then deduplicated per-CVE refs
    advisory_url = _ADVISORY_URL_TEMPLATE.format(advisory_id)
    refs: list[Reference] = [Reference(url=advisory_url, type="ADVISORY")]
    seen_urls: set[str] = {advisory_url}
    for r in all_refs:
        if r.url not in seen_urls:
            seen_urls.add(r.url)
            refs.append(r)

    # Summary and details
    short_name = coord.name.split(":")[-1]
    summary = f"Lightwell Security Advisory: {short_name} {coord.version}"
    details = _synthesize_details(coord, per_cve_descriptions)

    db_specific = AdvisoryDatabaseSpecific(
        lightwell=AdvisoryLevelMeta(
            csaf_advisory=advisory_url,
            cwe_ids=all_cwe_ids,
        )
    )

    record = OSVDocument(
        id=advisory_id,
        published=published,
        modified=modified,
        severity=best_severity,
        references=refs,
        summary=summary,
        details=details,
        upstream=all_upstream_ids,
        affected=affected,
        credits=[Credit(name="Red Hat Lightwell", type="REMEDIATION_DEVELOPER")],
        database_specific=db_specific,
    )
    logger.info("Generated advisory record %s with %d CVEs", advisory_id, len(cve_ids))
    return [record]


def convert(
    doc: InputDocument,
    embargo: bool = False,
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
) -> list[OSVDocument]:
    """Convert a PNC (Maven) gav-index into one OSV record per CVE.

    Thin adapter over :func:`_build_records`: resolves the Maven coordinate
    from the gav-index and delegates. See :func:`_build_records` for the data
    source priority and embargo semantics.
    """
    coord = maven_coordinate(doc.primary_gav, doc.upstream_version)
    built_coords = _maven_built_coords(doc.gavs, doc.upstream_version)
    return _build_records(
        coord,
        doc.vulns,
        doc.created,
        embargo=embargo,
        osidb_client=osidb_client,
        jira_client=jira_client,
        redact_embargoed=redact_embargoed,
        built_coords=built_coords,
        advisory_id=doc.advisory_id,
    )


def convert_build_index(
    bi: BuildIndex,
    embargo: bool = False,
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
) -> list[OSVDocument]:
    """Convert a unified build-index into one OSV record per vulnerability.

    Supports both Maven and PyPI ecosystems. The affected package is resolved
    from the build-index's ``primaryPurl`` and its ``version.upstream``.
    Delegates to the shared :func:`_build_records` core, so Maven and Python
    records share identical enrichment, embargo, and formatting behaviour.
    """
    coord = coordinate_from_purl(
        bi.primary_purl,
        ecosystem=bi.ecosystem,
        upstream_version=bi.version.upstream,
    )
    built_coords = _purl_built_coords(bi.purls, bi.ecosystem, bi.version.upstream)
    created = bi.created if bi.created else datetime.now(UTC)
    return _build_records(
        coord,
        bi.vulns,
        created,
        embargo=embargo,
        osidb_client=osidb_client,
        jira_client=jira_client,
        redact_embargoed=redact_embargoed,
        built_coords=built_coords,
        advisory_id=bi.advisory_id,
    )


def _build_records(
    coord: Coordinate,
    vulns: list[str],
    created: datetime,
    embargo: bool = False,
    osidb_client: OsidbClient | None = None,
    jira_client: JiraClient | None = None,
    redact_embargoed: bool = False,
    built_coords: list[Coordinate] | None = None,
    advisory_id: str | None = None,
) -> list[OSVDocument]:
    """Build OSV records for a resolved coordinate and vulnerability list.

    When ``advisory_id`` is set and neither ``embargo`` nor
    ``redact_embargoed`` is active, the new per-release path produces a
    single record for all CVEs. Otherwise the legacy per-CVE loop runs.
    """
    coordinates = coord.name
    version = coord.version
    base_ver = coord.base_version
    osv_ecosystem = coord.osv_ecosystem
    logger.debug("Converting %s (%s) with %d vulns", coordinates, version, len(vulns))

    created_utc = created if created.tzinfo else created.replace(tzinfo=UTC)
    published = created_utc.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    modified = published

    candidates = _candidate_index(built_coords or [])

    if advisory_id and not embargo and not redact_embargoed:
        return _build_advisory_record(
            advisory_id,
            coord,
            vulns,
            published,
            modified,
            candidates,
            osidb_client,
        )

    records: list[OSVDocument] = []
    seen_cves: set[str] = set()

    for cve_id in vulns:
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
                        package=Package(name="", purl=None, ecosystem=osv_ecosystem),
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
                        package=Package(name="", purl=None, ecosystem=osv_ecosystem),
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

        source = "novel-pipeline" if cve_id.startswith("LW-") else "pnc-build"

        if cve_id.startswith("LW-") and "lw_id" not in lw_meta_extra:
            lw_meta_extra["lw_id"] = cve_id

        # Resolve the affected module(s) to what was actually built, instead of
        # stamping the build's arbitrary primary coordinate on every vuln.
        matched, strict = _resolve_affected(upstream, osidb_meta, candidates, osv_ecosystem)
        if matched:
            affected_entries = [_affected_entry(mc, upstream) for mc in matched]
        elif strict:
            # Reached only when an authoritative source (upstream advisory, with
            # OSIDB consulted as a fallback in _resolve_affected) named affected
            # module(s) that this build demonstrably did not produce. Emitting the
            # primary coordinate here would re-introduce the primaryGav
            # mis-attribution this fix exists to eliminate (a false positive: a
            # scanner told the wrong component is fixed). For a remediation feed a
            # dropped record (false negative) is the safer failure, so we drop and
            # log loudly rather than guess. Note: a build with NO enumerated
            # modules is not strict (see _resolve_affected), so it still falls
            # back to the primary rather than vanishing.
            logger.error(
                "Skipping %s: authoritative affected package(s) not among this "
                "build's modules (built: %s); refusing to attribute to primary "
                "coordinate %s",
                cve_id,
                sorted(candidates) or "<none>",
                coordinates,
            )
            continue
        else:
            affected_entries = [_affected_entry(coord, upstream)]

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
            affected=affected_entries,
            credits=[Credit(name="Red Hat Lightwell", type="REMEDIATION_DEVELOPER")],
            database_specific=DatabaseSpecific(lightwell=lw_meta),
        )
        records.append(record)

    logger.info("Generated %d OSV records", len(records))
    return records
