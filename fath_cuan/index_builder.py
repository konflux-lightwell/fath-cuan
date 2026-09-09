"""Construct a ``build-index.json`` document for ``fath-cuan index create``.

Kept free of any CLI/IO concerns so it can be unit-tested directly: given
coordinate + version inputs and a vuln resolver, it returns the build-index as
a plain dict ready to serialize.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

from fath_cuan.ecosystems import (
    Coordinate,
    maven_coordinate,
    pypi_coordinate,
)
from fath_cuan.gittrailers import ResolvedVulns, resolve_vulns
from fath_cuan.models.build_index import BuildIndex
from fath_cuan.models.input import InputDocument

logger = logging.getLogger(__name__)


def _finalize(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate a build-index payload and dump it to a JSON-ready dict.

    Uses ``mode="json"`` so nested datetimes serialize to ISO strings, and
    drops an empty ``buildId`` so a manually-created index isn't cluttered.
    """
    bi = BuildIndex.model_validate(payload)
    data: dict[str, Any] = bi.model_dump(mode="json", by_alias=True, exclude_none=True)
    if not data.get("buildId"):
        data.pop("buildId", None)
    return data


def _split_purl(purl: str) -> tuple[str, str, str | None]:
    """Lenient PURL split allowing a versionless coordinate.

    Returns ``(ecosystem, coordinate, embedded_version_or_None)``. Unlike
    :func:`fath_cuan.ecosystems.parse_purl` (which requires ``@version``), the
    version is optional here — the coordinate-only form matches the documented
    contract that ``--version-local`` is authoritative.
    """
    if not purl.startswith("pkg:"):
        raise ValueError(f"Invalid PURL, must start with 'pkg:': {purl}")
    body = purl[len("pkg:") :].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        raise ValueError(f"Invalid PURL, missing type/coordinate separator: {purl}")
    type_part, rest = body.split("/", 1)
    coord, sep, version = rest.rpartition("@")
    if not sep:  # no @version — versionless coordinate
        coord, version = rest, ""
    return type_part.lower(), coord, (version or None)


def _warn_ignored_version(
    embedded: str | None, version_local: str, version_upstream: str | None
) -> None:
    if embedded and embedded not in (version_local, version_upstream):
        logger.warning(
            "ignoring version '%s' embedded in the coordinate; --version-local "
            "('%s') is authoritative for the full remediated version",
            embedded,
            version_local,
        )


def _resolve_coordinate(
    ecosystem: str | None,
    purl: str | None,
    gav: str | None,
    version_local: str,
    version_upstream: str | None,
) -> Coordinate:
    """Resolve a Coordinate from mutually-exclusive --purl/--gav + --version-local.

    ``version_local`` is authoritative for the full remediated version. The
    coordinate may be given without a version; any embedded version is ignored
    (a mismatching one is warned rather than silently dropped).
    """
    if bool(purl) == bool(gav):
        raise ValueError("provide exactly one of --purl or --gav")

    if gav:
        if ecosystem and ecosystem.lower() != "maven":
            raise ValueError("--gav is only valid for the maven ecosystem")
        parts = gav.split(":")
        if len(parts) not in (2, 3):
            raise ValueError(f"invalid GAV, expected 'group:artifact[:version]': {gav}")
        group_id, artifact_id = parts[0], parts[1]
        _warn_ignored_version(
            parts[2] if len(parts) == 3 else None, version_local, version_upstream
        )
        return maven_coordinate(f"{group_id}:{artifact_id}:{version_local}", version_upstream)

    assert purl is not None  # guaranteed by the XOR check above
    purl_ecosystem, coord, embedded = _split_purl(purl)
    if ecosystem and ecosystem.lower() != purl_ecosystem:
        raise ValueError(
            f"--ecosystem '{ecosystem}' does not match PURL ecosystem '{purl_ecosystem}'"
        )
    _warn_ignored_version(embedded, version_local, version_upstream)
    if purl_ecosystem == "maven":
        if coord.count("/") != 1:
            raise ValueError(f"invalid Maven PURL coordinate '{coord}'")
        return maven_coordinate(f"{coord.replace('/', ':')}:{version_local}", version_upstream)
    if purl_ecosystem == "pypi":
        return pypi_coordinate(coord, version_local, version_upstream)
    raise ValueError(f"unsupported PURL ecosystem '{purl_ecosystem}'")


def build_index_document(
    version_local: str,
    ecosystem: str | None = None,
    purl: str | None = None,
    gav: str | None = None,
    version_upstream: str | None = None,
    b: int = 0,
    n: int = 0,
    vulns: list[str] | None = None,
    git_dir: str | None = None,
    build_id: str = "",
    require_vuln: bool = False,
    *,
    vuln_resolver: Callable[..., ResolvedVulns] = resolve_vulns,
) -> dict[str, Any]:
    """Build a build-index document (as a dict) from create-command inputs.

    A remediation build must not silently produce ``vulns: []``. When
    ``require_vuln`` is set, or the version decomposition implies a remediation
    (``b > 0`` or ``n > 0``), an empty resolution is a hard error rather than a
    clean-build index.
    """
    coord = _resolve_coordinate(ecosystem, purl, gav, version_local, version_upstream)
    remediation = require_vuln or b > 0 or n > 0
    resolved = vuln_resolver(
        list(vulns or []),
        os.environ.get("VULN_IDS"),
        git_dir,
    )
    if remediation and not resolved.vulns:
        raise ValueError(
            "no vulnerability IDs resolved for a remediation build "
            f"(tier={resolved.tier}); pass --vuln/$VULN_IDS, ensure the git "
            "history carries ADR-0005 Lightwell-Fix trailers, or drop "
            "--require-vuln / --b / --n for a clean build"
        )
    # --require-vuln is an explicit "I fixed something" assertion; don't let it
    # be satisfied by tier-4, which greps the branch name / last 50 commit
    # messages and can surface an unrelated ID from history.
    if require_vuln and resolved.tier == "regex":
        raise ValueError(
            "--require-vuln will not accept vuln IDs discovered by the tier-4 "
            "regex sweep of branch/commit history; pass --vuln explicitly or "
            "add ADR-0005 Lightwell-Fix trailers to the remediation commit"
        )
    # The upstream-vs-full remediation guard now lives on the BuildIndex model
    # (fires when b/n > 0); cover the --require-vuln-without-counts case here.
    if require_vuln and coord.base_version == coord.version:
        raise ValueError(
            f"remediation build (--require-vuln) but upstream base equals the full "
            f"version ('{coord.version}'); --version-local must carry a remediation "
            f"qualifier (Maven '.rhlw-NNNNN', PyPI '+rhlw.N')"
        )
    if resolved.vulns:
        logger.info(
            "resolved %d vuln id(s) via tier '%s': %s",
            len(resolved.vulns),
            resolved.tier,
            ", ".join(resolved.vulns),
        )
    return _finalize(
        {
            "buildId": build_id,
            "ecosystem": coord.ecosystem,
            "version": {"upstream": coord.base_version, "full": coord.version, "b": b, "n": n},
            "primaryPurl": coord.purl,
            "purls": [coord.purl],
            "vulns": resolved.vulns,
        }
    )


def migrate_document(gav_index: dict[str, Any]) -> dict[str, Any]:
    """Convert a legacy PNC gav-index into a unified (Maven) build-index.

    Converts ``primaryGav`` and every ``gavs[]`` entry into canonical
    ``pkg:maven`` PURLs (primary first, de-duplicated), preserves ``vulns``
    and the build's ``created`` timestamp so downstream OSV records are
    unchanged, and records the primary's decomposed version. ``b``/``n`` are
    set to 0 — the legacy format doesn't carry backport/novel counts.
    """
    doc = InputDocument.from_dict(gav_index)
    primary = maven_coordinate(doc.primary_gav, doc.upstream_version)

    purls = [primary.purl]
    seen = {primary.purl}
    for gav in doc.gavs:
        purl = maven_coordinate(gav).purl
        if purl not in seen:
            seen.add(purl)
            purls.append(purl)

    return _finalize(
        {
            "buildId": doc.build_id,
            "ecosystem": "maven",
            "version": {
                "upstream": primary.base_version,
                "full": primary.version,
                "b": 0,
                "n": 0,
            },
            "primaryPurl": primary.purl,
            "purls": purls,
            "vulns": doc.vulns,
            "created": doc.created,
        }
    )
