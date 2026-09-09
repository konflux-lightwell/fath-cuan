"""Construct a ``build-index.json`` document for ``fath-cuan index create``.

Kept free of any CLI/IO concerns so it can be unit-tested directly: given
coordinate + version inputs and a vuln resolver, it returns the build-index as
a plain dict ready to serialize.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from fath_cuan.ecosystems import (
    Coordinate,
    maven_coordinate,
    parse_gav,
    parse_purl,
    pypi_coordinate,
)
from fath_cuan.gittrailers import ResolvedVulns, resolve_vulns
from fath_cuan.models.build_index import BuildIndex


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


def _resolve_coordinate(
    ecosystem: str | None,
    purl: str | None,
    gav: str | None,
    version_local: str,
    version_upstream: str | None,
) -> Coordinate:
    """Resolve a Coordinate from mutually-exclusive --purl/--gav + --version-local.

    ``version_local`` is authoritative for the full remediated version — any
    version embedded in the PURL/GAV is treated as coordinate context only.
    """
    if bool(purl) == bool(gav):
        raise ValueError("provide exactly one of --purl or --gav")

    if gav:
        if ecosystem and ecosystem.lower() != "maven":
            raise ValueError("--gav is only valid for the maven ecosystem")
        group_id, artifact_id, _ = parse_gav(gav)
        return maven_coordinate(f"{group_id}:{artifact_id}:{version_local}", version_upstream)

    assert purl is not None  # guaranteed by the XOR check above
    purl_ecosystem, coord, _ = parse_purl(purl)
    if ecosystem and ecosystem.lower() != purl_ecosystem:
        raise ValueError(
            f"--ecosystem '{ecosystem}' does not match PURL ecosystem '{purl_ecosystem}'"
        )
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
    resolved = vuln_resolver(
        list(vulns or []),
        os.environ.get("VULN_IDS"),
        git_dir,
    )
    if (require_vuln or b > 0 or n > 0) and not resolved.vulns:
        raise ValueError(
            "no vulnerability IDs resolved for a remediation build "
            f"(tier={resolved.tier}); pass --vuln/$VULN_IDS, ensure the git "
            "history carries ADR-0005 Lightwell-Fix trailers, or drop "
            "--require-vuln / --b / --n for a clean build"
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
