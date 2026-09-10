"""Ecosystem-specific coordinate handling for OSV/VEX generation.

fath-cuan started life as a Maven-only converter. This module isolates the
per-ecosystem rules (coordinate parsing, PURL construction, upstream base
version derivation, and the OSV ``package.ecosystem`` label) behind a single
:class:`Coordinate` value object so the OSV converter can serve both Maven and
PyPI from one code path.

The Maven helpers here are the canonical implementations that
``fath_cuan.converters.osv`` re-exports (``_parse_gav`` / ``_base_version``)
so their behaviour — and the exact Java OSV output — is unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packageurl import PackageURL

# Normalized (lowercase) ecosystem key -> OSV `package.ecosystem` label.
# OSV uses "Maven" and "PyPI" as its canonical ecosystem names.
_OSV_ECOSYSTEM = {
    "maven": "Maven",
    "pypi": "PyPI",
}

SUPPORTED_ECOSYSTEMS = frozenset(_OSV_ECOSYSTEM)


@dataclass(frozen=True)
class Coordinate:
    """A resolved package coordinate, ecosystem-agnostic for the converter.

    Attributes:
        ecosystem: Normalized lowercase key (``"maven"`` | ``"pypi"``).
        name: OSV ``package.name`` — ``"group:artifact"`` for Maven, the
            PEP 503-normalized project name for PyPI.
        version: The full remediated version — becomes the OSV ``fixed`` event.
        base_version: The upstream base version — becomes the OSV id suffix,
            ``versions[]`` entry, and ``backport_base_version`` metadata.
        purl: The Package URL at the full remediated version.
    """

    ecosystem: str
    name: str
    version: str
    base_version: str
    purl: str

    @property
    def osv_ecosystem(self) -> str:
        """The OSV ``package.ecosystem`` label (e.g. ``"Maven"``, ``"PyPI"``)."""
        return _OSV_ECOSYSTEM[self.ecosystem]


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------


def parse_gav(gav: str) -> tuple[str, str, str]:
    """Split a Maven GAV string ('group:artifact:version') into its parts."""
    parts = gav.split(":")
    if len(parts) != 3:
        raise ValueError(f"Invalid GAV format, expected 'group:artifact:version': {gav}")
    return parts[0], parts[1], parts[2]


def maven_base_version(version: str) -> str:
    """Strip the rhlw qualifier from a Maven version to get the upstream base."""
    m = re.match(r"^(.+?)\.rhlw-\w+-\d+$", version)
    if m:
        return m.group(1)
    m = re.match(r"^(.+?)\.rhlw-\d+$", version)
    if m:
        return m.group(1)
    return version


def maven_coordinate(primary_gav: str, upstream_version: str | None = None) -> Coordinate:
    """Resolve a Maven GAV (+ optional explicit upstream version) to a Coordinate."""
    group_id, artifact_id, version = parse_gav(primary_gav)
    base = upstream_version if upstream_version else maven_base_version(version)
    name = f"{group_id}:{artifact_id}"
    purl = PackageURL(
        type="maven", namespace=group_id, name=artifact_id, version=version
    ).to_string()
    return Coordinate(
        ecosystem="maven",
        name=name,
        version=version,
        base_version=base,
        purl=purl,
    )


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------


def pep503_normalize(name: str) -> str:
    """Normalize a Python project name per PEP 503.

    Lowercase and collapse any run of ``-``, ``_`` or ``.`` to a single ``-``.
    OSV scanners (pip-audit, osv-scanner, Dependabot) match on the normalized
    name, so an un-normalized PURL would silently fail to match the fix.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi_base_version(version: str) -> str:
    """Return the upstream base of a PEP 440 version by stripping the local segment.

    The remediated local version uses ``+`` as the local-version delimiter
    (e.g. ``7.6.12+rhlw.1`` -> ``7.6.12``).
    """
    return version.split("+", 1)[0]


def pypi_coordinate(name: str, version: str, upstream_version: str | None = None) -> Coordinate:
    """Resolve a PyPI project name + version (+ optional upstream) to a Coordinate.

    The PURL is built with ``packageurl`` so the PEP 440 local-version ``+`` is
    percent-encoded to ``%2B`` (canonical PURL serialization).
    """
    norm = pep503_normalize(name)
    base = upstream_version if upstream_version else pypi_base_version(version)
    purl = PackageURL(type="pypi", name=norm, version=version).to_string()
    return Coordinate(
        ecosystem="pypi",
        name=norm,
        version=version,
        base_version=base,
        purl=purl,
    )


# ---------------------------------------------------------------------------
# PURL parsing (for the unified build-index path)
# ---------------------------------------------------------------------------


def parse_purl(purl: str) -> tuple[str, str, str]:
    """Parse a PURL into ``(ecosystem, coordinate, version)``.

    ``coordinate`` is the type-specific coordinate string with qualifiers and
    subpath removed: ``"group/artifact"`` for Maven, ``"name"`` for PyPI. The
    version is percent-decoded (so ``%2B`` becomes ``+``). Raises ``ValueError``
    on a malformed or versionless PURL.
    """
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError as e:
        raise ValueError(f"Invalid PURL '{purl}': {e}") from e
    if not parsed.version:
        raise ValueError(f"Invalid PURL, missing '@version': {purl}")
    ecosystem = parsed.type.lower()
    coord = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
    return ecosystem, coord, parsed.version


def coordinate_from_purl(
    purl: str, ecosystem: str | None = None, upstream_version: str | None = None
) -> Coordinate:
    """Resolve a Coordinate from a PURL, validating against an expected ecosystem.

    If ``ecosystem`` is provided it must match the PURL's type (case-insensitive);
    a mismatch is a ``ValueError`` so a mislabeled build-index fails loudly.
    """
    purl_ecosystem, coord, version = parse_purl(purl)
    if ecosystem is not None and purl_ecosystem != ecosystem.lower():
        raise ValueError(
            f"PURL ecosystem '{purl_ecosystem}' does not match expected '{ecosystem}': {purl}"
        )
    if purl_ecosystem == "maven":
        # coord is "group/artifact"; OSV name is "group:artifact".
        if coord.count("/") != 1:
            raise ValueError(f"Invalid Maven PURL coordinate '{coord}': {purl}")
        return maven_coordinate(f"{coord.replace('/', ':')}:{version}", upstream_version)
    if purl_ecosystem == "pypi":
        return pypi_coordinate(coord, version, upstream_version)
    raise ValueError(f"Unsupported PURL ecosystem '{purl_ecosystem}': {purl}")
