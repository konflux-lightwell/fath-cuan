"""Deterministic Lightwell advisory IDs.

An advisory ID is derived from the affected package and its fixed version:
``RHLW-<year>-<lower 64 bits of MurmurHash3-128("<ecosystem>::<name>::<version>", seed 42)>``.
slan-cuan derives the primary module's ID the same way; fath-cuan derives
the IDs of the other modules of a multi-module build (LWLP-5917), so every
module's advisory gets the ID it would have had as the primary module.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import mmh3

_MURMURHASH_SEED = 42
_LOWER_64_MASK = 0xFFFF_FFFF_FFFF_FFFF
ADVISORY_ID_RE = re.compile(r"^RHLW-\d{4}-[0-9a-f]{16}$")


def derive_advisory_id(
    osv_ecosystem: str,
    name: str,
    version: str,
    created: datetime | None = None,
) -> str:
    """Return the advisory ID for *name* at *version* in *osv_ecosystem*.

    *osv_ecosystem* is the OSV ecosystem name (``Maven``, ``PyPI``); *name*
    is ``group:artifact`` for Maven. The year comes from *created* (the
    build time), or the current year when it is unknown.
    """
    if not name or not version:
        raise ValueError("advisory ID needs a package name and a version")
    combo_key = f"{osv_ecosystem}::{name}::{version}"
    lower64 = mmh3.hash128(combo_key, seed=_MURMURHASH_SEED) & _LOWER_64_MASK
    year = (created or datetime.now(UTC)).year
    return f"RHLW-{year}-{lower64:016x}"
