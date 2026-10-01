from __future__ import annotations

import re

VULN_ID_PATTERNS = [
    re.compile(r"^CVE-\d{4}-\d{4,}$"),
    re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$"),
    re.compile(r"^LW-\d{4}-\d{4,}$"),
]


def validate_vuln_ids(value: list[str]) -> list[str]:
    """Validate that each vuln ID matches CVE, GHSA, or LW format."""
    for v in value:
        if not any(p.fullmatch(v) for p in VULN_ID_PATTERNS):
            raise ValueError(
                f"vuln id '{v}' must match CVE-YYYY-NNNN+, GHSA-xxxx-xxxx-xxxx, or LW-YYYY-NNNN+"
            )
    return value


def validate_advisory_id(value: str | None) -> str | None:
    """Validate that advisory_id starts with RHLW- and has no path separators."""
    if value is not None:
        if not value.startswith("RHLW-"):
            raise ValueError(f"advisory_id must start with 'RHLW-', got '{value}'")
        if "/" in value or "\\" in value:
            raise ValueError(f"advisory_id must not contain path separators, got '{value}'")
    return value
