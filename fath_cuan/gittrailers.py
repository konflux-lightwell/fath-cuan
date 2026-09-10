"""Vulnerability-ID resolution for ``fath-cuan index create``.

Implements the prioritized resolution hierarchy from the build-index proposal
(§5). Explicit CLI/pipeline input wins; otherwise we inspect the git history
with progressively looser strategies, and fall back to an empty list (a clean /
validated build) if nothing is found:

    Tier 1  Explicit ``--vuln`` flags or the ``$VULN_IDS`` env var
    Tier 2  ADR-0005 ``Lightwell-Fix:`` git trailers on the HEAD commit
    Tier 3  Standard ``Resolves:`` / ``Fixes:`` / ``Closes:`` git trailers
    Tier 4  Regex scan of recent commit messages + branch name
    -----   Default: no vulns (clean build)

The parsing functions are pure (operate on strings) so they are unit-testable
without a git checkout; the git readers are thin ``git`` shell-outs that
degrade to an empty string on any failure.
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# CVE-YYYY-NNNN.. and the Lightwell LW-YYYY-NNNN.. novel identifier scheme.
_VULN_RE = re.compile(r"\b(?:CVE|LW)-\d{4}-\d{4,7}\b")
_STANDARD_TRAILER_RE = re.compile(r"^\s*(?:resolves|fixes|closes)\s*:\s*(.+)$", re.IGNORECASE)
_ENV_SPLIT_RE = re.compile(r"[,\s]+")


@dataclass(frozen=True)
class ResolvedVulns:
    """The resolved vulnerability list plus the tier that produced it."""

    vulns: list[str]
    tier: str


def _dedup(items: Iterable[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------


def parse_adr0005_trailers(text: str) -> list[str]:
    """Extract vuln IDs from ADR-0005 ``Lightwell-Fix:`` trailer lines.

    Each line carries comma-separated ``key=value`` pairs, e.g.::

        Lightwell-Fix: fix=LW-2026-0001, cve=CVE-2024-1234, jira=LTWL-201, ...

    One identifier is emitted per fix line: the public ``cve=`` when present,
    otherwise the internal ``fix=`` novel ID. Emitting both would create two
    OSV records for the same underlying flaw.

    Each candidate is validated against the CVE-/LW- shape (like tiers 3 and 4),
    so a placeholder such as ``cve=TBD`` / ``cve=none`` / ``fix=n/a`` is rejected
    and the line falls through to a looser tier instead of producing a junk
    advisory that would slip past the ``--require-vuln`` guard.
    """
    vulns: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.lower().startswith("lightwell-fix:"):
            continue
        body = line.split(":", 1)[1]
        fields: dict[str, str] = {}
        for pair in body.split(","):
            if "=" in pair:
                key, value = pair.split("=", 1)
                fields[key.strip().lower()] = value.strip()
        # Prefer cve, fall back to fix; one identifier per fix line (the cve or
        # fix names the same underlying flaw — emitting both would double-count).
        for candidate in (fields.get("cve"), fields.get("fix")):
            found = _VULN_RE.findall(candidate) if candidate else []
            if found:
                vulns.append(found[0])
                break
    return _dedup(vulns)


def parse_standard_trailers(text: str) -> list[str]:
    """Extract vuln IDs from standard ``Resolves:`` / ``Fixes:`` / ``Closes:`` trailers."""
    vulns: list[str] = []
    for line in text.splitlines():
        m = _STANDARD_TRAILER_RE.match(line)
        if m:
            vulns.extend(_VULN_RE.findall(m.group(1)))
    return _dedup(vulns)


def regex_scan(text: str) -> list[str]:
    """Scan arbitrary text for any CVE-/LW- identifiers."""
    return _dedup(_VULN_RE.findall(text))


def _parse_env(value: str | None) -> list[str]:
    if not value:
        return []
    # Validate through _VULN_RE like every other tier, so a placeholder such as
    # VULN_IDS='TBD none' (or an unexpanded CI variable) can't satisfy
    # --require-vuln with junk that then becomes a published advisory id.
    return _dedup(m for tok in _ENV_SPLIT_RE.split(value.strip()) for m in _VULN_RE.findall(tok))


# ---------------------------------------------------------------------------
# git readers (shell-outs; degrade to "" on failure)
# ---------------------------------------------------------------------------


def _git(git_dir: str, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", git_dir, *args],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug("git %s failed in %s: %s", args, git_dir, e)
        return ""
    if result.returncode != 0:
        logger.debug("git %s returned %d in %s", args, result.returncode, git_dir)
        return ""
    return result.stdout


def read_commit_message(git_dir: str) -> str:
    """Return the full HEAD commit message body."""
    return _git(git_dir, ["log", "-1", "--format=%B"])


def read_recent_log(git_dir: str, n: int = 50) -> str:
    """Return recent commit message bodies plus the current branch name."""
    log = _git(git_dir, ["log", f"-n{n}", "--format=%B"])
    branch = _git(git_dir, ["rev-parse", "--abbrev-ref", "HEAD"])
    return f"{log}\n{branch}"


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


def resolve_vulns(
    explicit: list[str],
    env_value: str | None = None,
    git_dir: str | None = None,
    *,
    commit_message_reader: Callable[[str], str] = read_commit_message,
    recent_log_reader: Callable[[str], str] = read_recent_log,
) -> ResolvedVulns:
    """Resolve the vulnerability list using the tiered strategy.

    The git readers are injectable so the tier logic can be tested without a
    real repository.
    """
    if explicit:
        # Validate explicit --vuln through _VULN_RE like every other tier, so
        # junk (`--vuln TBD`) can't satisfy --require-vuln and ship as an
        # advisory id. Returned as "cli" even if filtering empties it, so junk
        # surfaces via the require-vuln check rather than falling through to git.
        valid = _dedup(m for tok in explicit for m in _VULN_RE.findall(tok))
        return ResolvedVulns(valid, "cli")

    if env_value and env_value.strip():
        return ResolvedVulns(_parse_env(env_value), "env")

    if git_dir:
        message = commit_message_reader(git_dir)
        adr = parse_adr0005_trailers(message)
        if adr:
            return ResolvedVulns(adr, "adr0005-trailer")
        standard = parse_standard_trailers(message)
        if standard:
            return ResolvedVulns(standard, "standard-trailer")
        scanned = regex_scan(recent_log_reader(git_dir))
        if scanned:
            return ResolvedVulns(scanned, "regex")

    return ResolvedVulns([], "clean")
