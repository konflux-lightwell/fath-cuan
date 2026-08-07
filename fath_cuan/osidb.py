"""OSIDB client for fetching vulnerability metadata.

Authenticates via Kerberos negotiate to obtain a JWT, then uses the JWT
for subsequent API calls. Falls back gracefully when OSIDB is unreachable.

Requires a valid Kerberos ticket (kinit) for the target realm.

Environment variables:
    OSIDB_URL       — Base URL (default: https://osidb.lightwell.redhat.com)
    OSIDB_TOKEN     — Skip Kerberos and use a pre-obtained JWT access token
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_URL = "https://osidb.lightwell.redhat.com"
_TOKEN_PATH = "/auth/token"
_FLAWS_PATH = "/osidb/api/v1/flaws"

_FLAW_FIELDS = (
    "uuid,vulnerability_id,cve_id,title,impact,source,cwe_id,"
    "cvss_scores,cve_description,comment_zero,references,affects,"
    "components,embargoed,visibility"
)


def _get_base_url() -> str:
    return os.environ.get("OSIDB_URL", _DEFAULT_URL).rstrip("/")


def _obtain_token(base_url: str) -> str | None:
    env_token = os.environ.get("OSIDB_TOKEN", "")
    if env_token:
        return env_token

    url = f"{base_url}{_TOKEN_PATH}"
    try:
        import subprocess

        result = subprocess.run(
            ["curl", "-s", "--negotiate", "-u", ":", url],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            token: str | None = data.get("access")
            return token
    except Exception as e:
        log.warning("OSIDB token acquisition failed: %s", e)
    return None


class OsidbClient:
    """Lightweight OSIDB API client."""

    def __init__(self, base_url: str | None = None, token: str | None = None):
        self._base_url = base_url or _get_base_url()
        self._token = token or _obtain_token(self._base_url)
        if not self._token:
            log.warning("No OSIDB token available — OSIDB enrichment disabled")

    @property
    def available(self) -> bool:
        return self._token is not None

    def _get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any] | None:
        if not self._token:
            return None

        url = f"{self._base_url}{path}"
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{qs}"

        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self._token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result: dict[str, Any] = json.loads(resp.read())
                return result
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            log.warning("OSIDB request failed (%s): %s", path, e)
            return None

    def get_flaw(self, vuln_id: str) -> dict[str, Any] | None:
        """Fetch a single flaw by vulnerability_id (LW-YYYY-NNNN) or CVE ID."""
        data = self._get(
            _FLAWS_PATH,
            {
                "search": vuln_id,
                "include_fields": _FLAW_FIELDS,
                "limit": "5",
            },
        )
        if not data:
            return None

        results = data.get("results", [])
        if not results:
            return None

        if len(results) == 1:
            return results[0]  # type: ignore[no-any-return]

        for r in results:
            if r.get("vulnerability_id") == vuln_id or r.get("cve_id") == vuln_id:
                return r  # type: ignore[no-any-return]

        return results[0]  # type: ignore[no-any-return]


def extract_osidb_metadata(flaw: dict[str, Any]) -> dict[str, Any]:
    """Extract OSV-relevant fields from an OSIDB flaw record."""
    meta: dict[str, Any] = {}

    meta["title"] = flaw.get("title", "")
    meta["vulnerability_id"] = flaw.get("vulnerability_id", "")
    meta["cve_id"] = flaw.get("cve_id")
    meta["impact"] = flaw.get("impact", "")
    meta["cwe_id"] = flaw.get("cwe_id", "")

    desc = flaw.get("cve_description", "") or ""
    if not desc:
        comment_zero = flaw.get("comment_zero", "") or ""
        if "## Description" in comment_zero:
            parts = comment_zero.split("## Description", 1)
            if len(parts) > 1:
                desc_section = parts[1].split("##", 1)[0].strip()
                desc = desc_section
        elif comment_zero:
            desc = comment_zero
    meta["description"] = desc

    cvss_scores = flaw.get("cvss_scores", [])
    meta["cvss_vectors"] = []
    for cs in cvss_scores:
        vector = cs.get("vector", "")
        version = cs.get("cvss_version", "")
        if vector:
            osv_type = "CVSS_V4" if version == "V4" else "CVSS_V3"
            meta["cvss_vectors"].append({"type": osv_type, "score": vector})

    meta["references"] = []
    for ref in flaw.get("references", []):
        url = ref.get("url", "")
        ref_type = ref.get("type", "")
        if url:
            if "/commit/" in url or "/commits/" in url:
                osv_type = "FIX"
            elif "nvd.nist.gov" in url or "advisories" in url or ref_type == "ADVISORY":
                osv_type = "ADVISORY"
            else:
                osv_type = "WEB"
            meta["references"].append({"url": url, "type": osv_type})

    meta["components"] = flaw.get("components", [])

    meta["embargoed"] = flaw.get("embargoed", False)
    meta["visibility"] = flaw.get("visibility", "")

    return meta
