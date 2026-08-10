from __future__ import annotations

import base64
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fath_cuan.jira.models import JiraIssue, VulnerabilityData

_DEFAULT_SERVER = "https://redhat.atlassian.net/"
_API_PATH = "/rest/api/3"
_LW_ID_PATTERN = re.compile(r"^LW-\d{4}-\d{4}$")
_TITLE_PATTERN = re.compile(r"\*\*Title:\*\*\s*(.+)")
_DESCRIPTION_PATTERN = re.compile(r"\*\*Description:\*\*\s*(.+?)(?=\n\*\*|\Z)", re.DOTALL)

logger = logging.getLogger(__name__)


def _parse_description(text: str) -> tuple[str, str]:
    """Extract summary and details from a JIRA description containing markdown fields."""
    title_match = _TITLE_PATTERN.search(text)
    summary = title_match.group(1).strip() if title_match else ""

    desc_match = _DESCRIPTION_PATTERN.search(text)
    details = desc_match.group(1).strip() if desc_match else ""

    if not summary:
        logger.warning("Summary not found in JIRA's description: %s", text)
    if not details:
        logger.warning("Details not found in JIRA's description: %s", text)
    return summary, details


def _parse_adf_description(adf: dict[str, Any]) -> tuple[str, str]:
    """Extract summary and details from a JIRA ADF (Atlassian Document Format) description.

    Looks for paragraphs where the first text node is bold "Title:" or
    "Description:", then concatenates the remaining text nodes as the value.
    """
    summary = ""
    details = ""

    for block in adf.get("content", []):
        if block.get("type") != "paragraph":
            continue
        content = block.get("content", [])
        if not content:
            continue
        first = content[0]
        if first.get("type") != "text":
            continue
        marks = first.get("marks", [])
        is_bold = any(m.get("type") == "strong" for m in marks)
        if not is_bold:
            continue

        label = first.get("text", "").strip()
        value = "".join(node.get("text", "") for node in content[1:]).strip()

        if label == "Title:":
            summary = value
        elif label == "Description:":
            details = value

    return summary, details


def _extract_field_value(raw: object) -> str:
    """Extract a string value from a JIRA field that may be a dict or scalar."""
    if isinstance(raw, dict):
        return str(raw.get("value", "") or raw.get("name", ""))
    return str(raw) if raw else ""


class JiraClient:
    """Client for communicating with a JIRA instance via REST API v3."""

    def __init__(
        self,
        server: str = _DEFAULT_SERVER,
        email: str | None = None,
        token: str | None = None,
    ) -> None:
        self.server = server.rstrip("/")
        self._email = email
        self._token = token
        self._field_map: dict[str, str] | None = None

    def _build_url(self, endpoint: str, params: dict[str, str] | None = None) -> str:
        url = f"{self.server}{_API_PATH}{endpoint}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return url

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self._email and self._token:
            credentials = base64.b64encode(f"{self._email}:{self._token}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"
            logger.debug("Using Basic auth for %s", self._email)
        elif self._token:
            headers["Authorization"] = f"Bearer {self._token}"
            logger.debug("Using Bearer auth (no email configured)")
        else:
            logger.debug("No authentication configured")
        return headers

    def _fetch(self, endpoint: str, params: dict[str, str] | None = None) -> Any:
        """Perform a GET request and return the parsed JSON response."""
        logger.debug("Fetching %s with params %s", endpoint, params)
        url = self._build_url(endpoint, params)
        req = urllib.request.Request(url, headers=self._build_headers())
        try:
            logger.debug("Sending request to %s", url)
            with urllib.request.urlopen(req, timeout=30) as resp:
                logger.debug("Received response from %s", url)
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            logger.error("JIRA request failed: %s %s", e.code, e.reason)
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            logger.error("JIRA request failed: %s", e)
            raise

    def get(self, endpoint: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        """Perform a GET request against the JIRA REST API."""
        logger.debug("Getting %s with params %s", endpoint, params)
        return self._fetch(endpoint, params)  # type: ignore[no-any-return]

    def _resolve_field_ids(self) -> dict[str, str]:
        """Fetch JIRA field definitions and cache a name-to-id mapping."""
        if self._field_map is not None:
            logger.debug("Using cached field map")
            return self._field_map
        logger.debug("Fetching field definitions")
        fields: list[dict[str, Any]] = self._fetch("/field")
        logger.debug("Received %d field definitions", len(fields))
        self._field_map = {f.get("name", ""): f.get("id", "") for f in fields}
        return self._field_map

    def search_vulnerability(self, lw_id: str) -> list[JiraIssue]:
        """Search for JIRA Vulnerability issues matching a Lightwell identifier.

        Uses JQL: CVE ID ~ "<lw_id>" AND type = Vulnerability
        """
        logger.debug("Searching for vulnerability %s", lw_id)
        if not _LW_ID_PATTERN.match(lw_id):
            logger.error("Invalid Lightwell identifier format: %s, expected LW-YYYY-XXXX", lw_id)
            raise ValueError(
                f"Invalid Lightwell identifier format: {lw_id!r}, expected LW-YYYY-XXXX"
            )
        jql = f'"CVE ID[Short text]" ~ "{lw_id}" AND type = Vulnerability'
        data = self.get("/search/jql", {"jql": jql, "fields": "summary,status,issuetype"})
        issues: list[JiraIssue] = []
        logger.debug("Received %d issues", len(data.get("issues", [])))
        for raw_issue in data.get("issues", []):
            logger.debug("Processing issue %s", raw_issue.get("key", ""))
            issues.append(JiraIssue.from_raw(raw_issue))
        logger.debug("Found %d issues", len(issues))
        return issues

    def fetch_vulnerability(self, lw_id: str) -> VulnerabilityData | None:
        """Fetch and parse vulnerability data from JIRA for a Lightwell identifier.

        Resolves the custom field IDs for 'Severity' and 'CVE ID', searches
        for matching Vulnerability tickets, validates the CVE ID field, and
        parses the description for **Title:** and **Description:** sections.
        """
        logger.debug("Fetching vulnerability %s", lw_id)
        if not _LW_ID_PATTERN.match(lw_id):
            raise ValueError(
                f"Invalid Lightwell identifier format: {lw_id!r}, expected LW-YYYY-XXXX"
            )

        field_map = self._resolve_field_ids()
        logger.debug("Resolved field map: %s", field_map)
        severity_field = field_map.get("Severity", "")
        cve_id_field = field_map.get("CVE ID", "")

        if not severity_field or not cve_id_field:
            logger.error(
                "Required JIRA fields not found: Severity=%s, CVE ID=%s",
                severity_field,
                cve_id_field,
            )
            missing = [
                name
                for name, fid in [("Severity", severity_field), ("CVE ID", cve_id_field)]
                if not fid
            ]
            logger.error("Required JIRA fields not found: %s", ", ".join(missing))
            raise ValueError(f"Required JIRA fields not found: {', '.join(missing)}")

        request_fields = f"description,{severity_field},{cve_id_field}"
        jql = f'textfields ~ "{lw_id}" AND type = Vulnerability'
        logger.debug("JQL: %s", jql)
        data = self.get("/search/jql", {"jql": jql, "fields": request_fields})
        logger.debug("Received %d issues", len(data.get("issues", [])))

        for raw_issue in data.get("issues", []):
            logger.debug("Processing issue %s", raw_issue.get("key", ""))
            fields = raw_issue.get("fields", {})
            if not isinstance(fields, dict):
                continue

            issue_cve_id = _extract_field_value(fields.get(cve_id_field))
            if issue_cve_id != lw_id:
                logger.debug("Issue %s does not match %s", issue_cve_id, lw_id)
                continue

            description_raw = fields.get("description")
            logger.debug("Description: %s", description_raw)
            if isinstance(description_raw, dict):
                summary, details = _parse_adf_description(description_raw)
            else:
                summary, details = _parse_description(str(description_raw or ""))
            logger.debug("Summary: %s", summary)
            logger.debug("Details: %s", details)

            severity = _extract_field_value(fields.get(severity_field))
            logger.debug("Severity: %s", severity)
            return VulnerabilityData(
                key=str(raw_issue.get("key", "")),
                summary=summary,
                details=details,
                severity=severity,
                cve_id=issue_cve_id,
            )

        return None
