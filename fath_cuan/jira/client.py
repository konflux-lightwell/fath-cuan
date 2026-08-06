from __future__ import annotations

import base64
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fath_cuan.jira.models import JiraIssue

_DEFAULT_SERVER = "https://redhat.atlassian.net/"
_API_PATH = "/rest/api/2"
_LW_ID_PATTERN = re.compile(r"^LW-\d{4}-\d{4}$")

logger = logging.getLogger(__name__)


class JiraClient:
    """Client for communicating with a JIRA instance via REST API v2."""

    def __init__(
        self,
        server: str = _DEFAULT_SERVER,
        email: str | None = None,
        token: str | None = None,
    ) -> None:
        self.server = server.rstrip("/")
        self._email = email
        self._token = token

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
            credentials = base64.b64encode(
                f"{self._email}:{self._token}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"
        return headers

    def get(self, endpoint: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        """Perform a GET request against the JIRA REST API."""
        url = self._build_url(endpoint, params)
        req = urllib.request.Request(url, headers=self._build_headers())
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as e:
            logger.error("JIRA request failed: %s %s", e.code, e.reason)
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            logger.error("JIRA request failed: %s", e)
            raise

    def search_vulnerability(self, lw_id: str) -> list[JiraIssue]:
        """Search for JIRA Vulnerability issues matching a Lightwell identifier.

        Uses JQL: textfields ~ "<lw_id>" AND type = Vulnerability
        """
        if not _LW_ID_PATTERN.match(lw_id):
            raise ValueError(
                f"Invalid Lightwell identifier format: {lw_id!r}, expected LW-YYYY-XXXX"
            )
        jql = f'textfields ~ "{lw_id}" AND type = Vulnerability'
        data = self.get("/search", {"jql": jql, "fields": "summary,status,issuetype"})
        issues: list[JiraIssue] = []
        for raw_issue in data.get("issues", []):
            issues.append(JiraIssue.from_raw(raw_issue))
        return issues
