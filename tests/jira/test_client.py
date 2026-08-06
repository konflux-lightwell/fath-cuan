from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from fath_cuan.jira import JiraClient, JiraIssue
from fath_cuan.jira.client import _extract_field_value, _parse_description


class TestJiraClientInit:
    def test_default_server(self) -> None:
        client = JiraClient()
        assert client.server == "https://redhat.atlassian.net"

    def test_custom_server(self) -> None:
        client = JiraClient(server="https://jira.example.com/")
        assert client.server == "https://jira.example.com"

    def test_trailing_slash_stripped(self) -> None:
        client = JiraClient(server="https://jira.example.com///")
        assert client.server == "https://jira.example.com"


class TestBuildUrl:
    def test_endpoint_only(self) -> None:
        client = JiraClient(server="https://jira.example.com")
        url = client._build_url("/search")
        assert url == "https://jira.example.com/rest/api/2/search"

    def test_with_params(self) -> None:
        client = JiraClient(server="https://jira.example.com")
        url = client._build_url("/search", {"jql": "type = Bug", "maxResults": "10"})
        assert url.startswith("https://jira.example.com/rest/api/2/search?")
        assert "jql=type+%3D+Bug" in url or "jql=type+%3D+Bug" in url
        assert "maxResults=10" in url


class TestBuildHeaders:
    def test_no_auth(self) -> None:
        client = JiraClient()
        headers = client._build_headers()
        assert headers["Accept"] == "application/json"
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_basic_auth(self) -> None:
        client = JiraClient(email="user@example.com", token="secret-token")
        headers = client._build_headers()
        assert headers["Authorization"].startswith("Basic ")

    def test_partial_auth_ignored(self) -> None:
        client = JiraClient(email="user@example.com")
        headers = client._build_headers()
        assert "Authorization" not in headers


class TestGet:
    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_successful_get(self, mock_urlopen: MagicMock) -> None:
        response_data = {"issues": [], "total": 0}
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(response_data).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = JiraClient(server="https://jira.example.com")
        result = client.get("/search", {"jql": "type = Bug"})

        assert result == response_data
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert "jira.example.com/rest/api/2/search" in req.full_url

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_http_error_raises(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://jira.example.com/rest/api/2/search",
            code=401,
            msg="Unauthorized",
            hdrs=None,  # type: ignore[arg-type]
            fp=None,
        )
        client = JiraClient(server="https://jira.example.com")
        with pytest.raises(urllib.error.HTTPError):
            client.get("/search")

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_url_error_raises(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        client = JiraClient(server="https://jira.example.com")
        with pytest.raises(urllib.error.URLError):
            client.get("/search")

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_timeout_raises(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = TimeoutError()
        client = JiraClient(server="https://jira.example.com")
        with pytest.raises(TimeoutError):
            client.get("/search")


SAMPLE_JIRA_SEARCH_RESPONSE = {
    "total": 1,
    "issues": [
        {
            "key": "VULN-1234",
            "fields": {
                "summary": "Buffer overflow in libfoo",
                "status": {"name": "Open"},
                "issuetype": {"name": "Vulnerability"},
            },
        }
    ],
}

SAMPLE_JIRA_MULTI_RESULT_RESPONSE = {
    "total": 2,
    "issues": [
        {
            "key": "VULN-1234",
            "fields": {
                "summary": "Buffer overflow in libfoo",
                "status": {"name": "Open"},
                "issuetype": {"name": "Vulnerability"},
            },
        },
        {
            "key": "VULN-5678",
            "fields": {
                "summary": "Use-after-free in libbar",
                "status": {"name": "Closed"},
                "issuetype": {"name": "Vulnerability"},
            },
        },
    ],
}

SAMPLE_JIRA_EMPTY_RESPONSE = {"total": 0, "issues": []}


class TestSearchVulnerability:
    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_returns_matching_issues(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(SAMPLE_JIRA_SEARCH_RESPONSE).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = JiraClient(server="https://jira.example.com")
        results = client.search_vulnerability("LW-2026-0468")

        assert len(results) == 1
        assert results[0].key == "VULN-1234"
        assert results[0].summary == "Buffer overflow in libfoo"
        assert results[0].status == "Open"
        assert results[0].issue_type == "Vulnerability"

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_jql_query_format(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(SAMPLE_JIRA_EMPTY_RESPONSE).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = JiraClient(server="https://jira.example.com")
        client.search_vulnerability("LW-2026-0468")

        req = mock_urlopen.call_args[0][0]
        assert "textfields" in urllib.parse.unquote(req.full_url)
        assert "LW-2026-0468" in urllib.parse.unquote(req.full_url)
        assert "Vulnerability" in urllib.parse.unquote(req.full_url)

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_empty_results(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(SAMPLE_JIRA_EMPTY_RESPONSE).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = JiraClient(server="https://jira.example.com")
        results = client.search_vulnerability("LW-2026-0468")

        assert results == []

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_multiple_results(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            SAMPLE_JIRA_MULTI_RESULT_RESPONSE
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = JiraClient(server="https://jira.example.com")
        results = client.search_vulnerability("LW-2026-0468")

        assert len(results) == 2
        assert results[0].key == "VULN-1234"
        assert results[1].key == "VULN-5678"

    def test_invalid_lw_id_raises(self) -> None:
        client = JiraClient()
        with pytest.raises(ValueError, match="Invalid Lightwell identifier"):
            client.search_vulnerability("CVE-2024-25710")

    def test_invalid_lw_id_format_raises(self) -> None:
        client = JiraClient()
        with pytest.raises(ValueError, match="Invalid Lightwell identifier"):
            client.search_vulnerability("LW-26-0468")

    def test_empty_lw_id_raises(self) -> None:
        client = JiraClient()
        with pytest.raises(ValueError, match="Invalid Lightwell identifier"):
            client.search_vulnerability("")


class TestJiraIssueFromRaw:
    def test_full_fields(self) -> None:
        raw = {
            "key": "VULN-100",
            "fields": {
                "summary": "Test vuln",
                "status": {"name": "In Progress"},
                "issuetype": {"name": "Vulnerability"},
            },
        }
        issue = JiraIssue.from_raw(raw)
        assert issue.key == "VULN-100"
        assert issue.summary == "Test vuln"
        assert issue.status == "In Progress"
        assert issue.issue_type == "Vulnerability"

    def test_missing_fields(self) -> None:
        raw = {"key": "VULN-100"}
        issue = JiraIssue.from_raw(raw)
        assert issue.key == "VULN-100"
        assert issue.summary == ""
        assert issue.status == ""
        assert issue.issue_type == ""

    def test_null_status(self) -> None:
        raw = {
            "key": "VULN-100",
            "fields": {"summary": "Test", "status": None, "issuetype": None},
        }
        issue = JiraIssue.from_raw(raw)
        assert issue.status == ""
        assert issue.issue_type == ""


class TestParseDescription:
    def test_title_and_description(self) -> None:
        text = "**Title:** Buffer overflow in libfoo\n**Description:** A critical vulnerability."
        summary, details = _parse_description(text)
        assert summary == "Buffer overflow in libfoo"
        assert details == "A critical vulnerability."

    def test_multiline_description(self) -> None:
        text = (
            "**Title:** Buffer overflow\n"
            "**Description:** A critical vulnerability\n"
            "that spans multiple lines\n"
            "with additional context."
        )
        summary, details = _parse_description(text)
        assert summary == "Buffer overflow"
        expected = "A critical vulnerability\nthat spans multiple lines\nwith additional context."
        assert details == expected

    def test_description_stops_at_next_field(self) -> None:
        text = (
            "**Title:** Buffer overflow\n"
            "**Description:** Some details here.\n"
            "**Impact:** High"
        )
        summary, details = _parse_description(text)
        assert summary == "Buffer overflow"
        assert details == "Some details here."

    def test_missing_title(self) -> None:
        text = "**Description:** Only a description."
        summary, details = _parse_description(text)
        assert summary == ""
        assert details == "Only a description."

    def test_missing_description(self) -> None:
        text = "**Title:** Only a title"
        summary, details = _parse_description(text)
        assert summary == "Only a title"
        assert details == ""

    def test_empty_text(self) -> None:
        summary, details = _parse_description("")
        assert summary == ""
        assert details == ""

    def test_no_matching_fields(self) -> None:
        text = "Just some random text without any fields."
        summary, details = _parse_description(text)
        assert summary == ""
        assert details == ""

    def test_extra_whitespace(self) -> None:
        text = "**Title:**   padded title  \n**Description:**   padded details  "
        summary, details = _parse_description(text)
        assert summary == "padded title"
        assert details == "padded details"


class TestExtractFieldValue:
    def test_dict_with_value(self) -> None:
        assert _extract_field_value({"value": "Critical", "id": "1"}) == "Critical"

    def test_dict_with_name(self) -> None:
        assert _extract_field_value({"name": "High", "id": "2"}) == "High"

    def test_dict_prefers_value_over_name(self) -> None:
        assert _extract_field_value({"value": "Critical", "name": "Crit"}) == "Critical"

    def test_string_value(self) -> None:
        assert _extract_field_value("LW-2026-0468") == "LW-2026-0468"

    def test_none(self) -> None:
        assert _extract_field_value(None) == ""

    def test_empty_string(self) -> None:
        assert _extract_field_value("") == ""

    def test_empty_dict(self) -> None:
        assert _extract_field_value({}) == ""


SAMPLE_FIELD_DEFINITIONS = [
    {"id": "summary", "name": "Summary", "custom": False},
    {"id": "description", "name": "Description", "custom": False},
    {"id": "customfield_10100", "name": "Severity", "custom": True},
    {"id": "customfield_10200", "name": "CVE ID", "custom": True},
]


def _mock_urlopen_response(data: object) -> MagicMock:
    """Create a mock urlopen context manager returning JSON data."""
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(data).encode()
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)
    return mock_response


SAMPLE_VULN_SEARCH_RESPONSE = {
    "total": 1,
    "issues": [
        {
            "key": "VULN-1234",
            "fields": {
                "description": (
                    "**Title:** Buffer overflow in libfoo\n"
                    "**Description:** A buffer overflow vulnerability exists in libfoo "
                    "allowing remote code execution."
                ),
                "customfield_10100": {"value": "Critical"},
                "customfield_10200": "LW-2026-0468",
            },
        }
    ],
}


class TestResolveFieldIds:
    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_resolves_field_names_to_ids(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_urlopen_response(SAMPLE_FIELD_DEFINITIONS)

        client = JiraClient(server="https://jira.example.com")
        field_map = client._resolve_field_ids()

        assert field_map["Severity"] == "customfield_10100"
        assert field_map["CVE ID"] == "customfield_10200"
        assert field_map["Summary"] == "summary"

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_caches_results(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_urlopen_response(SAMPLE_FIELD_DEFINITIONS)

        client = JiraClient(server="https://jira.example.com")
        client._resolve_field_ids()
        client._resolve_field_ids()

        mock_urlopen.assert_called_once()


class TestFetchVulnerability:
    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_returns_parsed_vulnerability(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = [
            _mock_urlopen_response(SAMPLE_FIELD_DEFINITIONS),
            _mock_urlopen_response(SAMPLE_VULN_SEARCH_RESPONSE),
        ]

        client = JiraClient(server="https://jira.example.com")
        result = client.fetch_vulnerability("LW-2026-0468")

        assert result is not None
        assert result.key == "VULN-1234"
        assert result.summary == "Buffer overflow in libfoo"
        assert "remote code execution" in result.details
        assert result.severity == "Critical"
        assert result.cve_id == "LW-2026-0468"

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_returns_none_when_cve_id_mismatch(self, mock_urlopen: MagicMock) -> None:
        response = {
            "total": 1,
            "issues": [
                {
                    "key": "VULN-1234",
                    "fields": {
                        "description": "**Title:** Something\n**Description:** Details",
                        "customfield_10100": {"value": "High"},
                        "customfield_10200": "LW-2026-9999",
                    },
                }
            ],
        }
        mock_urlopen.side_effect = [
            _mock_urlopen_response(SAMPLE_FIELD_DEFINITIONS),
            _mock_urlopen_response(response),
        ]

        client = JiraClient(server="https://jira.example.com")
        result = client.fetch_vulnerability("LW-2026-0468")

        assert result is None

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_returns_none_when_no_issues(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = [
            _mock_urlopen_response(SAMPLE_FIELD_DEFINITIONS),
            _mock_urlopen_response(SAMPLE_JIRA_EMPTY_RESPONSE),
        ]

        client = JiraClient(server="https://jira.example.com")
        result = client.fetch_vulnerability("LW-2026-0468")

        assert result is None

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_skips_mismatch_returns_matching(self, mock_urlopen: MagicMock) -> None:
        response = {
            "total": 2,
            "issues": [
                {
                    "key": "VULN-0001",
                    "fields": {
                        "description": "**Title:** Wrong\n**Description:** Nope",
                        "customfield_10100": {"value": "Low"},
                        "customfield_10200": "LW-2026-9999",
                    },
                },
                {
                    "key": "VULN-0002",
                    "fields": {
                        "description": "**Title:** Correct\n**Description:** Yes",
                        "customfield_10100": {"value": "High"},
                        "customfield_10200": "LW-2026-0468",
                    },
                },
            ],
        }
        mock_urlopen.side_effect = [
            _mock_urlopen_response(SAMPLE_FIELD_DEFINITIONS),
            _mock_urlopen_response(response),
        ]

        client = JiraClient(server="https://jira.example.com")
        result = client.fetch_vulnerability("LW-2026-0468")

        assert result is not None
        assert result.key == "VULN-0002"
        assert result.summary == "Correct"
        assert result.severity == "High"

    def test_invalid_lw_id_raises(self) -> None:
        client = JiraClient()
        with pytest.raises(ValueError, match="Invalid Lightwell identifier"):
            client.fetch_vulnerability("CVE-2024-25710")

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_missing_severity_field_raises(self, mock_urlopen: MagicMock) -> None:
        fields_without_severity = [
            {"id": "summary", "name": "Summary", "custom": False},
            {"id": "customfield_10200", "name": "CVE ID", "custom": True},
        ]
        mock_urlopen.return_value = _mock_urlopen_response(fields_without_severity)

        client = JiraClient(server="https://jira.example.com")
        with pytest.raises(ValueError, match="Severity"):
            client.fetch_vulnerability("LW-2026-0468")

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_missing_cve_id_field_raises(self, mock_urlopen: MagicMock) -> None:
        fields_without_cve = [
            {"id": "summary", "name": "Summary", "custom": False},
            {"id": "customfield_10100", "name": "Severity", "custom": True},
        ]
        mock_urlopen.return_value = _mock_urlopen_response(fields_without_cve)

        client = JiraClient(server="https://jira.example.com")
        with pytest.raises(ValueError, match="CVE ID"):
            client.fetch_vulnerability("LW-2026-0468")

    @patch("fath_cuan.jira.client.urllib.request.urlopen")
    def test_severity_as_string_field(self, mock_urlopen: MagicMock) -> None:
        response = {
            "total": 1,
            "issues": [
                {
                    "key": "VULN-1234",
                    "fields": {
                        "description": "**Title:** Test\n**Description:** Details",
                        "customfield_10100": "Medium",
                        "customfield_10200": "LW-2026-0468",
                    },
                }
            ],
        }
        mock_urlopen.side_effect = [
            _mock_urlopen_response(SAMPLE_FIELD_DEFINITIONS),
            _mock_urlopen_response(response),
        ]

        client = JiraClient(server="https://jira.example.com")
        result = client.fetch_vulnerability("LW-2026-0468")

        assert result is not None
        assert result.severity == "Medium"
