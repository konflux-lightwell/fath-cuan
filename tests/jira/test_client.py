from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from fath_cuan.jira import JiraClient


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
