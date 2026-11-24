"""LWLP-6012: osv.dev retries for dropped connections, the overlap query, caches."""

from __future__ import annotations

import http.client
import json
import urllib.error
from email.message import Message
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fath_cuan.converters import osv
from fath_cuan.converters.osv import UpstreamFetchError, _fetch_nvd, _fetch_upstream_osv

# The real function: conftest replaces the module attribute for every test.
from fath_cuan.converters.osv import _fetch_lightwell_advisories as real_fetch_advisories

_URLOPEN = "fath_cuan.converters.osv.urllib.request.urlopen"
_SLEEP = "fath_cuan.converters.osv.time.sleep"


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.osv.dev/v1/query", code, "err", Message(), None)


def _response(body: dict[str, Any]) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(body).encode()
    resp.__enter__.return_value = resp
    return resp


# ── Dropped connections are retried (urllib doesn't wrap these) ──────────────


@pytest.mark.parametrize(
    "error",
    [
        http.client.RemoteDisconnected("Remote end closed connection without response"),
        ConnectionResetError(104, "Connection reset by peer"),
        http.client.IncompleteRead(b"{", 10),
    ],
    ids=["remote-disconnected", "connection-reset", "incomplete-read"],
)
@patch(_SLEEP)
@patch(_URLOPEN)
def test_dropped_connection_is_retried(mock_urlopen, mock_sleep, error) -> None:
    record = {"id": "CVE-2099-0001"}
    mock_urlopen.side_effect = [error, _response(record)]

    assert _fetch_upstream_osv("CVE-2099-0001") == record
    assert mock_urlopen.call_count == 2


@patch(_SLEEP)
@patch(_URLOPEN, side_effect=http.client.RemoteDisconnected("closed"))
def test_persistently_dropped_connection_raises(mock_urlopen, mock_sleep) -> None:
    with pytest.raises(UpstreamFetchError, match=r"osv\.dev lookup for CVE-2099-0001 failed"):
        _fetch_upstream_osv("CVE-2099-0001")
    assert mock_urlopen.call_count == osv._OSV_FETCH_ATTEMPTS


# ── The overlap query fails instead of returning "no advisories" ─────────────


@patch(_SLEEP)
@patch(_URLOPEN)
def test_overlap_query_retries_then_succeeds(mock_urlopen, mock_sleep) -> None:
    advisory = {"id": "RHLW-2026-0000000000000001"}
    mock_urlopen.side_effect = [_http_error(503), _response({"vulns": [advisory]})]

    assert real_fetch_advisories("org.example:a", "Maven") == [advisory]
    assert mock_urlopen.call_count == 2


@pytest.mark.parametrize("code", [503, 429])
@patch(_SLEEP)
@patch(_URLOPEN)
def test_overlap_query_failure_raises(mock_urlopen, mock_sleep, code) -> None:
    """A failed query must never be read as "no advisories" (introduced: 0 overlaps)."""
    mock_urlopen.side_effect = _http_error(code)

    with pytest.raises(UpstreamFetchError, match=r"osv\.dev query for org\.example:a advisories"):
        real_fetch_advisories("org.example:a", "Maven")
    assert mock_urlopen.call_count == osv._OSV_FETCH_ATTEMPTS


@patch(_SLEEP)
@patch(_URLOPEN, side_effect=_http_error(400))
def test_overlap_query_bad_request_raises_without_retry(mock_urlopen, mock_sleep) -> None:
    with pytest.raises(UpstreamFetchError):
        real_fetch_advisories("org.example:a", "Maven")
    assert mock_urlopen.call_count == 1


@patch(_URLOPEN, return_value=_response({}))
def test_overlap_query_empty_answer_is_no_advisories(mock_urlopen) -> None:
    assert real_fetch_advisories("org.example:a", "Maven") == []


@patch(_URLOPEN)
def test_overlap_query_follows_next_page_token(mock_urlopen) -> None:
    """Advisories on later pages count for the overlap guard too."""
    mock_urlopen.side_effect = [
        _response({"vulns": [{"id": "RHLW-2026-1"}], "next_page_token": "p2"}),
        _response({"vulns": [{"id": "RHLW-2026-2"}]}),
    ]
    found = real_fetch_advisories("org.example:a", "Maven")

    assert [a["id"] for a in found] == ["RHLW-2026-1", "RHLW-2026-2"]
    second = json.loads(mock_urlopen.call_args_list[1].args[0].data)
    assert second["page_token"] == "p2"


def _html_response() -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = b"<html>502 Bad Gateway</html>"
    resp.__enter__.return_value = resp
    return resp


@patch(_SLEEP)
@patch(_URLOPEN)
def test_body_that_is_not_json_is_retried(mock_urlopen, mock_sleep) -> None:
    """A proxy error page with HTTP 200 is a transient failure, not a crash."""
    record = {"id": "CVE-2099-0009", "aliases": []}
    mock_urlopen.side_effect = [_html_response(), _response(record)]

    assert _fetch_upstream_osv("CVE-2099-0009") == record
    assert mock_urlopen.call_count == 2


@patch(_SLEEP)
@patch(_URLOPEN)
def test_body_that_is_never_json_raises(mock_urlopen, mock_sleep) -> None:
    mock_urlopen.side_effect = lambda *a, **k: _html_response()

    with pytest.raises(UpstreamFetchError, match=r"osv\.dev lookup for CVE-2099-0010"):
        _fetch_upstream_osv("CVE-2099-0010")


# ── Per-run caches: answers cached, failures not, callers get copies ─────────


@patch(_URLOPEN)
def test_upstream_record_fetched_once_per_run(mock_urlopen) -> None:
    mock_urlopen.return_value = _response({"id": "CVE-2099-0001", "aliases": []})

    first = _fetch_upstream_osv("CVE-2099-0001")
    first["aliases"].append("changed by a caller")
    assert _fetch_upstream_osv("CVE-2099-0001") == {"id": "CVE-2099-0001", "aliases": []}
    assert mock_urlopen.call_count == 1


@patch(_URLOPEN, side_effect=_http_error(404))
def test_not_found_is_cached(mock_urlopen) -> None:
    assert _fetch_upstream_osv("CVE-2099-0002") is None
    assert _fetch_upstream_osv("CVE-2099-0002") is None
    assert mock_urlopen.call_count == 1


@patch(_SLEEP)
@patch(_URLOPEN)
def test_failed_lookup_is_not_cached(mock_urlopen, mock_sleep) -> None:
    record = {"id": "CVE-2099-0003"}
    mock_urlopen.side_effect = [_http_error(400), _response(record)]

    with pytest.raises(UpstreamFetchError):
        _fetch_upstream_osv("CVE-2099-0003")
    assert _fetch_upstream_osv("CVE-2099-0003") == record


@patch(_URLOPEN)
def test_overlap_query_cached(mock_urlopen) -> None:
    mock_urlopen.return_value = _response({"vulns": []})
    real_fetch_advisories("org.example:a", "Maven")
    real_fetch_advisories("org.example:a", "Maven")
    real_fetch_advisories("org.example:b", "Maven")
    assert mock_urlopen.call_count == 2


@patch(_URLOPEN)
def test_nvd_answer_cached_failure_not(mock_urlopen) -> None:
    nvd = {"vulnerabilities": [{"cve": {"id": "CVE-2099-0004"}}]}
    mock_urlopen.side_effect = [urllib.error.URLError("down"), _response(nvd)]

    assert _fetch_nvd("CVE-2099-0004") is None  # failure: not cached
    assert _fetch_nvd("CVE-2099-0004") == {"id": "CVE-2099-0004"}
    assert _fetch_nvd("CVE-2099-0004") == {"id": "CVE-2099-0004"}  # cached
    assert mock_urlopen.call_count == 2


@patch(_URLOPEN)
def test_clear_caches(mock_urlopen) -> None:
    mock_urlopen.return_value = _response({"id": "CVE-2099-0005"})
    _fetch_upstream_osv("CVE-2099-0005")
    osv.clear_caches()
    _fetch_upstream_osv("CVE-2099-0005")
    assert mock_urlopen.call_count == 2
