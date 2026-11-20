"""osv.dev lookup failures must not be mistaken for "no package data".

Module placement (LWLP-5917) reads ``_fetch_upstream_osv`` returning None as
"osv.dev has no package data" and then puts the CVE on the primary module. A
429, 5xx or timeout returning None silently reproduces the misattribution the
placement exists to fix, and slan-cuan never overwrites a published VEX. So
only a 404 returns None; other failures are retried and then raised.
"""

import io
import json
import logging
import urllib.error
from email.message import Message
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fath_cuan.converters import osv
from fath_cuan.converters.osv import UpstreamFetchError, _fetch_upstream_osv, convert
from fath_cuan.models.input import InputDocument
from fath_cuan.workflow import resolve_module_vulns

_URLOPEN = "fath_cuan.converters.osv.urllib.request.urlopen"
_SLEEP = "fath_cuan.converters.osv.time.sleep"


def _http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://api.osv.dev/v1/vulns/X", code, "err", headers, None)


def _response(body: dict[str, Any]) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(body).encode()
    resp.__enter__.return_value = resp
    return resp


# --- _fetch_upstream_osv -----------------------------------------------------


@patch(_SLEEP)
@patch(_URLOPEN)
def test_404_returns_none_without_retry(mock_urlopen: MagicMock, mock_sleep: MagicMock) -> None:
    mock_urlopen.side_effect = _http_error(404)
    assert _fetch_upstream_osv("CVE-2099-0001") is None
    assert mock_urlopen.call_count == 1
    mock_sleep.assert_not_called()


@patch(_SLEEP)
@patch(_URLOPEN)
def test_transient_429_is_retried_then_succeeds(
    mock_urlopen: MagicMock, mock_sleep: MagicMock
) -> None:
    record = {"id": "CVE-2099-0001", "affected": []}
    mock_urlopen.side_effect = [_http_error(429), _response(record)]
    assert _fetch_upstream_osv("CVE-2099-0001") == record
    assert mock_urlopen.call_count == 2
    mock_sleep.assert_called_once()


@pytest.mark.parametrize(
    "error",
    [
        _http_error(429),
        _http_error(500),
        _http_error(503),
        urllib.error.URLError("connection refused"),
        TimeoutError(),
    ],
    ids=["429", "500", "503", "url-error", "timeout"],
)
@patch(_SLEEP)
@patch(_URLOPEN)
def test_persistent_failure_raises_after_all_attempts(
    mock_urlopen: MagicMock, mock_sleep: MagicMock, error: Exception
) -> None:
    mock_urlopen.side_effect = error
    with pytest.raises(UpstreamFetchError, match="CVE-2099-0001"):
        _fetch_upstream_osv("CVE-2099-0001")
    assert mock_urlopen.call_count == osv._OSV_FETCH_ATTEMPTS
    assert mock_sleep.call_count == osv._OSV_FETCH_ATTEMPTS - 1


@patch(_SLEEP)
@patch(_URLOPEN)
def test_non_retryable_4xx_raises_immediately(
    mock_urlopen: MagicMock, mock_sleep: MagicMock
) -> None:
    mock_urlopen.side_effect = _http_error(400)
    with pytest.raises(UpstreamFetchError):
        _fetch_upstream_osv("CVE-2099-0001")
    assert mock_urlopen.call_count == 1
    mock_sleep.assert_not_called()


@patch(_SLEEP)
@patch(_URLOPEN)
def test_retry_after_is_honoured_and_capped(mock_urlopen: MagicMock, mock_sleep: MagicMock) -> None:
    record = {"id": "CVE-2099-0001"}
    mock_urlopen.side_effect = [
        _http_error(429, retry_after="4"),
        _http_error(429, retry_after="3600"),
        _response(record),
    ]
    assert _fetch_upstream_osv("CVE-2099-0001") == record
    delays = [c.args[0] for c in mock_sleep.call_args_list]
    assert delays == [4.0, osv._OSV_RETRY_MAX_DELAY]


# --- placement ----------------------------------------------------------------

# Two modules; each CVE's package name lives only on its GHSA alias, which is
# how osv.dev usually models Maven CVEs.
_GAV_INDEX = {
    "buildId": "B-FETCH",
    "created": "2099-01-01T00:00:00+00:00",
    "vulns": ["CVE-2099-0001", "CVE-2099-0002"],
    "primaryGav": "org.example:core:1.0.0.rhlw-00001",
    "gavs": [
        "org.example:core:1.0.0.rhlw-00001",
        "org.example:compiler:1.0.0.rhlw-00001",
    ],
}

_RECORDS: dict[str, dict[str, Any]] = {
    "CVE-2099-0001": {"id": "CVE-2099-0001", "aliases": ["GHSA-aaaa-aaaa-aaaa"], "affected": []},
    "CVE-2099-0002": {"id": "CVE-2099-0002", "aliases": ["GHSA-bbbb-bbbb-bbbb"], "affected": []},
    "GHSA-aaaa-aaaa-aaaa": {
        "affected": [{"package": {"ecosystem": "Maven", "name": "org.example:core"}}]
    },
    "GHSA-bbbb-bbbb-bbbb": {
        "affected": [{"package": {"ecosystem": "Maven", "name": "org.example:compiler"}}]
    },
}


def _osv_dev(ghsa_status: int | None = None) -> Any:
    """A fake urlopen serving _RECORDS; GHSA lookups fail with *ghsa_status*."""

    def fake(req: Any, timeout: float = 0) -> Any:
        vuln_id = req.full_url.rsplit("/", 1)[-1]
        if ghsa_status is not None and vuln_id.startswith("GHSA-"):
            raise _http_error(ghsa_status)
        if vuln_id not in _RECORDS:
            raise _http_error(404)
        return _response(_RECORDS[vuln_id])

    return fake


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch(_SLEEP)
@patch(_URLOPEN, side_effect=_osv_dev())
def test_placement_uses_ghsa_package_names(
    mock_urlopen: MagicMock, mock_sleep: MagicMock, mock_nvd: MagicMock
) -> None:
    assert resolve_module_vulns(_GAV_INDEX) == {
        "org.example:core": ["CVE-2099-0001"],
        "org.example:compiler": ["CVE-2099-0002"],
    }


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch(_SLEEP)
@patch(_URLOPEN, side_effect=_osv_dev(ghsa_status=429))
def test_rate_limited_ghsa_lookup_fails_placement(
    mock_urlopen: MagicMock, mock_sleep: MagicMock, mock_nvd: MagicMock
) -> None:
    """Rate-limited GHSA lookups used to put both CVEs on the primary module."""
    with pytest.raises(UpstreamFetchError, match="GHSA-"):
        resolve_module_vulns(_GAV_INDEX)


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch(_SLEEP)
@patch(_URLOPEN, side_effect=_osv_dev(ghsa_status=503))
def test_failed_lookup_fails_osv_conversion(
    mock_urlopen: MagicMock, mock_sleep: MagicMock, mock_nvd: MagicMock
) -> None:
    """The per-release path computes its own placement when none is passed: same rule."""
    data = {**_GAV_INDEX, "advisoryId": "RHLW-2099-00001"}
    with pytest.raises(UpstreamFetchError):
        convert(InputDocument.from_dict(data))


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_cve_fallback_to_primary_is_logged(
    mock_osv: MagicMock, mock_nvd: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """A public CVE with no package data still lands on the primary, but loudly."""
    with caplog.at_level(logging.WARNING, logger="fath_cuan.converters.osv"):
        placement = resolve_module_vulns(_GAV_INDEX)

    assert placement == {"org.example:core": ["CVE-2099-0001", "CVE-2099-0002"]}
    fallback = [r.getMessage() for r in caplog.records if "by fallback" in r.getMessage()]
    assert len(fallback) == 2
    assert all("org.example:core" in m for m in fallback)


@patch("fath_cuan.converters.osv._fetch_nvd", return_value=None)
@patch("fath_cuan.converters.osv._fetch_upstream_osv", return_value=None)
def test_lw_fallback_to_primary_is_not_warned(
    mock_osv: MagicMock, mock_nvd: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """LW- IDs have no osv.dev data by design; the primary fallback is expected."""
    data = {**_GAV_INDEX, "vulns": ["LW-2099-0001"]}
    with caplog.at_level(logging.WARNING, logger="fath_cuan.converters.osv"):
        resolve_module_vulns(data)
    assert not any("by fallback" in r.getMessage() for r in caplog.records)


def test_http_error_body_is_not_required() -> None:
    """HTTPError built with fp=None (as urllib does for some responses) is handled."""
    err = _http_error(503, retry_after="2")
    assert osv._retry_delay(err, 1) == 2.0
    err_no_headers = urllib.error.HTTPError("u", 503, "err", None, io.BytesIO())  # type: ignore[arg-type]
    assert osv._retry_delay(err_no_headers, 2) == osv._OSV_RETRY_BASE_DELAY * 2
