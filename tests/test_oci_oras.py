"""Unit tests for the OrasRegistry adapter — no network.

Uses a fake oras client that keeps the real Container URL builder but returns
canned HTTP responses, so URL composition, the Referrers API call (incl.
pagination), subject resolution, status guards, and the push kwargs are all
exercised without a live registry. (review #23)
"""

from unittest.mock import MagicMock

import pytest

pytest.importorskip("oras")  # adapter + these tests require the optional [oci] extra

from oras.client import OrasClient
from oras.oci import Subject

from fath_cuan.oci import BUILD_INDEX_ARTIFACT_TYPE, OciError
from fath_cuan.oci_oras import OrasRegistry

ART = BUILD_INDEX_ARTIFACT_TYPE
PAYLOAD = b'{"ecosystem":"pypi","purls":["pkg:pypi/coverage@7.6.12%2Brhlw.1"]}'


class _Resp:
    def __init__(self, status=200, headers=None, json_body=None, content=b""):
        self.status_code = status
        self.headers = headers or {}
        self._json = json_body
        self.content = content

    def json(self):
        return self._json


class FakeOras:
    """Fake OrasClient: real URL builder, canned responses keyed by URL substring."""

    prefix = "https"

    def __init__(self, responses, subject_digest="sha256:aaa"):
        self.auth = MagicMock()
        self._real = OrasClient()
        self.requests: list[tuple[str, str]] = []
        self.pushes: list[dict] = []
        self._responses = responses
        self._subject_digest = subject_digest
        self.push_result = _Resp(headers={"Docker-Content-Digest": "sha256:refmanifest"})
        self.push_exc: Exception | None = None

    def get_container(self, ref):
        return self._real.get_container(ref)

    def do_request(self, url, method="GET", headers=None, **kw):
        self.requests.append((method, url))
        if method == "HEAD":
            return _Resp(
                200,
                {
                    "Docker-Content-Digest": self._subject_digest,
                    "Content-Type": "application/vnd.oci.image.manifest.v1+json",
                    "Content-Length": "123",
                },
            )
        for key, resp in self._responses.items():
            if key in url:
                return resp
        return _Resp(404, {})

    def push(self, **kwargs):
        if self.push_exc:
            raise self.push_exc
        self.pushes.append(kwargs)
        return self.push_result


REF = "quay.io/ns/repo:tag"


def _reg(responses, **kw):
    return OrasRegistry(client=FakeOras(responses, **kw))


def test_repo_ref_and_next_link_helpers() -> None:
    assert OrasRegistry._repo_ref("https://quay.io/v2/ns/repo") == "quay.io/ns/repo"
    assert OrasRegistry._repo_ref("http://localhost:5000/v2/img") == "localhost:5000/img"
    nxt = OrasRegistry._next_link(
        '</v2/ns/repo/referrers/sha256:aaa?n=2>; rel="next"', "https://quay.io/v2/ns/repo"
    )
    assert nxt == "https://quay.io/v2/ns/repo/referrers/sha256:aaa?n=2"
    assert OrasRegistry._next_link(None, "https://quay.io/v2/ns/repo") is None


def test_subject_descriptor_from_head() -> None:
    reg = _reg({})
    container = reg._container(REF)
    d = reg._subject_descriptor(container)
    assert d == {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": "sha256:aaa",
        "size": 123,
    }


def test_list_matches_artifact_type_and_skips_others() -> None:
    responses = {
        "/referrers/": _Resp(
            200,
            {},
            {
                "manifests": [
                    {"artifactType": ART, "digest": "sha256:ref1"},
                    {"artifactType": "application/other", "digest": "sha256:ref2"},
                ]
            },
        ),
        "/manifests/sha256:ref1": _Resp(
            200, {}, {"layers": [{"mediaType": ART, "digest": "sha256:blob1"}]}
        ),
        "/blobs/sha256:blob1": _Resp(200, {}, None, content=PAYLOAD),
    }
    payloads = _reg(responses).list_referrer_payloads(REF, ART)
    assert payloads == [PAYLOAD]  # ref2 (wrong artifactType) skipped


def test_list_follows_pagination() -> None:
    responses = {
        "n=2": _Resp(  # page 2 (checked first so it wins over the page-1 key)
            200, {}, {"manifests": [{"artifactType": ART, "digest": "sha256:ref3"}]}
        ),
        "/referrers/sha256:aaa": _Resp(
            200,
            {"Link": '</v2/ns/repo/referrers/sha256:aaa?n=2>; rel="next"'},
            {"manifests": [{"artifactType": ART, "digest": "sha256:ref1"}]},
        ),
        "/manifests/sha256:ref1": _Resp(
            200, {}, {"layers": [{"mediaType": ART, "digest": "sha256:blob1"}]}
        ),
        "/manifests/sha256:ref3": _Resp(
            200, {}, {"layers": [{"mediaType": ART, "digest": "sha256:blob3"}]}
        ),
        "/blobs/sha256:blob1": _Resp(200, {}, None, content=b"page1"),
        "/blobs/sha256:blob3": _Resp(200, {}, None, content=b"page2"),
    }
    payloads = _reg(responses).list_referrer_payloads(REF, ART)
    assert payloads == [b"page1", b"page2"]


def test_list_404_returns_empty() -> None:
    assert _reg({"/referrers/": _Resp(404, {})}).list_referrer_payloads(REF, ART) == []


def test_fetch_payload_status_guard() -> None:
    responses = {
        "/referrers/": _Resp(
            200, {}, {"manifests": [{"artifactType": ART, "digest": "sha256:ref1"}]}
        ),
        "/manifests/sha256:ref1": _Resp(401, {}),  # auth failure on the manifest GET
    }
    with pytest.raises(OciError, match="401"):
        _reg(responses).list_referrer_payloads(REF, ART)


def test_push_referrer_passes_subject_object() -> None:
    reg = _reg({})
    digest = reg.push_referrer(REF, PAYLOAD, ART)
    assert digest == "sha256:refmanifest"
    (push_kwargs,) = reg._client.pushes
    subj = push_kwargs["subject"]
    assert isinstance(subj, Subject)  # (review #1) real Subject, not a str
    assert subj.digest == "sha256:aaa"
    assert push_kwargs["manifest_config"].endswith(f":{ART}")  # (review #2) config mediaType
    assert push_kwargs["target"] == "quay.io/ns/repo:sha256-aaa.build-index"


def test_push_referrer_wraps_oras_errors() -> None:
    reg = _reg({})
    reg._client.push_exc = ValueError("Issue with push")
    with pytest.raises(OciError, match="failed to push"):
        reg.push_referrer(REF, PAYLOAD, ART)


def test_read_path_loads_credentials() -> None:
    reg = _reg({"/referrers/": _Resp(404, {})})
    reg.list_referrer_payloads(REF, ART)
    reg._client.auth.load_configs.assert_called()  # (review #6)
