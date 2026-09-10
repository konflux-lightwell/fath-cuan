import json

import pytest

from fath_cuan.oci import (
    BUILD_INDEX_ARTIFACT_TYPE,
    OciError,
    attach_build_index,
    fetch_build_index,
    payload_digest,
)


class FakeRegistry:
    """In-memory Registry: keyed by (image_ref, artifact_type) -> list[bytes]."""

    def __init__(self, initial: dict | None = None) -> None:
        self.store: dict[tuple[str, str], list[bytes]] = initial or {}
        self.push_count = 0

    def list_referrer_payloads(self, image_ref: str, artifact_type: str) -> list[bytes]:
        return list(self.store.get((image_ref, artifact_type), []))

    def push_referrer(self, image_ref: str, payload: bytes, artifact_type: str) -> str:
        self.store.setdefault((image_ref, artifact_type), []).append(payload)
        self.push_count += 1
        return payload_digest(payload)


REF = "quay.io/example/img:tag"
PAYLOAD = b'{"ecosystem":"pypi","purls":["pkg:pypi/coverage@7.6.12%2Brhlw.1"]}'
OTHER = b'{"ecosystem":"pypi","purls":["pkg:pypi/other@1.0.0"]}'


def test_payload_digest_deterministic() -> None:
    assert payload_digest(PAYLOAD) == payload_digest(PAYLOAD)
    assert payload_digest(PAYLOAD).startswith("sha256:")
    assert payload_digest(PAYLOAD) != payload_digest(OTHER)


def test_attach_pushes_when_none_exists() -> None:
    reg = FakeRegistry()
    result = attach_build_index(reg, REF, PAYLOAD)
    assert result.deduplicated is False
    assert result.referrer_digest == payload_digest(PAYLOAD)
    assert reg.push_count == 1
    assert reg.list_referrer_payloads(REF, BUILD_INDEX_ARTIFACT_TYPE) == [PAYLOAD]


def test_attach_deduplicates_identical_payload() -> None:
    reg = FakeRegistry({(REF, BUILD_INDEX_ARTIFACT_TYPE): [PAYLOAD]})
    result = attach_build_index(reg, REF, PAYLOAD)
    assert result.deduplicated is True
    assert result.referrer_digest is None
    assert reg.push_count == 0


def test_attach_conflict_on_divergent_payload() -> None:
    reg = FakeRegistry({(REF, BUILD_INDEX_ARTIFACT_TYPE): [OTHER]})
    with pytest.raises(OciError, match="divergent"):
        attach_build_index(reg, REF, PAYLOAD)
    assert reg.push_count == 0


def test_attach_is_idempotent_across_calls() -> None:
    reg = FakeRegistry()
    attach_build_index(reg, REF, PAYLOAD)
    second = attach_build_index(reg, REF, PAYLOAD)
    assert second.deduplicated is True
    assert reg.push_count == 1


def test_fetch_returns_none_when_absent() -> None:
    assert fetch_build_index(FakeRegistry(), REF) is None


def test_fetch_returns_parsed_payload() -> None:
    reg = FakeRegistry({(REF, BUILD_INDEX_ARTIFACT_TYPE): [PAYLOAD]})
    assert fetch_build_index(reg, REF) == json.loads(PAYLOAD)


def test_fetch_allows_duplicate_identical_referrers() -> None:
    reg = FakeRegistry({(REF, BUILD_INDEX_ARTIFACT_TYPE): [PAYLOAD, PAYLOAD]})
    assert fetch_build_index(reg, REF) == json.loads(PAYLOAD)


def test_fetch_raises_on_divergent_referrers() -> None:
    reg = FakeRegistry({(REF, BUILD_INDEX_ARTIFACT_TYPE): [PAYLOAD, OTHER]})
    with pytest.raises(OciError, match="divergent"):
        fetch_build_index(reg, REF)


def test_artifact_type_is_respected() -> None:
    reg = FakeRegistry({(REF, "application/other"): [OTHER]})
    # No build-index referrer of the expected type -> fetch is None, attach pushes.
    assert fetch_build_index(reg, REF) is None
    result = attach_build_index(reg, REF, PAYLOAD)
    assert result.deduplicated is False
