"""OCI referrer attach/fetch orchestration for the build-index.

The build-index is attached to a built image as an OCI referrer of artifact
type ``application/vnd.lightwell.build-index.v1+json`` (build time), and read
back off the image for OSV generation (release time).

This module holds the *policy* — payload-blob-digest deduplication and
conflict-failure for divergent payloads — behind a small :class:`Registry`
protocol, so it is fully unit-testable with a fake registry and carries no
dependency on any registry client. The concrete client lives in
:mod:`fath_cuan.oci_oras`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

BUILD_INDEX_ARTIFACT_TYPE = "application/vnd.lightwell.build-index.v1+json"


class OciError(Exception):
    """Raised for OCI referrer problems (e.g. a divergent build-index)."""


def payload_digest(payload: bytes) -> str:
    """Return the ``sha256:...`` digest of a referrer payload."""
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class AttachResult:
    """Outcome of an attach: the pushed referrer digest, or a dedup skip."""

    referrer_digest: str | None
    deduplicated: bool


class Registry(Protocol):
    """The minimal registry surface the orchestration needs."""

    def list_referrer_payloads(self, image_ref: str, artifact_type: str) -> list[bytes]:
        """Return the payload bytes of every referrer of ``artifact_type``."""
        ...

    def push_referrer(self, image_ref: str, payload: bytes, artifact_type: str) -> str:
        """Attach ``payload`` as a referrer and return the referrer manifest digest."""
        ...


def attach_build_index(
    registry: Registry,
    image_ref: str,
    payload: bytes,
    artifact_type: str = BUILD_INDEX_ARTIFACT_TYPE,
) -> AttachResult:
    """Attach a build-index payload to ``image_ref`` as an OCI referrer.

    - **Dedup:** if a referrer with the identical payload digest is already
      attached, nothing is pushed (``deduplicated=True``).
    - **Conflict:** if a referrer of the same artifact type is attached with a
      *different* payload, raise :class:`OciError` rather than overwrite.
    """
    existing = registry.list_referrer_payloads(image_ref, artifact_type)
    target = payload_digest(payload)
    if any(payload_digest(p) != target for p in existing):
        raise OciError(
            f"a divergent {artifact_type} referrer is already attached to {image_ref}; "
            "refusing to overwrite"
        )
    if any(payload_digest(p) == target for p in existing):
        return AttachResult(referrer_digest=None, deduplicated=True)
    digest = registry.push_referrer(image_ref, payload, artifact_type)
    return AttachResult(referrer_digest=digest, deduplicated=False)


def fetch_build_index(
    registry: Registry,
    image_ref: str,
    artifact_type: str = BUILD_INDEX_ARTIFACT_TYPE,
) -> dict[str, Any] | None:
    """Fetch and parse the build-index referrer attached to ``image_ref``.

    Returns ``None`` when no referrer of ``artifact_type`` is attached. Raises
    :class:`OciError` if multiple divergent build-index referrers are present.
    """
    payloads = registry.list_referrer_payloads(image_ref, artifact_type)
    if not payloads:
        return None
    if len({payload_digest(p) for p in payloads}) > 1:
        raise OciError(f"multiple divergent {artifact_type} referrers are attached to {image_ref}")
    parsed: dict[str, Any] = json.loads(payloads[0])
    return parsed
