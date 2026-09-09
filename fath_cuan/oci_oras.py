"""Concrete :class:`fath_cuan.oci.Registry` backed by the ``oras`` Python SDK.

Kept separate from :mod:`fath_cuan.oci` (the tested policy layer) so ``oras`` is
an optional dependency — install with ``pip install 'fath-cuan[oci]'``. The
import is lazy, so nothing here is loaded unless an OCI operation is requested.

The registry-protocol network paths (Referrers API discovery, referrer push
with a digest-qualified subject) implement the standard OCI referrers flow but
have not been validated against a live registry — treat them as the integration
surface to exercise once a target registry/credentials are wired up. All policy
(dedup, conflict handling) lives in :mod:`fath_cuan.oci` and is fully tested.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from fath_cuan.oci import OciError

logger = logging.getLogger(__name__)

# Accept both OCI and Docker manifest/index media types when resolving a subject.
_MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)
_REFERRERS_ACCEPT = "application/vnd.oci.image.index.v1+json"


def _tag_safe(digest: str) -> str:
    """Turn a ``sha256:...`` digest into a tag-safe string (``sha256-...``)."""
    return digest.replace(":", "-")


class OrasRegistry:
    """OCI referrer client for the build-index, backed by ``oras``."""

    def __init__(self, client: object | None = None) -> None:
        self._client = client

    def _c(self) -> Any:
        if self._client is None:
            try:
                from oras.client import OrasClient
            except ImportError as e:  # pragma: no cover - exercised via extras
                raise OciError(
                    "OCI support requires the 'oras' package; install with "
                    "\"pip install 'fath-cuan[oci]'\""
                ) from e
            self._client = OrasClient()
        return self._client

    def _manifest_base(self, image_ref: str) -> str:
        client = self._c()
        container = client.get_container(image_ref)
        return f"{client.prefix}://{container.manifest_url()}"

    @staticmethod
    def _root(manifest_base: str) -> str:
        # Strip the trailing "/manifests/<ref>" to get the repo API root.
        return manifest_base.rsplit("/manifests/", 1)[0]

    def _subject_digest(self, manifest_base: str) -> str:
        client = self._c()
        resp = client.do_request(manifest_base, "HEAD", headers={"Accept": _MANIFEST_ACCEPT})
        digest = resp.headers.get("Docker-Content-Digest")
        if not digest:
            raise OciError(f"could not resolve subject digest for {manifest_base}")
        return str(digest)

    def list_referrer_payloads(self, image_ref: str, artifact_type: str) -> list[bytes]:
        client = self._c()
        base = self._manifest_base(image_ref)
        root = self._root(base)
        subject_digest = self._subject_digest(base)

        resp = client.do_request(
            f"{root}/referrers/{subject_digest}",
            "GET",
            headers={"Accept": _REFERRERS_ACCEPT},
        )
        if resp.status_code == 404:
            logger.debug("No referrers API result for %s", subject_digest)
            return []
        if resp.status_code >= 400:
            raise OciError(f"referrers query failed ({resp.status_code}) for {image_ref}")

        manifests = resp.json().get("manifests", [])
        payloads: list[bytes] = []
        for desc in manifests:
            if desc.get("artifactType") != artifact_type:
                continue
            payloads.append(self._fetch_payload(root, desc["digest"], artifact_type))
        return payloads

    def _fetch_payload(self, root: str, referrer_digest: str, artifact_type: str) -> bytes:
        client = self._c()
        resp = client.do_request(
            f"{root}/manifests/{referrer_digest}",
            "GET",
            headers={"Accept": _MANIFEST_ACCEPT},
        )
        layers = resp.json().get("layers", [])
        blob_digest = None
        for layer in layers:
            if layer.get("mediaType") == artifact_type:
                blob_digest = layer["digest"]
                break
        if blob_digest is None and layers:
            blob_digest = layers[0]["digest"]
        if blob_digest is None:
            raise OciError(f"referrer {referrer_digest} has no build-index layer")
        blob = client.do_request(f"{root}/blobs/{blob_digest}", "GET")
        return bytes(blob.content)

    def push_referrer(self, image_ref: str, payload: bytes, artifact_type: str) -> str:
        client = self._c()
        container = client.get_container(image_ref)
        base = self._manifest_base(image_ref)
        # Digest-qualified subject: pin the referrer to the image by digest.
        subject_digest = self._subject_digest(base)
        subject_ref = (
            f"{container.registry}/{container.namespace}/{container.repository}@{subject_digest}"
        )
        target = (
            f"{container.registry}/{container.namespace}/{container.repository}"
            f":{_tag_safe(subject_digest)}.build-index"
        )

        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "build-index.json"
            index_path.write_bytes(payload)
            resp = client.push(
                target=target,
                files=[f"{index_path}:{artifact_type}"],
                subject=subject_ref,
                manifest_annotations={"org.opencontainers.image.created": ""},
                disable_path_validation=True,
                quiet=True,
            )
        digest = resp.headers.get("Docker-Content-Digest", "")
        return str(digest)
