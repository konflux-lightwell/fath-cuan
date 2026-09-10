"""Concrete :class:`fath_cuan.oci.Registry` backed by the ``oras`` Python SDK.

Kept separate from :mod:`fath_cuan.oci` (the tested policy layer) so ``oras`` is
an optional dependency — install with ``pip install 'fath-cuan[oci]'``. The
import is lazy, so nothing here is loaded unless an OCI operation is requested.

The registry-protocol network paths (Referrers API discovery, referrer push
with a digest-qualified subject) implement the standard OCI referrers flow.
They have not yet been exercised against a live registry — that's the remaining
integration surface — but the known correctness issues from review are handled:
the push carries a real ``oras.oci.Subject`` and sets the referrer's
``artifactType`` (via the config mediaType, per the dist-spec fallback) so the
referrers list is filterable; the read path loads registry credentials and
guards every response status. All policy (dedup, conflict handling) lives in
:mod:`fath_cuan.oci` and is fully tested.
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
_DEFAULT_SUBJECT_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"


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

    def _container(self, image_ref: str) -> Any:
        """Resolve a container and load registry credentials for do_request calls.

        ``push()`` loads ``~/.docker/config.json`` internally, but ``do_request``
        (used by the read path) does not — so without this the HEAD/GET requests
        go out anonymously and fail on private registries with 401/403.
        """
        client = self._c()
        container = client.get_container(image_ref)
        try:
            client.auth.load_configs(container)
        except Exception as e:  # pragma: no cover - best-effort, anon fallback
            logger.debug("load_configs failed (continuing anonymously): %s", e)
        return container

    def _manifest_base(self, container: Any) -> str:
        return f"{self._c().prefix}://{container.manifest_url()}"

    @staticmethod
    def _root(manifest_base: str) -> str:
        # Strip the trailing "/manifests/<ref>" to get the repo API root.
        return manifest_base.rsplit("/manifests/", 1)[0]

    @staticmethod
    def _repo_ref(root: str) -> str:
        """Derive ``registry/repo`` from the repo API root (handles no-namespace refs)."""
        # root == "{scheme}://{registry}/v2/{repo/path}"
        return root.split("://", 1)[-1].replace("/v2/", "/", 1)

    def _subject_descriptor(self, container: Any) -> dict[str, Any]:
        """HEAD the subject manifest → an OCI descriptor {mediaType, digest, size}."""
        client = self._c()
        base = self._manifest_base(container)
        resp = client.do_request(base, "HEAD", headers={"Accept": _MANIFEST_ACCEPT})
        if resp.status_code >= 400:
            raise OciError(f"could not resolve subject for {base} ({resp.status_code})")
        digest = resp.headers.get("Docker-Content-Digest")
        if not digest:
            raise OciError(f"could not resolve subject digest for {base}")
        try:
            size = int(resp.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            size = 0
        return {
            "mediaType": resp.headers.get("Content-Type") or _DEFAULT_SUBJECT_MEDIA_TYPE,
            "digest": str(digest),
            "size": size,
        }

    @staticmethod
    def _next_link(link_header: str | None, root: str) -> str | None:
        """Extract the ``rel="next"`` URL from a Referrers API ``Link`` header."""
        if not link_header:
            return None
        for part in link_header.split(","):
            seg = part.split(";")
            if len(seg) < 2:
                continue
            if 'rel="next"' in seg[1] or seg[1].strip() == "rel=next":
                url = seg[0].strip().lstrip("<").rstrip(">")
                if url.startswith("http"):
                    return url
                base = root.split("/v2/", 1)[0]  # scheme://registry
                return base + url if url.startswith("/") else f"{base}/{url}"
        return None

    def list_referrer_payloads(self, image_ref: str, artifact_type: str) -> list[bytes]:
        client = self._c()
        container = self._container(image_ref)
        root = self._root(self._manifest_base(container))
        subject_digest = self._subject_descriptor(container)["digest"]

        url: str | None = f"{root}/referrers/{subject_digest}"
        payloads: list[bytes] = []
        while url:
            resp = client.do_request(url, "GET", headers={"Accept": _REFERRERS_ACCEPT})
            if resp.status_code == 404:
                logger.debug("No referrers API result for %s", subject_digest)
                return []
            if resp.status_code >= 400:
                raise OciError(f"referrers query failed ({resp.status_code}) for {image_ref}")
            for desc in resp.json().get("manifests", []):
                if desc.get("artifactType") == artifact_type:
                    payloads.append(self._fetch_payload(root, desc["digest"], artifact_type))
            # Follow the Referrers API Link-header pagination (dist-spec).
            url = self._next_link(resp.headers.get("Link"), root)
        return payloads

    def _fetch_payload(self, root: str, referrer_digest: str, artifact_type: str) -> bytes:
        client = self._c()
        resp = client.do_request(
            f"{root}/manifests/{referrer_digest}",
            "GET",
            headers={"Accept": _MANIFEST_ACCEPT},
        )
        if resp.status_code >= 400:
            raise OciError(
                f"failed to fetch referrer manifest {referrer_digest} ({resp.status_code})"
            )
        layers = resp.json().get("layers", [])
        blob_digest = next(
            (layer["digest"] for layer in layers if layer.get("mediaType") == artifact_type),
            None,
        )
        if blob_digest is None and layers:
            blob_digest = layers[0]["digest"]
        if blob_digest is None:
            raise OciError(f"referrer {referrer_digest} has no build-index layer")
        blob = client.do_request(f"{root}/blobs/{blob_digest}", "GET")
        if blob.status_code >= 400:
            raise OciError(f"failed to fetch build-index blob {blob_digest} ({blob.status_code})")
        return bytes(blob.content)

    def push_referrer(self, image_ref: str, payload: bytes, artifact_type: str) -> str:
        try:
            from oras.oci import Subject
        except ImportError as e:  # pragma: no cover - exercised via extras
            raise OciError(
                "OCI support requires the 'oras' package; install with "
                "\"pip install 'fath-cuan[oci]'\""
            ) from e

        client = self._c()
        container = self._container(image_ref)
        root = self._root(self._manifest_base(container))
        subject_desc = self._subject_descriptor(container)  # digest-qualified subject
        subject = Subject(
            mediaType=subject_desc["mediaType"],
            digest=subject_desc["digest"],
            size=subject_desc["size"],
        )
        target = f"{self._repo_ref(root)}:{_tag_safe(subject_desc['digest'])}.build-index"

        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "build-index.json"
            index_path.write_bytes(payload)
            # Empty config whose mediaType IS the artifact type, so the registry's
            # referrers descriptor reports artifactType == artifact_type (dist-spec
            # fallback when the manifest carries no top-level artifactType).
            config_path = Path(tmp) / "config.json"
            config_path.write_text("{}")
            try:
                resp = client.push(
                    target=target,
                    files=[f"{index_path}:{artifact_type}"],
                    manifest_config=f"{config_path}:{artifact_type}",
                    subject=subject,
                    disable_path_validation=True,
                    quiet=True,
                )
            except Exception as e:  # oras raises bare builtins (ValueError, etc.)
                raise OciError(f"failed to push build-index referrer to {target}: {e}") from e
        return str(resp.headers.get("Docker-Content-Digest", ""))
