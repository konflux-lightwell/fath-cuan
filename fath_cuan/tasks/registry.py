"""Attach build-index payloads using the ORAS CLI and repository-scoped credentials."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

MEDIA_TYPE = "application/vnd.lightwell.build-index.v1+json"


def read_json(path: Path) -> Any:
    """Read JSON, rejecting duplicate object keys instead of silently losing evidence."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Collect keys without allowing a later value to replace an earlier one."""
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def pinned_reference(reference: str) -> str:
    """Validate a qualified SHA-256 subject reference and remove a redundant tag."""
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", reference):
        raise ValueError("Image reference must be pinned to a sha256 digest")
    repository, digest = reference.split("@", 1)
    if repository.startswith("-") or "/" not in repository:
        raise ValueError("Image reference must include a registry and repository")
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    return f"{repository}@{digest}"


def scoped_auth(reference: str, config: dict[str, Any]) -> dict[str, Any]:
    """Select the most specific repository credential, retaining helper fallbacks."""
    repository = reference.split("@", 1)[0]
    candidate = repository
    auths = config.get("auths", {})
    if not isinstance(auths, dict):
        raise ValueError("Registry auths must be an object")
    while candidate:
        if candidate in auths:
            return {"auths": {repository.split("/", 1)[0]: auths[candidate]}}
        if "/" not in candidate:
            break
        candidate = candidate.rsplit("/", 1)[0]
    return {key: value for key, value in config.items() if key in {"credsStore", "credHelpers"}} | {
        "auths": {}
    }


def attach_index(
    reference: str,
    payload: Path,
    *,
    auth_file: Path | None = None,
    ca_bundle: Path | None = None,
    timeout: float = 300,
) -> None:
    """Attach exact payload bytes with ORAS, retrying nonzero exits up to three times.

    Credentials come from the explicit auth file, AUTHFILE, or Docker's default
    configuration. A private temporary config scopes them to the target repository
    and is removed on success or failure. The input credential file is unchanged.
    This publishes a final OCI referrer; trusted-artifact transport stays in Tekton.

    Args:
        reference: Qualified digest-pinned subject image reference.
        payload: Generated build-index.json file; its basename is preserved on upload.
        auth_file: Docker configuration overriding environment/default credentials.
        ca_bundle: Optional PEM trust bundle passed to ORAS through SSL_CERT_FILE.
        timeout: Maximum seconds allowed for one attachment attempt.

    Raises:
        ValueError: The reference, credentials, or ORAS operation is invalid.
        OSError: Credentials or payload cannot be read.
    """
    reference = pinned_reference(reference)
    configured = Path(os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker"))) / "config.json"
    original = auth_file or Path(os.environ.get("AUTHFILE", str(configured)))
    config = read_json(original) if original.is_file() else {}
    if auth_file is not None and not original.is_file():
        raise ValueError("Explicit registry authentication file is missing")
    if not isinstance(config, dict):
        raise ValueError("Registry authentication configuration must be an object")
    environment = dict(os.environ)
    if ca_bundle is not None and ca_bundle.is_file():
        environment["SSL_CERT_FILE"] = str(ca_bundle.resolve())

    with tempfile.TemporaryDirectory(prefix="fath-cuan-auth-") as directory:
        credentials = Path(directory) / "config.json"
        credentials.touch(mode=0o600)
        credentials.write_text(json.dumps(scoped_auth(reference, config)), encoding="utf-8")
        command = [
            "oras",
            "attach",
            reference,
            "--registry-config",
            str(credentials),
            "--artifact-type",
            MEDIA_TYPE,
            f"{payload.name}:{MEDIA_TYPE}",
        ]
        for attempt in range(3):
            try:
                result = subprocess.run(
                    command,
                    cwd=payload.parent,
                    env=environment,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ValueError(f"Unable to execute ORAS: {type(exc).__name__}") from exc
            if result.returncode == 0:
                return
            if attempt < 2:
                time.sleep(2**attempt)
        raise ValueError(f"ORAS attachment failed with status {result.returncode}")
