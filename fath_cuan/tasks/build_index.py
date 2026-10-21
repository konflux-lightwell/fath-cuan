"""Generate and publish a Python build index from locally restored task inputs."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from functools import partial
from pathlib import Path
from urllib.parse import quote

import click
from packaging.utils import canonicalize_name
from packaging.version import Version

from fath_cuan.gittrailers import resolve_vulns
from fath_cuan.index_builder import build_index_document
from fath_cuan.tasks.registry import attach_index, pinned_reference, read_json


def version_counts(upstream: str, computed: str, build_type: str) -> tuple[int, int]:
    """Validate the pipeline's version policy and extract backport and novel counts.

    Args:
        upstream: Original PEP 440 package version.
        computed: Full wheel version, including any Lightwell remediation suffix.
        build_type: Backport, Novel, or Validated provenance policy.

    Returns:
        Backport and novel counts, both zero for Validated builds.
    """
    Version(upstream)
    Version(computed)
    if build_type == "Validated":
        if computed != upstream:
            raise ValueError("Validated builds must use the upstream version")
        return 0, 0
    if build_type not in {"Backport", "Novel"}:
        raise ValueError("Build type must be Backport, Novel, or Validated")
    match = re.fullmatch(re.escape(upstream) + r"\+rhlw\.(\d+)(?:\.n\.?(\d+))?", computed)
    if not match:
        raise ValueError("Computed version does not match the upstream remediation version scheme")
    backports, novel = int(match[1]), int(match[2] or 0)
    if build_type == "Backport" and novel:
        raise ValueError("Backport builds cannot have a novel component")
    return backports, novel


def manifest_purls(path: Path | None, primary: str) -> tuple[list[str], list[str]]:
    """Read disjoint produced/cached PURLs, excluding the primary distribution.

    A missing optional path means no companion manifest was supplied. An explicitly
    supplied path must exist and contain valid JSON. Produced entries take precedence
    over identical cached entries; names and PURL escaping match wheel publication.

    Args:
        path: Restored build-manifest.json file, or None for primary-only builds.
        primary: Distribution already represented by the primary PURL.

    Returns:
        Sorted produced and cached PURL lists with no shared entries.
    """
    if path is None:
        return [], []
    manifest = read_json(path)
    if not isinstance(manifest, dict):
        raise ValueError("Build manifest must be an object")
    primary = canonicalize_name(primary)
    categories: list[set[str]] = []
    for category in ("produced", "cached"):
        entries = manifest.get(category, [])
        if not isinstance(entries, list):
            raise ValueError(f"Manifest {category} must be a list")
        purls: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise ValueError("Manifest entry is missing a distribution name")
            if not isinstance(entry.get("version"), str) or not entry["version"]:
                raise ValueError("Manifest entry is missing a version string")
            name = canonicalize_name(entry["name"], validate=True)
            version = entry["version"]
            Version(version)
            if name != primary:
                purls.add(f"pkg:pypi/{name}@{quote(version, safe='')}")
        categories.append(purls)
    produced, cached = categories
    return sorted(produced), sorted(cached - produced)


def _git(source: str, *arguments: str) -> str:
    """Read restored Git history with repository-scoped trust and bounded execution."""
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={source}", "-C", source, *arguments],
            text=True,
            capture_output=True,
            timeout=15,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Unable to read restored source Git history") from exc
    return result.stdout


def _commit_message(source: str) -> str:
    """Return the tagged source commit's message for trailer interpretation."""
    return _git(source, "log", "-1", "--format=%B")


def _recent_history(source: str) -> str:
    """Return fallback history; remediation policy rejects regex-only evidence."""
    return _git(source, "log", "-n50", "--format=%B") + _git(
        source, "rev-parse", "--abbrev-ref", "HEAD"
    )


def run(
    *,
    package: str,
    version: str,
    computed_version: str,
    build_type: str,
    source_dir: Path,
    image_ref: str,
    workdir: Path,
    results_dir: Path,
    manifest_path: Path | None = None,
    auth_file: Path | None = None,
    ca_bundle: Path | None = None,
    command_timeout: float = 300,
) -> Path:
    """Create an index, attach its exact bytes, then emit successful Tekton results.

    Inputs are filesystem paths already restored by build-trusted-artifacts. Each
    invocation retains an isolated scratch directory for diagnosis. Vulnerability
    resolution and index schema validation reuse fath-cuan's existing policy.

    Args:
        package: Primary Python distribution name, canonicalized before use.
        version: Original upstream version.
        computed_version: Full version emitted by the source preparation task.
        build_type: Backport, Novel, or Validated provenance policy.
        source_dir: Restored source tree containing its .git history.
        image_ref: Digest-pinned wheels image receiving the index referrer.
        workdir: Writable directory containing retained per-invocation scratch trees.
        results_dir: Tekton result mount receiving attachment reference and digest.
        manifest_path: Optional restored manifest describing companion distributions.
        auth_file: Explicit Docker authentication configuration for publication.
        ca_bundle: Optional PEM trust bundle for the registry connection.
        command_timeout: Positive timeout in seconds for each ORAS attempt.

    Returns:
        The generated build-index.json path after successful publication.

    Raises:
        ValueError: Inputs violate the task contract or Git/ORAS execution fails.
        OSError: Required inputs or result files cannot be read or written.
    """
    if command_timeout <= 0:
        raise ValueError("Command timeout must be positive")
    package = canonicalize_name(package, validate=True)
    image_ref = pinned_reference(image_ref)
    backports, novel = version_counts(version, computed_version, build_type)
    source = source_dir.resolve()
    if not (source / ".git").is_dir():
        raise ValueError("Source artifact has no .git directory for Lightwell-Fix trailers")
    produced, cached = manifest_purls(manifest_path, package)

    document = build_index_document(
        ecosystem="pypi",
        purl=f"pkg:pypi/{package}@{quote(computed_version, safe='')}",
        version_upstream=version,
        version_local=computed_version,
        b=backports,
        n=novel,
        git_dir=str(source),
        require_vuln=build_type != "Validated",
        produced_purls=produced,
        extra_purls=cached,
        vuln_resolver=partial(
            resolve_vulns,
            commit_message_reader=_commit_message,
            recent_log_reader=_recent_history,
        ),
    )

    workdir.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="attach-build-index-", dir=workdir)).resolve()
    payload = scratch / "build-index.json"
    payload.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    digest = "sha256:" + hashlib.sha256(payload.read_bytes()).hexdigest()

    attach_index(
        image_ref,
        payload,
        auth_file=auth_file,
        ca_bundle=ca_bundle,
        timeout=command_timeout,
    )

    results_dir.mkdir(parents=True, exist_ok=True)
    for name, value in {
        "BUILD_INDEX_ATTACHED_REF": image_ref,
        "BUILD_INDEX_DIGEST": digest,
    }.items():
        (results_dir / name).write_text(value, encoding="utf-8")
    return payload


@click.command(context_settings={"auto_envvar_prefix": "FATH_CUAN_INDEX"})
@click.option("--package", required=True, help="Primary Python distribution name.")
@click.option("--version", required=True, help="Upstream package version.")
@click.option("--computed-version", required=True, help="Full version emitted by source-to-sdist.")
@click.option("--build-type", type=click.Choice(["Backport", "Novel", "Validated"]), required=True)
@click.option("--source-dir", type=click.Path(path_type=Path), required=True)
@click.option("--image-ref", required=True, help="Digest-pinned wheels image receiving the index.")
@click.option(
    "--workdir", type=click.Path(path_type=Path), default="/var/workdir", show_default=True
)
@click.option("--results-dir", type=click.Path(path_type=Path), default="/tekton/results")
@click.option("--manifest-path", type=click.Path(path_type=Path), default=None)
@click.option(
    "--manifest-artifact",
    default=None,
    help=(
        "Tekton manifest input, used only to select whether to read the restored file. "
        "An empty value skips the manifest; a nonempty value requires it. "
        "Artifact restoration is handled separately by Tekton."
    ),
)
@click.option("--auth-file", type=click.Path(path_type=Path), default=None)
@click.option(
    "--ca-bundle", type=click.Path(path_type=Path), default="/mnt/trusted-ca/ca-bundle.crt"
)
@click.option("--command-timeout", type=click.FloatRange(min=0, min_open=True), default=300)
def main(
    package: str,
    version: str,
    computed_version: str,
    build_type: str,
    source_dir: Path,
    image_ref: str,
    workdir: Path,
    results_dir: Path,
    manifest_path: Path | None,
    manifest_artifact: str | None,
    auth_file: Path | None,
    ca_bundle: Path | None,
    command_timeout: float,
) -> None:
    """Generate and attach an index from inputs restored by Tekton.

    Tekton passes its manifest parameter even when empty, matching the original
    task's conditional. Only its presence is inspected; Python never retrieves
    the artifact. Local callers can supply --manifest-path on its own.
    """
    if manifest_artifact is not None:
        if manifest_artifact:
            manifest_path = manifest_path or workdir / "manifest" / "build-manifest.json"
        else:
            manifest_path = None

    try:
        payload = run(
            package=package,
            version=version,
            computed_version=computed_version,
            build_type=build_type,
            source_dir=source_dir,
            image_ref=image_ref,
            workdir=workdir,
            results_dir=results_dir,
            manifest_path=manifest_path,
            auth_file=auth_file,
            ca_bundle=ca_bundle,
            command_timeout=command_timeout,
        )
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Attached build index: {payload}")
