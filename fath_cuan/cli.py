from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import click

import fath_cuan
from fath_cuan.index_builder import build_index_document, migrate_document
from fath_cuan.io.reader import read_input
from fath_cuan.io.writer import write_to_file, write_to_stdout
from fath_cuan.jira.client import JiraClient
from fath_cuan.oci import OciError, Registry, attach_build_index, fetch_build_index
from fath_cuan.workflow import process_osv, process_vex


def _build_registry() -> Registry:
    """Construct the OCI registry client (patch point for tests)."""
    from fath_cuan.oci_oras import OrasRegistry

    return OrasRegistry()


def _canonical_index_bytes(data: dict[str, Any]) -> bytes:
    """Deterministic build-index serialization for a stable referrer digest."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _emit_index(data: dict[str, Any], output: str, attach_to: str | None) -> None:
    """Write/echo a build-index and, if requested, attach it as an OCI referrer.

    The document is always emitted (stdout or file) even when ``--attach-to`` is
    given — attaching is additive, not a replacement for producing the file.
    """
    payload = json.dumps(data, indent=2)
    if output == "-":
        click.echo(payload)
    else:
        Path(output).write_text(payload + "\n")
        click.echo(f"Wrote {output}", err=True)

    if attach_to:
        try:
            result = attach_build_index(_build_registry(), attach_to, _canonical_index_bytes(data))
        except OciError as e:
            raise click.ClickException(str(e)) from e
        if result.deduplicated:
            click.echo(f"Build-index already attached to {attach_to} (deduplicated)", err=True)
        else:
            click.echo(f"Attached build-index to {attach_to} ({result.referrer_digest})", err=True)


def _build_jira_client() -> JiraClient | None:
    """Create a JiraClient from environment variables, if configured."""
    token = os.environ.get("JIRA_TOKEN")
    if not token:
        return None
    email = os.environ.get("JIRA_EMAIL", "")
    server = os.environ.get("JIRA_SERVER", "")
    kwargs: dict[str, str] = {"token": token}
    if email:
        kwargs["email"] = email
    if server:
        kwargs["server"] = server
    return JiraClient(**kwargs)


_LOG_LEVELS = [logging.WARNING, logging.INFO, logging.DEBUG]


@click.group()
@click.version_option(version=fath_cuan.__version__)
@click.option("-v", "--verbose", count=True, help="Increase verbosity (repeat for more: -vvv).")
def main(verbose: int) -> None:
    """fath-cuan: Convert JSON into OSV and VEX files."""
    level = _LOG_LEVELS[min(verbose, len(_LOG_LEVELS) - 1)]
    logging.basicConfig(format="%(levelname)s: %(name)s: %(message)s")
    logging.root.setLevel(level)


@main.command()
@click.argument("input", default="-")
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("."),
    help="Directory for output files.",
)
@click.option("--stdout", "use_stdout", is_flag=True, help="Print output to stdout.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["osv", "vex", "all"]),
    default="all",
    help="Which output format to generate.",
)
@click.option("--embargo", is_flag=True, help="Generate pre-disclosure embargo stubs.")
@click.option("--jira", is_flag=True, help="Enrich from JIRA (requires JIRA_TOKEN).")
@click.option("--osidb", is_flag=True, help="Enrich from OSIDB (requires Kerberos or OSIDB_TOKEN).")
@click.option(
    "--osidb-url",
    default=None,
    help="OSIDB base URL (default: env OSIDB_URL or production).",
)
@click.option(
    "--redact-embargoed",
    is_flag=True,
    help="Redact embargoed OSIDB flaws to stubs (for public feeds).",
)
def process(
    input: str,
    output_dir: Path,
    use_stdout: bool,
    output_format: str,
    embargo: bool,
    jira: bool,
    osidb: bool,
    osidb_url: str | None,
    redact_embargoed: bool,
) -> None:
    """Process INPUT JSON into OSV and/or VEX files."""
    source = None if input == "-" else input
    raw = read_input(source)

    osidb_client = None
    if osidb:
        from fath_cuan.osidb import OsidbClient

        osidb_client = OsidbClient(base_url=osidb_url)
        if osidb_client.available:
            click.echo("OSIDB enrichment enabled")
        else:
            click.echo(
                "WARNING: OSIDB unavailable — falling back to OSV/NVD",
                err=True,
            )

    jira_client = None
    if jira:
        jira_client = _build_jira_client()
        if jira_client is not None:
            click.echo("JIRA enrichment enabled")
        else:
            click.echo(
                "WARNING: JIRA unavailable — set JIRA_TOKEN to enable",
                err=True,
            )

    if output_format in ("osv", "all"):
        osv_records = process_osv(
            raw,
            embargo=embargo,
            osidb_client=osidb_client,
            jira_client=jira_client,
            redact_embargoed=redact_embargoed,
        )
        for record in osv_records:
            if use_stdout:
                write_to_stdout(record)
            else:
                filename = f"{record['id']}.json"
                path = write_to_file(record, output_dir, filename)
                click.echo(f"Wrote {path}")

    if output_format in ("vex", "all"):
        try:
            vex_data = process_vex(raw)
        except NotImplementedError as e:
            if output_format == "all":
                click.echo(f"WARNING: skipping VEX — {e}", err=True)
            else:
                raise click.ClickException(str(e)) from e
        else:
            if use_stdout:
                write_to_stdout(vex_data)
            else:
                path = write_to_file(vex_data, output_dir, "vex.json")
                click.echo(f"Wrote {path}")


@main.command()
@click.argument("image_ref")
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("."),
    help="Directory for output files.",
)
@click.option("--stdout", "use_stdout", is_flag=True, help="Print output to stdout.")
@click.option("--jira", is_flag=True, help="Enrich from JIRA (requires JIRA_TOKEN).")
@click.option("--osidb", is_flag=True, help="Enrich from OSIDB (requires Kerberos or OSIDB_TOKEN).")
@click.option("--osidb-url", default=None, help="OSIDB base URL (default: env or production).")
@click.option(
    "--redact-embargoed",
    is_flag=True,
    help="Redact embargoed OSIDB flaws to stubs (for public feeds).",
)
def refresh(
    image_ref: str,
    output_dir: Path,
    use_stdout: bool,
    jira: bool,
    osidb: bool,
    osidb_url: str | None,
    redact_embargoed: bool,
) -> None:
    """Generate OSV records from the build-index attached to IMAGE_REF."""
    try:
        raw = fetch_build_index(_build_registry(), image_ref)
    except OciError as e:
        raise click.ClickException(str(e)) from e
    if raw is None:
        raise click.ClickException(f"no build-index referrer attached to {image_ref}")

    osidb_client = None
    if osidb:
        from fath_cuan.osidb import OsidbClient

        osidb_client = OsidbClient(base_url=osidb_url)
        if not osidb_client.available:
            click.echo("WARNING: OSIDB unavailable — falling back to OSV/NVD", err=True)

    jira_client = None
    if jira:
        jira_client = _build_jira_client()
        if jira_client is None:
            click.echo("WARNING: JIRA unavailable — set JIRA_TOKEN to enable", err=True)

    osv_records = process_osv(
        raw,
        osidb_client=osidb_client,
        jira_client=jira_client,
        redact_embargoed=redact_embargoed,
    )
    for record in osv_records:
        if use_stdout:
            write_to_stdout(record)
        else:
            path = write_to_file(record, output_dir, f"{record['id']}.json")
            click.echo(f"Wrote {path}")


@main.group()
def index() -> None:
    """Create and manage build-index metadata."""


@index.command("create")
@click.option(
    "--ecosystem",
    type=click.Choice(["pypi", "maven"]),
    default=None,
    help="Package ecosystem (inferred from --purl/--gav if omitted).",
)
@click.option("--purl", default=None, help="Package URL (mutually exclusive with --gav).")
@click.option("--gav", default=None, help="Maven GAV (mutually exclusive with --purl).")
@click.option("--version-upstream", default=None, help="Upstream base version (derived if unset).")
@click.option(
    "--version-local",
    required=True,
    help="Full remediated version — Maven e.g. '1.0.0.rhlw-00001', PyPI e.g. '1.0.0+rhlw.1'.",
)
@click.option("--b", "b_count", type=int, default=0, help="Backport count.")
@click.option("--n", "n_count", type=int, default=0, help="Novel count.")
@click.option("--vuln", "vulns", multiple=True, help="Vulnerability ID (repeatable).")
@click.option(
    "--git-dir",
    type=click.Path(),
    default=None,
    help="Repo to inspect for vuln IDs when none are passed explicitly.",
)
@click.option("--build-id", default="", help="Build identifier to record in the index.")
@click.option(
    "--require-vuln",
    is_flag=True,
    help="Fail if no vuln IDs resolve (remediation build); default allows a clean build.",
)
@click.option(
    "--attach-to",
    default=None,
    help="Image reference to attach the build-index to as an OCI referrer.",
)
@click.option("--output", default="-", help="Output path, or '-' for stdout.")
def index_create(
    ecosystem: str | None,
    purl: str | None,
    gav: str | None,
    version_upstream: str | None,
    version_local: str,
    b_count: int,
    n_count: int,
    vulns: tuple[str, ...],
    git_dir: str | None,
    build_id: str,
    require_vuln: bool,
    attach_to: str | None,
    output: str,
) -> None:
    """Create a build-index.json for a remediated build."""
    try:
        data = build_index_document(
            version_local=version_local,
            ecosystem=ecosystem,
            purl=purl,
            gav=gav,
            version_upstream=version_upstream,
            b=b_count,
            n=n_count,
            vulns=list(vulns),
            git_dir=git_dir,
            build_id=build_id,
            require_vuln=require_vuln,
        )
    except ValueError as e:
        raise click.UsageError(str(e)) from e

    _emit_index(data, output, attach_to)


@index.command("migrate")
@click.option(
    "--source-legacy-index",
    required=True,
    help="Legacy PNC gav-index.json path, or '-' for stdin.",
)
@click.option(
    "--attach-to",
    default=None,
    help="Image reference to attach the migrated build-index to as an OCI referrer.",
)
@click.option("--output", default="-", help="Output path, or '-' for stdout.")
def index_migrate(source_legacy_index: str, attach_to: str | None, output: str) -> None:
    """Convert a legacy PNC gav-index into a unified build-index.json."""
    raw = read_input(None if source_legacy_index == "-" else source_legacy_index)
    if not isinstance(raw, dict) or "primaryGav" not in raw:
        # Cheap pre-check: migrate is the command most likely pointed at the
        # wrong file (e.g. an already-migrated build-index). Fail with a clear
        # line instead of a multi-line pydantic ValidationError dump.
        raise click.UsageError(
            "input is not a legacy PNC gav-index (no 'primaryGav' field); "
            "index migrate expects a gav-index.json, not a build-index"
        )
    try:
        data = migrate_document(raw)
    except ValueError as e:
        raise click.UsageError(str(e)) from e

    _emit_index(data, output, attach_to)
