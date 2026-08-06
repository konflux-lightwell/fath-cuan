from __future__ import annotations

import os
from pathlib import Path

import click

import fath_cuan
from fath_cuan.io.reader import read_input
from fath_cuan.io.writer import write_to_file, write_to_stdout
from fath_cuan.jira.client import JiraClient
from fath_cuan.workflow import process_osv, process_vex


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


@click.group()
@click.version_option(version=fath_cuan.__version__)
def main() -> None:
    """fath-cuan: Convert JSON into OSV and VEX files."""


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

    jira_client = _build_jira_client()

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
        vex_data = process_vex(raw)
        if use_stdout:
            write_to_stdout(vex_data)
        else:
            path = write_to_file(vex_data, output_dir, "vex.json")
            click.echo(f"Wrote {path}")
