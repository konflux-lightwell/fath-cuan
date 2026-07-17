from __future__ import annotations

from pathlib import Path

import click

import fath_cuan
from fath_cuan.io.reader import read_input
from fath_cuan.io.writer import write_to_file, write_to_stdout
from fath_cuan.workflow import process_osv, process_vex


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
def process(
    input: str,
    output_dir: Path,
    use_stdout: bool,
    output_format: str,
) -> None:
    """Process INPUT JSON into OSV and/or VEX files."""
    source = None if input == "-" else input
    raw = read_input(source)

    if output_format in ("osv", "all"):
        osv_records = process_osv(raw)
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
