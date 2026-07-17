from __future__ import annotations

from pathlib import Path

import click

import fath_cuan
from fath_cuan.io.reader import read_input
from fath_cuan.io.writer import write_to_file, write_to_stdout
from fath_cuan.workflow import process_all, process_osv, process_vex


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

    if output_format == "all":
        results = process_all(raw)
    elif output_format == "osv":
        results = {"osv": process_osv(raw)}
    elif output_format == "vex":
        results = {"vex": process_vex(raw)}
    else:
        raise ValueError(f"Invalid output format: {output_format}")

    if use_stdout:
        if len(results) == 1:
            write_to_stdout(next(iter(results.values())))
        else:
            write_to_stdout(results)
    else:
        for _fmt, data in results.items():
            name = data.get("id", _fmt)
            path = write_to_file(data, output_dir, f"{name}.json")
            click.echo(f"Wrote {path}")
