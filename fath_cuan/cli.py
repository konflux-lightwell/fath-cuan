from __future__ import annotations

from pathlib import Path
from typing import Any

import click

import fath_cuan
from fath_cuan.converters import osv as osv_converter
from fath_cuan.converters import vex as vex_converter
from fath_cuan.io.reader import read_input
from fath_cuan.io.writer import write_to_file, write_to_stdout
from fath_cuan.models.input import InputDocument


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
    doc = InputDocument.from_dict(raw)

    results: dict[str, Any] = {}

    if output_format in ("osv", "all"):
        osv_doc = osv_converter.convert(doc)
        results["osv"] = (osv_doc.id, osv_doc.model_dump(exclude_none=True))

    if output_format in ("vex", "all"):
        vex_doc = vex_converter.convert(doc)
        results["vex"] = ("vex", vex_doc.model_dump())

    if use_stdout:
        payloads = {k: v[1] for k, v in results.items()}
        if len(payloads) == 1:
            write_to_stdout(next(iter(payloads.values())))
        else:
            write_to_stdout(payloads)
    else:
        for _fmt, (name, data) in results.items():
            path = write_to_file(data, output_dir, f"{name}.json")
            click.echo(f"Wrote {path}")
