"""CLI entry point for fath-cuan."""

import click


@click.command()
def main() -> None:
    """Convert JSON into OSV and VEX files."""
    click.echo("fath-cuan: placeholder CLI")


if __name__ == "__main__":
    main()
