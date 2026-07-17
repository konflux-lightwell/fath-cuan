# fath-cuan

CLI tool to convert PNC build metadata (`gav-index.json`) into [OSV](https://ossf.github.io/osv-schema/) and VEX vulnerability records for the Lightwell remediated packages feed.

## Installation

```bash
pip install -e .

# With development dependencies
pip install -e ".[dev]"
```

## Quick Start

```bash
# Generate OSV files from a PNC gav-index.json
fath-cuan process gav-index.json --format osv --output-dir output/

# Generate to stdout (for piping)
fath-cuan process gav-index.json --format osv --stdout

# Read from stdin
cat gav-index.json | fath-cuan process - --format osv --stdout
```

## CLI Reference

### `fath-cuan process`

Convert a PNC `gav-index.json` into OSV and/or VEX files.

```
Usage: fath-cuan process [OPTIONS] [INPUT]

  Process INPUT JSON into OSV and/or VEX files.

Arguments:
  INPUT   Path to input JSON file, or "-" for stdin (default: -)

Options:
  --output-dir PATH           Directory for output files (default: .)
  --stdout                    Print output to stdout instead of files
  --format [osv|vex|all]      Which output format to generate (default: all)
  --help                      Show this message and exit.
```

### Output

**OSV format** (`--format osv`): Generates one JSON file per CVE listed in the input's `cves` array. Each file follows the [OSV 1.6.8 schema](https://ossf.github.io/osv-schema/) and matches the format published by balor-fianna to the Lightwell Pulp OSV repository.

Output filenames follow the pattern: `x_RHLW-{CVE_ID}-{base_version}.json`

**VEX format** (`--format vex`): Not yet implemented.

### Examples

```bash
# Generate OSV files to a directory
$ fath-cuan process gav-index.json --format osv --output-dir output/osv/
Wrote output/osv/x_RHLW-CVE-2024-25710-4.0.4.json
Wrote output/osv/x_RHLW-CVE-2024-26308-4.0.4.json

# Generate to stdout (single CVE)
$ fath-cuan process gav-index.json --format osv --stdout
{
  "schema_version": "1.6.8",
  "id": "x_RHLW-CVE-2024-25710-4.0.4",
  ...
}

# Pipe from another command
$ oras pull quay.io/light-castle/secure-pnc:idx-BQA6SUOGYCIAA -o /tmp/idx
$ fath-cuan process /tmp/idx/gav-index.json --format osv --output-dir output/
```

## Input Format

The input is a PNC build metadata file (`gav-index.json`) with this structure:

```json
{
  "buildId": "BQA6SUOGYCIAA",
  "created": "2026-07-15T14:02:27+00:00",
  "cves": ["CVE-2024-25710", "CVE-2024-26308"],
  "evidence": {
    "additionalTags": ["com.sun.xml.bind.external_relaxng-datatype_4.0.4.rhlw-dp-00002"],
    "digestRef": "quay.io/light-castle/secure-pnc@sha256:2c511d...",
    "ref": "quay.io/light-castle/secure-pnc:lw-BQA6SUOGYCIAA"
  },
  "gavCount": 17,
  "gavIndexTag": "idx-BQA6SUOGYCIAA",
  "gavs": [
    "com.sun.xml.bind.external:relaxng-datatype:4.0.4.rhlw-dp-00002",
    "org.glassfish.jaxb:jaxb-runtime:4.0.4.rhlw-dp-00002"
  ],
  "primaryGav": "com.sun.xml.bind.external:relaxng-datatype:4.0.4.rhlw-dp-00002"
}
```

| Field | Description |
|-------|-------------|
| `buildId` | PNC build identifier |
| `created` | Build timestamp (ISO 8601) |
| `cves` | List of CVE IDs remediated by this build |
| `evidence` | OCI artifact references (digest, tag) |
| `gavs` | All Maven GAV coordinates produced by the build |
| `primaryGav` | The primary Maven coordinate (used for the OSV `affected` package) |

## OSV Output Format

Each generated OSV record contains:

| Field | Source |
|-------|--------|
| `id` | `x_RHLW-{CVE_ID}-{base_version}` |
| `schema_version` | `1.6.8` |
| `modified` | From input `created` timestamp |
| `severity` | CVSS v3.1 vector from upstream osv.dev (when available) |
| `summary` | CVE description from upstream osv.dev |
| `details` | Full vulnerability details from upstream osv.dev |
| `references` | NVD link + upstream advisory/patch URLs from osv.dev |
| `aliases` | CVE ID + GHSA ID (when available from upstream) |
| `affected[].package` | Maven coordinate from `primaryGav` with PURL |
| `affected[].ranges[].events[].fixed` | Full version from GAV (e.g., `4.0.4.rhlw-dp-00002`) |
| `credits` | Red Hat Lightwell as `REMEDIATION_DEVELOPER` |
| `database_specific.lightwell` | `source: pnc-build`, `backport_base_version`, `build_id` |

The `fixed` version uses the exact version string from the PNC build GAV — Pulp is the source of truth for version naming.

## Upstream Data Enrichment

The converter fetches upstream CVE data from [osv.dev](https://osv.dev) to populate `severity`, `summary`, `details`, `references`, and `aliases`. If the upstream API is unavailable or the CVE has no OSV record, those fields are omitted or minimally populated (NVD reference link only).

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy fath_cuan/

# Run all checks via tox
tox
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
