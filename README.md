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

# Enrich vulnerability metadata from OSIDB (requires a Kerberos ticket or OSIDB_TOKEN)
fath-cuan process gav-index.json --format osv --osidb --output-dir output/

# Enrich Lightwell (LW-) novels from JIRA as well (requires JIRA_TOKEN)
fath-cuan process gav-index.json --format osv --osidb --jira --output-dir output/

# Generate to stdout (for piping)
fath-cuan process gav-index.json --format osv --stdout

# Read from stdin
cat gav-index.json | fath-cuan process - --format osv --stdout
```

## CLI Reference

### Global options

```
Usage: fath-cuan [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbose   Increase verbosity (repeat for more: -vvv → WARNING/INFO/DEBUG).
  --version       Show the version and exit.
  --help          Show this message and exit.
```

### `fath-cuan process`

Convert a PNC `gav-index.json` into OSV and/or VEX files.

```
Usage: fath-cuan process [OPTIONS] [INPUT]

  Process INPUT JSON into OSV and/or VEX files.

Arguments:
  INPUT   Path to input JSON file, or "-" for stdin (default: -)

Options:
  --output-dir PATH           Directory for output files (default: .)
  --stdout                    Print output to stdout instead of writing files
  --format [osv|vex|all]      Which output format to generate (default: all)
  --embargo                   Generate pre-disclosure embargo stubs (empty affected)
  --jira                      Enrich LW- novels from JIRA (requires JIRA_TOKEN)
  --osidb                     Enrich from OSIDB (requires Kerberos ticket or OSIDB_TOKEN)
  --osidb-url TEXT            OSIDB base URL (default: $OSIDB_URL or production)
  --redact-embargoed          Redact embargoed OSIDB flaws to stubs (for public feeds)
  --help                      Show this message and exit.
```

#### Flags in detail

| Flag | Effect |
|------|--------|
| `--output-dir PATH` | Directory to write output files (default: current dir). One file per record: `x_RHLW-{VULN_ID}-{base_version}.json`. |
| `--stdout` | Print records to stdout instead of files (useful for piping/inspection). |
| `--format [osv\|vex\|all]` | Which format(s) to emit. `vex` is not yet implemented. Default `all`. |
| `--embargo` | Emit **pre-disclosure embargo stubs** for *every* vuln — a valid OSV skeleton with empty `affected` and `database_specific.lightwell.embargo_status: pre-disclosure`. Use when metadata must not be revealed yet. Does not contact OSIDB/osv.dev/JIRA. |
| `--jira` | Enable JIRA enrichment for Lightwell `LW-` novel IDs (pulls summary/details/severity from the ticket). Requires `JIRA_TOKEN` (see Environment Variables). Only consulted for `LW-` IDs and only when OSIDB did not already supply the data. |
| `--osidb` | Enable OSIDB enrichment (the primary source). Authenticates via Kerberos negotiate to obtain a JWT, or uses `OSIDB_TOKEN` if set. If OSIDB is unreachable, it logs a warning and falls back to the next source. |
| `--osidb-url TEXT` | Override the OSIDB base URL. Defaults to `$OSIDB_URL`, or the production instance if unset. Point at the stage instance for testing. |
| `--redact-embargoed` | When an OSIDB flaw is marked `embargoed`, emit a redacted stub instead of full content. Use when generating for a public or less-trusted distribution; the default (protected, content-guarded Pulp feed) keeps full records. |

### Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `OSIDB_URL` | `--osidb` | OSIDB base URL. Default: `https://osidb.lightwell.redhat.com` (production). Stage: `https://osidb.stage.lightwell.redhat.com`. |
| `OSIDB_TOKEN` | `--osidb` | Pre-obtained JWT access token — skips Kerberos. If unset, a token is fetched via `curl --negotiate` using your current Kerberos ticket (`kinit`). |
| `JIRA_TOKEN` | `--jira` | JIRA API token. Required for JIRA enrichment. |
| `JIRA_EMAIL` | `--jira` | JIRA account email (optional). |
| `JIRA_SERVER` | `--jira` | JIRA base URL (optional). |

### Output

**OSV format** (`--format osv`): Generates one JSON file per vulnerability ID listed in the input's `vulns` array — both CVEs (`CVE-…`) and Lightwell novel IDs (`LW-…`). Each file follows the [OSV 1.6.8 schema](https://ossf.github.io/osv-schema/) and matches the format published by balor-fianna to the Lightwell Pulp OSV repository.

Output filenames follow the pattern: `x_RHLW-{VULN_ID}-{base_version}.json`

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
  "vulns": ["CVE-2024-25710", "CVE-2024-26308", "LW-2026-0468"],
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
| `vulns` | List of vulnerability IDs remediated by this build — CVEs (`CVE-…`) and/or Lightwell novel IDs (`LW-…`). One OSV record is produced per ID. |
| `evidence` | OCI artifact references (digest, tag) |
| `gavCount` | Number of GAVs produced by the build |
| `gavIndexTag` | The `idx-<buildId>` OCI tag holding this gav-index |
| `gavs` | All Maven GAV coordinates produced by the build |
| `primaryGav` | The primary Maven coordinate (used for the OSV `affected` package) |
| `upstreamVersion` | *(optional)* Explicit upstream base version; otherwise derived by stripping the `.rhlw-…` qualifier |

## OSV Output Format

Each generated OSV record contains:

| Field | Source |
|-------|--------|
| `id` | `x_RHLW-{VULN_ID}-{base_version}` (VULN_ID = CVE or `LW-…`) |
| `schema_version` | `1.6.8` |
| `modified` / `published` | From input `created` timestamp |
| `severity` | CVSS vector — from OSIDB, else osv.dev/NVD (CVEs), else JIRA (novels). May be empty when no CVSS exists (e.g., novels with a qualitative `impact` only). |
| `summary` | OSIDB flaw title → osv.dev/NVD → JIRA ticket title |
| `details` | OSIDB description → osv.dev/NVD → JIRA ticket description |
| `references` | OSIDB references → osv.dev advisory/patch URLs; NVD link added for CVEs |
| `aliases` | The vuln ID + CVE/GHSA aliases (when available) |
| `affected[].package` | Maven coordinate from `primaryGav` with PURL |
| `affected[].ranges[].events[].fixed` | Full version from GAV (e.g., `4.0.4.rhlw-00001`) |
| `credits` | Red Hat Lightwell as `REMEDIATION_DEVELOPER` |
| `database_specific.lightwell` | `source` (`pnc-build` for CVEs, `novel-pipeline` for `LW-`), `backport_base_version`, plus `lw_id` / `vulnerability_class` (CWE) when known |

The `fixed` version uses the exact version string from the PNC build GAV — Pulp is the source of truth for version naming.

## Data Enrichment & Source Priority

For each vulnerability ID, the converter enriches metadata from the first available source, in priority order:

1. **OSIDB** (`--osidb`) — the primary, structured source for both CVEs and Lightwell `LW-` novels. Authenticates via Kerberos negotiate to obtain a JWT (or uses `OSIDB_TOKEN`).
2. **osv.dev** — *CVE IDs only*.
3. **NVD** — *CVE IDs only*; fallback for missing `summary`/`severity`.
4. **JIRA** (`--jira`) — *`LW-` novel IDs only*; pulls summary/details/severity from the Lightwell ticket.

### Behavior when a source has no record

The converter **never fails or drops a record** — it always emits a schema-valid OSV file, degrading gracefully:

- **CVE with no OSIDB record** → falls back to osv.dev, then NVD. If all miss, the record still carries an NVD advisory reference and the fixed-version data; `summary`/`details`/`severity` may be empty.
- **`LW-` novel with no OSIDB record** → osv.dev/NVD are skipped (CVE-only); it tries JIRA. If JIRA also has nothing, the result is a **valid but content-empty stub**: `id`, `aliases`, `affected` package/PURL/fixed, `credits`, and `database_specific.lightwell` are populated, while `summary`/`details`/`severity`/`references` are empty.
- **Missing/invalid credentials or unreachable services degrade cleanly.** If OSIDB is unreachable it logs a warning and falls through. If the JIRA secret is absent, the (unauthenticated) request returns `401`/`URLError`/timeout, which is caught — a warning is logged and enrichment simply yields nothing. No exception propagates.

> Note: JIRA enrichment is attempted for `LW-` IDs when OSIDB supplied nothing, even without `--jira` (using a default client). Without a valid `JIRA_TOKEN` this call fails and is caught — harmless, but it makes a failing network hop per novel unless egress is blocked.

### Intentional stub modes

- `--embargo` — emit pre-disclosure embargo stubs for *every* vuln (empty `affected`, `embargo_status: pre-disclosure`); no external lookups.
- `--redact-embargoed` — when an OSIDB flaw is flagged `embargoed`, redact it to a stub. Use for public/less-trusted feeds; omit for the protected, content-guarded Pulp feed where full records are appropriate.

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
