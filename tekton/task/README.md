# Build-index task

[attach-build-index](attach-build-index/0.2/attach-build-index.yaml) generates
`build-index.json` from source Git history and attaches it to the wheels image
using ORAS. One `fath-cuan-attach-build-index` invocation handles the task logic;
trusted artifacts are restored by separate `build-trusted-artifacts` steps.

## Inputs

- `FATH_CUAN_IMAGE`: digest-pinned image built from this repository's Dockerfile.
- `SOURCE_ARTIFACT`: source tree including `.git` history.
- `MANIFEST_ARTIFACT`: optional wheel manifest for companion packages.
- `IMAGE_REF`: digest-pinned wheels image to attach the index to.
- `PACKAGE`, `VERSION`, `COMPUTED_VERSION`, `BUILD_TYPE`: package and build identity.

Registry credentials are selected by `select-oci-auth`, using the existing
Konflux service-account setup. No additional Secret or workspace is required.
Local runs can override discovery with `--auth-file`. Trusted-artifact steps
retain their existing credentials. Requires Tekton Pipelines 1.0 or newer.

Backport and Novel builds require vulnerability evidence. An omitted manifest
is allowed; a supplied manifest must exist and be valid.

## Results

- `BUILD_INDEX_ATTACHED_REF`: image receiving the index.
- `BUILD_INDEX_DIGEST`: SHA-256 of the attached JSON bytes.

Results are written after successful attachment. For local usage, run
`fath-cuan-attach-build-index --help`.
