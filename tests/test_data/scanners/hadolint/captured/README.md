# Captured hadolint output

Real output of hadolint 2.15.1 (the version pinned in
`automated_security_helper/utils/tool_downloads.py`), used by
`tests/unit/plugin_modules/ash_builtin/test_hadolint_scanner_behavior.py`.
`tests/integration/scanners/test_hadolint_scanner.py` re-runs the binary and
fails if these files no longer match what it writes, so regenerate them when
the pin moves.

Each file is the output of the argv `HadolintScanner` builds, run from the
fixture directory named in the first column:

| File | Directory | Command |
| --- | --- | --- |
| `positive.sarif` | `../positive` | `hadolint --no-fail --no-color --format sarif -- Dockerfile services/Dockerfile.broken services/api.Dockerfile` |
| `positive.json` | `../positive` | the same, with `--format json` |
| `negative.sarif` | `../negative` | `hadolint --no-fail --no-color --format sarif -- Containerfile` |
| `configured.sarif` | `../configured` | `hadolint --no-fail --no-color --config .hadolint.yaml --format sarif -- Dockerfile` |
| `configured.json` | `../configured` | the same, with `--format json` |

`services/Dockerfile.dockerignore` in `../positive` is deliberately absent from
the argv: it is a BuildKit ignore file, and the scanner must not lint it.
