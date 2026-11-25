# Captured TFLint output

`positive.sarif` and `negative.sarif` are the stdout of a real TFLint 0.66.0 run
(release asset `tflint_linux_amd64.zip`, sha256
`22be11cadc25cd02401e94c0ccc91aa63467debb8485c2a755d98f4c0a9d1e2e`, bundled
`terraform` ruleset 0.17.0), run with the flags ASH passes:

    tflint --format=sarif --recursive --chdir=. --config=<empty file> --no-color

from inside a one-file source tree.

- `positive.sarif`: exit 2. The tree held `main.tf` with `variable "unused" {}` and an
  empty `terraform {}` block. Three warning-level results, no `error` or `note` level
  result was produced by these inputs.
- `negative.sarif`: exit 0. The tree held `main.tf` with
  `terraform { required_version = ">= 1.0" }`. Both runs are present and empty.

The same run over a `main.tf` that does not parse exited 1 and wrote the
`tflint-errors` run with one `application_error` result at level `error`, whose message
quotes the offending source line and carries ANSI color escapes. That output is not
committed: the scanner treats any result in that run as a failed scan and never copies
the message, and the hand-built SARIF in
`tests/unit/plugin_modules/ash_tflint_plugins/test_tflint_scanner_behavior.py` covers
the shape.

Reported paths are relative to the working directory the tool was started in, not to
`--chdir`.
