# gosec captured reports

Real output of gosec, not hand-written SARIF. The scanner tests read these files as
the oracle; the expected findings in
`tests/unit/plugin_modules/ash_gosec_plugins/test_gosec_scanner_behavior.py` are
written out by hand from them.

## How they were made

- Tool: gosec v2.30.0 (`gosec -version` printed `Version: 2.30.0`, `Git tag: v2.30.0`),
  the `gosec_2.30.0_linux_amd64.tar.gz` release asset, SHA256
  `3fcce2c4e802ff4169217874602a7df355e9a37bcb6ffaa34b08f3d5f336cdfb`, checked against
  the release's `gosec_2.30.0_checksums.txt` before use.
- Go toolchain: go1.27.4 linux/amd64, `GOTOOLCHAIN=local`, module cache and build cache
  in an empty scratch directory. The inputs import only the standard library, so no
  module download was needed.
- Host: Linux x86_64, environment reduced to `PATH`, `GOPATH`, `GOCACHE` and
  `GOTOOLCHAIN`; no network use by gosec.
- Command, run from the root of each input directory, with the flags ASH passes:

  ```text
  gosec -fmt=sarif -out=<report> -nosec=true -- ./...
  ```

| Report | Input directory | Exit status |
|---|---|---|
| `positive.sarif` | `../positive/` | 1 (findings) |
| `negative.sarif` | `../negative/` | 0 (clean) |

The reports are gosec's bytes, unchanged. `<report>` was a path outside the input tree.

## Inputs

- `../positive/`: a Go module (`go.mod`, `main.go`, `pkg/util.go`, `pkg/client.go`)
  with three deliberate findings: `G402` (TLS `InsecureSkipVerify: true`, rule tag
  HIGH), `G304` (file read from a caller-chosen path, MEDIUM) and `G104` (an unhandled
  `Close` error, LOW).
- `../negative/`: a Go module whose only file prints a string. gosec reports nothing.

No input holds a secret or a credential. A fabricated password constant in an
earlier draft of the positive input did not trigger `G101` (its entropy check), so it
was removed rather than kept as a decoy.

## Facts the scanner relies on

- gosec's SARIF result `level` is `warning` for LOW and `error` for MEDIUM and HIGH.
  A result carries no severity property; the severity is the second entry of the
  rule's `properties.tags` (`["security", "<SEVERITY>"]`). G304 and G402 are both
  `error` natively and differ only by that tag.
- The first rule (index 0) has no `ruleIndex` on its results (G104 above): the field
  is omitted when zero, so the scanner must key on `ruleId`, not the index.
- Results carry no `fingerprints` or `partialFingerprints`.
- The run's `tool.driver.version` and `semanticVersion` are both `2.30.0` (no leading
  `v`), and `negative.sarif` still lists CWE taxonomies with `"results": []`.
- Rules carry CWE ids only in `relationships` and the run's `taxonomies`, not in the
  rule tags.
- Progress lines (`[gosec] ... Checking file: ...`) go to stderr, which can quote
  scanned paths; the scanner keeps stderr out of its errors.
