# Malcontent fixtures

`recorded/ls.json` and `recorded/injector.json` are `mal --format=json` reports as
Malcontent's own test suite records them: the files `tests/macOS/clean/ls.json` and
`tests/linux/2024.kubo_injector/injector.json` of
[chainguard-dev/malcontent](https://github.com/chainguard-dev/malcontent) at tag v1.28.2
(Apache-2.0). The content is upstream's (upstream's files have sha256 `88ac1c6c...` and
`e3aa72ff...`); this repository's `pretty-format-json` hook sorted the keys and re-indented
them to two spaces, so the bytes differ and the parsed documents are equal. Upstream
checks each one against the output of its own scan, so they are the tool's output, but
ASH did not run the tool to produce them: Malcontent publishes no release binary, and
building it needs Go, Rust and YARA-X.

- `ls.json`: a clean system binary, six LOW behaviors.
- `injector.json`: a process-injection sample, sixteen behaviors (CRITICAL 1, HIGH 3,
  MEDIUM 4, LOW 8), every rule one of Malcontent's own (no `3P/` third-party rule).

There is no recorded negative report: upstream's renderer writes `{}` for a scan with no
files, and a scan of a clean file still lists its LOW behaviors. A report with no
behaviors is covered by the hand-written `NEGATIVE` in the behavior test.

The converter reads these through `convert_malcontent_report`, and the facets corpus
check reads them through a prep (see `.scanner-pr-body/malcontent.md`). Replace them with
a capture made by ASH once a `mal` binary is available.
