# cargo-audit captured output

Real output of `cargo-audit audit --json --file=<Cargo.lock>`, cargo-audit 0.23.0
(built with `cargo install cargo-audit --locked`), run on 2026-11-25 against a lockfile
pinning `time 0.1.43` and `atty 0.2.14`, with the RustSec advisory database at commit
`10db6998b5d74ec438bcf0763125bd425a068a8f` (1567 advisories). The tool exited 1, its
"vulnerabilities found" code.

| File | What it is |
|---|---|
| `positive.json` | The tool's report: one vulnerability (`RUSTSEC-2020-0071`, CVSS 5.5) and two warnings (`unmaintained`, `unsound`). Re-indented; no value changed. |
| `positive.sarif` | What `convert_cargo_audit_report` writes for `positive.json` with the lockfile at the root of the scanned tree (`Cargo.lock`), inside the run `CargoAuditScanner` reports. Regenerate it with the test `test_the_committed_sarif_is_what_the_converter_writes`. |

The SARIF file is the corpus the facets register's consistency gate reads.
`../transcripts.json` records the run for `ash plugin verify` (the argv shape, exit code
1, the date, and both files by SHA256), so the verify harness and the consistency gate
judge the facets register over the same results. A change to either file needs its
digest updated there.
