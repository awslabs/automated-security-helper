# Captured cargo-deny output

Output of cargo-deny 0.21.0 (linux x86_64 musl release asset), captured on
2026-11-19 and written to stderr with `--format=json` (stdout stays empty). Used by
`tests/unit/plugin_modules/ash_cargo_deny_plugins/test_cargo_deny_scanner_behavior.py`,
which serves these files through a fake subprocess, so the tests need neither the
binary nor a Rust toolchain.

| File | Project | What it is |
| --- | --- | --- |
| `positive.jsonl` | a two-crate project, `smallvec =0.6.10` and `atty =0.2.14` | four advisory diagnostics and the `summary` line; exit status 1 (advisories bit) |
| `negative.jsonl` | a project with no advisories | the `summary` line only; exit status 0 |
| `no-lock.jsonl` | a project with no `Cargo.lock`, run with `--locked` | two `log` lines at level ERROR and no `summary`; exit status 1, a failed run and not an advisory |

The advisory `description` and the `notes` beyond the first line were shortened
when the files were committed (`"(shortened)"`); every other field is as written
by the tool. The argv was
`cargo-deny --manifest-path=Cargo.toml --locked --format=json --log-level=warn --color=never --config=<stub> check --hide-inclusion-graph advisories`.

cargo-deny is not provisioned by ASH, so no integration test re-runs the binary;
regenerate these files by hand when the supported version moves.
