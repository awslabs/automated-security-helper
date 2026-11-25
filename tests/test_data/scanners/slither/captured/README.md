# Captured Slither 0.11.6 output

Captured on 2026-11-25 from `slither-analyzer` 0.11.6 (installed with `uv tool install`),
solc 0.8.28 through `solc-select`. The unit tests serve these files from a fake
subprocess, so they run on every platform without Slither.

Argv, from the directory of each input (the working directory ASH uses), with
`<empty>` an empty `{}` config file and `<none>` a path that does not exist:

```text
slither --json=<file> --config-file=<empty> --triage-database=<none> \
  --fail-none --exclude-dependencies -- contracts
```

* `positive.json`: one Solidity file (`contracts/Vault.sol`) with a reentrant
  `withdraw`, an unprotected `selfdestruct`, and a `.call`. Four findings: `reentrancy-eth`
  (High), `suicidal` (High), `solc-version` (Informational), `low-level-calls`
  (Informational). The lane directory in `filename_absolute` was rewritten to `/work`.
* `clean.json` and `clean.stderr.txt`: a file pinned to 0.8.28 with no finding. The
  document has an empty `results` object, and the log's summary line says one contract
  was analyzed.
* `no-contract-analyzed.json` and `no-contract-analyzed.stderr.txt`: the same tree as
  the positive run, scanned as `.` (the Solidity is in `contracts/`, and the root has no
  hardhat or foundry project). The document is byte-identical to `clean.json`; only the
  log differs (`No contract was analyzed`, 0 contracts). That is why the scanner reads the
  log and not the document to tell a clean scan from one that compiled nothing.
* `positive.sarif`: what `convert_slither_json` makes of `positive.json`, for the facets
  register's corpus gate.

Two measurements behind the argv, same version and inputs: a `slither.config.json` with
`detectors_to_exclude` in the working directory hid 3 of the 4 findings, and a
`slither.db.json` triage database there hid all 4; with `--config-file` and
`--triage-database` as above all 4 came back. A `// slither-disable-next-line
reentrancy-eth` comment in the source removed that finding (the other three stayed).
