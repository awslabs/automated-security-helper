# skillcheck captures

Real output of Mondoo's skillcheck (https://github.com/mondoohq/skillcheck),
release `v0.4.0` (`skillcheck 0.4.0 (commit: ab7db03, built: 2026-10-09T20:25:25Z)`),
linux/amd64, archive sha256
`3f3fa982898a438078dafe4d13a7c47adfc6acbab89a58b6f71f08a39fe05528` (read from the
release's `checksums.txt` and matched against the downloaded archive).

## How each file was made

Run on a development desktop with the environment cleared, `HOME` an empty
directory, and network access (the hash lookup reached the Mondoo database and
answered `unknown` for every skill here):

```text
env -i PATH=/usr/bin:/bin CI=1 HOME=<empty dir> skillcheck --project <input> --json --no-color
```

| File | Input | Exit |
| --- | --- | --- |
| `benign.json` | `fixture_repo/benign` | 0 |
| `spec_violation.json` | `fixture_repo/spec_violation` | 0 |
| `home_leak.json` | `fixture_repo/benign`, with `HOME` holding `.claude/skills/leaky/SKILL.md` | 0 |

The files hold the tool's output with its object keys sorted (the repository's
`pretty-format-json` hook rewrites them; the values are untouched). The
`configPath` and `source` fields hold the desktop's lane path, verbatim. The
adapter makes each `source` relative to its agent's `configPath`, so the lane path
never matters.

`home_leak.json` is why the adapter points `HOME` at an empty directory: with a home
that holds an agent directory, the tool reports it as a second agent beside the
`Project` one.

A run at a path that is not a directory (`--project /nonexistent-dir`) exits 1 with
nothing on stdout and `Error: project /nonexistent-dir is not a directory` on stderr.
That is why exit 1 alone does not mean a finding.

## affected_schema_derived.json

SCHEMA-DERIVED, not captured. The tool flags a skill only when the Mondoo database
holds a report for the skill's content hash, so no input made here can make the real
tool print a verdict. This file is written by hand from the `SkillResult` struct in
`internal/reporter/reporter.go` at v0.4.0 (`status`, `riskScore`, `topSeverity`,
`summary`, `purl`, `url`). Every name, hash and URL in it is synthetic.

## Inputs

`fixture_repo/benign` is a conformant skill. `fixture_repo/spec_violation` is a skill
whose `name` is `MySkill`: not a lowercase slug, which is the one specification check
the tool reports for it. Neither holds anything a scanner would flag. The seeded
marker skill the unit tests use is written by the test itself.
