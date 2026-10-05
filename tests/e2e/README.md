# End-to-end fixtures and the exit-code triggers

Every v4 install channel runs the same three scans and judges them the same way. This
directory holds what they share. The workflow is `.github/workflows/ash-e2e.yml`, and
the verdict is `scripts/e2e/assert_outcome.py`.

## The cases

`fixtures/cases.json` defines three cases. A channel copies `fixtures/<source>/` into a
scratch directory and runs:

```
ashx scan --source-dir <copy> --output-dir <scratch> --no-progress --scanners <scanners>
```

with the case's `env` applied. `scripts/e2e/run_case.py` does this for any channel that
ends in a local executable.

| case | source | scanners | env | exit | findings |
|---|---|---|---|---|---|
| findings | findings/ | detect-secrets | none | 2 | exactly 3, from detect-secrets |
| clean | clean/ | detect-secrets | none | 0 | 0 |
| incomplete | findings/ | detect-secrets, opengrep | `ASH_OFFLINE=YES`, `OPENGREP_RULES_CACHE_DIR=` (empty) | 1 | 3, and opengrep MISSING |

`findings/leak.py` plants AWS's published example secret access key, which is
non-functional by construction. detect-secrets reports three rules on it:
SECRET-SECRET-KEYWORD, SECRET-BASE64-HIGH-ENTROPY-STRING and SECRET-AWS-ACCESS-KEY. The
repository's own scan already suppresses it through the `SECRET-*` entry for `tests/**`
in `.ash/.ash.yaml`, so the fixture needs no entry of its own. The channels scan a copy,
so that suppression never applies inside an e2e run.

The incomplete case reuses the findings tree on purpose. Exit 1 has to win over exit 2.
A channel that ignored incomplete coverage would report 2 here, and that fails.

## Why exit 1 needs a measured trigger

ASH exits 1 when a selected scanner ends MISSING or ERROR while
`fail_on_incomplete_scanners` is on, which is the default. It also exits 1 when it
crashes. So an exit-1 case needs a selected scanner that cannot run on every channel, for
the same reason each time, and the assertion has to name that scanner. Otherwise a crash
would pass.

## Measurements (2026-10-05, head of the ashx rename)

Commands were run from a wheel built at that head and installed into a bare venv on Linux
(Python 3.12). The environment was cleared with `env -i`, `PATH` was the venv plus
`/usr/bin:/bin`, `HOME` was a scratch directory, and `ASH_BIN_PATH` was an empty
directory. The host had `gem`, `cc` and a semgrep install outside that PATH. The
container was the image built locally with `docker build --target non-root` from the
same head, and it was never pushed. The table shows exit code and non-SKIPPED scanner
statuses.

| id | where | scanners | env | exit | statuses |
|---|---|---|---|---|---|
| baseline | venv | detect-secrets | none | 2 | detect-secrets FAILED (3) |
| baseline | venv, clean | detect-secrets | none | 0 | detect-secrets PASSED |
| T1 | venv | detect-secrets,opengrep | ASH_OFFLINE=YES, cache empty | 1 | opengrep MISSING |
| T1 online | venv | detect-secrets,opengrep | none | 1 | opengrep MISSING (binary absent) |
| T1 semgrep | venv | detect-secrets,semgrep | ASH_OFFLINE=YES | 1 | semgrep MISSING |
| semgrep online | venv | detect-secrets,semgrep | none | 1 | semgrep ERROR, after ASH tried to provision it through `uv tool` |
| T2 | venv | detect-secrets,cfn-nag | none | 1 | cfn-nag MISSING (no cfn_nag_scan reachable) |
| baseline | image | detect-secrets | none | 2 / 0 | as on the venv |
| T1 | image | detect-secrets,opengrep | ASH_OFFLINE=YES, cache empty | 1 | opengrep MISSING, "no rule cache was found" |
| T1 | image, `--network none` | same | same | 1 | opengrep MISSING |
| T1 control | image | same | ASH_OFFLINE=YES, cache = a dir with one rule | 2 | opengrep PASSED |
| T1 online | image | detect-secrets,opengrep | none | 2 | opengrep PASSED |
| T2 | image | detect-secrets,cfn-nag | none | 2 | cfn-nag SKIPPED (no templates to scan) |
| T3 | image | detect-secrets,opengrep, with `.ash/.ash.yaml` setting opengrep `config: /nonexistent/ruleset.yml` | none | 2 | opengrep PASSED; the bad config did not produce an ERROR |

The chosen trigger is T1: `--scanners detect-secrets,opengrep` with `ASH_OFFLINE=YES` and
`OPENGREP_RULES_CACHE_DIR` set to an empty string. It works the same way everywhere.
Offline opengrep reads its rules only from the directory that variable names
(`_grep_scanner_base.py`). An empty value fails closed and marks the scanner MISSING
before anything runs. That holds whether or not the opengrep binary is installed, and
with or without network. The control row shows that the cache is the cause: point the
variable at one rule and opengrep runs. Setting it empty, instead of leaving it out, also
covers an image built with `--offline`, which sets the variable to a populated cache.

Rejected:

- semgrep online. ASH installs semgrep through `uv tool` when it can, so the outcome
  depends on the network and on what the runner already has.
- T2 (cfn-nag). It is MISSING on a bare host only because no `cfn_nag_scan` is
  reachable, and it is SKIPPED in the image when the tree has no templates.
- T3 (a nonexistent opengrep config). It did not produce an ERROR.

Not measured locally: macOS and Windows bare venvs. The `wheel` job in ash-e2e.yml runs
the incomplete case on ubuntu-latest, macos-latest and windows-latest, so its first run
is that measurement. The trigger does not depend on the platform. It depends on an
environment variable that ASH reads the same way everywhere.
