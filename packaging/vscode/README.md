# Automated Security Helper for VS Code

Runs the ASH CLI on the open workspace folder and shows its SARIF findings as
editor diagnostics.

## What it does

One command, `ASH: Scan Workspace`, which:

1. Runs `ash scan --source-dir <folder> --output-dir <folder>/.ash/ash_output`.
2. Reads `<output-dir>/reports/ash.sarif`.
3. Publishes the findings into a diagnostic collection, so they appear in the
   editor gutter and in the Problems panel.

## What it does not do

It ships no scanner. There are no third-party scanner binaries, rules, or
databases inside the `.vsix`, and the extension has no runtime npm dependencies
at all -- it invokes the `ash` you installed and reads the report that ASH
writes. If ASH is not installed, the command says so rather than doing nothing.

Install ASH first: <https://github.com/awslabs/automated-security-helper>.

## Settings

| Setting | Default | Scope | Meaning |
| --- | --- | --- | --- |
| `ash.executablePath` | `""` | machine | Path to `ash`. Empty resolves `ash` from `PATH`. Set it when ASH lives in a virtualenv the window's `PATH` does not include. No shell expansion is done, so `~` is not expanded -- use an absolute path. |
| `ash.outputDirectory` | `.ash/ash_output` | resource | Where ASH writes results, relative to the workspace folder **and required to stay inside it**. Matches the CLI default so a terminal run and this command agree. An absolute path, or a relative one that escapes the folder, is refused with an error rather than silently rebased. |
| `ash.scanTimeoutSeconds` | `600` | window | Seconds to wait for `ash scan` before stopping it. `0` waits indefinitely. The scan is also cancellable from its progress notification. |

`ash.executablePath` is deliberately **machine**-scoped: it names a program that
gets executed, so a cloned repository must not be able to set it from its own
`.vscode/settings.json`. This is the same reason `python.defaultInterpreterPath`
and `eslint.runtime` are machine-scoped, and it matters more here than usual --
the whole point of this extension is scanning code you have reason to distrust,
and trusting a folder in VS Code is a routine act.

## What is and is not shown

Not every result in an ASH report becomes a diagnostic. Three groups are counted
and excluded, and the counts appear in the ASH output channel after each scan:

- **Suppressed findings.** A result with a non-empty `suppressions` array is one
  ASH was configured to ignore -- by a path pattern, or by an in-source marker.
  Re-displaying it would defeat the suppression, so it is not shown. This is keyed
  on `suppressions`, not on severity: a finding can be suppressed while still
  carrying `level: "error"`, and on a real report seven of them do.
- **Non-failures.** A result whose `kind` is `pass`, `notApplicable`, `review`,
  `open` or `informational` is a statement that a rule was considered, not that
  there is a problem. `fail` is the default when `kind` is absent.
- **Findings with no location.** These have nowhere to be drawn. Unlike the two
  above, this one raises a warning notification, because it is a finding you would
  have wanted to see.

For scale, on the report in `tests/test_data/outputs/`: 126 results in, 92
suppressed, 34 shown.

## An empty Problems panel is not the same as clean

Two different questions: *was anything found*, and *did what I asked for actually
run*. The exit code answers only the first.

A selected scanner can be **MISSING** -- selected, its tool unavailable, never ran.
`fail_on_incomplete_scanners` defaults to **false**, deliberately, so a machine that
legitimately lacks a tool keeps its exit codes. So if the scanners that did run
found nothing, ASH exits 0 and the panel is empty while most scanners never ran.

This extension reads ASH's scanner roster from `ash_aggregated_results.json` beside
the SARIF, and warns when any scanner has status `ERROR` or `MISSING`, naming them.
With zero findings the warning says so explicitly. It does **not** refuse to
publish: if you lack grype you should still get every other scanner's findings,
which is what that default protects.

Two keys are read, because ASH moved the roster: `scanner_results` at the top level
(the field the model declares, populated by 3.7.0) and `metadata.scanner_status`
(present in 3.0.0-era output, absent from the models). Whichever is populated wins,
with the declared field preferred; an empty roster counts as absent rather than as
complete.

**`invocations[].executionSuccessful` is not a completeness signal**, and is worth
naming so nobody rebuilds a checker on it. A real 3.7.0 run on a host missing most
scanner tools produced `executionSuccessful: true` for a scanner ASH itself marked
`FAILED`, and no invocation at all for one marked `MISSING` -- 8 invocations for 10
scanners. A `false` is reported where it appears; nothing is inferred from absence.

Three cases are distinguished, because reporting them alike would hide two of them:

- **Some scanner did not reach a verdict** -- named, with its status.
- **Every scanner was skipped** -- nothing was measured at all.
- **Completeness unknown** -- no readable roster beside the SARIF. Reported as
  unknown rather than as fine.

## Exit codes

ASH's codes, from `interactions/run_ash_scan.py` and `models/workspace.py`:

| Code | Meaning | Treated as |
| --- | --- | --- |
| 0 | Success, no actionable findings | success |
| 1 | Error during execution -- a crash, or scanners that failed or were incomplete | **failure** |
| 2 | Actionable findings above threshold | success |
| 3 | Invalid project configuration | **failure** |
| 4 | Workspace definition or policy error | **failure** |

**2 is a successful scan**, not an error: `fail_on_findings` defaults to true, so 2
is the ordinary result of any scan that finds something.

On a failing code the report is treated as incomplete and **not** published, and
the error names the code and its meaning. Publishing a partial report would show a
Problems panel that looks complete and is not.

The report is deleted before each scan, so a run that fails without writing one
cannot leave the previous run's findings on screen as the current result. If the
report cannot be deleted -- a read-only output directory -- its modification time
is compared instead, and an unchanged report is refused rather than read.

## Severity mapping

SARIF `level` maps to editor severity as follows. `none` means the rule did not
fire as a problem, so it is a hint rather than a squiggle.

| SARIF `level` | Editor severity |
| --- | --- |
| `error` | Error |
| `warning` | Warning |
| `note` | Information |
| `none` | Hint |
| absent | Error -- matching the default ASH's own schema model declares for `Result.level`, so a level-less result is not quietly shown a band below what ASH would call it |

A report that spells a level as a Python enum member name -- `Level.error`
rather than `error` -- is mapped to the severity it plainly means **and** a
warning notification names the spelling. Correcting it silently would map the
severity right and leave the producing bug invisible, which is how that defect
survived in ASH's own SARIF handling.

## Development

Requires the Node version in the repository's `.nvmrc` (22).

```bash
cd packaging/vscode
npm ci
npm run compile
npm run lint
npm test          # needs a display; see below
```

The test suite downloads a real VS Code build via `@vscode/test-electron` and
drives it, so on a headless host it needs a virtual display:

```bash
xvfb-run -a npm test
```

To build the artifact:

```bash
npm run package   # writes automated-security-helper.vsix
```
