# ASH for VS Code

Runs the ASH CLI over the open workspace folder and reports its SARIF findings in
the Problems panel.

The extension ships no scanners, no rules, and no copy of ASH. It invokes the
`ashx` (or, failing that, `ash`) on your PATH, or the executable you configure,
and reads the SARIF and `ash_aggregated_results.json` that executable already
writes. It has no runtime npm dependencies at all.

## Install

Publishing to the VS Code Marketplace is out of scope for this directory: nothing
here submits to a registry, and there is no publisher account. Build the `.vsix`
and install it from the file:

```
cd editors/vscode
npm ci
npm run package
code --install-extension ash-vscode.vsix
```

ASH itself has to be installed separately. `ashx --version` (or `ash --version`)
should print a string naming `automated-security-helper`; if it does not, read the
MSYS2 section below before filing anything.

## Commands and settings

`ASH: Scan workspace` scans the first workspace folder and replaces the extension's
diagnostics with what the scan found. `ASH: Clear findings` empties them.

| Setting | Default | What it is for |
|---|---|---|
| `ash.executablePath` | empty | Empty runs `ashx` from PATH, and `ash` when no `ashx` is installed. Anything else is run exactly as given, with no fallback. Machine-scoped, so a cloned repository cannot set it. |
| `ash.outputDirectory` | `.ash/ash_output` | Where the scan writes, relative to the workspace folder. It must resolve, symlinks included, to a folder inside the workspace: ASH clears directories under it before scanning, so an absolute path or an escape is refused and nothing runs. A symlink at `reports/`, `reports/ash.sarif` or `ash_aggregated_results.json` below it is refused too, before the previous report is deleted. |
| `ash.extraArguments` | `[]` | Appended to `ashx scan`, for example `--scanners detect-secrets` or `--offline`. `--output-dir` and `--source-dir` are refused, because the extension sets both. Machine-scoped, so a cloned repository cannot set it; see Restricted Mode below. |
| `ash.scanTimeoutSeconds` | `1800` | Seconds before a scan is stopped, with every process it started. `0` waits indefinitely. |

The scan runs as a child process without blocking the editor, under a progress
notification with a Cancel button. Cancelling, or the timeout firing, stops the
whole process tree: on POSIX the scan is started as a process-group leader and the
group gets SIGTERM, then SIGKILL after five seconds, even when ASH itself has
already exited, because a scanner that ignores SIGTERM outlives it; on Windows
`taskkill /T /F` walks the tree. Without that, the scanners ASH starts would keep
running and writing into the output directory after the scan was reported stopped.
The group kill has one limit: a process that moved itself into a new session or
group (`setsid`, Python's `start_new_session=True`) is outside the group and keeps
running. No ASH code does that today, but a scanner or a container CLI could. So
the extension does not wait on such a process: once the scan's own process has
exited, it gives the output pipes two seconds to close and then stops waiting,
so the scan always settles and the next one can start.
The `--version` probe that runs before the scan is asynchronous too, with a
one-minute limit, since a cold Python start can take seconds. A second
`ASH: Scan workspace` while one is running returns the running scan's result.

## Restricted Mode

The extension does not run in an untrusted workspace (`capabilities.untrustedWorkspaces`
is `supported: false`). A scan runs ASH and its scanners over the workspace, and
ASH reads the workspace's own ASH config: `.ash/.ash.yaml`, an `.ashrc.*` file, or
a `[tool.ash]` table in `pyproject.toml`, all discovered under the folder passed as
`--source-dir`. ASH treats that config as the repository's, not yours: it cannot
import plugin modules from the workspace, swap the tool packages ASH installs for
others, hand a scanner a config file from the workspace, or widen the scanner
sandbox (see "Settings a repository's config cannot choose" in ASH's configuration
guide). It still chooses which scanners run and which findings are suppressed, so
the result is only as trustworthy as the repository. Trust the workspace to scan
it.

`ash.executablePath` and `ash.extraArguments` are machine-scoped, so a
repository's own `.vscode/settings.json` cannot set either. The first names the
program that runs. The second reaches `ashx scan` as command-line options, which
ASH takes as yours and lets do what the workspace's config cannot: `--sandbox off`,
`--config-overrides sandbox.extra_read_paths=[...]` or `--ash-plugin-modules` from
a cloned repository would undo every limit above. To choose scanners for one
repository, put them in its `.ash/.ash.yaml`.

## Which executable runs

`ashx` is the v4 entry point and the default. When `ash.executablePath` is empty
and `ashx` is not on PATH at all, the extension runs `ash` instead and says so in a
notification shown once; the flag that it has been shown is kept in the
extension's global state, so it does not return on every scan or every window. The
fallback is taken only for "not found". An `ashx` that answers and is not ASH is an
error, because scanning with a different program would hide it. A configured value
is never substituted: if you name `ashx` and it is missing, the scan refuses.

The two names are constants in `src/ash-cli.ts` (`DEFAULT_EXECUTABLE`,
`LEGACY_EXECUTABLE`).

## The MSYS2 collision, which is why there is a startup check

MSYS2 ships the Almquist shell as `ash`. On a Windows machine with MSYS2 or Git
Bash ahead of ASH on PATH, spawning `ash` starts a shell — it has already shadowed
ASH's entry point in this project's own CI and produced `Illegal option --`.

In a terminal that is a visible error. Here it would not be. A shell handed
`scan --source-dir ...` writes no SARIF report, and an extension that read a
missing report as "no findings" would paint a clean Problems panel. A clean panel
is exactly what a successful scan of clean code looks like, so the wrong binary
would be indistinguishable from safety.

So the extension runs `<executable> --version` before every scan and refuses to
scan unless the answer contains the string `automated-security-helper`. The
refusal names `automated-security-helper` as the fix, because that is the console
script ASH keeps indefinitely and silently for exactly this case — `ashx` is
canonical, and `ash` and `ashv3` are deprecated aliases.

Two details of that check are deliberate. It reads the output rather than the exit
code, because `ashx scan` exits 2 for "actionable findings detected" and the
Almquist shell also exits 2 for an illegal option, so no numeric test can tell
them apart. And it uses `--version` and not `-v`: `-v` is `--verbose` and starts a
logging session.

## Everything that produces zero findings is reported

Zero diagnostics is what a clean scan looks like. It is also what a missing
executable, a shadowed one, a crashed scan, an unwritten report, the previous
run's report and a scan whose scanners never ran look like. `src/extension.ts`
returns a distinct status for each, and every one of them puts a message on screen:

| Status | What happened |
|---|---|
| `ok` | The scan ran, exited 0 or 2, and its results name no coverage gap. `summary.diagnostics` may be zero, and that is a real clean result. |
| `incomplete` | Findings are published, and the scan did not cover everything. See below. |
| `no-workspace` | No folder is open. |
| `wrong-executable` | The executable is missing, or answered without naming ASH. |
| `scan-failed` | ASH exited 1 having written no report (a crash), exited 3 or 4, was killed, could not be started, or outran `ash.scanTimeoutSeconds`. |
| `no-report` | The scan exited 0 or 2 and wrote no SARIF. There is no evidence the tree is clean. |
| `stale-report` | The previous run's report could not be deleted and this run did not rewrite it. |
| `unreadable-report` | A report exists and is not SARIF. |
| `cancelled` | The scan was cancelled from its progress notification. |

Only `ok` and `incomplete` leave findings on screen. Every other status clears the
previous scan's findings and shows its message, as the JetBrains plugin does:
findings left from an earlier scan next to an error about this one read as this
scan's result.

### The exit-code contract

ASH exits 0 for a clean scan and 2 for findings; both publish. Exit 1 is two
things. With results written by this run it is `ScanIncompleteExit`: the scan
finished with partial coverage, and since `fail_on_incomplete_scanners` defaults to
true that is the ordinary result on a host missing one scanner's tool. The findings
that were reported are real, so they are published and the scan is reported
`incomplete` with what is missing. Exit 1 with no report from this run is a crash.

Both reports are deleted before each scan, so a report present afterwards can only
be this run's. When the delete fails, modification times are compared instead.

### Where "incomplete" comes from

`coverage_complete` is not a field of `ash_aggregated_results.json`. ASH computes
it on demand for its MCP payloads, as
`not coverage_has_gap(scan_incompleteness(results, gate=True).to_payload())`.
Every input that reads is in the results file, so `src/coverage.ts` asks the same
five questions of it: a scanner that is ERROR or MISSING or lost targets, no
scanner having run, a converter that did not run, a rule that was not evaluated,
and a stale content database. The scan is `incomplete` when ASH exited 1 or when
that answer is false, so a scan run with the gate turned off still says what it
did not cover.

Being a second reader of one rule, it can drift. `test/fixtures/coverage-cases/cases.json`
records the verdict ASH reaches on each of 18 cases built from captured scans;
jest holds `src/coverage.ts` to it and
`tests/unit/test_vscode_coverage_parity.py` holds ASH to it.

This replaces, deliberately, an earlier design that also read the SARIF report's
`runs[].invocations[]` and reported any `executionSuccessful: false` as a failed
scanner. That field cannot carry the answer: a scanner that fails returns before
ASH injects its invocation, so it leaves no invocation at all, and a real run on a
host missing most scanner tools reported `executionSuccessful: true` for a
scanner ASH marked FAILED. `assess_coverage` reads ASH's per-scanner status
instead, and reproducing ASH's own rule, with a parity test against ASH, keeps the
editor and ASH agreeing. The consequence is that an invocation marked
unsuccessful whose scanner status is a complete one is not reported as a gap,
here or by ASH.

### Suppressed results and where findings land

A result ASH suppressed keeps its `kind` and `level` and gains a `suppressions`
entry, so it is identified by that entry alone and is counted, not published.
Results whose `kind` is not `fail` are counted the same way. A suppression hides
the result when its `state` is `accepted`, null, absent or unreadable.
`underReview`, `rejected` and any other string leave it shown, so only a recorded
decision hides a finding.

A SARIF location is resolved whether it is relative to the scanned folder,
relative to a `uriBaseId` the run declares (ASH's workspace mode writes
`PROJECTROOT`), a `file:` URI, or an absolute POSIX or Windows path. One that
names no file on this machine -- another URI scheme, or a Windows path off
Windows -- is counted and reported rather than attached to the wrong file.

A path on another host is counted the same way on every platform, in each
spelling: `\\host\share`, `//host/share`, mixed separators, the `\\?\` and `\\.\`
device forms, `file://host/` and `file:////host/`. The extension never checks
whether such a file exists, because on Windows that check opens an SMB
connection to the host named in the report.

## How the .vsix stays free of third-party code

`packaging/README.md` draws the line every artifact this project publishes has to
stay on: ASH's own code may ship in a published artifact, third-party code never
may. A `.vsix` is published as a GitHub Release asset, and `vsce package` bundles
the `dependencies` tree from `node_modules` by default — so the default behavior of
the packaging tool is the thing that would cross the line.

Two mechanisms, and only the second is a guard:

- `.vscodeignore` asks `vsce` to leave `node_modules`, `src` and `test` out. It is
  a request. A rename or a new directory silently stops it covering anything.
- `npm run verify:vsix` opens the built archive and checks its member list against
  an allowlist derived from this package's own output. Anything else fails the
  build, whether or not `.vscodeignore` mentioned it.

The rule is an allowlist rather than a denylist for the reason `packaging/README.md`
gives for "exactly one bundled wheel": a denylist needs a judgment call per
dependency and gets enforced by whoever reviewed the build script that day. And it
carries a required-present check alongside the allowlist, because a subset test
passes on the empty set — an archive built before `tsc` ran would otherwise satisfy
"every member is allowed" by having no members to disallow.

The reader in `src/vsix-contents.ts` walks the ZIP central directory itself rather
than taking a dependency. Adding an npm package to the checker that exists to keep
npm packages out would be its own answer to the question.

## Why the jest configuration lives in package.json

`.github/scripts/assert-coverage-completeness.mjs` takes a census of every tracked
`.ts`, `.tsx`, `.mts`, `.cts`, `.js` and `.mjs` file and requires each one to be
either measured by a coverage report or named in
`.github/typescript-coverage-exclusions.json` with a reason. A `jest.config.js` is
a `.js` file that jest loads in the parent process before instrumentation exists,
so it can never be measured — which is why both packages under `deploy/` carry a
`harness-config` exclusion for theirs.

This package adds no such entry. Its jest configuration is a `"jest"` key in
`package.json`, which the census does not cover because it is not source by
extension. That keeps the exclusions file at the size it was.

The cost is that the configuration cannot carry comments, so the one piece of
reasoning that would have been a comment is here instead. `roots` lists `src`
alongside `test`. With `roots` confined to `test`, jest's crawler never sees a
source file that no test imports, `collectCoverageFrom` silently matches nothing
for it, and the file is omitted from the report entirely rather than appearing at
0%. That inflates the percentage with no error anywhere:
`deploy/cdk-constructs` reported 97.35% that way while an untested file sat in
`src/`, and read 82.51% once the file was counted.

## What the tests do and do not prove

The suite's central assertion is that `test/fixtures/planted_secret.py`, which
carries AWS's published example secret access key, produces a **non-zero** count of
diagnostics in the diagnostic collection. Not that the command completed, and not
that a SARIF file appeared: an empty ASH scan exits 0 and still writes a report, so
both of those are satisfied by a scan that saw nothing.
`packaging/deb/verify-in-container.sh` asserts the same thing at the package layer,
against the same planted value, so the whole branch plants one known secret.

`test/fixtures/planted-secret.sarif` is real output from
`ash scan --source-dir . --output-dir .ash/ash_output --scanners detect-secrets
--no-progress` over that fixture, with the scanning machine's absolute path
replaced by `/workspace`. That run exited 2 and reported three results
(`SECRET-AWS-ACCESS-KEY`, `SECRET-SECRET-KEYWORD`,
`SECRET-BASE64-HIGH-ENTROPY-STRING`), and the tests assert both numbers, so a
fixture edited into something ASH would not produce fails rather than passes.
`test/fixtures/clean-scan.sarif` is the same document with `results` emptied, and
it is required to produce zero diagnostics — without that control, an assertion
could be satisfied by a mapper that invented findings.

`vscode` is a stub in `test/vscode-stub.ts` for jest, which is what the coverage
gate measures: a gate that downloaded an editor and needed a display would flake,
and a gate that flakes gets ignored. The real editor is the integration suite's
job.

## The integration suite

`npm run test:integration` downloads VS Code, opens a temporary copy of the
fixture, and drives the registered command through a real extension host: real
command dispatch, the real diagnostics API, settings, global state, and a real
child process on a PATH the suite controls. On a host without a display run it
under Xvfb, as CI does:

```
xvfb-run -a npm run test:integration
```

By default the CLI is `test/integration/ash-stub.ts` behind wrappers named `ash`
and `ashx`, replaying the captured runs under `test/fixtures/scans/` with their
exit codes. Set `ASH_IT_REAL_ASH_DIR` to a directory holding an installed ASH
(a venv's `bin/`, with both `ashx` and `ash`) to run the same suite against
genuine scans instead. Real mode scans the shared e2e cases in
`tests/e2e/fixtures/cases.json` and judges each output directory with
`scripts/e2e/assert_outcome.py`, the verdict every install channel uses. Both
modes cover the `ashx` -> `ash` fallback and its one-time notice, exit 2
findings, exit 1 with partial findings, exit 0 clearing the editor, exit 1 with no
report, a scan timeout, and a configured executable used as given.

`npm run test:e2e-vsix` is the channel end to end. It needs `ASH_IT_REAL_ASH_DIR`
and a built `ash-vscode.vsix` (or `ASH_IT_VSIX`). It installs the `.vsix` into a
fresh extensions directory with VS Code's own CLI, runs the real-mode suite
against that installed copy, uninstalls it, and upgrades from an N-1 `.vsix`
built from this tree at a lower version. Its negative controls are a truncated
`.vsix` that must be refused, a suite run against a cases file expecting one
finding too many that must fail through `assert_outcome`, and the post-uninstall
absence check run while the extension is still installed, where it must fail. See
`test/integration/vsix-e2e.ts`.

VS Code is launched with `--force-disable-user-env`. Without it VS Code resolves
your login shell's environment and puts its PATH ahead of the suite's, so an
installed scanner or a real `ash` on the development machine answers instead of
the one under test.

## Snapshot tests

What the extension shows a user is pinned twice: jest snapshots of every
notification, diagnostic, log line and contribution (`test/ui-snapshots.test.ts`),
and PNG baselines of the Problems panel, a hover and two notifications rendered by
VS Code 1.141.0 in a pinned container (`test/visual/`). A change to either fails
until it is rewritten with `npm run snapshots -- --snapshot-update <structural|visual>`
and committed with a `Snapshot-Update: <reason>` trailer, which CI checks. See
[test/visual/README.md](test/visual/README.md).

## Why this is not in the agentic-coding transpiler

`ash-agent-plugins/agentic-coding/transpiler/transpiler/packagers.py` names a
`.vsix` packager as future work, so the question is a real one. It belongs in its
own tree for three reasons.

The transpiler renders one `_base/` directory into 17 agent-plugin trees plus
`skills/`; everything it touches is generated, and editing a generated copy is
pointless because the next run overwrites it. This extension is hand-written
TypeScript with a `tsc` step, a jest suite and a coverage gate, so putting its
sources under that tree would put them where a regeneration deletes them.

The determinism argument in that docstring does not transfer either. `.mcpb` is
built by `zipfile` with a fixed mtime because the archive is committed and
drift-checked, and byte-identical output is what makes the check possible. A
`.vsix` is not committed — root `.gitignore:263` is a bare `*.vsix` — and `vsce`
owns the ZIP writer, so there is no way to make it reproducible short of
reimplementing `vsce`. The check that replaces drift detection here is the member
list, which is what `verify:vsix` does.

And the two artifacts do different things. The transpiler's future `.vsix` would
package generated agent-plugin content for a VS Code host. This one spawns a
process and maps SARIF onto editor diagnostics. Sharing a packager between them
would mean one build producing both a Python-rendered manifest tree and a
TypeScript compile.
