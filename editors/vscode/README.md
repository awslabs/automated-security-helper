# ASH for VS Code

Runs the `ash` CLI over the open workspace folder and reports its SARIF findings in
the Problems panel.

The extension ships no scanners, no rules, and no copy of ASH. It invokes whatever
`ash` is on your PATH — or the executable you configure — and reads the SARIF that
executable already writes. It has no runtime npm dependencies at all.

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

ASH itself has to be installed separately. `ash --version` should print a string
naming `automated-security-helper`; if it does not, read the next section before
filing anything.

## Commands and settings

`ASH: Scan workspace` scans the first workspace folder and replaces the extension's
diagnostics with what the scan found. `ASH: Clear findings` empties them.

| Setting | Default | What it is for |
|---|---|---|
| `ash.executablePath` | `ash` | The executable to run. Set it to `automated-security-helper` or to a full path when a bare `ash` resolves to something else. |
| `ash.outputDirectory` | `.ash/ash_output` | Where the scan writes, relative to the workspace folder. An absolute path is used as given. |
| `ash.extraArguments` | `[]` | Appended to `ash scan`, for example `--scanners detect-secrets` or `--offline`. |

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
script ASH keeps indefinitely and silently for exactly this case — `ash` is
canonical and `ashv3` is deprecated.

Two details of that check are deliberate. It reads the output rather than the exit
code, because `ash scan` exits 2 for "actionable findings detected" and the
Almquist shell also exits 2 for an illegal option, so no numeric test can tell
them apart. And it uses `--version` and not `-v`: `-v` is `--verbose` and starts a
logging session.

## Everything that produces zero findings is reported

Zero diagnostics is what a clean scan looks like. It is also what a missing `ash`,
a shadowed `ash`, a crashed scan, an unwritten report and an unparseable report
look like. `src/extension.ts` returns a distinct status for each, and every one of
them puts a message on screen:

| Status | What happened |
|---|---|
| `ok` | The scan ran. `summary.diagnostics` may be zero, and that is a real clean result. |
| `no-workspace` | No folder is open. |
| `wrong-executable` | The configured executable is missing, or answered without naming ASH. |
| `scan-failed` | ASH exited 1, was killed, or could not be started. Exit 2 is NOT a failure. |
| `no-report` | The scan exited 0 or 2 and wrote no SARIF. There is no evidence the tree is clean. |
| `unreadable-report` | A report exists and is not SARIF. |

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

The limitation worth stating: `vscode` is a stub in `test/vscode-stub.ts`, not the
real editor. `@vscode/test-electron` downloads a full VS Code build and needs a
display server, which would add a network fetch and an xvfb dependency to a
coverage gate, and a gate that flakes gets ignored. So the assertion is about the
diagnostic model as the stub reproduces it — `set` keyed on the URI's string form,
`clear` emptying everything, `Range` ordering its ends — and not about pixels.

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
