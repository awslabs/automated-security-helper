# Move to the scan subjects

ASH 3.9 names what a scan scans: `ash scan fs` scans a directory, given as its path
argument, and `ash scan workspace` scans the projects of a `.code-workspace` file, given
as its file argument. The commands that read the results a scan already wrote moved under
`ash results`, and `ash build-image` is now `ash container build`.

The old spellings still work in 3.9. Each runs the same command as before and prints one
deprecation line on standard error that names its replacement. Standard output, the
options and the exit codes are unchanged, so a script keeps working while you move it.
ASH 4.0 removes the old spellings, and their deprecation lines say so, except the line for
`--scanners` and `ASH_SCANNERS`, which names no removal release.

If you pin ASH 3.8 or older, keep the old spellings until you move the pin: the new ones
arrive in 3.9.

## Old and new spellings {#spellings}

| Old spelling | New spelling | Notes |
|---|---|---|
| `ash --mode local` | `ash scan fs --mode local` | `ash` with options and no subcommand runs a scan. Every scan option moves along unchanged. |
| `ash scan --mode local` | `ash scan fs --mode local` | `ash scan` with no subject runs the same scan. |
| `ash scan fs --source-dir ../app` | `ash scan fs ../app` | The directory is the path argument, the current directory when you give none. `ash --source-dir ../app` and `ash scan --source-dir ../app` move the same way. A path argument and a different `--source-dir` together are a usage error, exit code 5. |
| `ash scan --workspace project.code-workspace` | `ash scan workspace project.code-workspace` | `ash --workspace project.code-workspace` moves the same way. `--workspace-config`, `--allow-missing-projects` and `--dry-run` go with the subject: `ash scan fs` does not take them. |
| `ash scan fs --scanners bandit,semgrep` | `ash scan fs --only-scanners bandit,semgrep` | `--only-scanners` states the whole selection, and `--add-scanners` adds scanners to the mode's default set. `ASH_SCANNERS` is deprecated with `--scanners`. `--scanners` keeps its behavior and prints one `DeprecationWarning:` line that names no removal release. |
| `ash report` | `ash results report` | |
| `ash merge` | `ash results merge` | |
| `ash inspect findings` | `ash results inspect findings` | `ash inspect sarif-fields` moves the same way. |
| `ash build-image` | `ash container build` | It takes the same options. |

`ASH_SOURCE_DIR` still names the directory to scan when you give no path argument, and
`ASH_WORKSPACE` and `ASH_WORKSPACE_CONFIG` still name the file and the policy file of a
workspace scan when you give no file argument and no `--workspace-config`. A scan that
reads one of them that way prints one deprecation line for it, as `--source-dir` does, and
ASH 4.0 stops reading them for a scan. The argument, or `--workspace-config`, takes its
place and prints no line.

A workspace scan reached without its subject, `ash scan --workspace project.code-workspace`
or `ash --workspace project.code-workspace`, still runs in 3.9 and prints one deprecation
line that names `ash scan workspace <file>`.

`ash results diff` and `ash results trend` are new in 3.9, so they have no older spelling
to move from.

A local pre-commit hook (`repo: local`) whose `entry` runs `ash --mode precommit` moves to
`ash scan fs --mode precommit`, as any other command line does.

The [Python API](../reference/python-api.md) and the
[MCP server's tools](../reference/mcp-tools.md) do not use these spellings, so nothing
changes there.

## What the old spellings print {#warnings}

In a project with one hardcoded password, a scan with the old root spelling finds it and
exits 2, as it always did:

<!-- doctest: run expect-exit=2 -->
```bash
ash --only-scanners detect-secrets --offline --no-progress
```

Before anything else, it prints:

<!-- doctest: output -->
```text
Deprecated: `ash` without a subcommand runs a scan; that form is deprecated and will be removed in ASH v4.0. Use `ash scan fs <path>`.
```

`ash scan` with no subject says so too:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --only-scanners detect-secrets --offline --no-progress
```

<!-- doctest: output -->
```text
Deprecated: `ash scan` without a subject is deprecated and will be removed in ASH v4.0. Use `ash scan fs <path>`.
```

So does `--source-dir`, typed on `ash scan fs`:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan fs --source-dir . --only-scanners detect-secrets --offline --no-progress
```

<!-- doctest: output -->
```text
Deprecated: `--source-dir` is deprecated and will be removed in ASH v4.0. Give the directory as the argument: `ash scan fs <path>`.
```

A command that moved under `ash results` names the spelling that replaces it, and then
prints what it always printed:

<!-- doctest: run -->
```bash
ash report
```

<!-- doctest: output -->
```text
DeprecationWarning: 'ash report' is deprecated and is removed in 4.0. Use 'ash results report' instead; 'ash report' keeps its current behavior until then.
# ASH security scan report
```

## Find the old spellings a pipeline still uses {#find}

Every old spelling says so on standard error, so the log of a pipeline shows what is left
to move. Keep a scan's standard error, then look for the deprecation lines:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan fs . --only-scanners detect-secrets --offline --no-progress 2> ash-stderr.log
```

<!-- doctest: run expect-exit=1 -->
```bash
grep -E 'Deprecated|DeprecationWarning' ash-stderr.log
```

`grep` finds no line and exits 1, because this command line uses only the new spellings.
The same search finds the other options 3.9 deprecates, such as `--scanners`, which
prints a `DeprecationWarning:` line naming `--only-scanners` and `--add-scanners`.
