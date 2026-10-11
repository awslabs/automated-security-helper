# Migrate from v2

ASH v3 is a rewrite. v2 was a shell script that ran every scanner in a container. v3 is
a Python program that runs scanners on your machine by default, reads a configuration
file, writes different output files, and uses exit codes with fixed meanings. This page
lists what changes for a v2 user and what to do about each.

| | v2 | v3 |
|---|---|---|
| Install | clone the repository and add it to `PATH` | install from GitHub with uv, pipx, or pip ([Install ASH](install.md)) |
| Where scanners run | always in a container built on each run | on your machine, or in a container with `ash --mode container` |
| Configuration | none | `.ash/.ash.yaml`, with ignore paths, suppressions, thresholds, and scanner settings |
| Output | `ash_output/aggregated_results.txt` | `.ash/ash_output/`, with a JSON results file and a `reports/` directory |
| Exit code | the highest exit code of any scanner | 0, 1, 2, 3, or 4, each with one meaning |
| Requirements | a container runtime | Python 3.10 to 3.14, plus scanner tools or a container runtime |

## Install v3

1. Remove the v2 clone from your `PATH`. The v3 repository still has an `ash` script at
   its root, so a clone on your `PATH` can shadow the `ash` command you install.
2. Install v3 as described in [Install ASH](install.md).
3. Choose where the scanners run:
   - To run them on your machine, as v3 does by default, install them with
     `ash dependencies install`. See [Manage scanner tools](../docs/advanced-usage.md).
   - To keep v2's behavior of running everything in a container, run
     `ash --mode container`. See [Run ASH in a container](run-in-a-container.md).

## Command-line options

v2's options were parsed by its shell scripts. In v3, `ash` with no subcommand is the
same as `ash scan`.

| v2 option | v3 |
|---|---|
| --source-dir | `--source-dir`, unchanged |
| --output-dir | `--output-dir`. The default is now `.ash/ash_output` inside the source directory, instead of `ash_output`. |
| --ext, -extension | removed. Choose scanners with `--scanners` and `--exclude-scanners`, or turn them on and off in the configuration. |
| --format text, --format json | changed. `--format` is now an alias of `--output-formats`, which takes reporter names such as `sarif` or `html`. `json` is not one of them, so a v2 `--format json` exits 2 with `'json' is not a valid format`. `text` is the text reporter, so a v2 `--format text` keeps only `ash.summary.txt` in `reports/`. v3 always writes its JSON results file. |
| --offline | `--offline`. In local mode the scanners then need their databases and rules already on the machine; see [Run ASH offline](run-offline.md). |
| --offline-semgrep-rulesets | `--offline-semgrep-rulesets`, changed. In v2 it also turned on offline mode. In v3 it only chooses the rulesets an offline container image is built with, and does nothing in local mode; pass `--offline` as well. |
| --build-target, --no-build, --no-run, --force | unchanged, for container mode |
| --no-cleanup | accepted. v3 keeps its working files by default; `--cleanup` removes them. |
| -c, --no-color | `--no-color`. `-c` now means `--config`. |
| -s, --single-process | `ash --strategy sequential` |
| -o, --oci-runner | `--oci-runner` and `-o`, unchanged. The `OCI_RUNNER` variable also works. |
| -p, --preserve-report | removed. Use a different `--output-dir` for each run. `-p` now means `--progress`. |
| -d, --debug | `--debug` and `-d`, unchanged |
| -q, --quiet | `--quiet` only |
| -v, --version | `--version` only. `-v` now means `--verbose`. |
| -h, --help | `--help` only |
| --container-uid -u, --container-gid | `--container-uid` (`-u`) and `--container-gid` (`-g`) |
| --finch, -f | removed; use `ash --mode container --oci-runner finch`. `-f` now means `--output-formats`. |

Remove v2 options from your scripts. `ash` rejects an option it does not know with exit
code 2, which is also the exit code for findings, so a CI job can read a stale command
line as a failed scan. `ash scan` ignores options it does not know, so with it a v2
option is dropped without a warning.

## Configuration

v2 had no configuration file. It skipped files matched by `.gitignore` and `.ignore`
files, and in a git repository it scanned a clone, so only committed files were
scanned.

v3 also honors `.gitignore` and `.ignore`, but it scans the working tree, so
uncommitted and untracked files that are not ignored are scanned too. Expect findings in
files v2 never saw. Neither version reads a `.ashignore` file.

Everything else is set in a configuration file. `ash config init` writes a starting
file at `.ash/.ash.yaml`. In it you can:

- skip paths, each with a reason, under `global_settings.ignore_paths`;
- suppress findings, each with a reason and an optional expiration date, under
  `global_settings.suppressions`;
- set the severity that fails a scan, `global_settings.severity_threshold`;
- turn scanners on and off, and set their options, under `scanners`.

See [Configure ASH](configure.md) and [Suppress findings](suppress-findings.md). The
scanners' own inline comments, such as bandit's `# nosec`, still work.

## Output

v2 wrote one text file, `ash_output/aggregated_results.txt`, made by joining each
scanner's text output. v3 writes `.ash/ash_output/` in the scanned directory:

- `ash_aggregated_results.json`: every scanner's status and findings.
- `reports/`: the same results in several formats. `ash.summary.txt` and
  `ash.summary.md` are the closest to v2's file; there are also `ash.html`,
  `ash.sarif`, `ash.junit.xml`, `ash.csv`, and others.
- `scanners/`: each scanner's raw output.
- `ash.log`: the scan's log.

`ash report` prints a summary of the latest results in the terminal. See
[Output files](../reference/output-files.md).

## Exit codes

v2 exited with the highest exit code that any scanner returned, so any finding or any
error gave a nonzero code. v3 uses fixed codes:

| Code | Meaning |
|---|---|
| 0 | nothing actionable |
| 1 | the scan is incomplete, for example a scanner is MISSING, or ASH hit an error |
| 2 | actionable findings |
| 3 | invalid configuration |
| 4 | workspace error |

Two defaults affect CI jobs that you move from v2:

- Only findings at or above MEDIUM severity fail the scan. Low-severity findings that
  failed a v2 scan pass in v3. To fail on them too, set
  `global_settings.severity_threshold` to `LOW`.
- A scanner whose tool is missing fails the scan with code 1, even when nothing else is
  wrong. Install the tools, use container mode, or exclude the scanners you do not run.

See [Set the gate](set-the-gate.md) and [Exit codes](../reference/exit-codes.md).

## Scanners

v2 ran git-secrets, bandit, semgrep, checkov, cfn_nag, cdk-nag, npm audit, grype, and
syft, choosing them by the file types it found. v3 runs actionlint, bandit, cdk-nag,
cfn-guard, cfn-lint, cfn-nag, checkov, detect-secrets, gitleaks, grype, npm-audit,
opengrep, semgrep, syft, trivy, and zizmor. A scanner whose tool is installed shows as
SKIPPED when the project has nothing for it to scan.

- git-secrets is gone. detect-secrets and gitleaks look for secrets.
- semgrep runs the `p/ci` ruleset by default. v2 ran `--config=auto`.
- More scanners can report the same problem, because v3 does not merge findings from
  different scanners.

See [Scanners reference](../reference/scanners.md).

## Modes

v2 always ran in a container. v3 has four modes, chosen with `--mode`:

- `local`, the default: scanners run on your machine.
- `container`: ASH builds its image on your machine and scans inside it. It looks for
  finch, docker, nerdctl, and podman in that order, as v2 did.
- `precommit`: a faster scan with a smaller set of scanners, for pre-commit hooks.
- `nix`: scanners come from ASH's Nix flake. No release has it yet; see
  [Install ASH](install.md#nix-mode).

## pre-commit and CI

The `ash` pre-commit hook ID still exists. In v3 it runs a local scan in precommit mode
instead of a full container scan. See [Run ASH with pre-commit](pre-commit.md).

v2's CI examples cloned the repository and ran its script. In v3, install ASH from its
GitHub URL with a pinned version in the job, or call the reusable GitHub Actions
workflow. See [Add ASH to a GitHub Actions pipeline](../getting-started/ci.md).
