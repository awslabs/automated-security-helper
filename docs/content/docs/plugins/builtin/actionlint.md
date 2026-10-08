# actionlint

[actionlint](https://github.com/rhysd/actionlint) checks GitHub Actions workflow files: workflow syntax, `${{ }}` expression types, script injection from untrusted event data, hard-coded container credentials, `if:` conditions that are always true, undefined `needs:` jobs, unknown runner labels, and more. It is a single Go binary, MIT licensed. zizmor, also a builtin scanner, flags template injection too; ASH does not deduplicate across scanners, so with both enabled such a step is reported by each, under its own rule id.

## Enabling it

actionlint is a builtin scanner, enabled by default: a default scan runs it. `scanners.actionlint.enabled: false` in the ASH config turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), as for every builtin scanner; `ash dependencies install` and the container image provide it.

## Installing

| Where | How |
|---|---|
| Container image | Installed (pinned v1.7.12) |
| Local / pip install | `ash dependencies install --tool actionlint` downloads the pinned release asset and checks its SHA256 |
| Nix | `pkgs.actionlint` is in the flake's scanner set |

The pinned version and digests are in `automated_security_helper/utils/tool_downloads.py`, transcribed from the release's `actionlint_<version>_checksums.txt`.

## What is scanned

ASH passes actionlint every `*.yml` / `*.yaml` file whose parent directory is `.github/workflows`, at any depth, taken from the scan set. Files excluded by `.gitignore`, `.ignore` or `global_settings.ignore_paths`, and anything under ASH's output directory, are not passed. A workflow that is a symlink pointing outside the scan root is skipped with a warning. Other YAML is never linted.

If the scan root has no workflow files, actionlint does not run and the scanner reports `SKIPPED` (it evaluated nothing). A scan that selects only actionlint (`--scanners actionlint`) on such a tree therefore exits 1 with "Scan ran no scanners".

## Configuration

```yaml
scanners:
  actionlint:
    enabled: true           # the default; false turns it off
    options:
      config_file: null     # actionlint config, relative to the source directory
      shellcheck: null      # "shellcheck" to enable it; null disables the integration
      pyflakes: null        # "pyflakes" to enable it; null disables the integration
      severity_threshold: null
      scan_timeout: 1800
```

### `config_file`

ASH always hands actionlint an explicit `-config-file`:

1. `options.config_file`, if set. A path that does not exist fails the scan with `ERROR`.
2. Otherwise `.github/actionlint.yaml` or `.github/actionlint.yml` directly under the scan root.
3. Otherwise an empty config ASH writes into its own results directory.

actionlint's own discovery walks up to the nearest `.git` directory, so whether a config applied used to depend on whether the checkout had a `.git` (often missing in container builds and archives), and a scan of a subdirectory could pick up a config from outside the scan root. The explicit file removes both.

If the config has `paths.<glob>.ignore` patterns, actionlint drops matching findings before ASH sees them. ASH logs a warning naming the patterns. Prefer ASH suppressions, which are reported and tracked.

### `shellcheck` and `pyflakes`

actionlint runs `shellcheck` on `run:` scripts and `pyflakes` on `shell: python` steps when they are on `PATH`, and skips them silently when they are not. Results would then depend on what a host happens to have installed, so ASH disables both by default (`-shellcheck= -pyflakes=`).

To use them, set the option to `shellcheck` or `pyflakes`, which is looked up on `PATH` and in ASH's bin directory. If the configured tool cannot be found or is not executable, the scanner reports `MISSING` rather than running without it. shellcheck and pyflakes findings are LOW severity. Neither is installed in the ASH container image.

Each option names the program actionlint pipes every `run:` script to, started from the root of the scanned tree. Set to a shell or an interpreter, that program runs the repository's code. ASH's config usually comes from the repository being scanned (`.ash/.ash.yaml`), so from a config file inside the scanned tree each option accepts only its own name. Another program, or an absolute path, is honored only from `--config-overrides` or a config file outside the scanned tree:

```bash
ash scan --config-overrides 'scanners.actionlint.options.shellcheck=/opt/shellcheck/bin/shellcheck'
```

Whoever sets it, a program that resolves inside the scanned tree is refused, and so is a relative path. A refused value is logged as a warning and actionlint runs with that integration off.

## Severity mapping

actionlint has no severity of its own; its upstream SARIF template marks everything `error`. ASH maps each finding by its rule kind (the SARIF `ruleId`):

| Severity | SARIF level | Findings |
|---|---|---|
| HIGH | `error` | `expression` findings whose message says the value is "potentially untrusted" (script injection), and `credentials` (a password written into `container:` or `services:`) |
| MEDIUM | `warning` | `if-cond` (an `if:` that is always true), `permissions`, and `deprecated-commands` for `set-env` / `add-path` |
| LOW | `note` | everything else: `syntax-check`, other `expression` errors, `action`, `runner-label`, `job-needs`, `glob`, `matrix`, `events`, `id`, `env-var`, `shell-name`, `workflow-call`, `set-output` / `save-state` deprecations, `shellcheck`, `pyflakes` |

A kind not in this table (a newer actionlint) is LOW and logged once. A binary whose version differs from the pin runs with a warning, since the mapping keys on kinds and message text of the pinned release. The snippet of a `credentials` finding (the password itself) is not copied into the report. With the default MEDIUM threshold, lint-only findings do not fail a scan and script injection does.

## Suppressions

Rule, path and line suppressions work as for any scanner. The rule id is the actionlint kind:

```yaml
global_settings:
  suppressions:
    - rule_id: runner-label
      path: .github/workflows/self-hosted.yml
      reason: Custom self-hosted runner labels
    - rule_id: expression
      path: .github/workflows/triage.yml
      line_start: 20
      line_end: 20
      reason: Title is only echoed into the job log
```

Script injection is reported under `expression`, the same kind as expression type errors, so suppressing `expression` by rule alone also suppresses injection findings. Use a line-scoped suppression for those.

Package- and symbol-scoped suppressions do not apply: a workflow file has no package identity and no function or class symbols.

## Offline

actionlint makes no network calls (its action metadata is compiled in), so it works unchanged with `ASH_OFFLINE=true` and on air-gapped hosts. A run that exceeds `scan_timeout` is killed and reported as `ERROR` with a timeout message.

## Errors

actionlint exits 0 when clean, 1 when it found problems, 2 for a bad command line and 3 for a fatal error such as an unreadable file or an invalid config. ASH treats 0 and 1 as success and everything else as `ERROR`, as it does output that is not the expected JSON and an exit code that contradicts the findings. The raw output is kept at `scanners/actionlint/<target>/actionlint.json` (with `credentials` snippets removed) and the SARIF ASH built from it at `actionlint.sarif`.

## Relation to zizmor

zizmor also audits GitHub Actions workflows, including template injection. If ASH's zizmor scanner is enabled as well, the two run independently: they share no configuration or results, and an injection is reported once by each.
