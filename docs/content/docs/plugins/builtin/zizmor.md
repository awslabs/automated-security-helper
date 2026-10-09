# zizmor (GitHub Actions)

[zizmor](https://docs.zizmor.sh) is a static analyzer for GitHub Actions. ASH runs it
over a repository's workflows and composite actions and reports template
injection, dangerous triggers, credential persistence, unpinned actions,
excessive permissions and the rest of zizmor's
[audits](https://docs.zizmor.sh/audits/).

actionlint, also a builtin scanner, flags template injection from untrusted event data too.
ASH does not deduplicate across scanners, so with both enabled such a step is
reported by each, under its own rule id.

## Enabling it

zizmor is a builtin scanner, enabled by default: a default scan runs it. `scanners.zizmor.enabled: false` in the ASH config turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), as for every builtin scanner; `ash dependencies install` and the container image provide it.

## What gets scanned

ASH passes zizmor two kinds of file, taken from its scan set so `.gitignore`,
`.ashignore` and `global_settings.ignore_paths` apply:

- workflows: `*.yml` and `*.yaml` directly inside a `.github/workflows` directory
  (the only place GitHub runs a workflow from; subdirectories are not scanned);
- composite actions: every `action.yml` and `action.yaml`.

Files under `node_modules/` and virtual environments are skipped, and so is a
file that is a symlink resolving outside the scan root, with a warning: zizmor
would read it where it points. A repository
with neither kind of file does not start zizmor; the scanner reports `SKIPPED`
with zero findings, the same as cfn-nag on a repository with no templates.

A file named `action.yml` that is not a GitHub Actions definition is not counted.
A workflow or action that zizmor cannot load (a YAML syntax error, or a file in
`.github/workflows` that is not a valid workflow) is counted as a target that
failed, which `--fail-on-incomplete-scanners` reports.

## Configuration

```yaml
scanners:
  zizmor:
    enabled: true
    options:
      persona: regular        # regular, pedantic or auditor
      config_file: null       # zizmor config; relative to the source dir, or absolute
      online_audits: false    # see "Network access and tokens"
      tool_version: ">=1.29.0,<2.0.0"
      install_timeout: 300
      scan_timeout: 1800
      severity_threshold: null
```

- `persona`: zizmor's [persona](https://docs.zizmor.sh/usage/#using-personas).
  `regular` has the fewest false positives, `pedantic` adds code-smell findings,
  and `auditor` reports everything.
- `config_file`: passed as `--config`, when the operator set it: from
  `--config-overrides`, or an ASH config file outside the scanned tree. A relative
  path is resolved against the source directory; an absolute path may point outside
  it (a config shared across repositories). Without it, ASH runs zizmor with
  `--no-config`, so a `zizmor.yml` or `.github/zizmor.yml` in the scanned
  repository is not read: a config there can disable audits or ignore findings,
  which zizmor then never reports, so they would be neither in ASH's results nor
  counted as suppressed. `config_file` set by an ASH config inside the scanned tree
  is ignored with a warning. A configured file that
  does not exist fails the scan rather than being ignored. zizmor quotes the
  offending text of a config it cannot parse in its error, and that error reaches
  ASH's log and the scanner's stderr log, so do not point this at a file holding
  anything else.
- `tool_version`: the pip-style constraint for installing zizmor.

## Network access and tokens

zizmor always runs with `--offline` unless `online_audits: true`. Offline is the
default because zizmor reads a GitHub token from `GH_TOKEN`, `GITHUB_TOKEN` or
`ZIZMOR_GITHUB_TOKEN` by itself, and a token that happens to be in a CI job's
environment is not permission to use it. While offline, ASH removes those three
variables from zizmor's environment.

`online_audits: true` disables `--offline` and lets those variables reach zizmor
unchanged, which enables the audits that query the GitHub API (for example
known-vulnerable actions and impostor commits). It is honored only when the
operator sets it, with `--config-overrides` or an ASH config file outside the
scanned tree; set by a config in the scanned tree, or by an MCP client, it is
ignored with a warning and zizmor runs offline without the tokens. ASH never
reads, copies or logs the token and never puts it on zizmor's command line.
ASH's own offline mode (`ASH_OFFLINE=true` or `ash scan --offline`) overrides
`online_audits`.

`ZIZMOR_CONFIG`, `ZIZMOR_OFFLINE` and `ZIZMOR_NO_ONLINE_AUDITS` are always
removed from zizmor's environment, so a scan's result depends on the repository
and the ASH config rather than on the shell it ran in. Use `config_file` instead
of `ZIZMOR_CONFIG`.

## Severity mapping

zizmor rates each finding with a severity and a confidence. ASH combines them:

| zizmor severity | confidence Medium or High | confidence Low |
|-----------------|---------------------------|----------------|
| High            | HIGH                      | MEDIUM         |
| Medium          | MEDIUM                    | LOW            |
| Low             | LOW                       | INFO           |
| Informational   | INFO                      | INFO           |

zizmor's scale stops at High, so no zizmor finding is CRITICAL. A low-confidence
finding is one zizmor expects to be wrong some of the time, so it is reported one
band lower. The SARIF `level` is set to match (HIGH `error`, MEDIUM `warning`, LOW
`note`, INFO `none`), and zizmor's own values stay on the result as
`properties["zizmor/severity"]` and `properties["zizmor/confidence"]`. A finding
missing either value keeps zizmor's own level.

With the default `MEDIUM` threshold, the low-confidence `artipacked` finding
(Medium, Low) is reported LOW and does not fail the scan on its own.

## Suppressions

Rule IDs are zizmor's audit names with a `zizmor/` prefix, for example
`zizmor/template-injection`. ASH suppressions by rule, path and line all apply:

```yaml
global_settings:
  suppressions:
    - rule_id: zizmor/dangerous-triggers
      path: .github/workflows/release.yml
      line_start: 3
      reason: "Runs only on tags pushed by maintainers"
```

zizmor's own [ignore comments](https://docs.zizmor.sh/usage/#ignoring-results)
(`# zizmor: ignore[template-injection]`) are honored as well, and so are the rules
of an operator's `config_file`; a `zizmor.yml` in the scanned repository is not
read. Package-scoped and symbol-scoped suppressions do not apply: zizmor reports
no packages, and a workflow has no functions or classes.

## Installation

`ash dependencies install` installs zizmor with `uv tool install`, and the ASH
container image ships it. ASH also uses any `zizmor` already on `PATH` whose
`zizmor --version` satisfies `tool_version`, which covers the nix flake (nixpkgs
supplies zizmor), Homebrew, and `cargo install`. Offline, ASH does not try to
install zizmor; install it first.

zizmor is MIT licensed.
