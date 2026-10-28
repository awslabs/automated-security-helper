# Choose scanners

ASH runs every enabled scanner it has, and all 16 built-in scanners are enabled by default (on Windows, semgrep and opengrep are off by default). This page shows how to see which scanners a scan will run, turn some off, add community scanners, and set a scanner's options. The [scanner reference](../reference/scanners.md) lists each scanner with its tool and options.

## See which scanners will run

```bash
ash plugin list
```

`ash plugin list` prints the scanners, reporters, and converters, with an **Enabled** column that applies the config ASH finds in the current directory. Add `--show-versions` to see which scanner tools are installed on this machine.

A scanner whose tool is not installed is recorded MISSING, and the scan exits 1, because `fail_on_incomplete_scanners` is on by default. Install the tools with `ash dependencies install` (see [Manage scanner tools](../docs/advanced-usage.md)), run the scan in the [container image](run-in-a-container.md), or turn the scanner off. [Set the gate](set-the-gate.md#incomplete) explains the incomplete-scan rule.

A scanner that has nothing to scan in the source is the exception: it is recorded SKIPPED, whether or not its tool is installed, and the scanner's `skipped_reason` in `ash_aggregated_results.json` says why. cdk-nag, cfn-nag, cfn-guard, and cfn-lint have nothing to scan when no scanned file is a CloudFormation template; actionlint when there is no GitHub Actions workflow; zizmor when there is no workflow or composite action; and npm-audit when no `package.json` has a lockfile (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, or `pnpm-lock.yaml`) beside it. When a scanner's tool is not installed, ASH counts a `.json`, `.yaml`, or `.yml` file that does not parse as a template, and records the scanner MISSING, when the file's text has `AWSTemplateFormatVersion` or a `Type: AWS::` resource type, as a damaged template does. With the tool installed, the scanner passes over such a file and is SKIPPED.

In a repository with no CloudFormation template and one detect-secrets finding, cfn-nag is SKIPPED, so this scan exits 2 for the finding rather than 1, also on a machine without cfn-nag's tool:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets,cfn-nag --offline --no-progress
```

## Turn scanners off

To turn a scanner off for every scan of a repository, set `enabled: false` in its config section:

```yaml
scanners:
  cfn-guard:
    enabled: false
  trivy:
    enabled: false
```

Use the hyphenated names that `ash plugin list` shows (`detect-secrets`, `cdk-nag`, and `npm-audit`). A misspelled name is ignored without a warning, so the scanner keeps running.

To choose scanners for one run, use `--scanners` to run only the ones you name, or `--exclude-scanners` to run all but those:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

<!-- doctest: illustrative reason="runs every scanner, which needs each scanner's tool installed" -->
```bash
ash --source-dir . --exclude-scanners trivy,grype
```

Both options take a comma-separated list or can be repeated, and the `ASH_SCANNERS` and `ASH_EXCLUDED_SCANNERS` environment variables set them too. How they combine with the config:

- A scanner runs only when it is enabled in the config, named by `--scanners` (when given), and not named by `--exclude-scanners`.
- `--scanners` cannot run a scanner the config disables. To turn one back on for a run, override the config: `--config-overrides scanners.bandit.enabled=true`.
- A name in both lists is excluded. If every scanner `--scanners` names is also excluded, ASH refuses the run with exit 5, the code for a usage error.
- An unknown name in `--scanners` gets a warning when another name matches; when none matches, ASH refuses the run with exit 5. When some match, the scan runs those, and the results record the names that matched nothing in `metadata.requested_scanners_not_run` ([Output files](../reference/output-files.md)); the console summary lists them after the scanner table, as in `Requested but not run: trivyy (no registered scanner has this name)`. An unknown name in `--exclude-scanners` excludes nothing, and a warning names it; the scan still runs, and the results do not record the name.

A scanner that is turned off, not selected, or excluded is recorded SKIPPED and does not affect the exit code. If every selected scanner is SKIPPED, including when none of them has a file to scan, the scan exits 1 (with `fail_on_incomplete_scanners` on, the default).

### Run only Python-based scanners

`--python-only` keeps the scanners that need nothing but Python: bandit, cfn-lint, checkov, detect-secrets, semgrep, and zizmor. ASH applies it before it checks the scanners' tools, so every other scanner is recorded SKIPPED whether or not its tool is installed, and does not affect the exit code. When the run selects no Python-only scanner, as with `--python-only --scanners grype`, no scanner runs and the scan exits 1.

## Add community scanners {#community}

Community scanners ship with ASH in plugin modules that load only when you name them. Add the module to `ash_plugin_modules`:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins
scanners:
  ferret-scan:
    enabled: true
```

You can also load a module for one run with `--ash-plugin-modules` or the `ASH_PLUGIN_MODULES` environment variable. The modules and their scanners are listed in [Community plugins](../docs/plugins/community/index.md). Two modules send data off the host, `ash_snyk_plugins` (the scanned source) and `ash_aws_plugins` (findings), and ASH loads them only from an operator source: `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides`, or a config file outside every git checkout and the scanned directory ([Configuration trust model](../concepts/trust-model.md#how-the-tier-is-decided)). From any other config file they are ignored with a warning.

## Set a scanner's options

Each scanner's options go under `scanners.<name>.options`:

```yaml
scanners:
  bandit:
    options:
      confidence_level: high
      severity_threshold: HIGH
      scan_timeout: 600
```

Every scanner has `severity_threshold`, which overrides the global threshold for that scanner ([Set the gate](set-the-gate.md#thresholds)), and `scan_timeout`, in seconds (default 1800; `null` for none). The other options are per scanner and listed in the [scanner reference](../reference/scanners.md). An option the scanner does not have makes the config invalid (exit 3), also for a scanner the run does not select. When a declared option is close to the unknown one, the error names it:

<!-- doctest: run expect-exit=3 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides scanners.bandit.options.severity_level=HIGH
```

```text
Unknown key 'severity_level' (did you mean 'severity_threshold'?) in these plugin options.
```

An option belongs under `options`, not beside `enabled`. ASH refuses a config that sets one directly in the scanner's section (exit 3), and the error says to move the key under `options`:

<!-- doctest: run expect-exit=3 -->
```bash
cat > section-key.yaml <<'EOF'
project_name: payments-api
scanners:
  bandit:
    enabled: true
    severity_threshold: HIGH
EOF
ash config validate --config section-key.yaml
```

## Keep one scanner of an overlapping pair {#overlap}

Some default scanners cover the same ground, and ASH does not deduplicate their findings: the same problem reported by two scanners is two findings, each with its own rule ID ([How ASH works](../concepts/how-ash-works.md#findings-are-merged-not-deduplicated)).

| Scanners | What they both do |
|---|---|
| semgrep and opengrep | Run the same `p/ci` ruleset by default |
| grype and trivy | Report known vulnerabilities in dependencies |
| detect-secrets and gitleaks | Find secrets in the source |

The community scanner trivy-repo runs trivy as well. To keep one of each pair, turn the other off:

```yaml
scanners:
  opengrep:
    enabled: false
  trivy:
    enabled: false
  gitleaks:
    enabled: false
```

Keeping both reports more and costs scan time. A suppression matches findings by rule ID, so a suppression for one scanner's rule leaves the other scanner's finding in place.

## Options only the operator can set {#operator-only}

Some scanner options name a file, a rule directory, or a program for the scanner's tool to use, or choose which part of a tool's own config applies, whether the tool sends usage data to its vendor, or which release of the tool runs. For the scanners in this table, ASH honors these options only from an operator source: `--config-overrides`, or a config file outside every git checkout and the scanned directory, named with `--config` or `ASH_CONFIG` ([The scanned tree](../concepts/trust-model.md#scanned-tree)). A config in an ops checkout of its own is not an operator source here. A config file that an MCP client delivered is limited the same way, and under the MCP server's default policy one that sets these options is refused ([What a delivered config cannot set](mcp-server.md#what-a-delivered-config-cannot-set)).

| Scanner | Operator-only options | Path may be inside the scanned repository |
|---|---|---|
| actionlint | `config_file` | yes |
| actionlint | `shellcheck`, `pyflakes`: a repository may set only the plain names `shellcheck` and `pyflakes`, or leave them empty; a path is operator-only | no |
| bandit | `config_file` | yes |
| cfn-guard | `rules_paths` | yes |
| cfn-lint | `config_file` | no |
| checkov | `config_file` | no |
| detect-secrets | `baseline_file` | no |
| gitleaks | `config_file`, `baseline_path` | yes |
| grype | `config_file` | yes |
| opengrep | `config`, `patterns`, and `metrics` other than `off` | yes |
| semgrep | `config`, and `metrics` other than `off` | yes |
| syft | `config_file` | yes |
| trivy | `config_file`, `ignore_file`, `secret_config_file` | no |
| zizmor | `config_file` | yes |
| zizmor | `online_audits` | not a path |
| ferret-scan (community) | `config_file` | no |
| ferret-scan (community) | `profile`, `use_default_config` | not a path |
| snyk-code (community) | `honor_tree_exclusions` | not a path |
| trivy-repo (community) | `config_file`, `ignore_file`, `secret_config_file`, `module_dir` | no |
| trivy-repo (community) | `disable_telemetry` set to `false` | not a path |

`tool_version`, in the section of every scanner and converter, is operator-only too: it chooses which release of the tool ASH installs and accepts.

When a repository config sets one of these to a value other than the operator's, ASH ignores the value, logs a warning that names the option and says how to keep it, and runs the scanner with the operator's value or its default (for trivy's `ignore_file` and `secret_config_file`, with the file the matching `TRIVY_IGNOREFILE` or `TRIVY_SECRET_CONFIG` environment variable names, if you set one). When an operator source names a path that does not exist, the scanner fails (ERROR; MISSING for actionlint's `shellcheck` and `pyflakes`), and the scan exits 1. bandit, grype, and syft are the exception: they run with an empty config, and bandit logs a warning.

<!-- doctest: illustrative reason="names a gitleaks config file that the sample project does not have" -->
```bash
ash --source-dir . --config-overrides scanners.gitleaks.options.config_file=/etc/ash/gitleaks.toml
```

These scanners do not read the repository's own config files for their tools, such as `.gitleaks.toml`, `.gitleaksignore`, `zizmor.yml`, `actionlint.yaml`, `.bandit`, `bandit.yaml`, `bandit.toml`, `.grype.yaml`, `.syft.yaml`, `trivy.yaml`, `.trivyignore`, or `.cfnlintrc`. To use one, point the option at it from an operator source.

The options in this table are the only scanner options ASH limits this way. Other scanners' options apply from any repository config, and detect-secrets still reads a `.secrets.baseline` it finds in the scanned directory. semgrep and opengrep do not read a `.semgrepignore` there. When you scan a repository you do not control, set scanner options from an operator source and pass your config with `--config`, so the repository config is not read; [Configuration trust model](../concepts/trust-model.md#not-protected) lists what that does not cover.
