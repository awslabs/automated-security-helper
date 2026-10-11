# Choose scanners

ASH runs every enabled scanner it has, and all 16 built-in scanners are enabled by default (on Windows, semgrep and opengrep are off by default). This page shows how to see which scanners a scan will run, turn some off, add community scanners, and set a scanner's options. The [scanner reference](../reference/scanners.md) lists each scanner with its tool and options.

## See which scanners will run

```bash
ash plugin list
```

`ash plugin list` prints the scanners, reporters and converters, with an **Enabled** column that applies the config ASH finds in the current directory. Add `--show-versions` to see which scanner tools are installed on this machine.

A scanner whose tool is not installed is recorded MISSING, and the scan exits 1, because `fail_on_incomplete_scanners` is on by default. Install the tools with `ash dependencies install` (see [Manage scanner tools](../docs/advanced-usage.md)), run the scan in the [container image](run-in-a-container.md), or turn the scanner off. [Set the gate](set-the-gate.md#incomplete) explains the incomplete-scan rule.

## Turn scanners off

To turn a scanner off for every scan of a repository, set `enabled: false` in its config section:

```yaml
scanners:
  cfn-guard:
    enabled: false
  trivy:
    enabled: false
```

Use the hyphenated names that `ash plugin list` shows (`detect-secrets`, `cdk-nag`, `npm-audit`). A misspelled name is ignored without a warning, so the scanner keeps running.

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
- A name in both lists is excluded. If every scanner `--scanners` names is also excluded, ASH refuses the run with exit 1.
- An unknown name in `--scanners` gets a warning when another name matches; when none matches, the run fails with exit 1. An unknown name in `--exclude-scanners` is ignored.

A scanner that is turned off, not selected or excluded is recorded SKIPPED and does not affect the exit code. If no scanner runs at all, the scan exits 1.

### Run only Python-based scanners

`--python-only` keeps the scanners whose tools ASH installs from Python packages: bandit, cdk-nag, cfn-lint, checkov, detect-secrets, semgrep and zizmor. ASH records the other scanners SKIPPED.

ASH checks each scanner's tool before it applies `--python-only`. A non-Python scanner whose tool is not installed is therefore recorded MISSING, not SKIPPED, and the scan exits 1. On a machine without those tools, exclude them as well, or turn them off in the config.

## Add community scanners {#community}

Community scanners ship with ASH in plugin modules that load only when you name them. Add the module to `ash_plugin_modules`:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins
scanners:
  ferret-scan:
    enabled: true
```

You can also load a module for one run with `--ash-plugin-modules` or the `ASH_PLUGIN_MODULES` environment variable. The modules and their scanners are listed in [Community plugins](../docs/plugins/community/index.md). Two modules send data off the host, `ash_snyk_plugins` (the scanned source) and `ash_aws_plugins` (findings), and ASH loads them only from operator configuration: `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides`, or a config file outside every git checkout and outside the scanned directory. From a repository's config they are ignored with a warning.

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

Every scanner has `severity_threshold`, which overrides the global threshold for that scanner ([Set the gate](set-the-gate.md#thresholds)), and `scan_timeout`, in seconds (default 1800; `null` for none). The other options are per scanner and listed in the [scanner reference](../reference/scanners.md). ASH accepts an option it does not know and ignores it, so check the spelling against the reference.

## Keep one scanner of an overlapping pair {#overlap}

Some default scanners cover the same ground, and ASH does not deduplicate their findings: the same problem reported by two scanners is two findings, each with its own rule ID ([How ASH works](../concepts/how-ash-works.md#findings-are-merged-not-deduplicated)).

| Scanners | What they both do |
|---|---|
| semgrep and opengrep | Run the same `p/ci` rule set by default |
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

Some scanner options name a file, a rule directory or a program for the scanner's tool to use. A repository's config could use them to hide findings or to make a tool run code, so ASH honors them only from operator configuration: `--config-overrides`, or a config file outside every git checkout and outside the scanned directory, named with `--config` or `ASH_CONFIG`. A config file that an MCP client delivered counts as repository configuration.

| Scanner | Operator-only options | Path may be inside the scanned repository |
|---|---|---|
| actionlint | `config_file` | yes |
| actionlint | `shellcheck`, `pyflakes`: a repository may set only the plain names `shellcheck` and `pyflakes`, or leave them empty; a path is operator-only | no |
| cfn-guard | `rules_paths` | yes |
| cfn-lint | `config_file` | no |
| gitleaks | `config_file`, `baseline_path` | yes |
| trivy | `config_file`, `ignore_file`, `secret_config_file` | no |
| zizmor | `config_file` | yes |
| zizmor | `online_audits` | not a path |
| trivy-repo (community) | `config_file`, `ignore_file`, `secret_config_file`, `module_dir` | no |
| hadolint (community) | `config_file` | no |

When a repository's config sets one of these, ASH ignores the value, logs a warning that names the option, and runs the scanner with its default. When the operator names a path that does not exist, the scanner fails (ERROR), and the scan exits 1.

<!-- doctest: illustrative reason="names a gitleaks config file that the sample project does not have" -->
```bash
ash --source-dir . --config-overrides scanners.gitleaks.options.config_file=/etc/ash/gitleaks.toml
```

These scanners do not read the repository's own config files for their tools, such as `.gitleaks.toml`, `.gitleaksignore`, `zizmor.yml`, `actionlint.yaml`, `trivy.yaml`, `.trivyignore`, `.cfnlintrc` or `.hadolint.yaml`. To use one, point the option at it from operator configuration. Some other scanners do read tool config files they find in the source directory by name, such as bandit's `.bandit` and grype's `.grype.yaml`; [Configuration trust model](../concepts/trust-model.md#not-protected) lists them.
