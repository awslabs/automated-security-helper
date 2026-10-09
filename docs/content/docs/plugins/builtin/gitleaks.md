# Gitleaks scanner

[gitleaks](https://github.com/gitleaks/gitleaks) finds credentials (API keys, tokens, private keys) by matching its rule set against file contents. ASH runs it as `gitleaks dir` over the files in the scan target. It does not scan git history.

detect-secrets stays on by default and is unaffected; the two can run side by side. ASH does not deduplicate across scanners, so a secret both of them find is reported twice, once under each scanner's name and rule id; suppress it for each scanner, or enable only one.

## Enabling it

Gitleaks is a builtin scanner, enabled by default: a default scan runs it. `scanners.gitleaks.enabled: false` in the ASH config turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), as for every builtin scanner; `ash dependencies install` and the container image provide it.

## Installing gitleaks

- Container image: included. The image installs the pinned release (currently v8.30.1) whether or not you enable the scanner.
- Local mode: `ash dependencies install` downloads the pinned release asset from GitHub and checks it against the SHA256 recorded in `automated_security_helper/utils/tool_downloads.py` before installing it. A download that does not match is refused.
- Nix mode: the flake supplies nixpkgs' `gitleaks`.
- A `gitleaks` already on `PATH` is used as is. ASH is tested against the pinned version.

gitleaks makes no network calls while scanning, so it works offline and in air-gapped environments with no extra setup.

## Configuration

```yaml
scanners:
  gitleaks:
    enabled: true
    options:
      # A gitleaks TOML config, relative to the source directory.
      config_file: null
      # A gitleaks JSON report whose findings gitleaks ignores (--baseline-path).
      baseline_path: null
      # Skip files larger than this many megabytes.
      max_target_megabytes: null
      # Seconds before the gitleaks process is killed. Inherited by every scanner.
      scan_timeout: 1800
```

### Which gitleaks config is used

The scanned repository's own gitleaks configuration is not used. A `.gitleaks.toml` can replace gitleaks' rules or allowlist every path, and a `.gitleaksignore` drops findings by fingerprint, before ASH sees the report: what they hide is neither reported nor counted as suppressed. Tune findings with ASH suppressions, which are both.

1. `options.config_file`, when the operator set it: from `--config-overrides`, or an ASH config file outside the scanned tree. A path that does not exist fails the scan rather than falling back to gitleaks' default rules.
2. Otherwise, if `GITLEAKS_CONFIG` or `GITLEAKS_CONFIG_TOML` is set in the environment, gitleaks resolves the config from it. Under `--sandbox` those variables are not passed in, and step 3 applies.
3. Otherwise gitleaks' default rules, through a config ASH writes that extends them and adds nothing. It is passed as `--config`, so gitleaks does not fall back to a `.gitleaks.toml` in the scanned tree.

`config_file` or `baseline_path` set by an ASH config inside the scanned tree (`.ash/.ash.yaml`) is ignored with a warning, and a `.gitleaks.toml` or `.ash/.gitleaks.toml` in the tree is noted at INFO. The operator's files may be absolute paths or point outside the source directory.

gitleaks always reads `.gitleaksignore` at the root of the path it scans, whatever `--gitleaks-ignore-path` says, and has no flag to turn that off. When the scan root has one, ASH runs gitleaks again on each file it names, one file per run (such a run reads no `.gitleaksignore`), and reports the findings the first run dropped. A failed re-run fails the scan.

gitleaks's options are described by the JSON schema (`automated_security_helper/schemas/AshConfig.json`) and listed below.

## Severity

gitleaks reports no severity of its own. ASH rates every gitleaks finding CRITICAL (SARIF `level: error`), the same rating it gives detect-secrets findings, so a credential reads the same whichever scanner found it. gitleaks has no per-rule confidence to grade on: each rule says "a credential of this kind is present".

## Secret values never reach ASH's output

ASH always runs gitleaks with `--redact=100`, so gitleaks writes `REDACTED` in place of each secret in its report and its log. ASH also overwrites any report snippet that is not `REDACTED` before the result is stored, so the value cannot appear in `ash_aggregated_results.json`, the SARIF, or any other report.

## Suppressing findings

Use ASH suppressions: they are recorded in the reports and counted. gitleaks' own mechanisms drop findings before ASH sees the report, so only these still apply:

- A `gitleaks:allow` comment on the line with the secret.
- `[[allowlists]]` in an operator's `config_file` (paths, regexes, stopwords, per-rule).
- An operator's `baseline_path`: a previous gitleaks JSON report whose findings are ignored.

The scanned repository's `.gitleaks.toml` and `.gitleaksignore` do not apply (see above).

ASH suppressions use the gitleaks rule id (for example `github-pat`, `aws-access-token`) and the path relative to the source directory:

```yaml
global_settings:
  suppressions:
    - rule_id: github-pat
      path: tests/fixtures/settings.py
      line_start: 12
      line_end: 12
      reason: Fabricated token used by the test suite
```

Rule, path and line suppressions apply. A `symbol` suppression (the enclosing function or class) applies to a finding in a source language ASH can parse. Package-scoped suppressions do not apply: a gitleaks finding is about a file, not a dependency. `global_settings.ignore_paths` removes gitleaks findings under those paths, and findings inside ASH's own output directory are always removed.

## Exit codes

ASH runs gitleaks with `--exit-code=2`, because gitleaks otherwise exits 1 both when it finds leaks and when it fails. 0 (nothing found) and 2 (leaks found) are success; any other code, including 1 for an unreadable config or path, makes the scanner report an error and the scan exit 1.

## Known limitations

- Working tree only. Secrets that were committed and later removed are not reported; run `gitleaks git` separately if you need history.
- gitleaks reads ASH's output directory when it sits inside the source tree (the default `.ash/ash_output`). Findings there are discarded by ASH, but the files are still read.
- The SARIF `semanticVersion` that gitleaks 8.30.1 writes is wrong (`v8.0.0`), so ASH removes it; the real version comes from `gitleaks --version`.
