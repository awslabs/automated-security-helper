# Gitleaks scanner (opt-in)

[gitleaks](https://github.com/gitleaks/gitleaks) finds credentials (API keys, tokens, private keys) by matching its rule set against file contents. ASH runs it as `gitleaks dir` over the files in the scan target. It does not scan git history.

gitleaks is opt-in. A default `ash scan` does not run it and does not mention it: there is no gitleaks row in the summary, the reports or the SARIF until you enable it. detect-secrets stays on by default and is unaffected; the two can run side by side.

## Enabling it

Any one of these turns it on:

```yaml
# .ash/.ash.yaml
scanners:
  gitleaks:
    enabled: true
```

```bash
# For one run, alongside the default scanners
ash scan --config-overrides 'scanners.gitleaks.enabled=true'

# For one run, on its own
ash scan --scanners gitleaks
```

Naming gitleaks in `--scanners` runs it even when the config says `enabled: false`. `--exclude-scanners gitleaks` wins over both.

Once enabled it behaves like every other scanner. If the `gitleaks` binary is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), so an enabled scanner can never silently not run.

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

1. `options.config_file`, when set. A path that does not exist fails the scan rather than falling back to gitleaks' default rules.
2. Otherwise, if `GITLEAKS_CONFIG` or `GITLEAKS_CONFIG_TOML` is set in the environment, gitleaks resolves the config from it.
3. Otherwise `.gitleaks.toml`, then `.ash/.gitleaks.toml`, in the source directory.
4. Otherwise gitleaks' built-in rules.

ASH passes the file it finds in step 3 explicitly, so archives and notebooks that ASH extracts into its work directory are scanned with the same rules as the source tree. Path-based allowlists and `.gitleaksignore` fingerprints are matched against relative paths, so they do not match findings in that extracted content, which gitleaks reports by absolute path.

`config_file` and `baseline_path` may also be absolute paths or point outside the source directory. They are read from your ASH config, which ASH treats as trusted input.

`ash config init` and `ash config get` do not list gitleaks until you configure it, because ASH leaves an opt-in scanner at its defaults out of every config it writes. The JSON schema (`automated_security_helper/schemas/AshConfig.json`) lists all of its options.

## Severity

gitleaks reports no severity of its own. ASH rates every gitleaks finding CRITICAL (SARIF `level: error`), the same rating it gives detect-secrets findings, so a credential reads the same whichever scanner found it. gitleaks has no per-rule confidence to grade on: each rule says "a credential of this kind is present".

## Secret values never reach ASH's output

ASH always runs gitleaks with `--redact=100`, so gitleaks writes `REDACTED` in place of each secret in its report and its log. ASH also overwrites any report snippet that is not `REDACTED` before the result is stored, so the value cannot appear in `ash_aggregated_results.json`, the SARIF, or any other report.

## Suppressing findings

gitleaks' own mechanisms and ASH's suppressions both apply. gitleaks drops what its mechanisms allow before ASH sees the report; ASH then applies its suppressions to what is left.

gitleaks mechanisms:

- `[[allowlists]]` in the gitleaks config (paths, regexes, stopwords, per-rule).
- A `gitleaks:allow` comment on the line with the secret.
- `.gitleaksignore` in the source directory, one fingerprint per line in the form `<file>:<rule-id>:<line>`, for example `src/settings.py:github-pat:12`. ASH runs gitleaks from the source directory with the source as `.`, so file paths in fingerprints are relative to the source directory, the same as a plain `gitleaks dir .` run.
- `baseline_path`: a previous gitleaks JSON report whose findings are ignored.

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
