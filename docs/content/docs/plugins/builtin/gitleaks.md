# Gitleaks scanner

[gitleaks](https://github.com/gitleaks/gitleaks) finds credentials (API keys, tokens, private keys) by matching its rule set against file contents. ASH runs it as `gitleaks dir` over the files in the scan target. It does not scan git history.

detect-secrets stays on by default and is unaffected; the two can run side by side. ASH does not deduplicate across scanners, so a secret both of them find is reported twice, once under each scanner's name and rule id; suppress it for each scanner, or enable only one.

## Enabling it

Gitleaks is a builtin scanner, enabled by default: a default scan runs it. `scanners.gitleaks.enabled: false` in the ASH config turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), as for every builtin scanner; `ash dependencies install` and the container image provide it.

gitleaks is a native binary, so `--python-only` does not run it.

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
      # A gitleaks TOML config; a relative path is taken from where it is set.
      config_file: null
      # A gitleaks JSON report whose findings gitleaks ignores (--baseline-path).
      baseline_path: null
      # Honor gitleaks:allow comments in the scanned tree. Off by default.
      honor_inline_ignores: false
      # Skip files larger than this many megabytes. Operator-only.
      max_target_megabytes: null
      # Seconds before the gitleaks process is killed. Inherited by every scanner.
      scan_timeout: 1800
      # This scanner's override of the global severity threshold. Every gitleaks
      # finding is CRITICAL, so any threshold still fails on them.
      severity_threshold: null
```

### Which gitleaks config is used

The scanned repository's own gitleaks configuration is not used. A `.gitleaks.toml` can replace gitleaks' rules or allowlist every path, and a `.gitleaksignore` drops findings by fingerprint, before ASH sees the report: what they hide is neither reported nor counted as suppressed. Tune findings with ASH suppressions, which are both.

1. `options.config_file`, when the operator set it: from `--config-overrides`, or an ASH config file outside every git checkout and the scanned directory (one that is not [repository-written](../../../concepts/trust-model.md#how-the-tier-is-decided)). A path that does not exist fails the scan rather than falling back to gitleaks' default rules.
2. Otherwise, if `GITLEAKS_CONFIG` or `GITLEAKS_CONFIG_TOML` is set in the environment, gitleaks resolves the config from it. Under `--sandbox` those variables are not passed in, and step 3 applies.
3. Otherwise gitleaks' default rules, through a config ASH writes that extends them and adds nothing. It is passed as `gitleaks --config`, so gitleaks does not fall back to a `.gitleaks.toml` in the scanned tree. ASH writes it outside the scanned tree, with the empty directory it passes as `gitleaks --gitleaks-ignore-path`, and removes both when the scan ends.

`config_file`, `baseline_path`, `max_target_megabytes` or `honor_inline_ignores` set by an ASH config inside any git checkout or the scanned directory (such as `.ash/.ash.yaml`), or by an MCP client, is ignored with a warning, and a `.gitleaks.toml` or `.ash/.gitleaks.toml` in the tree is noted at INFO. The operator's files may be absolute paths or point outside the source directory. A relative `config_file` or `baseline_path` is taken from the directory of the ASH config file that sets it, or from the working directory for `--config-overrides`, not from the source directory (see [Relative paths in the operator's settings](../../../how-to/configure.md#relative-paths)). A file the operator names may also be inside the scanned tree, unless that path leads out of the tree through a symlink: the scanned repository decides what is there, so such a path stops the scanner with an error and gitleaks is not run.

gitleaks always reads `.gitleaksignore` at the root of the path it scans, whatever `gitleaks --gitleaks-ignore-path` says, and has no flag to turn that off. When the scan root has one, ASH copies the files it names into a directory of its own, at the same paths, runs gitleaks once more over the copies (there is no `.gitleaksignore` there), and reports the findings the first run dropped. That directory is outside the scanned tree, in a directory of the scanner run's own made with mode 0700, and under `--sandbox` gitleaks can read it and cannot write to it. ASH reads `.gitleaksignore` the way gitleaks does (a line ends at a newline only, surrounding whitespace is trimmed as Go trims it, and a backslash in a path is a slash), so it re-scans the files gitleaks matched. Files the first run does not read are not copied: files under `.git` or another directory gitleaks' allowlists skip, files reached through a symlink, and anything that is not a regular file. A failed re-run fails the scan, and the copies are deleted when it ends. The re-run copies at most 10,000 files and runs within one `scan_timeout`; when the file names more, the rest are not re-scanned, a warning gives their number, and the scan exits 1 as incomplete, because a finding the file hides in them would not be reported.

A `.gitleaksignore` at the scan root that is a symlink, a FIFO or another file that is not a regular file, or one with a second hard link, stops the scanner with an error before gitleaks runs: gitleaks would open whatever the name points to and copy lines of it into its log.

gitleaks' options are described by the JSON schema (`automated_security_helper/schemas/AshConfig.json`) and listed above.

## Severity

gitleaks reports no severity of its own. ASH rates every gitleaks finding CRITICAL, in the summaries and in every report: the SARIF result has `level: error` and the finding carries CRITICAL as its own severity, which `ash.flat.json` and the CSV report read. A detect-secrets finding carries only `level: error`, so the summaries rate it CRITICAL too, while `ash.flat.json` and the CSV report read HIGH for it; the same credential found by both scanners can therefore read differently in those two reports. gitleaks has no per-rule confidence to grade on: each rule says "a credential of this kind is present".

## Secret values never reach ASH's output

ASH always runs `gitleaks --redact=100`, so gitleaks writes `REDACTED` in place of each secret in its report and its log. ASH also overwrites any report snippet that is not `REDACTED` before the result is stored, so the value cannot appear in `ash_aggregated_results.json`, the SARIF, or any other report.

gitleaks is a secrets scanner (tool type `SECRETS`), so a gitleaks finding is a secret finding: in ASH's reports the line it reports reads `[masked: a secret finding reports this line]` in every snippet, its own included (see "Secret values in reports" in the output formats page), and the Bedrock summary reporter counts gitleaks findings rather than sending them to the model. gitleaks' own report under `scanners/gitleaks/` keeps its `REDACTED`.

gitleaks' log repeats each line of a `.gitleaksignore` it cannot parse. ASH cuts those lines short in the log it keeps (`GitleaksScanner.stderr.log`), and does not quote gitleaks' log in error messages; an error names the log file instead.

## Suppressing findings

Use ASH suppressions: they are recorded in the reports and counted. gitleaks' own mechanisms drop findings before ASH sees the report, so only these still apply:

- A `gitleaks:allow` comment on the line with the secret, only when the operator sets `options.honor_inline_ignores: true` with `--config-overrides` or an ASH config file outside every git checkout and the scanned directory. By default ASH runs `gitleaks --ignore-gitleaks-allow`, so the comment hides nothing; set from a config inside a git checkout or the scanned directory, the option is ignored with a warning.
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

Rule, path and line suppressions apply. A `symbol` suppression (the enclosing function or class) applies to a finding in a source language ASH can parse. Package-scoped suppressions do not apply: a gitleaks finding is about a file, not a dependency. `global_settings.ignore_paths` removes gitleaks findings under those paths, and findings inside ASH's own output directory are removed, except in the files ASH extracted from archives and notebooks, and in files the repository committed there. In a git checkout, a file git tracks in that directory is the repository's and keeps its findings; outside a checkout nothing tells the repository's files from ASH's, and every finding there is removed.

## Exit codes

ASH runs `gitleaks --exit-code=2`, because gitleaks otherwise exits 1 both when it finds leaks and when it fails. 0 (nothing found) and 2 (leaks found) are success; any other code, including 1 for an unreadable config or path, makes the scanner report an error and the scan exit 1.

## Known limitations

- Working tree only. Secrets that were committed and later removed are not reported; run `gitleaks git` separately if you need history.
- gitleaks reads ASH's output directory when it sits inside the source tree (the default `.ash/ash_output`), because it has no option to skip a directory. ASH discards the findings there, except those in files the repository committed to that directory, but the files are still read. That directory holds the files ASH extracts from archives and notebooks; gitleaks scans those copies separately, so a secret in an archive is reported once, at its extracted path.
- The SARIF `semanticVersion` that gitleaks 8.30.1 writes is wrong (`v8.0.0`), so ASH removes it; the real version comes from `gitleaks --version`.
