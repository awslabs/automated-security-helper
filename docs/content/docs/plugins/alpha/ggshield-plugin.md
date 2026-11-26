# ggshield (community plugin)

[ggshield](https://github.com/GitGuardian/ggshield) is the command line client of GitGuardian, a hosted secret detection service. ASH runs it as `ggshield secret scan path --recursive` over the scan target and reads the SARIF it writes. ASH pins ggshield 1.56.1.

> **ggshield uploads the files it scans.** Unlike the builtin `gitleaks` and `detect-secrets` scanners, the detection happens on GitGuardian's servers: the content of every file ggshield reads is sent to the GitGuardian API. GitGuardian states that it keeps call metadata and does not store file content; ASH does not verify that. Enable this scanner only for code you are allowed to send to a third party.

## Enabling it

Two steps, both explicit. Listing the module makes the scanner available. It stays off until you enable it, and it does not run without an API key.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ggshield_plugins

scanners:
  ggshield:
    enabled: true
```

<!-- doctest: illustrative reason="runs a full scan and calls the GitGuardian API" -->
```bash
export GITGUARDIAN_API_KEY=<your key>
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_ggshield_plugins
```

The gate:

- **No key, no scan.** Without `GITGUARDIAN_API_KEY` in the environment the scanner is reported `MISSING`, with a message that names the variable, and the scan exits 1 (the incomplete-scan gate), so a scan never reads as clean because nothing was checked. A blank value counts as unset. ASH does not read the credentials `ggshield auth login` stores.
- **Network required.** Every scan calls the GitGuardian API. Under `ASH_OFFLINE` the scanner is skipped. Under `--sandbox` the scanner gets network access and only the `GITGUARDIAN_` environment variables.
- **Nothing ASH was told to leave out is uploaded.** ggshield has no exclusion ASH can rely on, so a run is refused, with the reason in the error, when `global_settings.ignore_paths` is set, or when ASH's own output directory is inside the scanned tree (pass `--output-dir` with a directory outside the tree).
- Your API key is not written to the scan log.

The `GITGUARDIAN_INSTANCE` and `GITGUARDIAN_API_URL` variables that select a self-hosted or EU GitGuardian instance reach ggshield too.

## Installing ggshield

ggshield is a Python package and ASH runs it through `uv`.

- **Container mode and local mode:** `ash dependencies install --tool ggshield`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_ggshield_plugins"]'`), installs the pinned release with `uv tool install`. An existing `ggshield` on `PATH` is used as well.
- **Nix mode:** the flake does not supply ggshield. Install it with `ash dependencies install`, or have it on `PATH`.

## What is scanned

ggshield is handed the whole target as an absolute path and walks it itself, skipping what its built-in defaults exclude (its `.git` and `node_modules` style wildcards). ASH passes `--all-secrets` so that findings ggshield would discard by its own ignore reasons still reach ASH, where suppressions are reported and counted. It does not pass `--ignore-known-secrets`, `--exclude`, `--use-gitignore` or `--exit-zero`.

ggshield reads a `.gitguardian.yaml` from the project root of its working directory, and that file can hide findings. ASH runs it from a new empty directory outside the scanned tree, so a `.gitguardian.yaml` in the scanned repository is not read. Locations in the report are mapped back to source-relative paths.

The report holds no secret value: ggshield writes the detector name, the match types and positions, and a hash fingerprint. ASH overwrites any snippet text with `REDACTED`.

## Configuration

```yaml
scanners:
  ggshield:
    enabled: false # true to opt in
    options:
      # Version constraint for the ggshield install, in pip requirement syntax.
      # Unset, ASH uses the release the report reader was written against.
      tool_version: null
      # Seconds allowed for the install.
      install_timeout: 300
      # Seconds for the whole ggshield scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no option that reads a file from the scanned tree or hides findings, so no option is restricted to the operator.

## Exit status

ggshield exits 0 when it finds nothing and 1 when it finds secrets; ASH accepts both. 2 (usage), 3 (authentication error), 4 (GitGuardian unavailable) and 128 (unexpected error) fail the scan with a message that names the cause. ggshield's own error output is kept in the scanner's log file and is not copied into the scan's errors, because it can quote the scanned tree. A run that writes no report, or a report ASH cannot read, fails the scan.

## Severity

ggshield results carry no severity of their own. Every result is `error` in SARIF and CRITICAL in ASH: each one says a secret of one detector's kind is present, which is how ASH rates the builtin `gitleaks` scanner too. With ASH's default `severity_threshold` of `MEDIUM`, every finding fails the scan.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule is the detector's display name, which is what ggshield writes as the SARIF rule id:

```yaml
global_settings:
  suppressions:
    - rule_id: Generic High Entropy Secret
      path: tests/fixtures/example.py
      line_start: 4
      line_end: 4
      reason: a documented example value, not a credential
```

Package-scoped and symbol-scoped suppressions do not apply: no ggshield finding names a package or a symbol. A `.gitguardian.yaml` in the scanned tree is not read (see "What is scanned").

## Offline and air-gapped use

This scanner cannot run offline: every scan calls the GitGuardian API. Under `ASH_OFFLINE` it is skipped. Use the builtin `gitleaks` or `detect-secrets` scanners, or the Betterleaks plugin, where scanned files must stay on the host.

## License

ggshield is MIT-licensed. ASH does not redistribute it: it is installed from PyPI with `uv`, and the GitGuardian service it calls has its own terms of use.
