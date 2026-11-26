# Titus Plugin

[Titus](https://github.com/praetorian-inc/titus) finds secrets in files. It is Praetorian's Go port of Nosey Parker, with rules derived from Nosey Parker and Kingfisher, and ships 502 rules (counted from the v1.3.0 report). ASH runs `titus scan` over the scan target: the files as they are on disk, not git history, which is what ASH's builtin gitleaks and detect-secrets scanners read too. This plugin was written against release v1.3.0.

## Enabling it

Titus is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_titus_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_titus_plugins
```

With the module listed, `titus` runs by default, like every other scanner. `scanners.titus.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners titus` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

There is no license or service gate: Titus is a local binary, and ASH passes no flag that validates a secret against its provider or calls an outside API. Titus runs beside the builtin `gitleaks` and `detect-secrets` scanners, not instead of them, so a secret more than one finds is reported once by each.

## Installing Titus

ASH pins Titus v1.3.0 in the plugin's own install module (`ash_titus_plugins/titus_install.py`: the version, one release executable per platform and a SHA256 for each, taken from the release's `checksums.txt`). Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_titus_plugins"]' --tool titus
```

A download that does not hash to its pin is refused. Linux and macOS on x86_64 and arm64, and Windows on x86_64, have release executables. If `titus` is already on `PATH`, ASH uses it. The ASH container image installs it the same way.

## What is scanned

Titus is handed the whole target and walks it itself, skipping what its built-in ignore defaults exclude. ASH runs:

<!-- doctest: illustrative reason="shows the argv ASH passes to the titus binary" -->
```bash
titus scan --format=sarif --output=:memory: --accessibility=private --context-lines=0 -- .
```

- `titus scan --format=sarif` prints SARIF 2.1.0 on standard output, which ASH reads. Titus has no report-file flag.
- `titus scan --output=:memory:` keeps Titus' finding datastore in memory, so no `titus.ds` is written into the scanned tree.
- `titus scan --accessibility=private` applies Titus' private-code score penalty. Its default, `auto`, detects public repositories through the git remote and the GitHub API, a network call.
- `titus scan --context-lines=0` leaves text around a match out of the output.

ASH never passes any of these, so the built-in default rules run, rules marked noisy stay off, nothing in the scanned tree selects rules, and nothing calls a provider API:

- `titus scan --validate`, which checks each secret against its provider's API
- `titus scan --score-scope`, which calls external APIs to work out a secret's scope for its score
- `titus scan --rules` (a custom rules file or directory) and `titus scan --ruleset` (which ruleset to load)
- `titus scan --ignore`, which replaces the built-in ignore defaults with a gitignore-style file
- `titus scan --include-noisy`, which turns on the rules marked noisy

A finding is reported at the file and line, with the matched text replaced by `REDACTED` in the report. ASH's own output directory sits inside the source tree by default, so Titus reads it; ASH drops every result under it.

## Configuration

```yaml
scanners:
  titus:
    enabled: true
    options:
      # Seconds for the whole Titus scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

Titus has no option of its own in ASH.

## Severity

Titus gives every result a score from 0 to 100, written as `security-severity` (the score divided by ten). ASH rates the result from it and sets the SARIF level to match:

| Titus score | ASH severity | SARIF level |
|---|---|---|
| 80 and up | CRITICAL | `error` |
| 60 up to 80 | HIGH | `error` |
| 40 up to 60 | MEDIUM | `warning` |
| 20 up to 40 | LOW | `note` |
| below 20 | INFO | `none` |

These are Titus' own level bands (below 20 none, below 40 note, below 60 warning, otherwise error), with the top band split into CRITICAL and HIGH. A result with no score is rated from its level (error HIGH, warning MEDIUM, note LOW, none INFO). A result with no level is MEDIUM and one with an unknown level is HIGH, so an unexpected value errs severe. With ASH's default `severity_threshold` of `MEDIUM`, results rated MEDIUM and above fail the scan.

Because ASH passes `titus scan --accessibility=private`, every score carries Titus' -25 penalty for private code.

## Exit status

Only exit code 0 is accepted as a finished run. Titus' exit codes are not documented, so any other code fails the scan, even when output was printed.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: np.aws.1
      path: tests/fixtures/example.py
      line_start: 4
      line_end: 4
      reason: a documented example value, not a credential
```

Package-scoped and symbol-scoped suppressions do not apply: no Titus finding names a package or a symbol.

## Offline and air-gapped use

Titus reads only the files it is given and its rules are compiled into the binary, so with the flags above it behaves the same offline. Install it before going offline.

## License

Titus is Apache-2.0 licensed; its rules derive from Nosey Parker and Kingfisher, both Apache-2.0, with attribution in Titus' `NOTICE` file. The ASH container image redistributes the pinned release binary, so it carries the repository `LICENSE` and `NOTICE` at the pinned commit beside it (the `titus` entry in `THIRD_PARTY_LICENSES`); the release publishes bare executables, with no archive around them. Nothing of Titus is shipped in the ASH Python package itself.
