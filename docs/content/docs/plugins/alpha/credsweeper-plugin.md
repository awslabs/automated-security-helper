# CredSweeper (community plugin)

[CredSweeper](https://github.com/Samsung/CredSweeper) finds credentials in files. It matches candidates with rules, then scores each one with a small machine-learning model, so a finding carries a confidence and an ML probability. ASH runs it as `credsweeper --path` over the scan target: the files as they are on disk, not git history.

## Enabling it

CredSweeper is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_credsweeper_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_credsweeper_plugins
```

With the module listed, `credsweeper` runs by default, like every other scanner. `scanners.credsweeper.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners credsweeper` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING`.

CredSweeper runs beside the builtin `detect-secrets` and `gitleaks` scanners, not instead of them, so a credential more than one of them finds is reported once by each. There is no license or service gate: it needs no account and no key.

## Installing CredSweeper

CredSweeper is a Python tool. ASH installs it with uv, from PyPI, into its own tool environment.

<!-- doctest: illustrative reason="downloads and installs from PyPI" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_credsweeper_plugins"]' --tool credsweeper
```

- The default version constraint is `>=1.19.6,<2.0.0`, installed into a Python in `>=3.11,<3.14`. Set `scanners.credsweeper.options.tool_version` to change the constraint.
- Any `credsweeper` already on `PATH` is also used when uv is not available.
- Container and Nix modes do not supply CredSweeper. Install it with `ash dependencies install`, or have it on `PATH`.

## What is scanned

CredSweeper is handed the whole target and walks it itself. Its rules and its model ship in the package. A finding is reported at the file and line. ASH passes `credsweeper --hashed`, so the report the tool writes holds no credential text, and ASH never reads the matched line or value: the SARIF snippet is always `REDACTED`.

ASH's own output directory sits inside the source tree by default, so CredSweeper reads it. ASH drops every result under it, except for a file the repository committed there.

## Configuration

```yaml
scanners:
  credsweeper:
    enabled: true
    options:
      # Version constraint for the credsweeper install, in pip requirement syntax.
      tool_version: null
      # Seconds allowed for the tool install.
      install_timeout: 300
      # Seconds for the whole CredSweeper scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

ASH does not expose CredSweeper's own config, rules, ML threshold, deny list or `.gitignore` handling. Each either reads from the scanned tree or can hide findings, so the scanned repository would decide what is reported. Tune findings with ASH suppressions.

## How ASH runs it

Each option is one `--flag=value` token:

<!-- doctest: config kind=other reason="the argv ASH builds, not an ASH configuration" -->
```text
credsweeper --path=. --save-json=<results>/source/credsweeper.json --no-stdout --no-color --no-progress --hashed --no-error
```

`--no-error` keeps the exit code at 0 whether or not credentials are found, because CredSweeper uses 1 both for "found credentials" (with `--error`) and for a failed scan. A run that exits with anything other than 0 fails the scan, even if a report is on disk.

## Severity

CredSweeper rates each finding with a rule severity, a confidence and an ML probability. ASH rates by confidence and sets the SARIF level to match:

| CredSweeper confidence | ASH severity | SARIF level |
|---|---|---|
| strong | HIGH | error |
| moderate | MEDIUM | warning |
| weak | LOW | note |

A finding with no confidence, or one not in the table, is HIGH: the more severe choice when the tool's rating cannot be read. The ceiling is HIGH, not CRITICAL, because CredSweeper reports a candidate its model scored and does not validate the credential. The rule's severity and the ML probability are kept in the result's properties.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: Password
      path: tests/fixtures/example.py
      line_start: 4
      line_end: 4
      reason: a documented example value, not a credential
```

Package-scoped and symbol-scoped suppressions do not apply: no CredSweeper finding names a package or a symbol.

## Offline and air-gapped use

A scan reads only the files it is given, with a rule set and model that ship in the package, so it behaves the same offline. ASH does not install tools in offline mode: install CredSweeper before going offline.

## License

CredSweeper is MIT-licensed (Copyright 2021 Samsung). ASH installs it from PyPI with `uv` at run time and does not redistribute it: the ASH container image cannot build it (credsweeper depends on `pyjks`, whose `twofish` dependency is an sdist-only C extension, and the image carries no compiler), so the image does not carry it and `THIRD_PARTY_LICENSES` deliberately has no `credsweeper` entry.
