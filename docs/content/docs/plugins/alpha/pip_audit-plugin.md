# pip-audit (alpha plugin)

[pip-audit](https://github.com/pypa/pip-audit) (Apache-2.0, a PyPA project) checks the pinned dependencies of Python requirements files against a vulnerability database and reports the advisories that affect them. ASH runs it once per requirements file in the scanned directory and reports each advisory on the line of the file that names the package. ASH pins pip-audit 2.10.1.

## Enabling it

pip-audit is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_pip_audit_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_pip_audit_plugins
```

With the module listed, `pip-audit` runs by default, like every other scanner. `scanners.pip-audit.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners pip-audit` without the module listed is refused, with a message naming the module to add. If pip-audit is not installed, an online scan installs it with `uv tool install` before running it; offline, or when that install fails, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

There is no license or account gate: pip-audit needs no key or sign-in. Its one requirement is network access to the vulnerability service (see Offline below), which ASH declares to its sandbox.

## Installing pip-audit

pip-audit is a Python package and ASH runs it through `uv`.

- **Local mode:** `ash dependencies install --tool pip-audit`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_pip_audit_plugins"]'`), runs `uv tool install pip-audit==2.10.1`.
- **Container mode:** the ASH container image installs pip-audit 2.10.1 the same way when it is built, for root and again for the image's non-root user, and the build fails if `pip-audit --version` does not run.
- **Nix mode:** the flake does not supply pip-audit. Install it with `ash dependencies install`, or have it on `PATH`.
- Any `pip-audit` already on `PATH` that satisfies the pinned constraint is also used.

## What is scanned

ASH looks in the scan set (`.gitignore` and `.ignore` applied, without `node_modules/`, `.venv/` and `venv/` directories, ASH's output directory and `global_settings.ignore_paths`) for requirements files and runs pip-audit on each one:

- `requirements.txt` and variants such as `requirements-dev.txt`, `dev-requirements.txt` and `requirements_test.txt`;
- any `.txt` file directly under a directory named `requirements`.

Symbolic links are not followed. pip-audit also reads `pyproject.toml` and installed environments; ASH does not use those modes.

Every run uses these flags, each as one `--flag=value` token:

```text
pip-audit --format=json --vulnerability-service=pypi --progress-spinner=off
          --desc=on --aliases=on --no-deps --disable-pip --timeout=15
          --cache-dir=<results dir> --output=<results dir>/pip-audit.json
          --requirement=<requirements file>
```

`--no-deps --disable-pip` keep pip out of the run: pip-audit then reads the file itself and looks up each pinned version, and nothing in the scanned tree is built or installed. The consequence is that **every requirement must be pinned to an exact version** (`name==1.2.3`). A file with an unpinned requirement makes pip-audit exit 1 without a report, and ASH reports that file as a failed target, not as clean. Generate a pinned file with `uv pip compile` or `pip freeze`.

pip-audit has no SARIF output. ASH reads its JSON report (`{"dependencies": [...], "fixes": [...]}`) and converts it.

A dependency pip-audit could not audit (it names a skip reason, for example a package that is not on the index) is a failed target too: the dependency was not checked, so the run is not a clean scan. Exclude the file with `global_settings.ignore_paths` if it holds only packages that are not on the index.

## Configuration

<!-- doctest: config kind=other reason="alpha plugin options are validated by the plugin module, which a bare config check does not load" -->
```yaml
scanners:
  pip-audit:
    enabled: true
    options:
      # Where advisories come from: pypi (default) or osv. Both need network access.
      vulnerability_service: pypi
      # Socket timeout in seconds for each service request.
      request_timeout: 15
      # Seconds for one requirements file (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override, or null for the global one.
      severity_threshold: null
      # Version constraint for the installed pip-audit; unset uses ==2.10.1.
      tool_version: null
      install_timeout: 300
```

None of these options can hide a finding or point at a file, so none is operator-only. ASH never passes `--ignore-vuln`, `--index-url`, `--extra-index-url`, `--fix` or `--strict`; use [ASH suppressions](../../../concepts/suppressions.md) to accept an advisory.

## Severity

pip-audit reports no severity, score or vector for an advisory. Every result is `error` in SARIF and HIGH in ASH: a published advisory affects an exact version the project pins, and the fix is to change the pin. Rating them lower would drop real findings under ASH's default `severity_threshold` of `MEDIUM`, and pip-audit gives nothing to rate them by. The result's `issue_severity` and its SARIF level are set together.

Each result is on the first line of the requirements file that names the package, with the advisory id (`PYSEC-…`, `GHSA-…` or `CVE-…`) as the rule id, the aliases and fixed versions in the message, and a link to the advisory on osv.dev in the rule.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: PYSEC-2019-179
      path: requirements.txt
      line_start: 2
      line_end: 2
      reason: the vulnerable code path is not reachable in this service
```

Package-scoped and symbol-scoped suppressions do not apply: a pip-audit result is on a requirements line, not in code.

## Offline and air-gapped use

pip-audit asks a vulnerability service (PyPI's JSON API or OSV) about every dependency and has no offline mode: it has no `--offline` flag, and `--dry-run` audits nothing. Run offline, ASH does not run it, because a tool that cannot ask would have nothing to report and a scan that said so would read as clean. The scanner is reported `MISSING` with the reason, and `--exclude-scanners pip-audit` leaves it out. Under `--sandbox` the scanner declares a network need, as `npm-audit` does.

## License

pip-audit is Apache-2.0-licensed. ASH installs it from PyPI with `uv`, pinned to 2.10.1 (the release its license read was made on); the ASH container image pre-installs it at that version and ships the wheel's `LICENSE` beside it (the `pip-audit` entry in `THIRD_PARTY_LICENSES`).
