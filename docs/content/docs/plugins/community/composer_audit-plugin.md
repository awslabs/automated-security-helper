# Composer Audit (community plugin)

[Composer](https://getcomposer.org/) is the PHP dependency manager. Its [`composer audit`](https://getcomposer.org/doc/03-cli.md#audit) command checks the locked packages against the security advisories Packagist publishes, and reports packages their maintainers abandoned. ASH runs it as `composer audit --locked --format=json` over every `composer.lock` in the scan target and reports each advisory as a finding on the lock file.

## Enabling it

Composer Audit is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_composer_audit_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_composer_audit_plugins
```

With the module listed, `composer_audit` runs by default, like every other scanner. `scanners.composer_audit.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners composer_audit` without the module listed is refused, with a message naming the module to add. If Composer is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

There is no license or service gate: Composer is open source and the advisory data needs no account.

## Installing Composer

ASH does not bundle or install Composer, and `ash dependencies install` has nothing to install for this scanner. Install Composer 2.8 or later (the first release with `composer audit --abandoned`), and the PHP it needs, from <https://getcomposer.org/download/>. Any `composer` on `PATH` is used. The ASH container image does not include it.

## What is scanned

ASH looks for every `composer.lock` under the scan target and runs Composer once for each, in the directory that holds it. The directory also needs its `composer.json`; a lock file without one is a failed target. Lock files under `vendor/`, `node_modules/` and `.git/` are not audited (installed dependencies carry their own lock files), nor are links, nor paths excluded by `ignore_paths`. A tree with no lock file is reported as skipped, not as passed.

Each finding is on `composer.lock`, on the line that names the package. A finding names the package and the version the lock pins, the advisory title, the CVE when there is one, the affected version range and the advisory link. The rule id is the advisory id (for example `PKSA-...`). An abandoned package is reported under the rule `COMPOSER-ABANDONED`, with the replacement Composer suggests when there is one.

ASH passes `--no-plugins` and `--no-scripts`, so code the scanned project declares does not run during the audit, and `--abandoned=report` so abandoned packages are listed whatever the project configures. It removes `COMPOSER_POLICY` and `COMPOSER_AUDIT_ABANDONED` from Composer's environment.

## Configuration

```yaml
scanners:
  composer_audit:
    enabled: true
    options:
      # Seconds for the whole scan, every lock file included (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

The plugin has no options of its own. Nothing that could drop findings (ignored severities, skipping dev packages) is exposed.

## Severity

ASH severity and the SARIF level are set together from the advisory's severity:

| Composer severity | ASH severity | SARIF level |
|---|---|---|
| critical | CRITICAL | error |
| high | HIGH | error |
| medium | MEDIUM | warning |
| low | LOW | note |
| none (null) | MEDIUM | warning |
| any other value | HIGH | error |

An advisory with no severity is still a known vulnerability, so it is rated MEDIUM and not lower. A severity word Composer does not document errs to the more severe rating. An abandoned package is LOW (`note`): a maintenance finding with no known vulnerability.

## Exit status and failures

Composer's documentation lists exit code 0 for no issues and 1 for packages matching its policies. ASH accepts the exit codes 0 to 3 as "Composer ran", and then requires the output to be a JSON object with an `advisories` key. A run whose output is not that fails the scan whatever its exit code, which covers the exit 1 Composer gives, with a text message, for a lock file that holds nothing to audit. Any other exit code, a timeout, and an unreachable advisory repository also fail the scan, and the failure names the lock file. Composer's stderr is not copied into the scan's errors, because it can quote text from the scanned project.

## Limits

- The scanned project's `composer.json` can carry `config.audit` settings (ignored advisories, ignored severities) that Composer applies. No Composer flag that turns them off was found, so a project can hide advisories from this scanner. Advisories ignored that way are not reported.
- The audit needs the network and has no offline mode. With `--offline` the scanner is skipped.
- Locations are the package's line in `composer.lock`, not the line in `composer.json` that required it.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: PKSA-xxxx-xxxx
      path: composer.lock
      line_start: 120
      line_end: 120
      reason: not reachable from the application; fix scheduled
```

Package-scoped and symbol-scoped suppressions do not apply: a finding names a lock file and a line.

## Offline and air-gapped use

`composer audit` fetches advisories when it runs, so the scanner cannot run offline and is skipped under `--offline`. Run the scan online, or use a Composer repository mirror that serves advisories and configure it in the project's `composer.json`.

## License

Composer is MIT-licensed. ASH does not redistribute it: the system installation is used.
