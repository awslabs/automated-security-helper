# Composer Audit Plugin

[Composer](https://getcomposer.org/) (MIT) is the PHP dependency manager. Its [`composer audit`](https://getcomposer.org/doc/03-cli.md#audit) command checks the locked packages against the security advisories Packagist publishes, reports packages their maintainers abandoned, and reports locked versions that match a filter list, such as the `malware` list repositories advertise. ASH runs it as `composer audit --locked --format=json` over every `composer.lock` in the scan target and reports each advisory and each filter-list match as a finding on the lock file.

## Enabling it

Composer Audit is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_composer_audit_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_composer_audit_plugins
```

With the module listed, `composer-audit` runs by default, like every other scanner. `scanners.composer-audit.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners composer-audit` without the module listed is refused, with a message naming the module to add. If Composer or PHP is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

There is no license or service gate: Composer is open source and the advisory data needs no account.

## Installing Composer

ASH pins Composer 2.11.3 in the plugin's own install module (`ash_composer_audit_plugins/composer_install.py`: the version, the `composer.phar` release asset and the SHA-256 Composer publishes beside it). Install it with:

<!-- doctest: illustrative reason="downloads a release asset" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_composer_audit_plugins"]' --tool composer-audit
```

- **Local mode:** the command downloads the phar, refuses it unless it hashes to its pin, and places it in ASH's bin directory: as `composer` on Linux and macOS, and on Windows as `composer.phar` with a `composer.bat` launcher beside it (`@php "%~dp0composer.phar" %*`, the layout of the manual Windows install in [Composer's introduction](https://getcomposer.org/doc/00-intro.md)). On Windows the scanner runs the phar with `php` directly whenever the `composer.bat` or `composer.cmd` found on `PATH` has `composer.phar` beside it, so cmd.exe does not read the audit's arguments a second time.
- **PHP:** Composer is a PHP program, and ASH does not install PHP. Composer 2.11.3 needs PHP 7.2.5 or later on `PATH`; with no `php` there the scanner is `MISSING`.
- **Container and Nix modes:** the image and the flake do not supply Composer or PHP.
- Any `composer` already on `PATH` is also used. Composer 2.8 or later is needed (the first release with `composer audit --abandoned`).

## What is scanned

ASH looks for every `composer.lock` under the scan target and runs Composer once for each, in the directory that holds it. The directory also needs its `composer.json`; a lock file without one is a failed target. Lock files under `vendor/`, `node_modules/` and `.git/` are not audited (installed dependencies carry their own lock files), nor are links, nor paths excluded by `ignore_paths`. A tree with no lock file is reported as skipped, not as passed.

Each finding is on `composer.lock`, on the line that names the package, and carries the package name and the version the lock pins. An advisory finding names the advisory title, the CVE when there is one, the affected version range and the advisory link; the rule id is the advisory id (for example `PKSA-...`) and the link is the rule's help link. A filter-list match is reported under the rule `COMPOSER-FILTER-<list>` (`COMPOSER-FILTER-malware` for the `malware` list) and names the list entry's id, reason, listed versions and link. An abandoned package is reported under the rule `COMPOSER-ABANDONED`, with the replacement Composer suggests when there is one.

ASH runs `composer audit --no-plugins --no-scripts`, so code the scanned project declares does not run during the audit, and passes `composer audit --abandoned=report` so abandoned packages are listed whatever the project configures. It removes `COMPOSER_POLICY` and `COMPOSER_AUDIT_ABANDONED` from Composer's environment.

## Configuration

<!-- doctest: config kind=other reason="a scanner section shown in isolation" -->
```yaml
scanners:
  composer-audit:
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

An advisory with no severity is still a known vulnerability, so it is rated MEDIUM and not lower. A severity word Composer does not document errs to the more severe rating. A match in the `malware` filter list is CRITICAL (`error`), and a match in any other filter list is HIGH (`error`), the more severe choice for a list whose meaning ASH cannot read. An abandoned package is LOW (`note`): a maintenance finding with no known vulnerability.

## Exit status and failures

Read in Composer 2.11.3's source: the audit exits 0 when no policy failed and 1 when a policy set to fail matched (an advisory or a filter-list entry, by default), and two runs exit without writing JSON: a lock file with no packages exits 0 when `composer.json` requires nothing, and 1 when it requires something. ASH accepts the exit codes 0 to 3 as "Composer ran", and then requires the output to be a JSON object with an `advisories` key. A run whose output is not that fails the scan whatever its exit code, which covers both runs without JSON. Any other exit code, a timeout, and an unreachable advisory repository also fail the scan, and the failure names the lock file. Composer's stderr is not copied into the scan's errors, because it can quote text from the scanned project.

## Limits

- The scanned project's `composer.json` can carry `config.policy` settings, and the older `config.audit` ones, that Composer applies: ignore lists for advisories and filter lists, and ignored severities. No Composer flag that turns them off was found, so a project can hide advisories from this scanner. Advisories ignored that way are not reported. A project that turns the advisories audit off altogether (`config.policy: false`) gets no advisory results from Composer, and its lock file is a failed target instead.
- Composer's `cooldown` entries (locked versions newer than a `policy.cooldown` period the project configured) are not reported: they are a release-age policy, not a finding about the package.
- The audit needs the network and has no offline mode. With `--offline` the scanner is skipped.
- Locations are the package's line in `composer.lock`, not the line in `composer.json` that required it.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner, and so do package-scoped ones: each finding carries the package name and the locked version.

```yaml
global_settings:
  suppressions:
    - rule_id: PKSA-xxxx-xxxx
      path: composer.lock
      package_name: guzzlehttp/psr7
      package_version: 1.8.3
      reason: not reachable from the application; fix scheduled
```

Symbol-scoped suppressions do not apply: a finding names a lock file and a package, not a symbol.

## Offline and air-gapped use

`composer audit` fetches advisories when it runs, so the scanner cannot run offline and is skipped under `--offline`. Run the scan online, or use a Composer repository mirror that serves advisories and configure it in the project's `composer.json`.

## License

Composer is MIT licensed. ASH does not redistribute it: the pinned phar is downloaded when you install it (it carries the repository `LICENSE` inside it), or the system installation is used. Nothing of Composer is shipped in the ASH Python package or the ASH container image.
