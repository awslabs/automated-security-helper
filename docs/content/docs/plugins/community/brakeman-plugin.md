# Brakeman (community plugin)

[Brakeman](https://brakemanscanner.org) is a static analysis scanner for Ruby on Rails applications. ASH runs it as `brakeman --format=sarif` over the scan target and reads the SARIF it writes. It looks for the vulnerability classes its checks cover, such as SQL injection, command injection, cross-site scripting and unsafe redirects, in the application's Ruby code and templates.

## License gate

Brakeman is free for non-commercial use only. Its terms are the Brakeman Public Use License, and the [Brakeman repository](https://github.com/presidentbeef/brakeman) says "Brakeman is free for non-commercial use." ASH does not install or redistribute it: the plugin has no install command and no pinned download, and `ash dependencies install` has nothing to do for it. You install Brakeman after reading its license, and listing this plugin's module is your statement that the license covers your use.

This is the same shape as the `snyk-code` plugin, which also needs a tool ASH does not provide: with the module listed and the tool absent, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate). The message names the license and the install command.

## Enabling it

Brakeman is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_brakeman_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_brakeman_plugins
```

With the module listed, `brakeman` runs by default. `scanners.brakeman.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners brakeman` without the module listed is refused, with a message naming the module to add.

## Installing Brakeman

ASH does not install it, in any mode. Install the gem yourself:

<!-- doctest: illustrative reason="installs a Ruby gem on the host" -->
```bash
gem install brakeman
```

Any `brakeman` on `PATH` is used. The container image does not include it, and the Nix flake does not supply it. A copy found only inside the scanned tree is refused, as for other scanners.

## What is scanned

Brakeman is handed the whole target (`--path`) and decides what to read. It treats a directory as a Rails application when it has a top-level `app` directory. A tree without one is not a failure: Brakeman exits 4 with "Please supply the path to a Rails application", ASH logs an INFO line and the scanner reports no findings. ASH never passes `--force-scan`.

The command, as measured with Brakeman 8.1.0:

```text
brakeman --format=sarif --output=<results>/<target_type>/brakeman.sarif --no-pager --quiet --no-progress --config-file=<empty yaml> --ignore-config=<empty json> --path=.
```

The working directory is the source directory, so reported paths are source-relative (for example `app/controllers/users_controller.rb`). For the converted target, `--path` is the absolute path of that directory.

## Configuration

```yaml
scanners:
  brakeman:
    enabled: true
    options:
      # Seconds for the whole Brakeman scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no options of its own, so nothing in the scanned tree or in an ASH config file can point Brakeman at a config or an ignore file.

Brakeman reads `config/brakeman.yml` from the scanned application, then `~/.brakeman/config.yml` and `/etc/brakeman/config.yml`, and `config/brakeman.ignore` from the application. ASH passes empty files outside the scanned tree for both (`--config-file` and `--ignore-config`), so the scanned repository cannot disable checks, skip files, load check code or hide findings. Tune the findings with ASH suppressions.

ASH also never passes `--allow-check-paths-in-config`, `--github-repo`, `--compare`, `--absolute-paths` or `--ensure-latest`.

## Exit status

| Exit code | Brakeman | ASH |
|---|---|---|
| 0 | no warnings | scan succeeds |
| 3 | warnings found | scan succeeds, findings reported |
| 4 | no Rails application found | no-op, no findings |
| anything else (5 to 9, 255, a signal) | not the latest version, missing checks, errors found, ignore-file notes, invalid option | the scan fails, even if a report is on disk |

A run that wrote no report, or one that is not valid SARIF, also fails the scan. A timeout fails the scan and says so. Brakeman's stderr is not copied into the scan's error lines, since its parse errors can quote the scanned code; it stays in the scanner's log file.

## Severity

Brakeman does not rate severity. It rates each warning with a confidence and writes it as the SARIF level. ASH keeps that reading and sets `issue_severity` to match, so the level and the severity always agree:

| Brakeman confidence | SARIF level | ASH severity |
|---|---|---|
| High | `error` | HIGH |
| Medium | `warning` | MEDIUM |
| Weak | `note` | LOW |

A result with no level is MEDIUM and `warning`, the level Brakeman's own writer falls back to. High confidence is HIGH and not CRITICAL: it says the finding is probably real, not how much damage it does. With ASH's default `severity_threshold` of `MEDIUM`, a high or medium confidence warning fails the scan.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. Rule ids are Brakeman's warning codes, written `BRAKE` plus four digits (for example `BRAKE0000` for SQL injection):

```yaml
global_settings:
  suppressions:
    - rule_id: BRAKE0000
      path: app/controllers/reports_controller.rb
      line_start: 12
      line_end: 12
      reason: the interpolated value is a constant column name
```

Package-scoped and symbol-scoped suppressions do not apply: no Brakeman finding names a package or a symbol.

## Offline and air-gapped use

Brakeman's checks are part of the gem and a scan makes no network call, so it behaves the same offline. Install the gem before going offline.

## License

Brakeman is not redistributed by ASH and has no entry in ASH's third-party license files. Its license (free for non-commercial use) is yours to read and accept before you install it.
