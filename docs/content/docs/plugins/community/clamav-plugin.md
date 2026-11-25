# ClamAV (community plugin)

[ClamAV](https://www.clamav.net/) is an open-source antivirus engine. ASH runs `clamscan --recursive` over the scan target and reports each file whose content matches a ClamAV signature. It looks for malware and known-bad files in the tree, which the builtin code and secret scanners do not.

## Enabling it

ClamAV is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_clamav_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_clamav_plugins
```

With the module listed, `clamav` runs by default, like every other scanner. `scanners.clamav.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners clamav` without the module listed is refused, with a message naming the module to add. If `clamscan` is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate). No license or service gate applies: ClamAV is GPL-2.0 licensed and ASH only runs it as a separate program.

## Installing ClamAV

ClamAV is a system package that ASH does not download or pin. Install it with your package manager, then fetch the signature database:

<!-- doctest: illustrative reason="installs a system package; the command depends on the platform" -->
```bash
sudo apt-get install clamav   # or: dnf install clamav, brew install clamav
sudo freshclam
```

- **Container mode:** the ASH image does not include ClamAV. Build an image that does, or mount a host install.
- **Nix mode:** the flake does not supply ClamAV; have `clamscan` on `PATH`.
- Any `clamscan` on `PATH` is used.

Without a signature database, `clamscan` exits 2 and the scan fails. When the newest `daily.cvd` or `daily.cld` in the usual database directories is more than 7 days old, ASH notes it at INFO in the scan log and goes on. The note never changes the result.

## What is scanned

ASH passes the whole target to `clamscan --recursive` and lets ClamAV walk it. It passes `--follow-dir-symlinks=0` and `--follow-file-symlinks=0`, so a link in the scanned tree never leads the scan outside it. It does not pass `--database`, `--move`, `--copy` or `--remove`: a database chosen by the tree could drop signatures, and the others change the scanned files. ASH's own output directory sits inside the source tree by default; findings under it are dropped.

ClamAV has no SARIF or JSON output. ASH has it write its report with `--log=FILE` and reads the documented text: `<path>: <signature> FOUND` for a detection, and the `SCAN SUMMARY` block that ends every scan. A log without the summary, or whose `Infected files` count differs from the number of `FOUND` lines, fails the scan, so a truncated log is never read as clean. A finding has no line number; it is reported at line 1 of the file.

## Configuration

```yaml
scanners:
  clamav:
    enabled: true
    options:
      # Seconds for the whole clamscan run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no option that reads a file or hides a finding, so none is operator-only.

## Exit status

| `clamscan` exit | ASH |
|---|---|
| 0 | scan passed, nothing found |
| 1 | scan completed, malware found |
| 2 | the scan fails: an error occurred, such as an unreadable file or no signature database |

Any other code fails the scan too, even when a log was written. An unreadable file fails the scan on purpose, because it may be the one that matters. The tool's stderr is not copied into the scan's error list, since it quotes file names from the scanned tree.

## Severity

Every detection is `error` in SARIF and HIGH in ASH. It is HIGH and not CRITICAL because a signature match says a file matches known malware or a known-bad pattern, not that it ran or can be exploited, and signature sets include potentially-unwanted-application and test signatures. With ASH's default `severity_threshold` of `MEDIUM`, every detection fails the scan.

## Suppressions

ASH suppressions by rule and path work as for any scanner. The rule id is the signature name:

```yaml
global_settings:
  suppressions:
    - rule_id: Win.Test.EICAR_HDB-1
      path: tests/fixtures/eicar.com
      line_start: 1
      line_end: 1
      reason: the standard antivirus test file, kept as a test fixture
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

`clamscan` reads only the files and the local signature database and makes no network call. Run `freshclam` before going offline, and update the database on your own schedule.

## License

ClamAV is licensed under the GPL-2.0. ASH does not redistribute it or link to it: the plugin runs the separate `clamscan` program you installed and reads its output.
