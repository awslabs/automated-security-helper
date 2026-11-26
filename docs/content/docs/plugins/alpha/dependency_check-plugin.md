# Dependency-Check (community plugin)

[OWASP Dependency-Check](https://github.com/dependency-check/DependencyCheck) is a software composition analysis tool. It identifies the third-party libraries in a tree from file names, hashes and package manifests (Java and .NET archives, `package-lock.json`, `requirements.txt`, Ruby, Go and others), matches them to CPE identifiers, and reports the known vulnerabilities that apply, mostly from the NVD. ASH runs it over the scan target and reads the SARIF report it writes. ASH pins release v13.0.0.

## Enabling it

Dependency-Check is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_dependency_check_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_dependency_check_plugins
```

With the module listed, `dependency-check` runs by default, like every other scanner. `scanners.dependency-check.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners dependency-check` without the module listed is refused, with a message naming the module to add. If the tool or Java is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Requirements and the opt-in gate

Two things must be true for it to run, and ASH checks both before starting the tool.

- **Java.** Dependency-Check is a Java program. With no `java` on `PATH` the scanner is `MISSING`.
- **Network.** The vulnerability database is downloaded from the NVD. Like `snyk-code`, the scanner is skipped under `--offline` and not run.

`NVD_API_KEY` is optional. Without it Dependency-Check still works, but the first database download is slow and rate limited, and ASH logs a warning. When the variable is set, ASH writes it to a mode 0600 properties file (`nvd.api.key`) in a directory outside the scanned tree that is removed when the run ends, and passes `--propertyfile=<file>`. The key is never on the command line, which ASH logs and the process table shows. The variable is passed through the scanner sandbox by name.

## Installing Dependency-Check

- **Local mode:** `ash dependencies install --tool dependency-check`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_dependency_check_plugins"]'`), downloads the v13.0.0 release zip from GitHub, checks it against the SHA-256 digest pinned in ASH, unpacks it into a `.dependency-check` directory beside ASH's bin directory, and writes a `dependency-check` launcher script there. Linux and macOS are supported. On Windows, install the release yourself and put its `dependency-check.bat` on `PATH` under the name ASH runs.
- **Container and Nix modes:** the image and the flake do not supply Dependency-Check or Java. Install them, or have `dependency-check` and `java` on `PATH`.
- Any `dependency-check` already on `PATH` is also used.

## What is scanned

ASH runs `dependency-check` from the source directory with the source target as `.`, so the report names files relative to the source. The tool writes absolute `file://` URIs; ASH rewrites those under the source directory to relative paths and leaves any other as it is.

Flags ASH passes, each as one `--flag=value` token:

- `--format=SARIF` and `--out=<directory>`: the report, `dependency-check-report.sarif`.
- `--scan=.`: the target. `--scan` takes its value and has no `--` form.
- `--disableOssIndex`: OSS Index sends package coordinates to a third party and needs an account, so it is off.
- `--exclude=**/<directory>/**`: ASH's own output directory when it is inside the source tree, so the copies of files ASH converted are not analyzed.
- `--propertyfile=<file>`: only when `NVD_API_KEY` is set.

ASH never passes `--failOnCVSS` (ASH rates the findings), `--noupdate`, `--purge`, `--updateonly`, `--suppression`, `--hints`, or any flag that names a credential, a database connection or an artifact repository. The other analyzers keep the tool's defaults, so the Maven Central and RetireJS lookups run, and the tool's own `--enableExperimental` analyzers do not.

## Configuration

The plugin has no options of its own. The shared scanner options apply.

<!-- doctest: config kind=other reason="a scanner section shown in isolation" -->
```yaml
scanners:
  dependency-check:
    enabled: true
    options:
      # Seconds for the whole scan (default 1800; null for no limit). The first
      # run downloads the database, so raise this for a first scan without
      # NVD_API_KEY.
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

Nothing in the options can point the tool at a file or hide a finding. The Maven Central lookups send the hash of each jar the tool finds, so the whole `scanners.dependency-check` section is the operator's: an MCP client's runtime override of any part of it, `enabled` included, is refused whatever the server's `denied_paths` lists.

## Severity

Dependency-Check writes every result with SARIF level `warning`, whatever the vulnerability's score. The score is on the rule the result points to: `security-severity` holds the CVSS v3 or v4 base score (v4 wins when both are present), and a rule with only a CVSS v2 entry has `cvssv2_severity`. ASH rates each result from its rule, sets `issue_severity` and sets the SARIF level to agree:

| CVSS score | ASH severity | SARIF level |
|---|---|---|
| 9.0 to 10.0 | CRITICAL | error |
| 7.0 to 8.9 | HIGH | error |
| 4.0 to 6.9 | MEDIUM | warning |
| 0.1 to 3.9 | LOW | note |
| 0.0 | INFO | note |

With no v3 or v4 score, the CVSS v2 word names the rating: HIGH, MEDIUM or LOW. With neither, the result is MEDIUM with level `warning`, which is what the tool wrote. These are vulnerabilities in a dependency, not necessarily reachable from your code, so a CRITICAL result means a critical advisory exists for a library the tree contains.

## Exit status

Without `--failOnCVSS` the tool exits 0 when the run finished, whether or not it found anything. Any other exit code fails the scan even when a report is on disk: 14 means an analyzer did not finish, so the report may be partial, and 11 to 13 are database, report and fatal analysis errors. Tool output is never copied into the scan's errors, because it names the files analyzed; the failure message names the scanner's log file instead.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule id is the vulnerability id, such as `CVE-2021-44228`.

<!-- doctest: config kind=other reason="a suppression entry shown in isolation" -->
```yaml
global_settings:
  suppressions:
    - rule_id: CVE-2021-44228
      path: lib/legacy.jar
      reason: the vulnerable class is removed from this jar
```

Dependency-Check's own suppression files are not read: ASH does not pass `--suppression`, so a file in the scanned tree cannot drop findings before ASH sees them. Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

The tool needs its vulnerability database. ASH passes neither `--noupdate` nor `--data`, so it cannot use a database prepared elsewhere, and under `--offline` the scanner is skipped. A scan that must run without the network needs a change to the plugin that exposes a database directory; none exists today. Online, the database lives where the tool keeps it by default, inside the unpacked release. Whether that location persists between runs under a scanner sandbox that discards writes was not measured; if it does not, every run downloads the database again, and an API key matters more.

## Limits of this page

The flags and the report shape come from the tool's documentation and source at v13.0.0. They were not measured against a run, because no host with Java was available when the plugin was written.

## License

Dependency-Check is Apache-2.0 licensed and ASH does not modify it. ASH does not redistribute it in the container image; the install step downloads the upstream release.
