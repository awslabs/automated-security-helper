# PMD (community plugin)

[PMD](https://pmd.github.io/) is a source code analyzer for Java, Apex, JavaScript and other languages. ASH runs it as `pmd check` over the scan target with PMD's security rule category and reads PMD's native SARIF report. ASH pins PMD 7.29.0. PMD is BSD-style licensed, and ASH does not redistribute it in the container image: it is downloaded at install time.

## Quality rules versus security rules

PMD is mostly a code-quality tool. Its rule categories are best practices, code style, design, documentation, error-prone, multithreading, performance and security. Only the `security` category is about vulnerabilities, and for Java it is small (hard-coded cryptographic keys and initialization vectors at the time of writing). ASH therefore runs `category/java/security.xml` by default. Adding another category through `options.rulesets` is allowed, and those findings are quality findings reported at the severity PMD gives them. PMD finds nothing in a tree without files of a language the chosen categories cover, so a clean PMD row on a tree without Java does not say the tree is secure.

## Enabling it

PMD is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_pmd_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_pmd_plugins
```

With the module listed, `pmd` runs by default, like every other scanner. `scanners.pmd.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners pmd` without the module listed is refused, with a message naming the module to add. If PMD or a Java runtime is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

The plugin has no license acceptance or service opt-in: PMD runs locally and makes no network calls.

## Installing PMD

PMD needs a Java runtime, version 11 or later, on `PATH`. ASH does not install Java.

- **Container mode:** the ASH image does not include PMD or a JVM. Install both in a derived image, or run locally.
- **Local mode:** `ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_pmd_plugins"]' --tool pmd` downloads the PMD 7.29.0 release archive from GitHub over HTTPS, verifies it against the SHA256 digest pinned in the plugin, unpacks it into ASH's bin directory and writes a `pmd` launcher. Linux, macOS and Windows on x86_64 and arm64 are supported, because the archive is portable.
- **Nix mode:** the flake does not supply PMD.
- Any `pmd` already on `PATH` is also used.

## What is scanned

PMD is handed the whole target and picks the files of the languages its chosen rule categories cover by file extension. A finding is reported at the file, line and column of the construct. ASH's own output directory is excluded when it sits inside the target (PMD's `--exclude`, which needs PMD 7.14 or later).

ASH passes `--no-cache`, so PMD writes no incremental-analysis cache into the tree, and `--suppress-marker=ASH_PMD_NO_INLINE_SUPPRESSION`. By default PMD hides a violation on a line holding a `NOPMD` comment; that comment belongs to the scanned tree, so ASH moves the marker to a token no source uses and every finding reaches ASH, where suppressions are reported and counted. A Java `@SuppressWarnings("PMD")` annotation is a language feature PMD has no switch for, and still hides the findings it covers.

PMD's `check` command reads no configuration from the scanned tree. `options.rulesets` accepts only built-in `category/<language>/<name>.xml` references, so the repository cannot pick the rules with a ruleset file or URL.

## Configuration

```yaml
scanners:
  pmd:
    enabled: true
    options:
      # PMD built-in categories; ruleset files and URLs are refused.
      rulesets:
        - category/java/security.xml
      # PMD's own priority filter, 1 (highest) to 5 (everything).
      minimum_priority: 5
      # Seconds for the whole PMD scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Exit status

PMD exits 0 when it finds nothing and 4 when it finds violations; both are a completed scan. Exit 5 means PMD could not analyze at least one file (for example a file with a syntax error), 1 an exception and 2 a usage error. Any code other than 0 and 4 fails the scan even when a report is on disk, because the report is partial. PMD's log is kept in the scanner's results directory and is not copied into the scan's error text, since PMD's messages can quote the scanned files.

## Severity

PMD gives every rule a priority from 1 to 5 and writes the SARIF level itself: priorities 1 and 2 are `error`, 3 is `warning`, 4 and 5 are `note`. ASH keeps that level and sets the finding's severity to agree:

| PMD SARIF level | ASH severity |
|---|---|
| `error` | HIGH |
| `warning` | MEDIUM |
| `note` | LOW |

`error` is HIGH rather than CRITICAL because a PMD rule says a construct is risky, not that it is an exploitable vulnerability. A result PMD wrote without a level is rated MEDIUM with level `warning`. PMD's security rules are priority 3, so they report MEDIUM.

## Suppressions

ASH suppressions apply to PMD findings like any other scanner's, by rule, path and line:

```yaml
global_settings:
  suppressions:
    - rule_id: HardCodedCryptoKey
      path: src/test/java/com/example/FixtureKeys.java
      reason: Test fixture key, never used outside unit tests.
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

PMD's rules are inside its jars and `pmd check` makes no network calls, so a scan needs no network once PMD is installed. Installing it needs access to GitHub, or an archive mirrored to a location the install can reach.

## License

PMD is released under a BSD-style license that is not one of the license identifiers ASH bundles: it adds an end-user documentation acknowledgement clause and a no-endorsement clause. ASH therefore never ships PMD in the container image and never vendors its files. The plugin installs the pinned release only when you run `ash dependencies install` for it, from the PMD project's own release asset with its digest checked, so the license terms are between you and the PMD project. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses) for what the container image does include.
