# cppcheck (community plugin)

[Cppcheck](https://cppcheck.sourceforge.io/) is a static analyzer for C and C++. It
reports undefined behavior, memory and resource leaks, out-of-bounds access and
similar defects, and with the check groups ASH turns on, style, performance and
portability problems. It does not need the code to build.

## Enabling it

cppcheck is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cppcheck_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_cppcheck_plugins
```

With the module listed, `cppcheck` runs by default, like every other scanner. `scanners.cppcheck.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners cppcheck` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

The plugin has no license or service gate: there is no account, key or opt-in beyond listing the module.

## Installing cppcheck

- **Container mode:** the ASH image does not include cppcheck.
- **Local mode:** `ash dependencies install --tool cppcheck`, with the module listed in
  `ash_plugin_modules` (or added with
  `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_cppcheck_plugins"]'`),
  installs the `cppcheck` package with apt on Linux or Homebrew on macOS. The
  Cppcheck project publishes no Linux or macOS binary release, so ASH pins no
  download and takes the version the package manager carries. It must be a release
  that accepts `--output-format=sarif`.
- **Nix mode:** the flake does not supply cppcheck.
- Any `cppcheck` already on `PATH` is also used.

## What is scanned

Cppcheck is given the whole source directory (and, in a second run, the converted
copy of it) and picks the C and C++ files itself by extension. ASH's ignore files
and `global_settings.ignore_paths` are applied to the findings afterwards. A tree
with no C or C++ files produces no findings.

ASH runs:

```text
cppcheck --output-format=sarif --output-file=<results>/<target>/cppcheck.sarif
         --error-exitcode=2 --enable=warning,style,performance,portability --quiet .
```

- `--output-file` is used because Cppcheck writes SARIF to standard error otherwise.
- `--error-exitcode=2` separates "found something" (exit 2) from a Cppcheck failure
  (exit 1). Exit 0 and 2 succeed; any other exit fails the scan even if a report is on disk.
- `--enable=information` and `missingInclude` are left off: they report
  configuration notes such as a header that was not found, not defects.
- `--inline-suppr` is left off, so `// cppcheck-suppress` comments in the scanned
  tree do not hide findings from ASH. A project file, addon, library or suppression
  file in the tree is never read.

Cppcheck runs with the source directory as its working directory, so paths in the
report are relative to it.

## Configuration

<!-- doctest: config kind=other reason="shows the scanner's options; scan_timeout and severity_threshold are the only ones" -->
```yaml
scanners:
  cppcheck:
    enabled: true
    options:
      # Seconds for the whole cppcheck scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

Cppcheck has no operator-only options.

## Severity

Cppcheck's SARIF gives each result a level, and ASH rates from it together with the
rule's `security-severity` score. The SARIF level and ASH's severity agree on every
result. A real Cppcheck 2.17.1 run writes level `warning` for both its error and
warning severities and `note` for everything else; it never writes `error`.

| Condition | SARIF level written by ASH | ASH severity |
| --- | --- | --- |
| the rule's `security-severity` is 7.0 or more (leaks, out-of-bounds access) | error | HIGH |
| level `warning` | warning | MEDIUM |
| level `note` (style, performance, portability, information) | note | LOW |
| level `error` (not written by 2.17.1) | error | HIGH |

HIGH is not CRITICAL: these are static-analysis defects with no proof that they are
exploitable. A result with no level is MEDIUM; a level ASH does not know is HIGH, the
more severe choice. A rule with no numeric `security-severity` is rated by its level
alone.

## Suppressions

Suppress a finding with an ASH suppression, by rule, path and line:

<!-- doctest: config kind=other reason="shows an ASH suppression entry for a cppcheck rule" -->
```yaml
global_settings:
  suppressions:
    - rule_id: nullPointer
      path: src/legacy/parser.c
      line_start: 120
      line_end: 120
      reason: Checked by the caller.
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

Cppcheck's checks and its standard library definitions are part of the program, and
it makes no network call, so a scan needs no network once the tool is installed.

## License

Cppcheck is GPL-3.0-or-later. ASH runs it as a separate program and does not bundle
or link it.
