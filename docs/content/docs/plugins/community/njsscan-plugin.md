# njsscan (community plugin)

[njsscan](https://github.com/ajinabraham/njsscan) is a static security scanner for Node.js applications. It runs a curated rule pack over JavaScript files (semantic grep rules) and over server-side template files, and maps each finding to an OWASP category and a CWE. ASH runs it as `njsscan --sarif` over the scan target and reads the SARIF it writes.

## Enabling it

njsscan is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_njsscan_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_njsscan_plugins
```

With the module listed, `njsscan` runs by default, like every other scanner. `scanners.njsscan.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners njsscan` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

njsscan has no license or service gate: it runs locally, needs no account and sends nothing off the host.

## Installing njsscan

njsscan is a Python package. ASH installs it through `uv` into its own tool environment, pinned to `njsscan==1.0.2` and to an interpreter of Python 3.10 or later, which is what the package declares on PyPI.

- **Local mode:** `ash dependencies install` (or `ash dependencies install --tool njsscan`), with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_njsscan_plugins"]'`), runs `uv tool install`. Without that step, the first scan installs it. Either needs network access to PyPI.
- **Container and Nix modes:** njsscan is not bundled. With `uv` available it is installed the same way on first use, so an air-gapped run has to install it first.
- Any `njsscan` already on `PATH` is also used when it satisfies the pinned version.
- **Platforms:** Linux and macOS. The njsscan README says it supports only Mac and Linux, so on Windows an enabled scanner is skipped with that reason rather than reported missing.

`options.tool_version` replaces the pin with another pip version constraint. The result converter was written against 1.0.2.

## What is scanned

njsscan is handed the whole target and walks it itself, using its own file extensions for JavaScript and for templates. ASH runs it from the source directory with the path `.`, so reported paths are relative to the source.

ASH's own output directory sits inside the source tree by default, so njsscan reads it; ASH drops every result under it.

## Configuration

```yaml
scanners:
  njsscan:
    enabled: true
    options:
      # Seconds for the whole njsscan scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
      # A pip version constraint; unset uses ==1.0.2.
      tool_version: null
      install_timeout: 300
```

There is no option that points njsscan at a configuration file. njsscan reads a `.njsscan` file from the scanned tree, and that file can ignore rules, paths and extensions and filter by severity, which would hide findings from ASH. ASH therefore always passes `njsscan --config` with a file of its own that ignores nothing, written outside the scanned tree, so a `.njsscan` in the repository is not read. Use [ASH suppressions](../../../concepts/suppressions.md) to suppress a rule or a path.

## Inline ignore comments

njsscan drops a finding when its line carries a `// njsscan-ignore: <rule_id>` comment. It has no flag that turns this off, so ASH cannot: a finding hidden by such a comment is neither reported nor counted as suppressed. Review those comments in your own code review, and use ASH suppressions, which are reported and counted, for anything that should stay suppressed.

## Files njsscan does not read

ASH passes njsscan a configuration of its own that sets nothing, so a `.njsscan` file in the scanned tree is not read: its `ignore-rules`, `ignore-paths`, `severity-filter` and `severity-overrides` have no effect. njsscan's own built-in lists stay in force, and they leave out `node_modules`, `bower_components`, `fixtures`, `spec`, `example`, `.min.js` files and a few well-known minified libraries by name. Code under those paths is not scanned.

njsscan reads neither a symbolic link to a file nor a link to a directory (measured with njsscan 1.0.2 over a link to a file outside the tree and a link to a directory outside it, with a real file in the tree as the control), so a link that leaves the scanned tree cannot put outside content in a report.

## Severity

njsscan gives each rule a severity and writes it as the SARIF level. ASH sets the level and its own `issue_severity` together:

| njsscan severity | SARIF level | ASH severity |
|---|---|---|
| ERROR | `error` | HIGH |
| WARNING | `warning` | MEDIUM |
| INFO | `note` | LOW |
| anything else | `none` | INFO |

`error` is HIGH rather than the CRITICAL that ASH's generic `error` level maps to, because every njsscan rule is a pattern match that says the code has the shape of a weakness, not a confirmed vulnerability. A result that arrives with no level is MEDIUM. A level not in the table is HIGH, so an unrecognized value is never under-reported.

## Exit status and failed runs

njsscan exits 0 when it found nothing it counts, and 1 when it found an ERROR finding or when it could not read some file. ASH accepts both. When njsscan says its run was not successful in the SARIF, ASH carries that into its own invocation record, so the run is reported as incomplete and not as clean. Any other exit code (2 is a usage error) fails the scan, even when a report was written. A timeout, a report that cannot be read as SARIF and a run that writes no report each fail the scan with a message that says so.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: node_insecure_random_generator
      path: tests/fixtures/example.js
      line_start: 4
      line_end: 4
      reason: a documented example, not security-sensitive randomness
```

Package-scoped and symbol-scoped suppressions do not apply: no njsscan finding names a package or a symbol.

## Offline and air-gapped use

njsscan's rules ship inside the package and a scan makes no network call. Only the install needs the network, so install it before going offline.

## License

njsscan is licensed under the LGPL-3.0. ASH does not bundle it and does not import it: it runs as a separate process from its own tool environment, so installing and running it creates no combined work with ASH.
