# ScanCode scanner (community plugin)

[ScanCode Toolkit](https://github.com/aboutcode-org/scancode-toolkit) (Apache-2.0) matches
file text against its bundled license index and reports which licenses a file carries.
This plugin turns each match into an informational finding, so a scan can show which
licenses a project's files declare. It is a license and provenance inventory, not a
vulnerability scanner.

## Enabling it

ScanCode is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_scancode_plugins
```

ScanCode reads every file in the tree and matches it against thousands of license rules, so it is slow on a large tree. Listing the module is the opt-in: once it is listed the scanner runs with the others. To run only ScanCode, select it for one run:

<!-- doctest: illustrative reason="runs a full scan, which needs the scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_scancode_plugins --scanners scancode
```

`--scanners scancode` without the module listed is refused, with a message naming the module to add.

## Runtime cost

ScanCode starts one worker process per CPU (minus one) and reads every file. Expect minutes on a repository of thousands of files and longer on a large one. `scan_timeout` (default 1800 seconds) bounds one run; a run that hits it fails the scan rather than reporting a partial inventory.

## Installing ScanCode

ASH installs the `scancode-toolkit` package from PyPI with `uv tool install` on an online scan, at the release the result converter was written against. Locally:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_scancode_plugins]" --tool scancode
```

The install adds `pluggy<1.7` beside ScanCode: with pluggy 1.7.0 every `scancode` command exits 1 at import (measured with scancode-toolkit 32.5.0). ScanCode's installation guide lists system packages for Linux and says its pip install does not work on ARM CPUs such as Apple Silicon. Offline, or when the install fails, the scanner is reported `MISSING`.

## What ASH runs

<!-- doctest: illustrative reason="shows the command ASH runs" -->
```bash
scancode --license --json=<results>/scancode.json --quiet [--license-score=<n>] -- <path>
```

The path follows `--` so it is never read as a flag. ASH does not pass `--license-text`, so no file content is copied into the report.

## Configuration

<!-- doctest: config kind=other reason="community plugin options, loaded only with the module listed" -->
```yaml
scanners:
  scancode:
    enabled: true
    options:
      license_score: 0        # drop matches scoring below this, 0-100
      tool_version: null      # default "==32.5.0"
      scan_timeout: 1800
      install_timeout: 1200
```

## Severity

Every license match is reported as `INFO`, with SARIF level `none`, so the two agree. A license match is information about a file, not a vulnerability: whether a given license is acceptable is a project policy. Use `severity_threshold` to leave INFO findings out of the pass or fail decision.

## Exit status

ScanCode exits 0 when every file was scanned and 1 when any file has a scan error or a timeout occurred. ASH accepts only 0: a run that reports a scan error is not a complete inventory, so it fails the scan, and its log (not quoted in the result, since it can name files in your tree) is kept beside the results.

## Suppressions

ASH suppressions match by rule, path and line like any scanner's. The rule id is the SPDX license expression ScanCode reports (for example `MIT` or `GPL-2.0-only`), or `unknown-license` when a match carries none.

<!-- doctest: config kind=other reason="suppression example with a placeholder path" -->
```yaml
global_settings:
  suppressions:
    - rule_id: GPL-2.0-only
      path: vendor/legacy/*
      reason: Vendored tool, not linked into the product.
```

## Offline and air-gapped use

The license index ships inside the package, so a scan makes no network calls. Installing the tool needs the network; in an air-gapped environment, install `scancode-toolkit` ahead of time.

## License

ScanCode Toolkit is Apache-2.0, with CC-BY-4.0 for its reference data. ASH does not bundle it; it is installed on request.
