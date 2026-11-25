# ASH Psalm Plugin

[Psalm](https://psalm.dev) is a static analyzer for PHP. ASH runs it in taint analysis (security analysis) mode over the scan target and reports the tainted data flows it finds, such as user input reaching a SQL query or an HTML response. Psalm is MIT licensed. ASH pins the 6.x line.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_psalm_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_psalm_plugins
```

With the module listed, `psalm` runs by default. `scanners.psalm.enabled: false` turns it off again. There is no license or service gate: Psalm runs locally and makes no network call.

## Installing the tool

Psalm is a PHP program, so PHP 8.2 or newer must be on `PATH` as well as Psalm. If either is missing the scanner is reported `MISSING`. If the scan target holds no PHP file (`.php`, `.phtml`, `.inc`, outside `vendor`), the scanner is reported `SKIPPED` instead.

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_psalm_plugins]" --tool psalm
```

That installs the pinned `psalm.phar` release (checked against a pinned SHA256 digest) as `psalm` on Linux and macOS. Any `psalm` already on `PATH` is also used, for example one from `composer global require vimeo/psalm` or the `psalm.phar` renamed and made executable.

## Configuration

```yaml
scanners:
  psalm:
    enabled: true
    options:
      # Also report Psalm's non-security (type) issues. Off: only taint findings.
      include_type_issues: false
      # Seconds for the whole Psalm run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

ASH writes its own `psalm.xml` outside the scanned tree and passes it with `--config`. A `psalm.xml`, `vendor/autoload.php` or Psalm plugin in the scanned repository is not read, so the repository cannot choose what is analyzed or run its own PHP inside the scan.

## Severity

Taint findings are HIGH (SARIF `error`). Psalm reports a possible flow from a source to a sink, not a confirmed exploit, so they are not CRITICAL. A taint finding Psalm itself lowered to `note` is LOW. With `include_type_issues`, a type issue is MEDIUM (`warning`), or INFO (`none`) at `note`.

## Documentation

Suppressions, offline use and every option: [the Psalm plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/psalm-plugin/).
