# ASH ShellCheck Plugin

[ShellCheck](https://www.shellcheck.net/) is a static analysis tool for shell scripts. It reports quoting mistakes, fragile constructs, unused variables and syntax problems as `SC` rules. ShellCheck is licensed under GPL-3.0; ASH runs it as a separate program.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_shellcheck_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_shellcheck_plugins
```

With the module listed, `shellcheck` runs by default. `scanners.shellcheck.enabled: false` turns it off again. No license acceptance or account is needed.

## Installing the tool

ShellCheck is GPL-3.0-or-later, so ASH does not download or bundle it. Install it yourself, with your package manager (`apt-get install shellcheck`, `brew install shellcheck`) or from the [upstream releases](https://github.com/koalaman/shellcheck/releases). When `shellcheck` is not on `PATH`, the scanner reports an unmet dependency and does not run.

## What is scanned

Files ending `.sh`, `.bash`, `.ksh`, `.dash` or `.ash`, and extensionless files whose shebang names sh, bash, dash, ksh, ash or busybox. Files with a zsh or other non-shell shebang are skipped.

ShellCheck is run as `shellcheck --norc --format=json1 --severity=style -- <files>`, so `.shellcheckrc` files in the scanned tree and `SHELLCHECK_OPTS` cannot change which rules run. Its `json1` output is converted to SARIF: `error` is HIGH, `warning` MEDIUM, `info` LOW and `style` INFO.

## Configuration

```yaml
scanners:
  shellcheck:
    enabled: true
    options:
      # Seconds for the whole ShellCheck scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

See the [ShellCheck plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/shellcheck-plugin/) for the file selection rules, severity mapping, failure conditions and suppressions.
