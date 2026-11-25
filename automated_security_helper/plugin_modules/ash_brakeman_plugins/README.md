# ASH Brakeman Plugin

[Brakeman](https://brakemanscanner.org) is a static analysis scanner for Ruby on Rails applications. ASH runs it as `brakeman --format=sarif` over the scan target and reads the SARIF it writes. A tree with no Rails application (no top-level `app` directory) is a no-op: the scan logs an INFO line and reports no findings.

## License gate: ASH does not install Brakeman

Brakeman is free for non-commercial use only (the Brakeman Public Use License; see the [Brakeman repository](https://github.com/presidentbeef/brakeman)). ASH therefore ships no install command and no pinned download for it, and `ash dependencies install` does nothing for this plugin. You install it yourself after reading the license:

<!-- doctest: illustrative reason="installs a Ruby gem on the host" -->
```bash
gem install brakeman
```

Listing this plugin's module is your statement that the license covers your use. With the module listed and `brakeman` not on `PATH`, the scanner is reported `MISSING`, and the message names the license and the install command.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_brakeman_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_brakeman_plugins
```

With the module listed, `brakeman` runs by default. `scanners.brakeman.enabled: false` turns it off again.

## Configuration

```yaml
scanners:
  brakeman:
    enabled: true
    options:
      # Seconds for the whole Brakeman scan (null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

The scanned repository's `config/brakeman.yml` and `config/brakeman.ignore` are not read: ASH passes empty ones, so a repository cannot switch checks off or drop findings. Use ASH suppressions instead.

## Severity

Brakeman rates a warning with a confidence. ASH maps it: high confidence (`error`) is HIGH, medium (`warning`) is MEDIUM, weak (`note`) is LOW.

## Documentation

Invocation, exit codes, suppressions and offline use: [the Brakeman plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/brakeman-plugin/).
