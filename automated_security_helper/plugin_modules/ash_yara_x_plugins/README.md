# ASH YARA-X alpha scanner plugin

[YARA-X](https://virustotal.github.io/yara-x/) is VirusTotal's Rust rewrite of YARA, a pattern matching engine for files. ASH runs it as `yr scan` over the scan target with a rule set you supply. YARA-X ships no rules, so this scanner does nothing until you point it at yours. The scanner's name is `yara-x`.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_yara_x_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_yara_x_plugins
```

With the module listed, `yara-x` runs by default. `scanners.yara-x.enabled: false` turns it off again.

## Installing the tool

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_yara_x_plugins"]' --tool yara-x
```

This installs the pinned YARA-X release (v1.23.0, the `yr` executable), checked against the SHA256 of its archive and of the executable inside it. If `yr` is already on `PATH`, ASH uses it. The ASH container image installs it the same way.

## Configuration

```yaml
scanners:
  yara-x:
    enabled: true
    options:
      # One .yar or .yara file, or a directory searched recursively for them.
      # Honored only when set with --config-overrides or an ASH config file outside
      # every git checkout and the scanned tree. Unset, the scanner is a no-op that
      # logs at INFO and reports that nothing was scanned.
      rules_path: null
      # Seconds for the whole scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

A rule's severity is read from its own metadata: `meta: severity = "high"`. Without it a match is INFO.

## Documentation

Severity mapping, the rules gate, what is reported and every limit: <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/yara-x-plugin/>.
