# ASH TruffleHog Plugin

[TruffleHog](https://github.com/trufflesecurity/trufflehog) finds credentials with a detector written for each provider, and can ask the provider whether a credential it found is live. ASH runs it as `trufflehog filesystem` over the scan target: the files as they are on disk, not git history.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_trufflehog_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_trufflehog_plugins
```

With the module listed, `trufflehog` runs by default. `scanners.trufflehog.enabled: false` turns it off again. It runs beside the builtin secret scanners, so a secret two of them find is reported by each.

## Installing the tool

ASH does not install TruffleHog and the ASH container image does not include it: TruffleHog is licensed under AGPL-3.0. Install version 3.100.0 or later from its [releases](https://github.com/trufflesecurity/trufflehog/releases) and have `trufflehog` on `PATH`.

## Configuration

```yaml
scanners:
  trufflehog:
    enabled: true
    options:
      # Verify each credential found with its provider, which sends it off the
      # host. Honored only when set with --config-overrides or an ASH config
      # file outside every git checkout and the scanned tree. Off, TruffleHog
      # runs with --no-verification.
      verify: false
      # With verify on, which results to report: verified, unknown, unverified
      # (operator only).
      results: verified,unknown
      # Honor trufflehog:ignore comments in the scanned files (operator only;
      # off, every finding reaches ASH).
      honor_inline_ignores: false
      # Seconds for the whole TruffleHog scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Verification, severity, suppressions, offline and sandboxed use: [the TruffleHog plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/trufflehog-plugin/).
