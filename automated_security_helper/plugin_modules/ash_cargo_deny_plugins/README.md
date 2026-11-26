# cargo-deny alpha scanner plugin

[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) (MIT OR Apache-2.0) checks a Rust project's dependencies against the RustSec advisory database and, optionally, a license, ban and source policy. ASH runs it once for each `Cargo.toml` that has a `Cargo.lock` beside it and reports the diagnostics as findings. The scanner was measured against release 0.21.0, the release ASH installs.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cargo_deny_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_cargo_deny_plugins
```

With the module listed, `cargo-deny` runs by default. `scanners.cargo-deny.enabled: false` turns it off again. A tree with no `Cargo.lock` has nothing to scan and the scanner is reported `SKIPPED`.

## Installing the tool

<!-- doctest: illustrative reason="downloads and installs the scanner's pinned tool" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_cargo_deny_plugins"]' --tool cargo-deny
```

This installs the pinned cargo-deny 0.21.0 release (linux amd64 and arm64, macOS arm64, Windows amd64), checked against its published digests. If `cargo-deny` is already on `PATH`, ASH uses it. The container image ships it.

cargo-deny needs the `cargo` command too (it runs `cargo metadata`), which ASH does not install and the container image does not carry, and the network (the advisory database is fetched from the RustSec repository). Without `cargo`, or offline, the scanner is reported `MISSING`, unless the scan has no locked Cargo project, which is `SKIPPED`.

## Configuration

```yaml
scanners:
  cargo-deny:
    enabled: true
    options:
      # Which cargo-deny checks to run: advisories, bans, licenses, sources.
      checks:
        - advisories
      # A cargo-deny config (deny.toml), honored only when set with
      # --config-overrides or an ASH config file outside the scanned tree.
      # Unset, cargo-deny gets its default advisory settings and a deny.toml in
      # the scanned repository is not read.
      config_file: null
      # Seconds for the whole scan (default 1800; null for no limit).
      scan_timeout: 1800
```

## Documentation

Severity mapping, suppressions, what each check needs, offline use and every option: [the cargo-deny plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/cargo_deny-plugin/).
