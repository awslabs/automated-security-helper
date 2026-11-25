# cargo-audit (community plugin)

Audits `Cargo.lock` files with [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
against the RustSec advisory database. It reports crates with known vulnerabilities
and crates the database flags as unsound, unmaintained or yanked.

## Enabling it

The module is loaded only when you list it:

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cargo_audit_plugins
```

With the module listed, `cargo-audit` runs by default. `scanners.cargo-audit.enabled: false`
turns it off. A tree with no `Cargo.lock` reports `SKIPPED`.

## Installing

ASH does not install cargo-audit. Run `cargo install cargo-audit --locked`; a
`cargo-audit` on `PATH` is used.

## Network and offline use

Online, cargo-audit fetches the advisory database from GitHub into
`~/.cargo/advisory-db`. With `--offline`, ASH passes `--no-fetch`, and the database
has to be on disk already. ASH always passes `--file=<lockfile>`, so cargo-audit never
generates a lockfile, and it runs the tool outside the scanned tree so a repository's
`.cargo/audit.toml` cannot ignore advisories (`~/.cargo/audit.toml` still applies).

## Configuration

```yaml
scanners:
  cargo-audit:
    enabled: true
    options:
      scan_timeout: 1800
      offline: false
```

## Severity

Vulnerabilities are rated from the advisory's CVSS v3 score (9.0 and up CRITICAL,
7.0 and up HIGH, 4.0 and up MEDIUM, otherwise LOW); with no usable score they are HIGH.
Warnings: `unsound` MEDIUM, `unmaintained`, `yanked` and `notice` LOW.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/community/cargo_audit-plugin/>.
