# cargo-audit alpha scanner plugin

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

ASH pins cargo-audit v0.23.0 in this module (`cargo_audit_install.py`: one release asset
per platform, a SHA256 for each archive and for the executable inside it). Install it with
`ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_cargo_audit_plugins"]' --tool cargo-audit`.
A `cargo-audit` already on `PATH` is used, so `cargo install cargo-audit --version 0.23.0 --locked`
works as well. The ASH container image installs the pinned release.

## Network and offline use

Online, cargo-audit fetches the advisory database from GitHub into
`~/.cargo/advisory-db` and refuses a database whose newest commit is more than 90 days
old. A database it cannot fetch or load makes it exit 1 with no report, the code it
also uses for vulnerabilities found, and the scanner fails with cargo-audit's message.
ASH always passes `--file=<lockfile>`, so cargo-audit never generates a lockfile,
and it runs the tool outside the scanned tree so a repository's `.cargo/audit.toml`
cannot ignore advisories (`~/.cargo/audit.toml` still applies, outside the scanner
sandbox). Under a sandbox backend that mounts caches read-only, each run gets a
private, empty `CARGO_HOME` and clones the database there.

The scanner does not run offline (`--offline`, `ASH_OFFLINE`, or its own
`options.offline: true`). Without a fetch, cargo-audit reads whatever database is on disk
with no age check, and ASH holds no age bound for that database yet, so a stale copy
would read as a clean scan.

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

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/cargo_audit-plugin/>.
