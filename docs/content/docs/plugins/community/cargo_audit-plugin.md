# cargo-audit (community plugin)

[cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit) compares the
crates a `Cargo.lock` pins with the [RustSec advisory database](https://github.com/rustsec/advisory-db).
It is a Rust software composition scanner: it reads lockfiles, not source code. cargo-audit
is licensed Apache-2.0 or MIT, at your option.

## Enabling it

cargo-audit is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cargo_audit_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_cargo_audit_plugins
```

With the module listed, `cargo-audit` runs by default. `scanners.cargo-audit.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING`.

## Installing cargo-audit

ASH does not install cargo-audit. Install it yourself with `cargo install cargo-audit --locked`; a `cargo-audit` on `PATH` is used. Without it the scanner is reported `MISSING`.

## What is scanned

Every file named `Cargo.lock` in ASH's scan set (so `.gitignore`, `.ignore` and `global_settings.ignore_paths` apply). Lockfiles under a `target/` or `.git/` directory, ASH's own output directory, and links that resolve outside the source directory are skipped. cargo-audit runs once per lockfile, with `--file=<lockfile>`, so it never generates a lockfile for the project. The tool starts in a directory outside the scanned tree, because cargo-audit reads `./.cargo/audit.toml` from its working directory and a repository's own file could ignore advisories; your `~/.cargo/audit.toml` still applies. If there is no `Cargo.lock`, the tool is not run and the scanner reports `SKIPPED`.

## Configuration

```yaml
scanners:
  cargo-audit:
    enabled: true
    options:
      # Seconds for the whole scan, across every lockfile (default 1800).
      scan_timeout: 1800
      # Run without fetching the advisory database (ASH's --offline does the same).
      offline: false
```

The plugin has no options of its own, and none that the scanned tree could use to hide findings. Advisory `ignore` entries in an `audit.toml` that cargo-audit itself reads (for example one in the user's `~/.cargo`) apply on top of ASH suppressions.

## Severity

Both the ASH severity and the SARIF level are set on every result.

| Finding | ASH severity | SARIF level |
|---|---|---|
| Vulnerability, CVSS v3 score 9.0 or more | CRITICAL | error |
| Vulnerability, 7.0 to 8.9, or no usable score | HIGH | error |
| Vulnerability, 4.0 to 6.9 | MEDIUM | warning |
| Vulnerability, below 4.0 | LOW | note |
| Warning `unsound` | MEDIUM | warning |
| Warning `unmaintained`, `yanked`, `notice` or any other kind | LOW | note |

A vulnerability with no CVSS vector is HIGH: cargo-audit reports a known vulnerability in a pinned crate, and ASH does not rate it lower without a score.

## Suppressions

Use ASH suppressions by rule (the advisory id, such as `RUSTSEC-2020-0001`) and path (the lockfile). Package-scoped and symbol-scoped suppressions do not apply.

```yaml
global_settings:
  suppressions:
    - rule_id: RUSTSEC-2020-0001
      path: Cargo.lock
      reason: Not reachable; the crate is only used in tests.
```

## Offline and air-gapped use

Online, cargo-audit fetches the advisory database from GitHub into `~/.cargo/advisory-db`, so the scanner's sandbox requirement asks for a network and that directory. With `--offline` ASH passes `--no-fetch` and does not grant a network; the database has to be on disk already, and a scan without it fails with cargo-audit's own error.

## License

cargo-audit is Apache-2.0 or MIT. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
