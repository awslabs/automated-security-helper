# cargo-audit Plugin

[cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit) compares the
crates a `Cargo.lock` pins with the [RustSec advisory database](https://github.com/rustsec/advisory-db).
It is a Rust software composition scanner: it reads lockfiles, not source code. cargo-audit
is licensed Apache-2.0 or MIT, at your option.

## Enabling it

cargo-audit is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged.

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

With the module listed, `cargo-audit` runs by default. `scanners.cargo-audit.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing cargo-audit

ASH pins cargo-audit v0.23.0 in the plugin's own install module (`ash_cargo_audit_plugins/cargo_audit_install.py`: the version, one release asset per platform, a SHA256 for each archive and for the executable inside it). The release publishes no checksums file, so the archive digests are the ones GitHub reports for each asset, checked against a download of every archive. Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_cargo_audit_plugins"]' --tool cargo-audit
```

A download that does not hash to its pin is refused. On linux/amd64 the statically linked musl build is installed; linux/arm64 has only a glibc build, which needs glibc 2.18 or newer. If `cargo-audit` is already on `PATH`, ASH uses it, so `cargo install cargo-audit --version 0.23.0 --locked` works too. The ASH container image installs the pinned release.

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
      # true skips this scanner, as ASH's --offline does (see Offline use).
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

## Offline use

Online, cargo-audit fetches the advisory database from GitHub into `~/.cargo/advisory-db`, so the scanner's sandbox requirement asks for a network and that directory. When it fetches, cargo-audit refuses a database whose newest commit is more than 90 days old.

The scanner does not run offline (`--offline`, `ASH_OFFLINE`, or its own `options.offline: true`); it is reported `MISSING` with the reason. Without a fetch, cargo-audit reads whatever database is on disk with no age check, and ASH does not yet hold the RustSec database to an age bound the way it holds its other [content databases](../../../concepts/content-databases.md), so a stale copy would read as a clean scan.

## License

cargo-audit is Apache-2.0 or MIT. The ASH container image redistributes the pinned release binary, so it carries the crate's `LICENSE-APACHE` and `LICENSE-MIT` at the pinned commit beside it (the `cargo-audit` entry in `THIRD_PARTY_LICENSES`; the linux and macOS release archives carry byte-identical copies). Nothing of cargo-audit is shipped in the ASH Python package itself. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
