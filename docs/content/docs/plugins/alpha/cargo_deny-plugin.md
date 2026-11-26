# cargo-deny Plugin

[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) (MIT OR Apache-2.0) is a lint tool for Rust dependency graphs. Its `advisories` check matches the crates in a `Cargo.lock` against the [RustSec advisory database](https://rustsec.org/); its `licenses`, `bans` and `sources` checks apply a policy you write. ASH runs it as `cargo-deny check` for each Cargo project it finds and turns the diagnostics into findings. The scanner was measured against release 0.21.0, the release ASH installs.

## Enabling it

cargo-deny is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cargo_deny_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_cargo_deny_plugins
```

With the module listed, `cargo-deny` runs by default. `scanners.cargo-deny.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners cargo-deny` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate). There is no license key or account: the scanner has no opt-in gate beyond listing the module.

## Installing cargo-deny

ASH pins cargo-deny 0.21.0 in the plugin's own install module (`ash_cargo_deny_plugins/cargo_deny_install.py`: the version, one release asset per platform, a SHA256 for each archive, taken from the `.sha256` file the release publishes beside it, and one for the executable inside it). Release assets exist for linux amd64 and arm64, macOS arm64 and Windows amd64; cargo-deny publishes no x86_64 macOS build. Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_cargo_deny_plugins"]' --tool cargo-deny
```

A download that does not hash to its pin is refused. If `cargo-deny` is already on `PATH`, ASH uses it.

- **Container mode:** the ASH container image installs the pinned release the same way at build time and checks `cargo-deny --version`. The image carries no Rust toolchain, so a scan of a Cargo project in the image reports the scanner `MISSING` (`cargo` not found) unless the image you run adds one.
- **Local mode:** cargo-deny runs `cargo metadata`, so `cargo` must be installed too. ASH does not install it. Without it the scanner is reported `MISSING` with that reason.

## What is scanned

cargo-deny works on a Cargo project, not on single files. ASH runs it once for every `Cargo.toml` in the scan set that has a `Cargo.lock` next to it, from the source directory, with the manifest path relative to it. A workspace keeps one lock at its root, so its members are covered by the root's run. Manifests under a directory named `target` and paths in `ignore_paths` are skipped. A manifest with no lock is not scanned: ASH passes `--locked`, so cargo never creates or changes a lock in your tree.

The scan needs the network. cargo-deny fetches the advisory database, and `cargo metadata` can download crate metadata. ASH does not pass `--offline`: with no cached database cargo-deny has no advisories to check against. Under `--offline` the scanner is reported `MISSING`.

An advisory finding is placed on the `Cargo.lock` next to the manifest and any other finding on the manifest. cargo-deny's own line numbers are not carried over, so a finding has a file and no line.

## Configuration

```yaml
scanners:
  cargo-deny:
    enabled: true
    options:
      # Which checks to run: advisories, bans, licenses, sources.
      checks:
        - advisories
      # A cargo-deny config (deny.toml), honored only when set with
      # --config-overrides or an ASH config file outside every git checkout and
      # the scanned tree. A path that is honored but missing fails the scan.
      config_file: null
      # Seconds for the whole scan, every Cargo project together (default 1800;
      # null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

### The cargo-deny config

cargo-deny reads `deny.toml` from its working directory by default, and a `deny.toml` can ignore advisories. ASH therefore never lets the scanned repository choose it: ASH always passes `--config`. With `config_file` unset, the file is a stub ASH writes that holds only `[advisories]`, cargo-deny's default advisory settings, and a `deny.toml` in the repository is not read (the scan log says so). With `config_file` set by the operator, that file is used.

`licenses`, `bans` and `sources` apply the policy in the config. With the stub there is no license allow-list, so the `licenses` check reports every crate's license as not allowed. Use those checks with an operator `config_file` that states your policy.

## Severity

Each finding takes cargo-deny's own diagnostic severity, so the ASH severity and the SARIF level agree.

| cargo-deny severity | ASH severity | SARIF level |
|---|---|---|
| `error` (and `bug`) | HIGH | `error` |
| `warning` | MEDIUM | `warning` |
| `note` | LOW | `note` |
| `help` | INFO | `none` |

`error` is HIGH, not CRITICAL. cargo-deny's severity says how your policy treats a finding, not how exploitable it is: an advisory, an unmaintained crate and a license your policy does not allow are all `error`. A severity string cargo-deny does not document is rated HIGH, so nothing is under-reported. A finding's `ruleId` is the RustSec advisory id for an advisory and cargo-deny's diagnostic code (`unlicensed`, `rejected`, ...) for the other checks. Advisory results also carry the advisory's aliases (CVE and GHSA ids) and kind (`unsound`, `unmaintained`, or none for a vulnerability).

## Exit status and failures

cargo-deny's exit code is a bitset of the checks that reported an error: advisories 1, bans 2, licenses 4, sources 8. A run that fails to start also exits 1, so ASH counts a run as completed only when the code is between 0 and 15 and cargo-deny printed its `summary` line. A project that fails (no toolchain, no `Cargo.lock`, a network failure) is a failed target; its error text is quoted from cargo-deny's own error log, shortened. If every project fails, or the time budget runs out, the scan fails.

## Suppressions

ASH suppressions apply by `rule_id` and `path`:

```yaml
global_settings:
  suppressions:
    - rule_id: RUSTSEC-2021-0145
      path: Cargo.lock
      reason: "atty is only used by a dev tool that never runs on Windows"
```

Package-scoped and symbol-scoped suppressions do not apply. To suppress by advisory inside cargo-deny itself, use `advisories.ignore` in an operator `config_file`.

## Offline and air-gapped use

The scanner does not run offline: the advisory database comes from the network. Offline it is reported `MISSING` with that reason.

## License

cargo-deny is licensed MIT OR Apache-2.0. ASH only runs it as a separate program and does not link or import it. The ASH container image redistributes the pinned release binary, so it carries the repository's `LICENSE-MIT` and `LICENSE-APACHE` at the pinned commit beside it (the `cargo-deny` entry in `THIRD_PARTY_LICENSES`; the copies inside the release archives are byte-identical to those files). Nothing of cargo-deny is shipped in the ASH Python package itself. Notices for tools bundled in the container image are described under [Third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
