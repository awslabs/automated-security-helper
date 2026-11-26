# Polaris Plugin

Runs [Polaris](https://github.com/FairwindsOps/polaris) (Apache-2.0) over the Kubernetes YAML files in the scanned directory, using the checks built into the binary. It audits manifests only (`polaris audit --audit-path`): it does not talk to a cluster.

## Enabling

The scanner is on once its module is listed:

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_polaris_plugins
```

With the module listed, `polaris` runs by default. `scanners.polaris.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing Polaris

ASH pins Polaris v10.2.6 in the plugin's own install module (`ash_polaris_plugins/polaris_install.py`: the version, one release asset per platform, a SHA256 for each archive and for the executable inside it, taken from the release's `checksums.txt`). Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_polaris_plugins"]' --tool polaris
```

A download that does not hash to its pin is refused. If `polaris` is already on `PATH`, ASH uses it. The ASH container image installs it the same way.

## Configuration

The plugin has no options of its own, only the shared ones (`severity_threshold`, `scan_timeout`, `offline`). It passes no Polaris config file, and it turns Polaris exemptions off (`--disallow-exemptions`), so the scanned tree cannot hide findings with `polaris.fairwinds.com/<check>-exempt` annotations. Use ASH suppressions instead.

## Severity

Polaris `danger` is HIGH (SARIF level `error`); `warning` is MEDIUM (level `warning`).

## Offline use

Polaris's checks are compiled into the binary and the audit reads only the files it is given, so a scan behaves the same offline. Install the tool before going offline.

## License

Polaris is Apache-2.0 licensed. The ASH container image redistributes the pinned release binary, so it carries the repository `LICENSE` at the pinned commit beside it (the `polaris` entry in `THIRD_PARTY_LICENSES`; the release archive's own `LICENSE` is byte-identical to that file). Nothing of Polaris is shipped in the ASH Python package itself.
