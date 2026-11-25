# TruffleHog (alpha plugin)

[TruffleHog](https://github.com/trufflesecurity/trufflehog) finds credentials with a detector written for each provider, and can ask the provider whether a credential it found is live. ASH runs it as `trufflehog filesystem` over the scan target: the files as they are on disk, not git history, which is what ASH's builtin gitleaks and detect-secrets scanners read too. Everything on this page was measured with TruffleHog 3.100.0.

## Enabling it

TruffleHog is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_trufflehog_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_trufflehog_plugins
```

With the module listed, `trufflehog` runs by default, like every other scanner. `scanners.trufflehog.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan goes on.

TruffleHog runs beside the builtin secret scanners, not instead of them, so a secret two of them find is reported once by each.

## Installing TruffleHog

ASH does not install TruffleHog, and the ASH container image does not include it: TruffleHog is licensed under AGPL-3.0. Install version 3.100.0 or later from its [releases](https://github.com/trufflesecurity/trufflehog/releases) and have `trufflehog` on `PATH`. ASH runs it as a separate process and passes `trufflehog --no-update`, so it never replaces itself with a newer release.

## Verification

Verifying a credential sends it off the host: to its provider's API, and for some detectors to a host the scanned file names, such as the server in a database URL. So verification is off by default. ASH passes `trufflehog --no-verification`, TruffleHog makes no network call, and every detection is reported.

To turn it on, set `scanners.trufflehog.options.verify: true` with `--config-overrides`, or in an ASH config file outside every git checkout and the scanned directory. Set by a config inside the scanned repository, or by an MCP client, it is ignored with a warning: the repository being scanned does not decide whether the credentials found in it are sent anywhere. `--offline` and the scanner's own `offline` option turn verification off again, with a warning.

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed, and sends each credential found to its provider" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_trufflehog_plugins \
  --config-overrides 'scanners.trufflehog.options.verify=true'
```

With verification on, `results` chooses which results TruffleHog reports:

| Value | Meaning |
|---|---|
| `verified` | the provider confirmed the credential is live |
| `unknown` | the check failed (a network error, a rate limit), so the credential may be live |
| `unverified` | the provider rejected the credential, or its detector has no check |

The default is `verified,unknown`. Like `verify`, another value is used only when the operator sets it: narrowed by the scanned repository, it would leave findings out.

## What is scanned

TruffleHog is handed the whole target and walks it itself. It does not follow symbolic links. ASH excludes every `.git` directory: git's object store is not a checked-out file, and reading it reports a secret again for each object that holds it. TruffleHog opens archives and decodes encoded text by default.

A finding is reported at the file and line. ASH asks for TruffleHog's SARIF output, which names the detector and never holds the secret, and never for its JSON output, which does. A file TruffleHog cannot read is logged by it and skipped; ASH warns with the number of such files.

ASH's own output directory sits inside the source tree by default, so TruffleHog reads it; ASH drops every result under it, except for a file the repository committed there.

The generic `URI` detector matches a credential by its shape in a URL, so it often reports a line that a provider's detector reports too. ASH drops that `URI` result when a provider detector reports the same file and line at the same or a stronger level.

## Configuration

```yaml
scanners:
  trufflehog:
    enabled: true
    options:
      # Verify each credential found with its provider. Operator only. Off,
      # nothing leaves the host.
      verify: false
      # With verify on, which results to report. Operator only.
      results: verified,unknown
      # Honor trufflehog:ignore comments in the scanned files. Operator only.
      # Off, every finding reaches ASH.
      honor_inline_ignores: false
      # Seconds for the whole TruffleHog scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

ASH never passes `trufflehog --config`, so no custom detector or verification endpoint is loaded, and TruffleHog reads no configuration from the scanned repository.

A `trufflehog:ignore` comment on a line drops its finding before ASH sees it, so it would be neither reported nor counted as suppressed. ASH passes `trufflehog --no-ignore-tag` so such comments hide nothing, unless `honor_inline_ignores` is set by the operator.

## Severity

| TruffleHog result | SARIF level | ASH severity |
|---|---|---|
| The provider confirmed the credential is live | `error` | CRITICAL |
| Any other detection, verified or not | `warning` | HIGH |

Each result carries `properties.verification`, `verified` or `not verified`. With ASH's default `severity_threshold` of `MEDIUM`, every finding fails the scan.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule ID is the name of the TruffleHog detector:

```yaml
global_settings:
  suppressions:
    - rule_id: Github
      path: tests/fixtures/example.py
      line_start: 4
      line_end: 4
      reason: a documented example value, not a credential
```

Package-scoped and symbol-scoped suppressions do not apply: no TruffleHog finding names a package or a symbol.

## Offline and sandboxed use

TruffleHog's detectors are compiled into the binary, so without verification it behaves the same offline. Offline, nothing is verified.

Under `--sandbox`, TruffleHog gets no network unless `sandbox.network_scanners` lists `trufflehog`. With verification on and no network, each check fails, and TruffleHog still reports the detection: it is an `unknown` result, which ASH rates HIGH.

## License

TruffleHog is licensed under AGPL-3.0. ASH does not distribute it: this plugin runs the `trufflehog` you installed.
