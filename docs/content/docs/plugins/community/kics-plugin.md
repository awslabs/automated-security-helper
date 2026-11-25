# KICS (community plugin)

[KICS](https://github.com/Checkmarx/kics) (Keeping Infrastructure as Code Secure) finds security misconfigurations in infrastructure-as-code by running Rego queries over it. ASH runs it as `kics scan` over the scan target and reads its SARIF and JSON reports. KICS covers platforms the other IaC scanners ASH ships read less of, including OpenAPI, Pulumi and Azure Resource Manager. ASH pins KICS v2.1.20.

## Enabling it

KICS is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kics_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_kics_plugins
```

With the module listed, `kics` runs by default, like every other scanner. `scanners.kics.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners kics` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

KICS runs beside the builtin IaC scanners, not instead of them, so a misconfiguration more than one of them finds is reported once by each. The plugin has no license or service gate: KICS is Apache-2.0 and runs locally.

## Installing KICS

KICS publishes its binary and its queries separately: the release archive holds the `kics` executable only, and the queries and libraries it evaluates are a second download from the same release. ASH needs both.

- **Container mode:** the ASH image does not include KICS yet; install it as in local mode, or bring a `kics` with its queries beside it.
- **Local mode:** once the pinned download rows are added to ASH, `ash dependencies install --tool kics`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_kics_plugins"]'`), downloads the pinned release archive and the pinned queries, verifies each against the SHA256 digest pinned in ASH, and installs them. The queries go in an `assets` directory beside the `kics` executable (or in `../share/kics/assets`), which is where ASH looks. Linux, macOS and Windows on x86_64 and arm64 are supported.
- **Nix mode:** the flake does not supply KICS. Install it with `ash dependencies install`.
- Any `kics` already on `PATH` is also used, provided its `assets/queries` and `assets/libraries` directories are in one of those two places. A `kics` binary with no queries beside it fails the scan with a message naming the directories ASH looked in.

v2.1.20 is the newest KICS release that publishes binary archives; releases v2.1.21 to v2.2.1 publish none, so ASH stays on v2.1.20 until KICS publishes binaries again.

## What is scanned

KICS is handed the whole target and picks the files it understands. Findings are reported at the file and line. The source target is scanned from the source directory, so paths in the report are relative to it.

ASH's own output directory sits inside the source tree by default; ASH tells KICS to skip it.

A tree with nothing KICS reads (no Terraform, no CloudFormation, and so on) reports no findings. KICS reports it scanned 0 files in its own report, which ASH does not turn into a skipped result.

## Configuration

```yaml
scanners:
  kics:
    enabled: true
    options:
      # Seconds for the whole KICS scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

KICS has no plugin options beyond these. ASH fixes what KICS reads so the scanned repository does not choose it:

- A `kics.config` in the scanned directory is not read. KICS loads one on its own unless it is given a config, so ASH always passes an empty one it writes outside the tree.
- A `.gitignore` in the tree does not exclude paths from the scan (`kics scan --exclude-gitignore`). KICS skips what the file names by default.
- KICS' own secret detection is off (`kics scan --disable-secrets`); use the secret scanners.
- The queries are the ones installed with KICS, never a directory from the tree.

## Severity

KICS rates every query CRITICAL, HIGH, MEDIUM, LOW, INFO or TRACE. Its SARIF report carries only a level on each rule, with CRITICAL and HIGH both `error` and INFO `none`, so ASH reads the exact severity from the JSON report KICS writes in the same run and rates each result by its query:

| KICS severity | ASH severity | SARIF level | SARIF kind |
|---|---|---|---|
| CRITICAL | CRITICAL | `error` | `fail` |
| HIGH | HIGH | `error` | `fail` |
| MEDIUM | MEDIUM | `warning` | `fail` |
| LOW | LOW | `note` | `fail` |
| INFO | INFO | `none` | `informational` |
| TRACE | INFO | `none` | `informational` |

HIGH is HIGH and not CRITICAL: these are misconfigurations, and KICS itself keeps the two apart. If the JSON report cannot be read, ASH rates each result from its rule's SARIF level instead, and logs a warning. That level cannot tell CRITICAL from HIGH, so `error` becomes CRITICAL, the more severe reading; `warning` becomes MEDIUM, `note` LOW and `none` INFO. With ASH's default `severity_threshold` of `MEDIUM`, CRITICAL, HIGH and MEDIUM findings fail the scan.

## Exit status

ASH runs KICS with `--ignore-on-exit=results`, so a scan that finds things exits 0. Only an engine error exits non-zero (126 for an engine error, 70 for a remediation error, 130 for an interrupt), and any exit other than 0 fails the scan even when a report is on disk. KICS' output and logs can quote the scanned files, so a failure message names the log file instead of quoting it.

## What the scanned tree can still hide

KICS reads `# kics-scan ignore` and `# kics-scan disable=<query-id>` comments in the files it scans, and v2.1.20 has no flag that turns them off. A repository that carries those comments hides the findings they cover from this scanner, and ASH does not count them as suppressed. Review them in the tree, and use [ASH suppressions](../../../concepts/suppressions.md), which are reported and counted, to tune findings.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule is the KICS query id:

```yaml
global_settings:
  suppressions:
    - rule_id: 38c5ee0d-7f22-4260-ab72-5073048df100
      path: infra/public-assets.tf
      line_start: 3
      line_end: 3
      reason: a public website bucket, reviewed
```

Package-scoped and symbol-scoped suppressions do not apply: no KICS finding names a package or a symbol.

## Offline and air-gapped use

The queries are installed with the binary and `kics scan` reads only the files it is given, so it behaves the same offline. Install it before going offline. KICS' crash reporter can contact a Sentry endpoint; the scanner sandbox grants no network, so it cannot.

## License

KICS is Apache-2.0 licensed. ASH installs the unmodified release binary and queries on request and does not redistribute them.
