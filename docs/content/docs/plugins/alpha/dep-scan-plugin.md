# dep-scan Plugin

[OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan) reports known vulnerabilities in the dependencies of a source tree. It builds a CycloneDX bill of materials with [cdxgen](https://github.com/CycloneDX/cdxgen), looks every component up in a local vulnerability database (OSV, NVD and GitHub advisories), and writes a CycloneDX Vulnerability Disclosure Report (VDR). ASH converts that report to SARIF. ASH pins dep-scan 6.3.2, the latest release on PyPI as `owasp-depscan`; the 7.x line on the development branch changes the command line and is not used.

## Enabling it

dep-scan is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_dep_scan_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_dep_scan_plugins
```

With the module listed, `dep-scan` runs by default, like every other scanner. `scanners.dep-scan.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners dep-scan` without the module listed is refused, with a message naming the module to add. If a tool it needs is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

There is no license acceptance, account or API key to set up, so no opt-in beyond listing the module. dep-scan is MIT-licensed and downloads its vulnerability database without credentials.

## Installing dep-scan

dep-scan needs two tools.

- **`depscan`:** `ash dependencies install --tool dep-scan`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_dep_scan_plugins"]'`), installs `owasp-depscan==6.3.2` as a uv tool. A `depscan` already on `PATH` is also used when uv is not available.
- **`cdxgen`:** dep-scan runs it to read a source tree. ASH does not install it; `npm install -g @cyclonedx/cdxgen` does. Without it the dependency check fails and the scanner is `MISSING`.

The ASH container image installs the pinned `depscan` the same way and checks it with `depscan --version`. It does not include cdxgen, so a scan in the image reports the scanner `MISSING` until cdxgen is on `PATH`. The flake supplies neither tool.

## What is scanned

ASH runs `depscan --src=<target>` from the source directory, so cdxgen reads every dependency manifest and lockfile it recognizes under the target. dep-scan keeps its reports in a directory under the scanner's results directory, and ASH reads every `*.vdr.json` there.

ASH's own output directory sits inside the source tree by default, so cdxgen can read manifests copied there; ASH drops every result located under it, except for a file the repository committed there.

A tree with no dependency manifest makes dep-scan stop with "No packages were found". ASH passes `depscan --fail-on-error`, because without it dep-scan carries on after cdxgen fails, writes no report and exits 0, which would read as a clean scan. So such a tree is reported as a scanner failure, not a pass.

A finding is located on the manifest the BOM recorded for the component. When the BOM records none, or one outside the scanned tree, the finding is located on the scan root (`.`). The finding carries the package name and version, the fixed versions dep-scan suggests, and a `reachable` tag when dep-scan's analysis traced the vulnerable package to the project's code.

## Configuration

```yaml
scanners:
  dep-scan:
    enabled: true
    options:
      # FrameworkReachability (dep-scan's default) adds a "reachable" tag to findings
      # dep-scan could trace to the project's code. "off" skips that analysis.
      # Neither value removes a finding.
      reachability_analyzer: FrameworkReachability
      # Version constraint for the owasp-depscan install, in pip requirement syntax.
      # Unset uses ==6.3.2, the release the converter is tested against.
      tool_version: null
      # Seconds to allow for installing the tool.
      install_timeout: 300
      # Seconds for the whole dep-scan run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

dep-scan reads `.config/depscan.toml` from its working directory, which is the scanned tree, and lets it set any option the command line does not name: a minimum `severity`, a `custom-data` directory that rewrites advisories, a report template. ASH passes `depscan --config` with an empty file that ASH writes outside the scanned tree, so the tree's file is never read and the scanned repository does not choose what dep-scan reports. The plugin offers no option that points dep-scan at a config file.

ASH also never passes `depscan --severity`, `depscan --custom-data`, `depscan --report-template`, `depscan --bom`, `depscan --server` or `depscan --cdxgen-server`. Environment variables dep-scan reads (`DEPSCAN_*`, `VDB_HOME`, `CDXGEN_*`) come from your environment, not the scanned tree.

## Severity

dep-scan's VDR rates each vulnerability with CycloneDX `ratings`. ASH takes the highest rating of a vulnerability:

| dep-scan rating | ASH severity | SARIF level |
|---|---|---|
| critical | CRITICAL | error |
| high | HIGH | error |
| medium | MEDIUM | warning |
| low | LOW | note |
| info, none | INFO | none |
| unknown, or no rating | MEDIUM | warning |

`error` covers both CRITICAL and HIGH, as it does for ASH's other SARIF. A vulnerability with no rating is a known advisory nobody has rated, so ASH reports it as MEDIUM: neither hidden below the default threshold nor called critical. With ASH's default `severity_threshold` of `MEDIUM`, an unrated finding fails the scan.

## Exit status

Only exit code 0 is a completed run, and finding vulnerabilities does not change it. Any other code fails the scan even if a report is on disk. A run that exits 0 and leaves no `*.vdr.json`, or a report that is not a CycloneDX JSON object with a list of vulnerabilities, fails the scan; nothing is read as "clean" unless dep-scan wrote a report that says so. A report left by an earlier run is removed before each run. dep-scan's stderr is not copied into the scan's errors, because it can quote paths and package names from the scanned tree; it is kept in the scanner's log file, and the failure message names that file.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule is the advisory id:

```yaml
global_settings:
  suppressions:
    - rule_id: CVE-2021-44228
      path: services/pom.xml
      reason: the vulnerable code path is not reachable in this service
```

Each finding also carries `package_name` and `package_version`, so a package-scoped suppression can name one dependency.

## Offline and air-gapped use

dep-scan downloads its vulnerability database on the first run (`VDB_HOME` moves its cache) and cdxgen may resolve dependencies over the network. dep-scan 6.3.2 has no offline option, so the scanner is skipped under `--offline`. Under `--sandbox` the scanner is granted a network and the database cache directories; those directories (`$VDB_HOME`, `~/.local/share/vdb`, `~/Library/Application Support/vdb`) are dep-scan's documented defaults and were not measured on a sandboxed run.

## License

dep-scan is MIT-licensed. The ASH container image installs the pinned release from PyPI, so it carries the wheel's `LICENSE` beside it (the `dep-scan` entry in `THIRD_PARTY_LICENSES`; that file is byte-identical to the repository's `LICENSE` at the v6.3.2 tag). Nothing of dep-scan is shipped in the ASH Python package itself, and cdxgen is not in the image.
