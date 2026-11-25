# retire.js (community plugin)

[retire.js](https://github.com/RetireJS/retire.js) finds JavaScript libraries with known vulnerabilities. It identifies a library by file name, file content and hash, then compares the version with a vulnerability repository. It finds a vulnerable jQuery copied into a `static/` directory that no lockfile names, which lockfile-based scanners such as `npm-audit` and `grype` do not see. It does not read `package.json` or a lockfile: at 6.1.1 a `package.json` that names a vulnerable dependency produces no finding, so dependency manifests stay with those scanners. ASH runs it as `retire` over the scan target and converts the JSON report to SARIF. ASH pins retire.js 6.1.1 (Apache-2.0).

## Enabling it

retire.js is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_retire_js_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_retire_js_plugins
```

With the module listed, `retire_js` runs by default, like every other scanner. `scanners.retire_js.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners retire_js` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

It needs no license acceptance, account or token.

## Installing retire.js

- **Local mode:** `ash dependencies install --tool retire_js`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_retire_js_plugins"]'`), runs `npm install -g retire@6.1.1`. It needs Node.js 20.19 or later (or 22.12 or later) and npm.
- **Container mode and Nix mode:** the image and the flake are not changed by this plugin; install it with `ash dependencies install`, or have `retire` on `PATH`.
- Any `retire` already on `PATH` is also used.

## What is scanned

retire.js is handed the whole target and walks it itself: JavaScript files (extension `js`) are matched against its signatures by name, content and hash; JavaScript files under `node_modules` are matched the same way, but `package.json` files are not read. A finding is reported at the file that holds the library, at line 1: retire.js reports a file, not a line.

ASH's own output directory sits inside the source tree by default. ASH passes it to `retire --ignore`, and drops every result under it after the scan.

ASH passes these options, each as one `--flag=value` token: `--outputformat=json`, `--outputpath=<file>`, `--exitwith=13`, `--nocache`, `--ignorefile=<file>`, `--ignore=<dirs>` and `--path=<dir>`. It never passes `--jsrepo`, `--proxy`, `--cacert`, `--insecure`, `--deep` or `--includeOsv`.

## Configuration

```yaml
scanners:
  retire_js:
    enabled: true
    options:
      # Seconds for the whole retire.js scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no options of its own, and nothing in the scanned tree can change how retire.js runs. retire.js reads a `.retireignore` or `.retireignore.json` from its working directory, which is the scanned tree, and what they list is dropped before ASH sees it. ASH passes `--ignorefile` with a file holding `[]`, so those files are not read. Move their entries to ASH suppressions.

## Severity

retire.js rates each vulnerability `low`, `medium`, `high` or `critical`. ASH sets the SARIF level and its own severity together:

| retire.js severity | SARIF level | ASH severity |
|---|---|---|
| `critical` | `error` | CRITICAL |
| `high` | `error` | HIGH |
| `medium` | `warning` | MEDIUM |
| `low` | `note` | LOW |
| none | `error` | CRITICAL |
| any other value | `error` | HIGH |

A vulnerability with no rating counts as critical, because retire.js's own exit logic treats it that way. A rating retire.js does not define is rated HIGH, the more severe of the two uncertain choices, and is logged. `critical` and `high` share the SARIF level `error`, so a consumer reading only the level sees both as errors.

## Exit status

retire.js exits 0 when it finds nothing, 13 when it finds a vulnerable library, and 1 on any error, which wins over a finding. ASH passes `--exitwith=13` so 13 does not depend on a default, and accepts 0 and 13. Any other exit code fails the scan even when a report is on disk, and so does a report that is not retire.js JSON.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule is the first CVE the vulnerability carries, else its GitHub advisory id, else `RETIREJS-<component>-<kind>-<id>`:

```yaml
global_settings:
  suppressions:
    - rule_id: CVE-2020-11022
      path: static/legacy/jquery-3.4.1.min.js
      line_start: 1
      line_end: 1
      reason: loaded only by an internal page that never renders untrusted HTML
```

A retire.js finding carries the library's name and version, so a suppression can also be scoped with `package_name: jquery` and `package_version: 1.6.1`. It names no package path, resource or symbol, so those scopes do not apply.

## Offline and air-gapped use

retire.js downloads its vulnerability repository from `raw.githubusercontent.com` on every run (ASH passes `--nocache`), so it cannot run offline. The scanner is skipped under `--offline`, and the sandbox grants it a network.

## License

retire.js is Apache-2.0. ASH does not redistribute it: `ash dependencies install` installs it from npm.
