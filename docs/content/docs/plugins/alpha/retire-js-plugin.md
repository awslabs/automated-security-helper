# retire.js (alpha plugin)

[retire.js](https://github.com/RetireJS/retire.js) finds JavaScript libraries with known vulnerabilities. It identifies a library by file name, file content and hash, then compares the version with a vulnerability repository. It finds a vulnerable jQuery copied into a `static/` directory that no lockfile names, which lockfile-based scanners such as `npm-audit` and `grype` do not see. It does not read `package.json` or a lockfile: at 6.1.1 a `package.json` that names a vulnerable dependency produces no finding, so dependency manifests stay with those scanners. ASH runs it as `retire` over the scan target and converts the JSON report to SARIF. ASH pins retire.js 6.1.1 (Apache-2.0).

## Enabling it

retire.js is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_retire_js_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_retire_js_plugins
```

With the module listed, `retire-js` runs by default, like every other scanner. `scanners.retire-js.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

It needs no license acceptance, account or token.

## Installing retire.js

retire.js is a Node.js tool and needs Node.js 20.19 or later (or 22.12 or later) and npm.

- **Container mode:** the ASH image includes retire.js 6.1.1, installed as below in both image stages, with the license files of retire.js and of the five packages it runs on.
- **Local mode:** `ash dependencies install --tool retire-js`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_retire_js_plugins"]'`), installs the whole package tree retire.js 6.1.1 runs on, not only retire.js itself: it runs `npm ci` on a lockfile ASH ships, in which each of the six packages (retire, astronomical, commander, meriyah, walkdir and zod) is pinned to one release and to the integrity the npm registry publishes for it, into `ash-retire-js` under ASH's bin directory, and puts `retire` in the bin directory. npm refuses a package that does not match its integrity, and ASH refuses the installed tree unless its files hash to the digest ASH pins. No install script of any package runs.
- Any `retire` already on `PATH` is also used.

## What is scanned

retire.js is handed the target's absolute path and walks it itself. JavaScript files (extension `js`) are matched against its signatures by name, content and hash, those under `node_modules` included, and each `bower.json` is checked by the name and version it declares. `package.json` files are not read. A symbolic link to a file is followed; one to a directory is not. A finding is reported at the file that holds the library, at line 1: retire.js reports a file, not a line.

ASH's own output directory sits inside the source tree by default. ASH lists it in the ignore file it passes to retire.js, as an absolute path ending in a separator so that a directory whose name only starts the same way is still scanned, and drops every result under it after the scan.

ASH passes these options, each as one `--flag=value` token: `--outputformat=json`, `--outputpath=<file>`, `--exitwith=13`, `--nocache`, `--ignorefile=<file>` and `--path=<dir>`. It never passes `--ignore`, `--jsrepo`, `--proxy`, `--cacert`, `--insecure`, `--deep` or `--includeOsv`.

## Configuration

```yaml
scanners:
  retire-js:
    enabled: true
    options:
      # Seconds for the whole retire.js scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no options of its own, and nothing in the scanned tree can change how retire.js runs. Without an ignore file of its own, retire.js reads a `.retireignore` or `.retireignore.json` from its working directory, which is the scanned tree, and drops what they list before ASH sees it. ASH always passes `--ignorefile` with a file it writes, so those files are not read. Move their entries to [ASH suppressions](../../../concepts/suppressions.md), which are reported and counted.

## Severity

retire.js rates each vulnerability `none`, `low`, `medium`, `high` or `critical`. ASH sets the SARIF level and its own severity together:

| retire.js severity | SARIF level | ASH severity |
|---|---|---|
| `critical` | `error` | CRITICAL |
| `high` | `error` | HIGH |
| `medium` | `warning` | MEDIUM |
| `low` | `note` | LOW |
| `none` | `note` | INFO |
| no rating | `error` | CRITICAL |
| any other value | `error` | HIGH |

A vulnerability with no rating counts as critical, because retire.js's own exit logic treats it that way. A rating retire.js does not define is rated HIGH, the more severe of the two uncertain choices, and is logged. `critical` and `high` share the SARIF level `error`, so a consumer reading only the level sees both as errors.

## Exit status

retire.js exits 0 when it finds nothing, 13 when it finds a vulnerable library, and 1 on any error, which wins over a finding. ASH passes `--exitwith=13` so 13 does not depend on a default, and accepts 0 and 13. Any other exit code fails the scan even when a report is on disk, and so does a report that is not retire.js JSON.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule is the first CVE the vulnerability carries, else its GitHub advisory id, else `RETIREJS-<component>-<kind>-<number>` from the issue, bug, pull request or retire.js id it names, else `RETIREJS-<component>-<digest>`, a digest of the library, the summary and the affected versions. Two different vulnerabilities of one library never share a rule id, so a suppression of one does not hide the other:

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

retire.js is Apache-2.0. Of the packages it runs on, astronomical is Apache-2.0, commander, walkdir and zod are MIT, and meriyah is ISC. ASH does not modify them. `ash dependencies install` downloads them from the npm registry, and the ASH container image, which includes them, ships each one's license file under `/usr/share/doc/ash/third-party/<package>`, beside a `SOURCE` file naming the upstream repository and the commit the release was published from.
