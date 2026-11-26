# retire.js alpha scanner plugin

[retire.js](https://github.com/RetireJS/retire.js) finds JavaScript libraries with known vulnerabilities. It recognizes a library by file name, file content and hash, so it finds a vulnerable jQuery copied into `static/` that no lockfile names. It does not read `package.json` or a lockfile (at 6.1.1 a `package.json` naming a vulnerable dependency produces no finding), so dependency manifests stay with `npm-audit`. ASH runs it as `retire --path=<target> --outputformat=json` over the scan target and converts its JSON report to SARIF. ASH pins retire.js 6.1.1.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_retire_js_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_retire_js_plugins
```

With the module listed, `retire-js` runs by default. `scanners.retire-js.enabled: false` turns it off again. It needs a network: retire.js downloads its vulnerability repository from GitHub on every run, so the scanner is skipped under `--offline`.

## Installing the tool

retire.js is a Node.js program (Node.js 20.19+ or 22.12+). Locally:

<!-- doctest: illustrative reason="installs the scanner's tool with npm" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_retire_js_plugins"]' --tool retire-js
```

This installs the whole package tree retire.js 6.1.1 runs on from a lockfile ASH ships (`retire_js_install.py`): `npm ci` installs the six packages, each pinned to one release and to the integrity the npm registry publishes for it, into `ash-retire-js` under ASH's bin directory, and ASH refuses the tree unless its files hash to the digest it pins. Any `retire` already on `PATH` is also used. The ASH container image includes the same tree, with the license files of all six packages.

## Configuration

```yaml
scanners:
  retire-js:
    enabled: true
    options:
      # Seconds for the whole retire.js scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

There are no retire.js-specific options. A `.retireignore` or `.retireignore.json` in the scanned tree is not read: ASH passes its own ignore file, so the tree cannot hide findings. Use [ASH suppressions](https://awslabs.github.io/automated-security-helper/concepts/suppressions/).

## Documentation

Severity mapping, rule ids, exit codes, suppressions and offline use: [the retire.js plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/retire-js-plugin/).
