# Secretlint (community plugin)

[Secretlint](https://github.com/secretlint/secretlint) finds credentials in files, with one rule per kind of credential (cloud keys, tokens, private keys and so on). ASH runs `secretlint` over the scan target with the recommended rule preset and reads the SARIF it writes. It reads the files as they are on disk, not git history, as ASH's builtin gitleaks and detect-secrets scanners do. ASH pins version 14.0.1.

## Enabling it

Secretlint is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_secretlint_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_secretlint_plugins
```

With the module listed, `secretlint` runs by default, like every other scanner. `scanners.secretlint.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners secretlint` without the module listed is refused, with a message naming the module to add. If Node.js or Secretlint is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

Secretlint runs beside the builtin `gitleaks` and `detect-secrets` scanners, not instead of them, so a secret more than one of them finds is reported once by each. It needs no account, token or license key.

## Installing Secretlint

Secretlint is a Node.js tool and requires Node.js 22 or later. The ASH container image does not include it.

- **Local mode:** with `node` and `npm` on `PATH`, `ash dependencies install --tool secretlint` (with the module listed in `ash_plugin_modules`, or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_secretlint_plugins"]'`) runs `npm install -g secretlint@14.0.1` and `npm install -g @secretlint/secretlint-formatter-sarif@14.0.1`. SARIF is not built into Secretlint; it comes from that second package.
- **Without Node.js:** the scanner is reported `MISSING`, and the scan log says Node.js 22 or later is needed.
- Any `secretlint` already on `PATH` is also used, but its SARIF formatter package must be installed alongside it.

## What is scanned

Secretlint is handed the glob `**/*` from the source directory (an absolute glob for a converted target) and walks it itself. ASH passes:

- `--secretlintrcJSON` with the recommended preset, so a `.secretlintrc.*` in the scanned tree is never looked up. Without it, Secretlint searches from the working directory upward for one, and the scanned repository would choose the rules.
- `--no-gitignore`, so files a `.gitignore` lists, where credentials often sit, are scanned.
- `--output`, `--format=@secretlint/secretlint-formatter-sarif`, `--no-color` and `--no-terminalLink`.

Secretlint masks secret values in its messages by default, and ASH never passes `--no-maskSecrets`. ASH's own output directory sits inside the source tree by default, so Secretlint reads it; ASH drops every result under it, except for a file the repository committed there. Secretlint makes no network calls while scanning.

## Configuration

Secretlint has no option of its own: the rules and masking are fixed by ASH.

```yaml
scanners:
  secretlint:
    enabled: true
    options:
      # Seconds for the whole Secretlint scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

## Ignore files and inline comments

Secretlint always reads a `.secretlintignore` in each directory, and its documentation names no flag that turns that off. A finding in a file such a file lists is not reported, and is not counted as suppressed. ASH logs a warning when the scan root holds one. Move its entries to [ASH suppressions](../../../concepts/suppressions.md), which are reported and counted.

The recommended preset includes Secretlint's `secretlint-disable` comment filter, which Secretlint applies itself, so a comment in a scanned file hides a finding before ASH sees it. Prefer ASH suppressions for the same reason.

## Severity

Secretlint rules report `error`, `warning` or `info`. The SARIF formatter writes `info` as `note`. ASH keeps the level and sets the matching severity:

| SARIF level | ASH severity |
|---|---|
| `error` | CRITICAL |
| `warning` | MEDIUM |
| `note` | LOW |

An `error` is a credential of one kind being present, which is the same severity whichever provider issued it, as for the other secret scanners. Secretlint always writes a level. A result that states none reads as `warning`, SARIF's default, so it is MEDIUM; a level not in this table is rated CRITICAL, the more severe choice. With ASH's default `severity_threshold` of `MEDIUM`, error and warning findings fail the scan.

## Exit status

With `--output`, Secretlint exits 0 when it finds errors too (without `--output` it would exit 1), and 2 for a fatal error. ASH always passes `--output`, so only 0 is a successful run, and any other code fails the scan even if a report is on disk. A run that writes no report, or one that is not valid SARIF, fails the scan rather than reading as clean.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule id is Secretlint's, written `preset > rule`:

```yaml
global_settings:
  suppressions:
    - rule_id: "@secretlint/secretlint-rule-preset-recommend > @secretlint/secretlint-rule-aws"
      path: tests/fixtures/example.py
      line_start: 4
      line_end: 4
      reason: a documented example value, not a credential
```

Package-scoped and symbol-scoped suppressions do not apply: no Secretlint finding names a package or a symbol.

## Offline and air-gapped use

Secretlint reads only the files it is given, and its rules are in the npm packages, so it behaves the same offline. Install it before going offline.

## License

Secretlint and its SARIF formatter are MIT-licensed. ASH does not redistribute them: the install step downloads them from the npm registry.
