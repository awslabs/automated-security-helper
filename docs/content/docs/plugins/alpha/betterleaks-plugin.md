# Betterleaks (alpha plugin)

[Betterleaks](https://github.com/betterleaks/betterleaks) finds secrets in files. It is the successor to gitleaks, written by gitleaks' author, and takes the same flags for everything ASH uses. ASH runs it as `betterleaks dir` over the scan target: the files as they are on disk, not git history, which is what ASH's builtin gitleaks and detect-secrets scanners read too. ASH pins the 1.x line (v1.10.1); the 2.0 release candidates are not used.

## Enabling it

Betterleaks is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ashx scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_betterleaks_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ashx scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_betterleaks_plugins
```

With the module listed, `betterleaks` runs by default, like every other scanner. `scanners.betterleaks.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners betterleaks` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

Betterleaks runs beside the builtin `gitleaks` scanner, not instead of it, so a secret both find is reported once by each.

## Installing Betterleaks

- **Container mode:** the ASH image includes Betterleaks v1.10.1.
- **Local mode:** `ashx dependencies install` (or `ashx dependencies install --tool betterleaks`),
  with the module listed in `ash_plugin_modules` (or added with
  `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_betterleaks_plugins"]'`),
  downloads the pinned v1.10.1 release archive from GitHub and verifies it against
  the SHA256 digest pinned in ASH, and the executable inside it against a second
  pinned digest, before installing it. Linux, macOS and Windows on x86_64 and arm64
  are supported.
- **Nix mode:** the flake does not supply Betterleaks. Install it with `ashx dependencies install`, or have it on `PATH`.
- Any `betterleaks` already on `PATH` is also used.

## What is scanned

Betterleaks is handed the whole target and walks it itself, skipping what its rules and filters exclude. Its default rules are compiled into the binary. A finding is reported at the file and line, with the secret replaced by `REDACTED` in the report and the log: ASH passes `betterleaks --redact=100` and rewrites any snippet that is not `REDACTED`.

ASH's own output directory sits inside the source tree by default, so Betterleaks reads it; ASH drops every result under it, except for a file the repository committed there. Betterleaks opens archives to a depth of 8 and decodes encoded text to a depth of 5 by default. It makes no network calls with these flags.

## Configuration

```yaml
scanners:
  betterleaks:
    enabled: true
    options:
      # A Betterleaks TOML config, honored only when set with --config-overrides
      # or an ASH config file outside every git checkout and the scanned tree.
      # Unset, Betterleaks uses BETTERLEAKS_CONFIG or BETTERLEAKS_CONFIG_TOML (or
      # the GITLEAKS_ names of them) from the environment if one is set, else its
      # built-in rules. A path that is honored but missing fails the scan.
      config_file: null
      # Honor betterleaks:allow and gitleaks:allow comments in the scanned files.
      # Operator only. Off, every finding reaches ASH.
      honor_inline_ignores: false
      # Run over a tree that holds a .betterleaksignore or .gitleaksignore.
      # Operator only. Off, such a tree fails the scan.
      honor_tree_ignore_files: false
      # Seconds for the whole Betterleaks scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

Betterleaks reads a `.betterleaks.toml` or `.gitleaks.toml` from the scanned tree only with `betterleaks --unsafe-auto-load-config`, which ASH never passes, so the scanned repository does not choose the rules. One of those files in the tree is noted in the scan log and not read. A relative `BETTERLEAKS_CONFIG` (or `GITLEAKS_CONFIG`) in your environment is anchored to the directory ASH runs in and passed with `--config`, because Betterleaks would otherwise read it from the scanned tree. Under `--sandbox` these variables, and a `config_file` outside the scanned tree, are not passed in.

Everything Betterleaks' configuration supports works in your `config_file`: rules, the global and per-rule `prefilter` and `filter` expressions, and the rest of its [config reference](https://github.com/betterleaks/betterleaks/blob/main/docs/config.md). A secret-validation block in a rule only runs with `betterleaks --validation`, which ASH does not pass.

## Ignore files

A `.betterleaksignore` (or a `.gitleaksignore`) at the root of the scan path lists finding fingerprints, `<file>:<rule>:<line>`, which Betterleaks drops before it writes its report. It reads that file whatever `betterleaks --gitleaks-ignore-path` says, so ASH cannot turn it off. What it hides would be neither reported nor counted as suppressed.

So a scan whose tree holds either file fails before Betterleaks runs, with a message naming the file. Move its entries to [ASH suppressions](../../../concepts/suppressions.md), which are reported and counted, or set `scanners.betterleaks.options.honor_tree_ignore_files: true` in a config outside the scanned tree to accept the file. ASH's gitleaks scanner instead re-scans the files such a file names and adds the dropped findings back; the Betterleaks plugin does not.

The same holds for inline `betterleaks:allow` and `gitleaks:allow` comments: ASH passes `betterleaks --ignore-gitleaks-allow` so they hide nothing, unless `honor_inline_ignores` is set by the operator.

## Severity

Betterleaks results carry no level. Every result is `error` in SARIF and CRITICAL in ASH: each rule says a credential of one kind is present, and an exposed credential is the same severity whichever provider issued it. With ASH's default `severity_threshold` of `MEDIUM`, every finding fails the scan.

## Differences from gitleaks

| | gitleaks (builtin scanner) | Betterleaks (this plugin) |
|---|---|---|
| Command | `gitleaks dir` | `betterleaks dir` |
| Config in the scanned tree | read by default; ASH passes a default-rules config to prevent it | not read unless `betterleaks --unsafe-auto-load-config`, which ASH never passes |
| Config environment variables | `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML` | `BETTERLEAKS_CONFIG`, `BETTERLEAKS_CONFIG_TOML`, with the `GITLEAKS_` names as the fallback |
| Ignore file | `.gitleaksignore`; ASH re-scans what it names | `.betterleaksignore` first, else `.gitleaksignore`; a tree that holds one fails the scan |
| Baseline file | `baseline_path` option | not offered |
| Exit codes | 0 clean, 1 failure or leaks, `gitleaks --exit-code=2` for leaks | the same; an unknown flag exits 126 |
| SARIF `semanticVersion` | `v8.0.0`, dropped by ASH | `v8.0.0`, dropped by ASH |
| `--version` | `8.30.1` | `betterleaks version 1.10.1` |

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: github-pat
      path: tests/fixtures/example.py
      line_start: 4
      line_end: 4
      reason: a documented example value, not a credential
```

Package-scoped and symbol-scoped suppressions do not apply: no Betterleaks finding names a package or a symbol.

## Offline and air-gapped use

Betterleaks reads only the files it is given and its rules are compiled into the binary, so it behaves the same offline. Install it before going offline (the container image already has it).

## License

Betterleaks is MIT-licensed. The ASH container image includes the unmodified binary, and its license is in the image at `/usr/share/doc/ash/third-party/betterleaks/`, installed the same way as every other bundled tool's (see
[Third-party license files](../../../how-to/run-in-a-container.md#third-party-licenses)).
