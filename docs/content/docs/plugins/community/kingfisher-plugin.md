# Kingfisher (community plugin)

[Kingfisher](https://github.com/mongodb/kingfisher) finds secrets in files. It is maintained by MongoDB and licensed Apache-2.0. ASH runs it as `kingfisher scan` over the scan target: the files as they are on disk, not git history, which is what ASH's builtin gitleaks and detect-secrets scanners read too. The flags ASH passes were checked against v2.19.1.

## Enabling it

Kingfisher is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kingfisher_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_kingfisher_plugins
```

With the module listed, `kingfisher` runs by default, like every other scanner. `scanners.kingfisher.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners kingfisher` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

Kingfisher runs beside the builtin secret scanners, not instead of them, so a secret more than one of them finds is reported once by each.

## Installing Kingfisher

ASH has no pinned release of Kingfisher: `utils/tool_downloads.py` has no `kingfisher` entry, and the ASH container image does not include it. Install the binary yourself, from the [Kingfisher releases](https://github.com/mongodb/kingfisher/releases), and put `kingfisher` on `PATH` (in a container run, in your own image). ASH's flags were checked against v2.19.1. If the binary is not found, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## What is scanned

Kingfisher is handed the whole target and walks it itself. Its rules are compiled into the binary. A finding is reported at the file and line. ASH passes `kingfisher scan --redact`, which makes Kingfisher write the matched text as `[REDACTED:<hash>]`, and rewrites any snippet that is not in that form to `REDACTED`.

ASH's own output directory sits inside the source tree by default, so Kingfisher reads it; ASH drops every result under it, except for a file the repository committed there.

Every run carries these flags, none of them configurable except where the validation section says so:

| Flag | Why |
|---|---|
| `--no-validate` | Kingfisher checks each finding against the provider's live API by default, which sends the candidate credential to a third party. See [Live validation](#live-validation). |
| `--no-update-check` | Kingfisher does not look for a newer release itself. |
| `--quiet` | No progress output. |
| `--redact` | Secrets are hashed in the report. |
| `--no-ignore` | Inline ignore directives in the scanned files hide nothing from ASH, where suppressions are reported and counted. |
| `--git-history=none` | Scan the working tree, not commit history. |
| `--format=sarif --output=<file>` | SARIF is the format ASH reads. Kingfisher's own help marks it experimental. |

Kingfisher does not read a `kingfisher.yaml` unless it is given `--config`, which ASH never passes, so the scanned repository does not choose the rules.

## Configuration

```yaml
scanners:
  kingfisher:
    enabled: true
    options:
      # Let Kingfisher validate each finding against the provider's live API.
      # Operator only. Off, ASH passes --no-validate and no credential leaves
      # the host.
      validate_credentials: false
      # Seconds for the whole Kingfisher scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

## Live validation

Validation is Kingfisher's default: it contacts the issuer of each credential it matched (a cloud provider, a SaaS API) to see whether the credential works. ASH turns it off, because that sends what may be a live secret from the scanned tree to a third party, and the scanned repository must not be able to cause that.

`validate_credentials: true` removes `--no-validate`. Like the options of the other community plugins that widen what a scan does, it is used only when the operator sets it, with `--config-overrides` or in a config file outside every git checkout and the scanned directory. Set in a config inside one, or by an MCP client, it is ignored with a warning and Kingfisher still runs with `--no-validate`. The scanner sandbox grants Kingfisher no network, so validation requests only succeed outside it.

With validation on, Kingfisher exits 205 when a credential is confirmed live; ASH treats that as a successful scan, as it does 0 (nothing found) and 200 (something found).

## Severity

Every result is `error` in SARIF and CRITICAL in ASH, and `issue_severity` and the SARIF level agree: each rule says a credential of one kind is present, and an exposed credential is the same severity whichever provider issued it. Kingfisher's own SARIF level follows its confidence (`note` for low, `warning` for medium, `error` for high); ASH does not let that lower the rating. With ASH's default `severity_threshold` of `MEDIUM`, every finding fails the scan.

## Exit codes

| Exit code | Meaning | ASH |
|---|---|---|
| 0 | nothing found | success |
| 200 | something found | success |
| 205 | a credential was confirmed live | success |
| 3 | nothing to scan | the scan fails |
| anything else | Kingfisher failed | the scan fails, even if a report is on disk |

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. Kingfisher's rule ids look like `betterleaks.github-pat`:

```yaml
global_settings:
  suppressions:
    - rule_id: betterleaks.github-pat
      path: tests/fixtures/example.py
      line_start: 4
      line_end: 4
      reason: a documented example value, not a credential
```

Package-scoped and symbol-scoped suppressions do not apply: no Kingfisher finding names a package or a symbol.

## Offline and air-gapped use

With `--no-validate` and `--no-update-check`, Kingfisher reads only the files it is given and its rules are compiled into the binary, so it behaves the same offline. Install it before going offline. With `validate_credentials` on, it needs network access to each credential's issuer.

## License

Kingfisher is Apache-2.0 licensed. ASH does not bundle or redistribute it: you install the binary under its own license, and nothing of Kingfisher is shipped in the ASH package or image.
