# SecretScanner (community plugin)

[SecretScanner](https://github.com/deepfence/SecretScanner) from Deepfence finds secrets in the files of a container image. ASH runs it as `SecretScanner -output=json -image-name=<image>` and converts its JSON report to SARIF. Unlike most ASH scanners it reads an image, not the scanned source tree.

## Enabling it

SecretScanner is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_secretscanner_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_secretscanner_plugins
```

With the module listed, the scanner is on by default, but it needs an image to do anything (next section). `scanners.secretscanner.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner.

## Naming the image (the opt-in)

Without `scanners.secretscanner.options.image_name`, SecretScanner runs nothing: it logs one INFO line, reports no findings, and its row is SKIPPED. With an image set, it scans that image once per run.

`image_name` is honored only when you set it with `--config-overrides` or in an ASH config file outside the scanned tree and every git checkout. Set by a config inside the scanned tree, or by an MCP client, it is ignored with a warning and the scanner does not run, because the setting makes ASH read an image through your Docker daemon. A value that is not an image reference (letters, digits and `. _ / : @ + -`, not starting with a dash) fails the scan.

## Installing SecretScanner

Deepfence publishes no release binaries, so ASH does not install it and does not pin a release.

- Build `SecretScanner` from source (`make`; it needs Hyperscan and YARA), or copy the binary out of the `quay.io/deepfenceio/deepfence_secret_scanner_ce` image.
- Put it on `PATH` as `SecretScanner`.
- Keep its rules file, `secret.yar`, in `/home/deepfence/usr`, where the tool looks by default. ASH passes neither `-rules-path` nor `-config-path`, so a repository cannot supply either.
- A missing binary reports the scanner `MISSING`, and the scan exits 1 (the incomplete-scan gate).
- The Docker daemon must be reachable by the user running ASH.

## What is scanned

SecretScanner unpacks the image and matches its files against its rule set of about 140 secret types. ASH passes only:

| Flag | Why |
|---|---|
| `-output=json` | The default output is a table. JSON goes to stdout; the tool's logs go to stderr. |
| `-image-name=<image>` | The image to scan. One token, so a value is never read as a flag. |
| `-temp-directory=<dir>` | Where the image is unpacked: a directory under ASH's results directory. |

ASH never passes `-local`, `-enable-updater` (downloads rules at run time), `-config-path`, `-rules-path`, `-console-url`, `-deepfence-key`, `-socket-path`, `-http-port`, `-standalone-http-port` or `-container-id`.

## Configuration

```yaml
scanners:
  secretscanner:
    enabled: true
    options:
      # The image to scan, with its tag. Operator only. Unset, nothing runs.
      image_name: registry.example.com/team/app:1.2.3
      # Seconds for the whole scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

## Findings

A finding is a file inside an image layer, so it has no line number: its SARIF location is the path inside the image, with no region. The report carries the rule name, the image and the layer ID. The matched text is the secret itself and is never copied into the report or the logs.

## Severity

SecretScanner rates each rule `high`, `medium` or `low`. ASH keeps that rating:

| SecretScanner | ASH severity | SARIF level |
|---|---|---|
| `high` | HIGH | `error` |
| `medium` | MEDIUM | `warning` |
| `low` | LOW | `note` |
| none | MEDIUM | `warning` |
| anything else | HIGH | `error` |

An unknown rating errs to the more severe, so nothing is under-reported.

## Failures

The scan fails, with an error that does not quote the tool's output, on a timeout, on any exit status other than 0 (no Docker daemon, image not found), on empty output, and on output that is not the JSON object the tool writes. The tool's stderr can quote the image's contents, so it stays in the scan's log directory.

## Suppressions

ASH suppressions by rule and path work as for any scanner. Line-scoped suppressions do not apply, since findings carry no line:

```yaml
global_settings:
  suppressions:
    - rule_id: aws-access-key
      path: /app/config/example.env
      reason: a documented example value, not a credential
```

## Offline and air-gapped use

The rules are files next to the binary and nothing is fetched at scan time. The image must already be in the local Docker daemon, or be pullable by it.

## License

SecretScanner is MIT-licensed. ASH does not redistribute it.
