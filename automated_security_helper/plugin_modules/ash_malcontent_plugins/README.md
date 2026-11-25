# Malcontent (community plugin)

Runs [Malcontent](https://github.com/chainguard-dev/malcontent) (Chainguard, Apache-2.0) over the scan target. `mal analyze` lists the capabilities of programs, scripts and archives (14,500+ embedded YARA-X rules) with a risk level per behavior. It looks for supply-chain compromise: droppers, obfuscation, exfiltration, persistence.

Malcontent describes what code can do, not defects. The README of the tool says `CRITICAL` findings "should be considered malicious" and `analyze` is "paranoid", so expect false positives. The plugin follows that: low-risk behaviors are INFO.

## Enabling it

The plugin is off unless its module is listed.

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_malcontent_plugins
```

Once listed, the scanner is enabled. Turn it off with `scanners.malcontent.enabled: false`.

## Installing Malcontent

Malcontent publishes no release binaries: its GitHub releases (v1.28.2 and earlier) carry no assets, so ASH has nothing to pin and verify and declares no install command. Provide `mal` (or `malcontent`) on `PATH` yourself:

- build from source: `make install-yara-x`, then `make out/mal` (needs Go and Rust, see the Malcontent README); or
- use the container image `cgr.dev/chainguard/malcontent:latest` as the base of your own scan image.

`ash dependencies install --tool malcontent` therefore has nothing to do. A scan without the binary reports the scanner as missing.

## What runs

```text
mal --format=json --output=<results>/<target>/malcontent.json --min-risk=low --third-party=false --ignore-self analyze -- <path>
```

Always passed: `--third-party=false` (Malcontent includes third-party rules, which may have licensing restrictions, unless it is turned off). Never passed: `--image`, `--processes`, `--oci-auth`, `--exit-first-hit`, `--exit-first-miss`. Only exit status 0 is a success.

## Severity

| Malcontent risk | ASH severity | SARIF level |
|---|---|---|
| critical | CRITICAL | error |
| high | HIGH | error |
| medium | MEDIUM | warning |
| low, harmless | INFO | none |
| anything else | HIGH | error |

Match strings (the text that matched in your files) are never copied into the report.

## Offline

The rules are embedded in the binary. The scan makes no network calls.

## Documentation

<https://awslabs.github.io/automated-security-helper/docs/plugins/community/malcontent-plugin/>
