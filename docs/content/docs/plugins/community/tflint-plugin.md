# TFLint (community plugin)

[TFLint](https://github.com/terraform-linters/tflint) is a Terraform linter. ASH runs it as `tflint --recursive` over the scan target, with TFLint's bundled `terraform` ruleset, and reads the SARIF it writes. It reports configuration problems in `*.tf` and `*.tf.json` files: deprecated syntax, unused declarations, missing version constraints and naming conventions. ASH pins release v0.66.0.

## Enabling it

TFLint is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_tflint_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_tflint_plugins
```

With the module listed, `tflint` runs by default, like every other scanner. `scanners.tflint.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners tflint` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING`, unless the scan target holds no Terraform file, in which case it is `SKIPPED`.

## Installing TFLint

- **Container mode:** the ASH image includes TFLint v0.66.0.
- **Local mode:** `ash dependencies install --tool tflint`, with the module listed in `ash_plugin_modules`, downloads the pinned release archive from GitHub and verifies it against the SHA256 digest pinned in ASH. Linux and macOS on x86_64 and arm64, and Windows on x86_64, are supported (TFLint publishes no Windows arm64 build).
- **Nix mode:** the flake does not supply TFLint. Install it with `ash dependencies install`, or have it on `PATH`.
- Any `tflint` already on `PATH` is also used.

## What is scanned

TFLint is run with `--recursive`, so it inspects every directory under the scan target that holds Terraform files; hidden directories (including ASH's default `.ash/ash_output`) are skipped. A directory with a Terraform module is linted as a module, so findings inside child modules are reported when TFLint attributes them to the module being linted.

## Configuration

```yaml
scanners:
  tflint:
    enabled: true
    options:
      # Seconds the tflint run may take, per target.
      scan_timeout: 1800
```

There are no TFLint-specific options. ASH always passes `--config` pointing at an empty file it writes outside the scanned tree, so a `.tflint.hcl` or `.tflint.json` in the repository (which could disable rules or declare plugins) is not read, and `TFLINT_CONFIG_FILE` is overridden.

## Severity

TFLint's three severities map one to one onto SARIF levels, and ASH sets `issue_severity` to agree:

| TFLint | SARIF level | ASH severity |
|---|---|---|
| error | error | HIGH |
| warning | warning | MEDIUM |
| notice | note | LOW |

`error` is HIGH rather than CRITICAL because the findings are lint results, not exploitable vulnerabilities. A result with no level is rated MEDIUM; a level TFLint does not document is rated HIGH.

A file TFLint cannot evaluate (an HCL parse error, a module it cannot load) appears in TFLint's separate `tflint-errors` SARIF run. ASH treats that as a failed scan and does not copy the messages, which can quote the scanned files.

Exit codes 0 (clean) and 2 (issues found) are success. Exit 1 and any other code fail the scan.

## Suppressions

Use ASH suppressions to tune findings:

<!-- doctest: config kind=other reason="a fragment of an ASH config, not a complete file" -->
```yaml
global_settings:
  suppressions:
    - rule_id: terraform_unused_declarations
      path: modules/legacy/main.tf
      reason: Variables are consumed by a wrapper module outside this repository.
```

TFLint also honors `# tflint-ignore: <rule>` and `# tflint-ignore-file: <rule>` comments in the scanned files. TFLint documents no command-line switch that turns them off, so findings a file annotates away never reach ASH.

## Offline and air-gapped use

The bundled `terraform` ruleset is compiled into the TFLint binary and needs no network. The `aws`, `azurerm` and `google` rulesets are separate plugins that `tflint --init` downloads from GitHub. ASH does not run `--init` and passes an empty config, so those rulesets are not used. Rules that need a ruleset plugin (for example, validating AWS instance types) are therefore not part of this scanner.

## License

TFLint is licensed MPL-2.0. Its release binaries also embed files of its `terraform` package that are licensed BUSL 1.1, and the project states that the executable form is bound by both licenses. ASH runs the binary as a separate process and does not link it. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
