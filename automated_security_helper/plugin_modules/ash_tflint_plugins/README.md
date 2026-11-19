# ASH TFLint Plugin

[TFLint](https://github.com/terraform-linters/tflint) is a Terraform linter. ASH runs it as `tflint --recursive` over the scan target with TFLint's bundled `terraform` ruleset, and reads its SARIF output. ASH pins release v0.66.0.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_tflint_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_tflint_plugins
```

With the module listed, `tflint` runs by default. `scanners.tflint.enabled: false` turns it off again.

## Installing the tool

The ASH container image includes it. Locally:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_tflint_plugins]" --tool tflint
```

Any `tflint` already on `PATH` is also used.

## Configuration

The plugin has no TFLint-specific options. ASH always passes an empty `--config`, so a `.tflint.hcl` in the scanned tree is not read, and only the bundled `terraform` ruleset runs. The `aws`, `azurerm` and `google` rulesets are plugins that `tflint --init` downloads from GitHub; ASH never runs `--init`, so they are not used.

## Notes

- A Terraform file TFLint cannot parse fails the scan; it is not reported as a finding.
- `# tflint-ignore:` comments in the scanned files are honored by TFLint and cannot be switched off from the command line.
- TFLint is MPL-2.0; its release binaries also embed files licensed under BUSL 1.1.

## Documentation

See `https://awslabs.github.io/automated-security-helper/docs/plugins/community/tflint-plugin/`.
