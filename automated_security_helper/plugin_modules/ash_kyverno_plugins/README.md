# ASH Kyverno Plugin

[Kyverno](https://kyverno.io) is a policy engine for Kubernetes. Its CLI, `kyverno apply`, evaluates policies against manifests on disk without a cluster. ASH runs it over the Kubernetes manifests in the scan target and reports each policy violation at the file and line that declares the resource. ASH pins v1.19.2.

Kyverno ships no policies, so the scanner is bring-your-own-policy: with none configured it does nothing, logs at INFO and the scan reports it as skipped.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kyverno_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_kyverno_plugins
```

Listing the module is not enough to scan: also name the policies to apply.

## Installing the tool

The ASH container image includes it. Locally:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_kyverno_plugins]" --tool kyverno
```

## Configuration

`policy_paths` is honored only when the operator sets it, so the `.ash/.ash.yaml` of the scanned repository is not a place for it (an entry there is ignored with a warning). Two forms work:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_kyverno_plugins \
  --config-overrides 'scanners.kyverno.options.policy_paths=["/etc/ash/kyverno-policies"]'
```

or a config file outside the repository, passed with `ash scan --config /etc/ash/ash.yaml`:

```yaml
# /etc/ash/ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kyverno_plugins
scanners:
  kyverno:
    enabled: true
    options:
      # Kyverno policy files, or directories of them (YAML or JSON). Prefer an
      # absolute path outside the checkout. Empty: the scanner is skipped. A path
      # that does not exist fails the scan.
      policy_paths:
        - /etc/ash/kyverno-policies
      # Seconds for the whole Kyverno scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

Policy files inside the scanned repository are owned by that repository: a change that loosens a policy is checked against its own loosened policy. A `PolicyException` under `policy_paths` is applied. Everything under a policy directory, Chainsaw tests and kustomize files are not scanned as resources, and two files that declare the same object are checked in separate Kyverno runs so each finding lands on its own file.

## Documentation

What is scanned, severity mapping, the policy kinds supported, suppressions and offline use: [the Kyverno plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/kyverno-plugin/).
