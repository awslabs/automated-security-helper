# ASH Kyverno Plugin

[Kyverno](https://kyverno.io) is a policy engine for Kubernetes. Its CLI, `kyverno apply`, evaluates policies against manifests on disk without a cluster. ASH runs it over the Kubernetes manifests in the scan target and reports each policy violation at the file and line that declares the resource. ASH pins v1.19.2.

Kyverno ships no policies, so the scanner is bring-your-own-policy: with none configured it does nothing, logs at INFO and the scan reports it as skipped.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash.yaml
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

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_kyverno_plugins"]' --tool kyverno
```

This installs the pinned Kyverno CLI release (v1.19.2, `kyverno_install.py`), and refuses a download that does not hash to its pin. If `kyverno` is already on `PATH`, ASH uses it. The ASH container image installs it the same way.

## Configuration

```yaml
scanners:
  kyverno:
    enabled: true
    options:
      # Kyverno policy files, or directories of them (YAML or JSON). A relative
      # path is taken from the source directory. Honored only when set with
      # --config-overrides or an ASH config file outside every git checkout and the
      # scanned tree. Empty: the scanner is skipped. A path that does not exist
      # fails the scan. A file under a directory that resolves outside it through
      # a link is skipped and not read.
      policy_paths:
        - policies/
      # Seconds for the whole Kyverno scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

What is scanned, severity mapping, the policy kinds supported, suppressions and offline use: [the Kyverno plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/kyverno-plugin/).
