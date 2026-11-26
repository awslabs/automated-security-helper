# Conftest alpha scanner plugin

[Conftest](https://www.conftest.dev/) tests configuration files (YAML, JSON, TOML, HCL, Terraform, Dockerfile and more) against policies written in Rego. ASH runs `conftest test` over the scan target's configuration files and reports each `deny` and `warn` result as a finding.

Conftest ships no rules, by design. You supply the policies.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_conftest_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_conftest_plugins
```

With the module listed, `conftest` runs by default. `scanners.conftest.enabled: false` turns it off again.

## The policy gate

Conftest has nothing to test without policies. Its own convention is a `policy/` directory. When the policy directory (`options.policy_dir`, default `policy`, taken from the source directory) holds no `.rego` file, ASH does not start Conftest: it logs one INFO line and the scanner is reported SKIPPED, not PASSED.

## Installing

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_conftest_plugins"]' --tool conftest
```

This installs the pinned Conftest release (v0.62.0), refusing a download that does not hash to its pin. The ASH container image carries the same binary. If `conftest` is already on `PATH`, ASH uses it. The scanner is reported `MISSING` until it is there.

## Configuration

```yaml
scanners:
  conftest:
    enabled: true
    options:
      # Directory of Rego policies, relative to the source directory or absolute.
      # Unset means "policy".
      policy_dir: null
      # Test the policies of every namespace (Rego package), not only `main`.
      all_namespaces: true
      # Seconds for the whole Conftest scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity mapping, what is scanned, suppressions and limits: [the Conftest plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/conftest-plugin/).
