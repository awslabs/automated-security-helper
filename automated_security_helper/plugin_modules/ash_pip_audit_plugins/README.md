# ASH pip-audit Plugin

[pip-audit](https://github.com/pypa/pip-audit) (Apache-2.0, a PyPA project) looks up the
pinned dependencies of Python requirements files in a vulnerability database (PyPI's JSON
API by default, or OSV) and reports the advisories that affect them. It needs network
access to that service and has no offline mode.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_pip_audit_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_pip_audit_plugins
```

With the module listed, `pip-audit` runs by default. `scanners.pip-audit.enabled: false` turns it off again. No license key or account is needed.

## Installing the tool

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_pip_audit_plugins]" --tool pip-audit
```

This runs `uv tool install pip-audit==2.10.1`.

## Configuration

```yaml
scanners:
  pip-audit:
    enabled: true                # once the module is listed; false turns it off
    options:
      vulnerability_service: pypi   # pypi | osv
      request_timeout: 15           # socket timeout per service request, seconds
      scan_timeout: 1800            # seconds per requirements file
      tool_version: null            # default "==2.10.1"
      install_timeout: 300
```

Every requirement in a scanned file must be pinned (`name==1.2.3`); an unpinned file is
reported as a failed target. Offline, the scanner is reported `MISSING`.

## Documentation

See the [plugin documentation](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/pip_audit-plugin/).
