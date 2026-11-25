# ASH bundler-audit Plugin

[bundler-audit](https://github.com/rubysec/bundler-audit) finds known-vulnerable gems in a Ruby project. ASH runs `bundler-audit check` over the `Gemfile.lock` at the root of the scan target and matches each locked gem against the [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db) advisories. It also reports a gem source fetched over `git://` or `http://`.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_bundler_audit_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_bundler_audit_plugins
```

With the module listed, `bundler_audit` runs by default. `scanners.bundler_audit.enabled: false` turns it off again. A scan target with no `Gemfile.lock` at its root is skipped.

## Installing the tool

bundler-audit is a Ruby gem, so Ruby and RubyGems must be installed; ASH does not install them. The ASH container image does not include the gem. Locally:

<!-- doctest: illustrative reason="installs a gem into the user's gem directory" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_bundler_audit_plugins]" --tool bundler_audit
```

Any `bundler-audit` already on `PATH` is also used.

## Network use

bundler-audit keeps the advisory database in `~/.local/share/ruby-advisory-db`, a git clone it downloads on first use and, with `update_database` on (the default), pulls on every run. The scanner therefore needs a network, and in offline mode it is not run (reported MISSING with the reason).

## Configuration

```yaml
scanners:
  bundler_audit:
    enabled: true
    options:
      # Pull the advisory database before each check (default true). Turn it off
      # to use the database as it is, for a read-only cache or a database prepared
      # before the scan. A missing database is downloaded either way.
      update_database: true
      # Seconds for the whole scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

ASH passes its own empty `ignore` list as `--config`, so a `.bundler-audit.yml` in the scanned repository does not hide advisories. Use ASH suppressions instead.

## Documentation

Severity mapping, suppressions, offline use and the license: [the bundler-audit plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/bundler_audit-plugin/).
