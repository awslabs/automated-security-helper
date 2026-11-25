# ASH ClamAV Plugin

[ClamAV](https://www.clamav.net/) is an open-source antivirus engine. ASH runs `clamscan --recursive` over the scan target and reports each file whose content matches a ClamAV signature (malware, or a known-bad pattern).

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_clamav_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_clamav_plugins
```

With the module listed, `clamav` runs by default. `scanners.clamav.enabled: false` turns it off again. If `clamscan` is not installed the scanner is reported `MISSING` and the scan exits 1.

## Installing the tool

ClamAV is a system package. ASH does not download it. Install it and fetch the signature database once:

<!-- doctest: illustrative reason="installs a system package; the command depends on the platform" -->
```bash
sudo apt-get install clamav   # or: dnf install clamav, brew install clamav
sudo freshclam
```

Without a signature database `clamscan` exits 2 and the scan fails. A database whose `daily.cvd` or `daily.cld` is older than 7 days is noted at INFO in the scan log.

## Configuration

```yaml
scanners:
  clamav:
    enabled: true
    options:
      # Seconds for the whole clamscan run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Findings and severity

Every detection is `error` in SARIF and HIGH in ASH, whatever the signature. There is no license or service gate: the scanner needs no account.

## Documentation

Exit codes, flags, suppressions and offline use: [the ClamAV plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/clamav-plugin/).
