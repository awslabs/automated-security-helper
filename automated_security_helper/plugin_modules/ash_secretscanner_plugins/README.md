# ASH SecretScanner plugin

Runs [Deepfence SecretScanner](https://github.com/deepfence/SecretScanner) (MIT) over a container image and reports the secrets it finds in the image's files.

## Enabling

The module is loaded only when you list it:

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_secretscanner_plugins
```

## Opt-in: name an image

SecretScanner reads an image through the local Docker daemon, not the scanned source tree. It does nothing until `scanners.secretscanner.options.image_name` is set; with no image it logs one INFO line and its row is SKIPPED. The option is honored only when you set it with `--config-overrides` or a config file outside the scanned tree and every git checkout.

```yaml
scanners:
  secretscanner:
    enabled: true
    options:
      image_name: registry.example.com/team/app:1.2.3
      scan_timeout: 1800
```

## Installing

Deepfence publishes no release binaries. Build `SecretScanner` from source, or take the binary from the `quay.io/deepfenceio/deepfence_secret_scanner_ce` image, put it on `PATH`, and keep its rules (`secret.yar`) in `/home/deepfence/usr`, where the tool looks by default. ASH does not install it.

## Severity

The tool's `high`, `medium` and `low` map to HIGH/`error`, MEDIUM/`warning` and LOW/`note`. No severity is MEDIUM; an unknown one is HIGH. The matched text is never copied into the report.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/community/secretscanner-plugin/>.
