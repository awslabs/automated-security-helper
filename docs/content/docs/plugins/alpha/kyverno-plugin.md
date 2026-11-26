# Kyverno Plugin

[Kyverno](https://kyverno.io) (Apache-2.0) is a Kubernetes policy engine. Its CLI evaluates policies against manifest files without a cluster, which is how ASH uses it: it runs `kyverno apply` over the Kubernetes manifests in the scan target and reports each violation at the file and line that declares the resource. ASH pins v1.19.2.

Kyverno ships no policies of its own, so this scanner is bring-your-own-policy. With no policy configured it does nothing: it logs at INFO and the scan reports it as skipped, the way a scanner reports a tree it has nothing to test in. Name the policies in `scanners.kyverno.options.policy_paths`.

## Enabling it

Kyverno is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kyverno_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_kyverno_plugins
```

With the module listed, `kyverno` runs by default, like every other scanner, once it has policies. `scanners.kyverno.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners kyverno` without the module listed is refused, with a message naming the module to add. If policies are configured and the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate). With no policies configured the tool is not looked for.

## Installing Kyverno

ASH pins the Kyverno CLI v1.19.2 in the plugin's own install module (`ash_kyverno_plugins/kyverno_install.py`: the version, one release asset per platform, a SHA256 for each archive and for the executable inside it, taken from the release's `checksums.txt`). Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_kyverno_plugins"]' --tool kyverno
```

A download that does not hash to its pin is refused. If `kyverno` is already on `PATH`, ASH uses it. The ASH container image installs it the same way. The pinned assets cover Linux, macOS and Windows on amd64 and arm64 (the [v1.19.2 release](https://github.com/kyverno/kyverno/releases/tag/v1.19.2) also publishes a linux/s390x build, which ASH does not install).

The pin is v1.19.2 and not v1.20.0 because v1.20.0 no longer loads the legacy `kyverno.io/v1` `ClusterPolicy` and `Policy` kinds. v1.19.2 loads those and the newer `policies.kyverno.io` kinds (`ValidatingPolicy` and the others), and prints a deprecation warning for each legacy policy file.

## Configuration

```yaml
scanners:
  kyverno:
    enabled: true
    options:
      # Kyverno policy files, or directories of them (YAML or JSON). A relative
      # path is taken from the source directory. Honored only when set with
      # --config-overrides or an ASH config file outside every git checkout and the
      # scanned tree. A path that does not exist fails the scan. Empty: skipped.
      policy_paths:
        - policies/
      # Seconds for the whole Kyverno scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

An entry set by a config file the scanned repository controls is ignored with a warning, so a scanned tree cannot choose which policy files ASH reads. A directory contributes every `.yaml`, `.yml` and `.json` file under it that holds a Kyverno policy document; other files in it are not passed to Kyverno. A file under the directory that resolves outside it, through a link to a file elsewhere or under a linked directory, is skipped with a warning and not read; to apply the policies such a link leads to, add their directory to `policy_paths`.

## What is scanned

ASH finds the Kubernetes manifests itself and passes each to Kyverno as its own `--resource=<file>`. A `--resource=<directory>` is not used because Kyverno stops the whole run at the first YAML file in it that is not a Kubernetes object, and its error quotes that file. A file is passed when every document in it parses and has `apiVersion` and `kind`. Left out: files that do not parse, Helm templates and other templated YAML, files over 5 MiB, the policy files themselves, Kyverno's own kinds (`kyverno.io`, `policies.kyverno.io`, `cli.kyverno.io`) and policy report kinds. `kind: List` files are read item by item.

Kyverno runs offline: ASH does not pass `--cluster`, `--registry` or any flag that reads a kubeconfig or reaches a git repository. Policies that need cluster data or registry access (`apiCall` context entries, image verification) do not get it and report what they can.

Kyverno's report names a resource (kind, namespace, name) and no file, so ASH maps each result back to the manifest that declares it. A resource it cannot match is reported against the scan directory.

## Severity

ASH reads the `severity` Kyverno puts on each result. It comes from the policy's `policies.kyverno.io/severity` annotation.

| Kyverno severity | ASH severity | SARIF level |
|---|---|---|
| `critical` | CRITICAL | `error` |
| `high` | HIGH | `error` |
| `medium` | MEDIUM | `warning` |
| `low` | LOW | `note` |
| `info` | INFO | `none` |

A policy with no severity gets MEDIUM for a `fail` and LOW for a `warn`. A severity outside the five is HIGH, so an unrecognized value is never under-reported. `error` is HIGH rather than CRITICAL because these are policy violations in manifests, not demonstrated exploits. The ASH severity and the SARIF level come from the same row, so they agree.

Only `fail` and `warn` results are findings. `pass` and `skip` are not. A result of `error` means Kyverno could not evaluate that rule on that resource; it is counted as a failed target and listed in the scan's errors by policy, rule and resource, without Kyverno's message.

## Exit status and failures

`kyverno apply` exits 0 when nothing failed and 1 for a failed result, a policy evaluation error, and also when it could not load its inputs. The exit code alone cannot tell those apart, so ASH counts a run that exits 1 as complete only when it printed a report. A run that exits 1 without one fails the scan, as does any other exit code, a timeout, or a report ASH cannot read. Kyverno's stderr is written to the scanner's log file and not quoted in the scan's errors, because it can contain text from a scanned file.

Kyverno silently skips a policy path that does not exist and a file that is not a valid policy, and exits 0. ASH therefore checks the paths itself: a missing path fails the scan, and a configured set with no policy document in it is skipped like an empty one. A run that prints no results at all is logged at WARNING, because it means no policy matched a manifest or every policy was skipped as invalid.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule ID is `<policy>/<rule>`, with `<namespace>/<policy>` for a namespaced policy:

```yaml
global_settings:
  suppressions:
    - rule_id: require-team-label/check-team-label
      path: k8s/legacy/bad.yaml
      line_start: 1
      line_end: 1
      reason: legacy workload scheduled for removal
```

Kyverno's own exceptions (`--exception` and `PolicyException`) are not passed, so a finding is hidden only by an ASH suppression, which is reported and counted. Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

Without `--cluster`, Kyverno reads only the files it is given, so it behaves the same offline. Install it before going offline.

## License

Kyverno is Apache-2.0 licensed. The ASH container image redistributes the pinned release binary, so it carries the repository `LICENSE` and `NOTICE` at the pinned commit beside it (the `kyverno` entry in `THIRD_PARTY_LICENSES`; each release archive's own `LICENSE` is byte-identical to that file). Nothing of Kyverno is shipped in the ASH Python package itself.
