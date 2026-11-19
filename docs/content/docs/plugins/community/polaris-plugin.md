# Polaris (community plugin)

[Polaris](https://github.com/FairwindsOps/polaris) checks Kubernetes manifests against
best-practice rules in three categories: security (host networking, privileged
containers, privilege escalation, running as root, read-only root filesystems),
reliability (image tags, probes, replica counts) and efficiency (CPU and memory
requests and limits). The checks are built into the Polaris binary, which is licensed
under Apache-2.0.

## Enabling it

Polaris is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF. There is no license or service gate to accept.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_polaris_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_polaris_plugins
```

With the module listed, `polaris` runs by default, like every other scanner. `scanners.polaris.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing Polaris

- **Container mode:** the ASH image includes the pinned Polaris release once the image build lists it.
- **Local mode:** `ash dependencies install --tool polaris`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_polaris_plugins"]'`), downloads the pinned release archive from GitHub and verifies it against the SHA256 digest pinned in ASH. Polaris publishes Linux (amd64, arm64), macOS (amd64, arm64) and Windows (amd64) builds.
- Any `polaris` already on `PATH` is also used.

## What is scanned

Polaris reads every `*.yaml` and `*.yml` file under the scanned directory and audits the Kubernetes objects it finds (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Pods and the other workload kinds it knows). A YAML file that is not Kubernetes yields no findings. The scan runs as `polaris audit --audit-path`, so it never contacts a cluster.

Polaris's report names the object (kind, namespace, name) but not the file. ASH finds the file by reading the YAML under the scanned directory for the same kind and name, and reports the line of `metadata.name`. An object defined in two files is reported against both. A check failure on an object that no regular file in the scanned tree defines (for example a file reached through a symbolic link that leaves the tree) is not reported, and a warning in the scan log counts them.

## Configuration

```yaml
scanners:
  polaris:
    enabled: true
    options:
      # Seconds for the Polaris run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no option for a Polaris config file and no option to honor exemptions. ASH passes `--disallow-exemptions`, so the `polaris.fairwinds.com/<check>-exempt` annotations on a manifest are ignored: the scanned tree cannot hide a finding from ASH. Polaris uses its built-in check set and severities.

## Severity

| Polaris severity | ASH severity | SARIF level |
|------------------|--------------|-------------|
| `danger`         | HIGH         | `error`     |
| `warning`        | MEDIUM       | `warning`   |

Polaris checks are configuration best practice, not exploitable vulnerabilities, so `danger` is HIGH rather than CRITICAL. A check with a severity Polaris does not document is reported as HIGH, the more severe choice. A passed check and a check whose severity is `ignore` are not findings.

With ASH's default `severity_threshold` of `MEDIUM`, both levels fail the scan.

## Exit status

Polaris is run with `--set-exit-code-on-danger`, so it exits 3 when a danger-level check failed and 0 otherwise. ASH accepts both. Any other exit code, 1 included (a path or option Polaris could not use), fails the scan even when a report was written. Polaris's log is not copied into the scan's errors, because it can name paths from the scanned tree; the failure message names the log file instead.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule id is the Polaris check id, for example `hostNetworkSet`:

```yaml
global_settings:
  suppressions:
    - rule_id: hostNetworkSet
      path: k8s/node-agent.yaml
      line_start: 5
      line_end: 5
      reason: the node agent needs the host network
```

Package-scoped and symbol-scoped suppressions do not apply. Polaris's own annotation exemptions are not honored, as described under Configuration.

## Offline and air-gapped use

The checks are compiled into the binary and `polaris audit --audit-path` makes no network call, so the scanner behaves the same offline. Install it before going offline.

## License

Polaris is licensed under Apache-2.0. ASH runs it as a separate program. The ASH container image includes the unmodified binary with its license text (see [Third-party license files](../../../how-to/run-in-a-container.md#third-party-licenses)).
