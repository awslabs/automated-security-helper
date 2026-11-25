# Kyverno (community plugin)

[Kyverno](https://kyverno.io) is a Kubernetes policy engine. Its CLI evaluates policies against manifest files without a cluster, which is how ASH uses it: it runs `kyverno apply` over the Kubernetes manifests in the scan target and reports each violation at the file and line that declares the resource. ASH pins v1.19.2.

Kyverno ships no policies of its own, so this scanner is bring-your-own-policy. With no policy configured it does nothing: it logs at INFO and the scan reports it as skipped, the way a scanner reports a tree it has nothing to test in. Name the policies in `scanners.kyverno.options.policy_paths`.

## Enabling it

Kyverno is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
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

- **Container mode:** the ASH image includes the Kyverno CLI v1.19.2.
- **Local mode:** `ash dependencies install --tool kyverno`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_kyverno_plugins"]'`), downloads the pinned v1.19.2 release archive and verifies it against the SHA256 digest pinned in ASH, and the executable inside it against a second pinned digest, before installing it. Linux and macOS on x86_64 and arm64, and Windows on x86_64 and arm64, are supported.
- **Nix mode:** the flake does not supply Kyverno. Install it with `ash dependencies install`, or have it on `PATH`.
- Any `kyverno` already on `PATH` is also used.

The pin is v1.19.2 and not v1.20.0 because v1.20.0 no longer loads the legacy `kyverno.io/v1` `ClusterPolicy` and `Policy` kinds. v1.19.2 loads those and the newer `policies.kyverno.io` kinds (`ValidatingPolicy` and the others), and prints a deprecation warning for each legacy policy file.

## Configuration

`policy_paths` is honored only when the operator sets it: with `--config-overrides`, or in an ASH config file that is outside every git checkout and outside the scanned tree. The `.ash/.ash.yaml` of the scanned repository does not count: an entry set there is ignored with a warning, so a scanned tree cannot choose which policy files ASH reads. Two forms work:

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# One run, on the command line
ash scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_kyverno_plugins \
  --config-overrides 'scanners.kyverno.options.policy_paths=["/etc/ash/kyverno-policies"]'

# Or a config file kept outside the repository
ash scan --config /etc/ash/ash.yaml
```

```yaml
# /etc/ash/ash.yaml (outside the scanned repository)
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kyverno_plugins
scanners:
  kyverno:
    enabled: true
    options:
      # Kyverno policy files, or directories of them (YAML or JSON). A relative
      # path is taken from the source directory; prefer an absolute path outside
      # the checkout. A path that does not exist fails the scan. Empty: skipped.
      policy_paths:
        - /etc/ash/kyverno-policies
      # Seconds for the whole Kyverno scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

Policy files that live inside the scanned repository (`policy_paths: [policies/]` resolved from the source directory) are read as the repository has them. The repository owns their contents, so a change that loosens a policy is checked against its own loosened policy; keep the policies outside the checkout, or review changes to them as changes to the check.

A directory contributes every `.yaml`, `.yml` and `.json` file under it that holds a policy document or a `PolicyException`. Other files in it are not passed to Kyverno. A configured set that holds no policy document (an empty directory, a submodule that was not checked out, a typo in every file, or only exceptions) is skipped like an empty one, and the log says so at INFO; check that the scan reports `kyverno` as scanned and not skipped. ASH does not report which file under a directory failed to parse as YAML.

ASH hands Kyverno the policies as one file written under the results directory, which holds every policy document found, and the exceptions as a second file passed with `--exception`. A `PolicyException` is applied, and the rule it waives then reports `skip` for that resource, which is not a finding. Kyverno's `CleanupPolicy`, `ClusterCleanupPolicy` and `GlobalContextEntry` kinds are not policies for `kyverno apply` and are left out.

## What is scanned

ASH finds the Kubernetes manifests itself and passes each to Kyverno as its own `--resource=<file>`. A `--resource=<directory>` is not used because Kyverno stops the whole run at the first YAML file in it that is not a Kubernetes object, and its error quotes that file. A file is passed when every document in it parses and has `apiVersion` and `kind`. Empty documents (a leading or trailing `---`, or a document that holds only comments) are ignored. `kind: List` files are read item by item.

Left out:

- Files that do not parse, files over 5 MiB, and Helm templates and other templated YAML. Run `helm template` into a directory of the scan target first to have a chart checked.
- The policy and exception files themselves, and everything under a directory named in `policy_paths`. A vendored policy library carries Chainsaw tests and negative fixtures that are meant to violate its policies; they are not workloads.
- Kyverno's own kinds (`kyverno.io`, `policies.kyverno.io`, `cli.kyverno.io`), Chainsaw tests (`chainsaw.kyverno.io`), kustomize files (`kustomize.config.k8s.io`) and policy report kinds. A kustomize patch file is a partial manifest of an ordinary kind and is scanned like any other.
- A file that holds an object beside a document that is not one (a Deployment and a `PolicyException`, or a manifest and a plain config document in one file). Kyverno stops the run at such a document, so the whole file is left out. ASH names the left-out files in one WARNING and does not count them; split the file to have its objects checked.
- A file whose name contains a comma or a double quote. Kyverno splits each `--resource` value on commas, so `a,b.yaml` would be read as two other paths, and a quote fails the flag. ASH names these files in a WARNING; rename them to have them scanned.

A tree with policies configured and no manifest that qualifies (a Helm-only repository, for instance) is skipped like a tree with no policies: Kyverno is not started, the log says "No Kubernetes manifests found" at INFO, and the row reports skipped.

Kyverno runs offline: ASH does not pass `--cluster`, `--registry` or any flag that reads a kubeconfig or reaches a git repository. Policies that need cluster data or registry access (`apiCall` context entries, image verification) do not get it and report what they can.

Kyverno's report names a resource (kind, namespace, name) and no file, so ASH maps each result back to the manifest that declares it. Two files often declare the same object: a kustomize base and its overlays, or per-environment copies. ASH never gives such files the same Kyverno run. It plans the runs so that, inside one run, each (kind, namespace, name) is declared by one file, and maps that run's report with that run's files alone. A copy with no namespace collides with a copy of the same kind and name in any namespace, because Kyverno may report a namespace the manifest does not state. A tree with a base and N overlays of one object therefore makes N+1 Kyverno runs, and every violation is reported at the file that declares the violating copy. A resource ASH cannot match to any file is reported against the scan directory.

## Severity

ASH reads the `severity` Kyverno puts on each result. It comes from the policy's `policies.kyverno.io/severity` annotation.

| Kyverno severity | ASH severity | SARIF level |
|---|---|---|
| `critical` | CRITICAL | `error` |
| `high` | HIGH | `error` |
| `medium` | MEDIUM | `warning` |
| `low` | LOW | `note` |
| `info` | INFO | `none` |

The names are matched without regard to case, so `Critical` is CRITICAL. A policy with no severity gets MEDIUM for a `fail` and LOW for a `warn`. A severity name outside the five (`severe`, say) is HIGH, SARIF `error`, and not CRITICAL: it is read as serious without being read as the worst. CRITICAL and HIGH both map to the SARIF level `error`, and the ASH severity and the SARIF level come from the same row, so they agree. These are policy violations in manifests, not demonstrated exploits, which is why nothing is raised above what the policy declares.

Only `fail` and `warn` results are findings. `pass` and `skip` are not. `error` is a result value, not a severity: it means Kyverno could not evaluate that rule on that resource. It is listed in the scan's errors by policy, rule and resource, without Kyverno's message, one line per resource. The scan counts a failed target once per file, not once per line: five resources of one manifest that a rule could not evaluate are one failed target out of one attempted.

## Exit status and failures

`kyverno apply` exits 0 when nothing failed and 1 for a failed result, a policy evaluation error, and also when it could not load its inputs. The exit code alone cannot tell those apart, so ASH counts a run that exits 1 as complete only when its report holds a `fail` or `error` result. A run that exits 1 with no such result did not evaluate what it was given. ASH splits that run's manifests in half and runs the halves again, down to single manifests (at most 32 splits per scan), so that one manifest Kyverno cannot load is a failed target named by its path while the other manifests keep their results. If no run completes at all, the scan fails; so does any other exit code, a timeout, a report ASH cannot read, or a run in which every policy was skipped as invalid. Kyverno's stderr is written to the scanner's log file and not quoted in the scan's errors, because it can contain text from a scanned file.

Kyverno silently skips a policy path that does not exist and a file that is not a valid policy, and exits 0. ASH therefore checks the paths itself: a missing path fails the scan, and a configured set with no policy document in it is skipped like an empty one. An invalid policy among valid ones is skipped by Kyverno, which says so in a "Policies Skipped" block on stdout; ASH reads the policy names from that block and lists each as a failed target named by the policy's file, without Kyverno's reason. A run that prints no results at all is logged at WARNING, because it means no policy matched a manifest or every policy was skipped as invalid.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule ID is `<policy>/<rule>` for a `ClusterPolicy`, and `<namespace>/<policy>/<rule>` for a namespaced `Policy`, whose name Kyverno reports as `<namespace>/<policy>`. The policy kinds in `policies.kyverno.io` (`ValidatingPolicy` and the others) have a list of validations rather than named rules, so Kyverno reports no rule for them and the rule ID is `<policy>/unknown-rule`.

```yaml
global_settings:
  suppressions:
    - rule_id: require-team-label/check-team-label
      path: k8s/legacy/bad.yaml
      line_start: 1
      line_end: 1
      reason: legacy workload scheduled for removal
    - rule_id: default/require-team-label/check-team-label
      path: k8s/legacy/bad.yaml
      line_start: 1
      line_end: 1
      reason: the same rule from the namespaced policy
```

A `PolicyException` found under `policy_paths` is applied by Kyverno, and the waived rule's result is `skip` (not a finding), so it is not reported or counted as a suppression. A finding hidden by an ASH suppression is reported and counted. Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

Without `--cluster`, Kyverno reads only the files it is given, so it behaves the same offline. Install it before going offline (the container image already has it).

## License

Kyverno is Apache-2.0 licensed. The ASH container image includes the unmodified CLI binary, and its license is in the image at `/usr/share/doc/ash/third-party/kyverno/`, installed the same way as every other bundled tool's (see [Third-party license files](../../../how-to/run-in-a-container.md#third-party-licenses)).
