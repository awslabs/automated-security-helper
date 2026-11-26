# KubeLinter alpha scanner plugin

Runs [KubeLinter](https://github.com/stackrox/kube-linter) (Apache-2.0) as the `kube-linter`
scanner over the Kubernetes manifests, Helm charts and Kustomize directories in the scan
target, using the checks built into the binary. It does not talk to a cluster.

## Enabling

The scanner is on once its module is listed:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kube_linter_plugins
```

A scan that does not list the module is unchanged. There is no license or service gate.

## Installing

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_kube_linter_plugins"]' --tool kube-linter
```

This installs the pinned KubeLinter release (v0.8.3, pinned in `utils/tool_downloads.py`
with a SHA256 for each release archive and for the executable inside it). A download that
does not hash to its pin is refused. If `kube-linter` is already on `PATH`, ASH uses it. The
ASH container image installs it the same way.

## Configuration

The scanner takes the common scanner options (`severity_threshold`, `scan_timeout`,
`offline`) and no KubeLinter-specific ones. ASH always runs KubeLinter's default checks
with an empty config of its own, so a `.kube-linter.yaml` in the scanned repository
cannot switch checks off. Tune findings with ASH suppressions.

Annotations in the scanned manifests can still drop findings: KubeLinter skips a check
on an object annotated `ignore-check.kube-linter.io/<check>`, and every check on one
annotated `kube-linter.io/ignore-all`, before ASH sees the report, so those findings are
neither reported nor counted as suppressed. KubeLinter has no option that turns the
annotations off.

## Severity

KubeLinter has no severity. ASH rates by check name: privileged containers, host
namespaces, the Docker socket, privilege escalation, sensitive host mounts and
wildcard, secret-reading, pod-creating or cluster-admin RBAC are HIGH (SARIF `error`);
every other check is MEDIUM (`warning`). The five RBAC and port checks in the HIGH list
(`access-to-create-pods`, `access-to-secrets`, `cluster-admin-role-binding`,
`privileged-ports`, `wildcard-in-rules`) are not among KubeLinter's default checks, and ASH
runs only the defaults, so a scan does not report them.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/kube-linter-plugin/>.
