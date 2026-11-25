# ASH KubeLinter plugin

Community scanner that runs [KubeLinter](https://github.com/stackrox/kube-linter) over
Kubernetes manifests, Helm charts and Kustomize directories in the scan target.

There is no license or service gate: the scanner is on once its module is listed. A scan
that does not list the module is unchanged.

## Enabling

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kube_linter_plugins
```

## Installing

The container image does not include KubeLinter unless your build adds it, and ASH has
no pinned release asset for it yet, so `ash dependencies install` cannot provision it.
Install KubeLinter v0.8.3 (the release this plugin was written against) from its GitHub
releases and put `kube-linter` on `PATH`.

## Configuration

The scanner takes the common scanner options (`severity_threshold`, `scan_timeout`,
`offline`) and no KubeLinter-specific ones. ASH always runs KubeLinter's default checks
with an empty config of its own, so a `.kube-linter.yaml` in the scanned repository
cannot switch checks off. Tune findings with ASH suppressions.

## Severity

KubeLinter has no severity. ASH rates by check name: privileged containers, host
namespaces, the Docker socket, privilege escalation, sensitive host mounts and
wildcard, secret-reading, pod-creating or cluster-admin RBAC are HIGH (SARIF `error`);
every other check is MEDIUM (`warning`). The five RBAC and port checks in the HIGH list
(`access-to-create-pods`, `access-to-secrets`, `cluster-admin-role-binding`,
`privileged-ports`, `wildcard-in-rules`) are not among KubeLinter's default checks, and ASH
runs only the defaults, so a scan does not report them.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/community/kube_linter-plugin/>.
