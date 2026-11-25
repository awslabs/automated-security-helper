# KubeLinter (community plugin)

The `kube_linter` scanner runs [KubeLinter](https://github.com/stackrox/kube-linter)
over Kubernetes YAML, Helm charts and Kustomize directories in your scan target and
reports its findings through ASH. KubeLinter is Apache-2.0 licensed.

This plugin is not part of the builtin scanner set. A scan that does not list its module
is unchanged. There is no license or service gate; listing the module is the opt-in.

## Enabling it

Add the module to `ash_plugin_modules` in your ASH config:

<!-- doctest: config kind=other reason="illustrative plugin-module list; the module is only importable once ASH is installed with community plugins available" -->
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kube_linter_plugins
```

Or on the command line:

<!-- doctest: illustrative reason="starts a scan that needs the kube-linter binary installed" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_kube_linter_plugins
```

## Installing KubeLinter

ASH does not install KubeLinter yet: it has no pinned release asset for it. Install the
release this plugin was written against (v0.8.3) from
<https://github.com/stackrox/kube-linter/releases> and put a `kube-linter` executable on
`PATH`, locally or in your own container build. When the pin lands, `ash dependencies
install` will provision it and this page will say so.

## What is scanned

KubeLinter reads Kubernetes YAML files (multi-document files and `List` objects
included), renders Helm charts (a directory with `Chart.yaml`) and Kustomize directories
itself, and checks the objects it finds. A tree with no Kubernetes object is a clean run
with no results: KubeLinter prints a warning and writes no report, and ASH reads that as
nothing found.

ASH runs `kube-linter lint --format=sarif --output=<report> --config=<empty config> -- <path>`
from the source directory, so reported paths are relative to it. KubeLinter writes every
result at line 1 of the manifest; ASH keeps that. Each result names the Kubernetes object
in its message.

## Configuration

The scanner has the common scanner options only (`severity_threshold`, `scan_timeout`,
`offline`) and no options of KubeLinter's. ASH passes an empty `--config`, so KubeLinter's
default checks run and a `.kube-linter.yaml` in the scanned repository cannot switch
checks off. Tune findings with ASH suppressions.

## Severity

KubeLinter reports no severity, so ASH rates by the check that fired. `issue_severity`
and the SARIF level agree.

| Check names | ASH severity | SARIF level |
|---|---|---|
| `privileged-container`, `privilege-escalation-container`, `host-network`, `host-pid`, `host-ipc`, `docker-sock`, `sensitive-host-mounts`, `privileged-ports`, `access-to-create-pods`, `access-to-secrets`, `cluster-admin-role-binding`, `wildcard-in-rules` | HIGH | error |
| every other check | MEDIUM | warning |

`privileged-ports`, `access-to-create-pods`, `access-to-secrets`, `cluster-admin-role-binding`
and `wildcard-in-rules` are not among the 31 checks KubeLinter 0.8.3 enables by default. ASH runs
only the defaults, so a scan does not report them; the rows stay so a future config change
rates them correctly.

The HIGH checks are the settings that widen what a compromised workload or identity can
reach. Nothing is CRITICAL: these are configuration findings, not a vulnerability in a
running service. A check name KubeLinter adds later is MEDIUM until it is added to the
list.

## Suppressions

Use ASH suppressions by rule and path:

<!-- doctest: config kind=other reason="illustrative suppression entry" -->
```yaml
global_settings:
  suppressions:
    - rule_id: no-read-only-root-fs
      path: deploy/legacy/app.yaml
      reason: The application writes to its root file system.
```

KubeLinter's own `ignore-check.kube-linter.io/<check>` annotations in a manifest are
read by KubeLinter and drop the finding before ASH sees it, so it is neither reported
nor counted as suppressed.

## Exit status

KubeLinter exits 0 when it finds nothing and 1 both when it finds problems and when it
fails. ASH separates the two by the report: it deletes the report before each run, so
exit 1 with a report is findings and exit 1 without one fails the scan. Any other exit
code fails the scan. KubeLinter's own log is kept in the scan's results directory and
is not copied into the scan's error lines, since it can quote text of your manifests.

## Offline and air-gapped use

The checks are compiled into the binary and a scan of plain manifests makes no network
call. ASH does not fetch Helm chart dependencies. Whether KubeLinter does for a chart
that lists any was not verified.

## License

KubeLinter is Apache-2.0. See
[third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
