# Community plugins

Community plugins are scanner plugins that ship inside ASH, under `automated_security_helper.plugin_modules`, and are maintained in the ASH repository, but that `ash scan` does not load by default. Each one wraps a tool that you install separately or that the ASH container image provides. [Plugins](../../../plugins/index.md) explains the plugin model, including how to write and package a plugin of your own.

## Load a community plugin

A scan runs a community scanner only when a module list names its module: `ash_plugin_modules` in an ASH config, `--ash-plugin-modules`, `ASH_PLUGIN_MODULES` or `--config-overrides` ([Load a plugin module](../../../plugins/index.md#load-a-plugin-module)). Once the module is loaded, its scanner is enabled. For example:

```bash
ash plugin list --ash-plugin-modules automated_security_helper.plugin_modules.ash_trivy_plugins
```

lists `trivy-repo` among the scanners.

A repository's own config file, such as `.ash/.ash.yaml`, may load every module on this page except `ash_snyk_plugins`: the snyk-code scanner sends the scanned source to Snyk with your Snyk credentials, so only the operator may load it ([Who may load a module](../../../plugins/index.md#who-may-load-a-module)).

`ash dependencies install` installs a community scanner's tool only while its module is loaded. The command has no `--ash-plugin-modules` option, so name the module with a config override:

<!-- doctest: illustrative reason="downloads the tool from its release page" -->
```bash
ash dependencies install \
  --config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_hadolint_plugins]' \
  --tool hadolint
```

Without the override, `--tool hadolint` fails with "Unknown tool(s): hadolint", and unless a config lists the module, `ash dependencies install` installs no community tool.

## The community plugins

Module names are short here; the full name is `automated_security_helper.plugin_modules.` followed by the module. Every option of each scanner is in the [scanner reference](../../../reference/scanners.md).

| Scanner | Module | Finds | Tool | Network | In the container image | Status |
|---|---|---|---|---|---|---|
| [`ferret-scan`](ferret-scan-plugin.md) | `ash_ferret_plugins` | sensitive data, such as card numbers, ID numbers and API keys | ferret-scan, from PyPI | none | no | |
| [`snyk-code`](snyk-plugin.md) | `ash_snyk_plugins` | code vulnerabilities (SAST) | the Snyk CLI, which you install | sends the source to Snyk | no | operator-only |
| [`trivy-repo`](trivy-plugin.md) | `ash_trivy_plugins` | vulnerable dependencies, misconfigurations, secrets and licenses | trivy, pinned release | downloads trivy's database when online | yes | |
| [`hadolint`](hadolint-plugin.md) | `ash_hadolint_plugins` | problems in Dockerfiles and Containerfiles | hadolint, pinned release | none | yes | pending licensing review |
| [`guarddog`](guarddog-plugin.md) | `ash_guarddog_plugins` | the patterns malicious packages use | GuardDog, from PyPI | none, unless its `verify` option is on | yes | pending licensing review |

hadolint status: pending licensing review. The review covers the third-party components that ASH's container image would redistribute for this plugin: the hadolint binary and the libraries statically linked into it.

GuardDog status: pending licensing review. The review covers the third-party components that ASH's container image would redistribute for this plugin: GuardDog and its pygit2 dependency, with the libgit2 library bundled in pygit2's package.

## trivy-repo and the built-in trivy scanner

ASH has a built-in `trivy` scanner, enabled by default, that runs `trivy fs` with only trivy's vulnerability scanner ([Trivy filesystem scanner](../builtin/trivy.md)). The community `trivy-repo` scanner runs `trivy repository` with trivy's vulnerability, misconfiguration, secret and license scanners. Both use the same trivy binary and database. If you load `ash_trivy_plugins` and leave the built-in scanner on, trivy runs twice and every vulnerability both find is reported once by each scanner, because ASH does not deduplicate findings.

For a new setup, use the built-in scanner and turn on the trivy scanners you want:

```yaml
project_name: my-service
scanners:
  trivy:
    options:
      scanners: [vuln, secret, misconfig, license]
```

If you already use trivy-repo, turn the built-in scanner off so that findings are not reported twice:

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_trivy_plugins]
scanners:
  trivy:
    enabled: false
```

The two do not have the same defaults: trivy-repo reports only vulnerabilities that have a fix (`ignore_unfixed: true`) and looks for licenses in file headers (`license_full: true`), and the built-in scanner does neither unless you set those options. [Trivy plugin](trivy-plugin.md) covers trivy-repo's options.
