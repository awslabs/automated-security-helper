# Plugins

ASH's converters, scanners and reporters are plugins, and so are event subscribers. Converters turn files that scanners cannot read, such as archives and notebooks, into files they can. Scanners run a security tool and return its findings as SARIF. Reporters turn the aggregated results into report files. Event subscribers are functions that ASH calls when something happens during a scan, such as a scanner finishing. [How ASH works](../concepts/how-ash-works.md) explains where each kind runs.

## Where plugins come from

| Source | Loaded | What it provides |
|---|---|---|
| Built in: `automated_security_helper.plugin_modules.ash_builtin` | on every run | the default scanners, reporters, converters and two event subscribers, listed in the [scanner](../reference/scanners.md), [reporter](../reference/reporters.md) and [converter](../reference/converters.md) references |
| Plugin modules that ship with ASH, under `automated_security_helper.plugin_modules` | only when named | the [community scanners](community.md) (ferret-scan, snyk-code, trivy-repo, hadolint and GuardDog) and the [AWS reporters](aws.md) |
| Third-party packages | only when named | anything you or someone else writes, installed in the same Python environment as ASH |

ASH has no automatic discovery. Installing a package does nothing until a module list names it, and `ash scan` imports none of the optional modules that ship with ASH unless a module list names them.

## Load a plugin module

Name the module in any of these:

- the `ash_plugin_modules` list in an ASH config file ([reference](../reference/configuration.md#ash_plugin_modules));
- the [`--ash-plugin-modules`](../reference/cli.md#scan--ash-plugin-modules) option of `ash scan` and `ash plugin list`, repeated once per module;
- the `ASH_PLUGIN_MODULES` environment variable, with module names separated by spaces;
- a config override, `--config-overrides 'ash_plugin_modules+=[module.name]'`, which also works for `ash dependencies install` and `ash report`, the commands that have no `--ash-plugin-modules` option;
- the `ash_plugin_modules` parameter of the [Python API](../reference/python-api.md).

This config loads the hadolint plugin module:

```yaml
project_name: my-service
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_hadolint_plugins
```

To check what a module provides before you scan with it, list the plugins with the module loaded. hadolint then appears in the scanners table:

```bash
ash plugin list --ash-plugin-modules automated_security_helper.plugin_modules.ash_hadolint_plugins
```

The plugins in the modules that ship with ASH are enabled as soon as their module is loaded, so loading one adds its scanners to a default scan; set `enabled: false` for a plugin in your config to turn it off. A third-party plugin's config class sets its own default. ASH imports the names from every source together; a name given twice is imported once. Separate names with commas only inside the config file's list: the command-line option and the environment variable take each value as one module name.

## Who may load a module

ASH sorts configuration by who controls it, as the [trust model](../concepts/trust-model.md#tiers) describes, and module loading follows the same tiers:

- You, the operator, may name any module: with `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides`, a config file outside every git checkout and outside the scanned directory, or the Python API.
- A config file inside a git checkout or inside the scanned directory (a repository's own `.ash/.ash.yaml`, for example), or a file an MCP client delivered, may add only modules that are installed outside every git checkout and the scanned directory. A virtual environment inside a checkout counts as inside it. Such a file may never add `ash_aws_plugins` or `ash_snyk_plugins`, because their plugins send findings or the scanned source to a remote service with your credentials.

An entry ASH will not import from that file is dropped with one warning naming it, and the scan runs without it. To load it anyway, name it from an operator source.

## What a plugin can do

A plugin is Python code that ASH imports into its own process. It runs as the same user as ASH, with the same files, environment variables and credentials, and its import-time code runs as soon as a module list names it, before any scanner starts. ASH's [scanner sandbox](../docs/scanner-sandbox.md) confines the tool processes that ASH starts on a scanner's behalf; it does not confine the plugin's own Python code, or a process the plugin starts by other means. Only install plugin packages you trust, and pin their versions as you would any other dependency of your build.

Plugins stay registered for the life of the process that loaded them. In a long-running process such as the MCP server started by `ash mcp`, install only the plugin packages, scanner tools and credentials that you want every scan in that process to be able to use.

## Package a third-party plugin

- Give the top-level package a name that ends in `ash_plugins`, such as `acme_ash_plugins`. That is the naming rule ASH's plugin loader applies to module names (it also accepts names under `ash_plugins.`), and it logs a warning for any other name.
- Decorate each plugin class (`@ash_scanner_plugin`, `@ash_reporter_plugin` or `@ash_converter_plugin`). The decorator is what registers a class for a scan. Also list the class in the module-level list for its kind, as each how-to shows, because `ash plugin list` reads those lists and not the registry.
- Give each plugin a config class whose `name` is a fixed string. That name is the key under `scanners`, `reporters` or `converters` in an ASH config, and the name `--scanners` and `ash report --format` select.
- Install the package into the Python environment that runs ASH. In container mode ASH passes the module names into the container, but the image does not contain third-party packages, so a third-party plugin needs an image you build with it installed ([Run ASH in a container](../how-to/run-in-a-container.md)).

## Write a plugin

- [Write a scanner](write-a-scanner.md) wraps a command-line tool that writes SARIF.
- [Write a reporter](write-a-reporter.md) writes a report file from the aggregated results.
- [Write a converter](write-a-converter.md) prepares files for the scanners.
- [Subscribe to scan events](event-subscribers.md) runs a function when a scanner or the whole scan finishes.

Each how-to builds a complete plugin in a package named `acme_ash_plugins` and runs it with `ash scan`.
