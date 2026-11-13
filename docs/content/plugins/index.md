# Plugins

ASH's converters, scanners, and reporters are plugins, and so are event subscribers. Converters turn files that scanners cannot read, such as archives and notebooks, into files they can. Scanners run a security tool and return its findings as SARIF. Reporters turn the aggregated results into report files. Event subscribers are functions that ASH calls when something happens during a scan, such as a scanner finishing. [How ASH works](../concepts/how-ash-works.md) explains where each kind runs.

## Where plugins come from

| Source | Loaded | What it provides |
|---|---|---|
| Built in: `automated_security_helper.plugin_modules.ash_builtin` | on every run | the default scanners, reporters, and converters, and two event subscribers, listed in the [scanner](../reference/scanners.md), [reporter](../reference/reporters.md), and [converter](../reference/converters.md) references |
| Plugin modules that ship with ASH, under `automated_security_helper.plugin_modules` | when a module list names them (for the MCP server, see [What a plugin can do](#what-a-plugin-can-do)) | the [community plugins](../docs/plugins/community/index.md) (`ferret-scan`, `snyk-code`, and `trivy-repo`) and the [AWS reporters](aws.md) |
| Third-party packages | when a module list names them | anything you or someone else writes, installed in the same Python environment as ASH |

ASH has no automatic discovery. Installing a package does nothing until a module list names it, and `ash scan` imports none of the optional modules that ship with ASH unless a module list names them.

## Load a plugin module

Name the module in any of these:

- the `ash_plugin_modules` list in an ASH config file ([reference](../reference/configuration.md#ash_plugin_modules));
- the [`--ash-plugin-modules`](../reference/cli.md#scan--ash-plugin-modules) option of `ash scan` and `ash plugin list`, repeated once per module or given names separated by commas;
- the `ASH_PLUGIN_MODULES` environment variable, with module names separated by spaces or commas, which `ash scan` and `ash plugin list` read;
- a config override, `--config-overrides 'ash_plugin_modules+=[module.name]'`, which also works for `ash dependencies install` and `ash report`, the commands that have no `--ash-plugin-modules` option;
- the `ash_plugin_modules` parameter of the [Python API](../reference/python-api.md).

This config loads the ferret-scan plugin module:

```yaml
project_name: my-service
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins
```

To check what a module provides before you scan with it, list the plugins with the module loaded. `ferret-scan` then appears in the scanners table:

```bash
ash plugin list --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins
```

The plugins in the modules that ship with ASH are enabled as soon as their module is loaded, so loading one adds its scanners to a default scan; set `enabled: false` for a plugin in your config to turn it off. The exceptions are the four AWS reporters, which stay off until the operator turns each one on ([AWS reporters](aws.md#enable)). A third-party plugin's config class sets its own default. ASH imports the names from every source together, in order, and a name given twice is imported once. Every source splits an entry on commas, so `"a_ash_plugins, b_ash_plugins"` names two modules. This lists the scanners of two community modules named in one value:

```bash
ash plugin list \
  --ash-plugin-modules "automated_security_helper.plugin_modules.ash_ferret_plugins, automated_security_helper.plugin_modules.ash_trivy_plugins" \
  | grep -E -o "ferret-scan|trivy-repo" | sort -u
```

```text
ferret-scan
trivy-repo
```

`ash plugin list` lists every plugin registered once the modules are imported, which is the set a scan selects from.

## Who may load a module

ASH sorts configuration by who controls it, as the [Configuration trust model](../concepts/trust-model.md#tiers) describes, and module loading follows the same tiers:

- You, the operator, may name any plugin module, wherever it is installed: with `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides`, a config file outside every git checkout and the scanned directory, or the Python API.
- A config file inside a git checkout or the scanned directory (a repository's own `.ash/.ash.yaml`, for example, or a config kept in an ops repository), or a file an MCP client delivered, may add only ASH's own plugin modules and modules installed outside every git checkout and the scanned directory. A third-party package in a virtual environment inside a checkout counts as inside it. Such a file may never add `ash_aws_plugins` or `ash_snyk_plugins`, or any module inside either, such as `automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter`, because their plugins send findings or the scanned source to a remote service with your credentials.

Every source, yours included, is held to ASH's plugin namespace: a module path that starts with `automated_security_helper.` or `ash_plugins`, or whose top-level package ends in `_ash_plugins`. A name outside it, ASH's plugin root itself, a namespace package, or a name that is not a dotted path of Python identifiers stops the scan with exit code 3 before anything is scanned, whatever its source, and so does a module you name that fails to import. A scan uses only the modules it names.

From a repository's file, ASH drops every entry it cannot find or will not import, names them in one warning, and runs the scan without them. For a module installed inside a checkout, the warning says where Python found it and which checkout it is in. ASH checks where each module is without importing it, so a dropped entry runs no code. To load a dropped module anyway, name it from an operator source, or install it outside every git checkout and the scanned directory. Under its default policy, the MCP server refuses a delivered config whose `ash_plugin_modules` list has such an entry instead of dropping it ([What a delivered config cannot set](../how-to/mcp-server.md#what-a-delivered-config-cannot-set)).

## What a plugin can do

A plugin is Python code that ASH imports into its own process. It runs as the same user as ASH, with the same files, environment variables, and credentials, and its import-time code runs as soon as a module list names it, before any scanner starts. The scanner sandbox ([Enable the scanner sandbox](../docs/scanner-sandbox.md)) confines the tool processes that ASH starts on a scanner's behalf; it does not confine the plugin's own Python code, or a process the plugin starts by other means. Only install plugin packages you trust, and pin their versions as you would any other dependency of your build.

Plugins stay registered for the life of the process that loaded them. In a long-running process such as the MCP server that `ash mcp` starts, do not rely on module lists to keep out a plugin that ships with ASH or is installed in its environment. Give that process only the scanner tools and credentials you are willing to let every scan in it use, and start a new process when you change which plugin modules it loads.

## Package a third-party plugin

- Give the top-level package a name that ends in `ash_plugins`, such as `acme_ash_plugins`; ASH also accepts names under `ash_plugins.`. Other names are not supported, and ASH logs a warning for them.
- Decorate each plugin class (`@ash_scanner_plugin`, `@ash_reporter_plugin`, or `@ash_converter_plugin`). The decorator registers the class when ASH imports the module, and `ash plugin list` shows every registered plugin. The module-level lists at the end of each how-to's module register nothing and are optional.
- Give each plugin a config class whose `name` is a fixed string. That name is the key under `scanners`, `reporters`, or `converters` in an ASH config, and the name that `--scanners` and `ash report --format` select. Put the plugin's options in a class derived from the options base for its kind; ASH checks a config's section for the plugin with that class and refuses an option it does not declare ([Write a scanner plugin](write-a-scanner.md#3-scan-with-it)). ASH finds the section by the name with case, punctuation, and the words Scanner, Reporter, and Converter ignored, so give the plugin a name of its own: two plugins of one type whose names read as one that way would read each other's section, and are refused with exit 3, naming both plugins and the modules that define them: a scan and a workspace scan refuse two such scanners, converters, or reporters, and `ash report` and `ash merge` refuse two such reporters. A reporter named `csv_` is refused this way beside the built-in `csv`, and one named `S3` when the [AWS reporters](aws.md), among them `s3`, are loaded. `ash config validate` imports no plugin module, so it does not see this. Two plugins of one type with the very same name, such as a subclass that keeps its base's config, are refused with exit 3 too, naming both classes and the modules that define them: a scan and a workspace scan refuse two such scanners, converters, or reporters, and `ash report` and `ash merge` refuse two such reporters. One class selected twice is one plugin. To run a subclass beside its base, give it a config class of its own with its own `name`, declare it as the subclass's `config` field, and build it in `model_post_init` when no config is given. A reporter subclass also needs its own `extension`; a different extension under the shared name is not enough. Two reporters with names of their own that write one report file are refused with exit 1 by a scan, a workspace scan, and `ash merge`, and without the `model_post_init` the subclass starts from its base's config and writes its base's file. This reporter runs beside the built-in `csv` and writes `ash.copy.csv`:

    ```python
    from typing import Literal

    from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
        CSVReporterConfig,
        CsvReporter,
    )
    from automated_security_helper.plugins.decorators import ash_reporter_plugin


    class CopyCsvConfig(CSVReporterConfig):
        name: Literal["csv-copy"] = "csv-copy"
        extension: str = "copy.csv"


    @ash_reporter_plugin
    class CopyCsvReporter(CsvReporter):
        config: CopyCsvConfig | None = None

        def model_post_init(self, context):
            if self.config is None:
                self.config = CopyCsvConfig()
            super().model_post_init(context)
    ```

- Install the package into the Python environment that runs ASH. In container mode ASH passes the module names into the container, but the image does not contain third-party packages, so a third-party plugin needs an image you build with it installed ([Run ASH in a container](../how-to/run-in-a-container.md)).

## Write a plugin

- [Write a scanner plugin](write-a-scanner.md) wraps a command-line tool that writes SARIF.
- [Write a reporter plugin](write-a-reporter.md) writes a report file from the aggregated results.
- [Write a converter plugin](write-a-converter.md) prepares files for the scanners.
- [Subscribe to scan events](event-subscribers.md) runs a function when a scanner or the whole scan finishes.

Each how-to builds a complete plugin in a package named `acme_ash_plugins` and runs it with `ash scan`.
