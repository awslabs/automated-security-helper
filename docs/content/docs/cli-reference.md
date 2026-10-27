# CLI Reference

This page provides detailed information about the ASH command-line interface.

!!! note "Flag tables on this page are hand-maintained"

    [CLI Reference (generated)](cli-reference-generated.md) is introspected from the
    Typer command definitions and is gated by a freshness test, so it is
    authoritative for **flag names and aliases, parameter types, defaults, and
    environment variables**. This page is authoritative for everything that cannot
    be introspected: worked examples, exit codes, and configuration-override
    syntax. If the two disagree about a flag, the generated page is right and this
    one has a bug — please report it.

## Common Parameters

These parameters are available across multiple ASH commands:

| Parameter              | Description                                                | Default           | Environment Variable | Commands                             |
|------------------------|------------------------------------------------------------|-------------------|----------------------|--------------------------------------|
| `--source-dir`         | Path to the directory containing code to scan              | Current directory | `ASH_SOURCE_DIR`     | `scan`                               |
| `--version`            | Print the installed ASH version and exit                   |                   |                      | `scan`                               |
| `--ash-revision-to-install` | ASH branch, tag or full commit id to install in the container image for usage during containerized scans | |  | `scan` |
| `--base-ref` | Git ref to diff against when --changed-files-only is set: a branch, a tag or a commit, optionally followed by `~<n>` or `^<n>` (`origin/main`, `v1.2.0`, `HEAD~1`). With --changed-files-only, a value that starts with `-`, holds a character other than letters, digits and `. _ / ~ ^ @ { } -`, or is not a ref name `git check-ref-format --allow-onelevel` accepts (`main..HEAD`, `main@{1}`) is refused with exit 1 before git runs, and nothing is scanned. Without --changed-files-only the value is not used. | `origin/main` | `ASH_BASE_REF` | `scan` |
| `--allow-stale-content-db` / `--no-allow-stale-content-db` | Let the scan pass when a scanner's content database is past its declared age bound (for grype, 5 days after it was built), recording a warning in the log and the reports. Without it such a scan exits 1, except for trivy's database in an image built with `OFFLINE=YES`, which warns by default. Takes precedence over the `content_db_staleness` config value; see [Failing on a stale content database](configuration-guide.md#failing-on-a-stale-content-database). | Unset: the `content_db_staleness` config value, then `fail` |  | `scan` |
| `--allow-in-tree-tools` | Let ASH start scanners and other tools found inside the scanned directory, such as an activated in-repo `.venv/bin` or `node_modules/.bin`, and the scanner sandbox's own programs (`bwrap`, `firejail`, `readlink`, `true`). Without it such a tool is treated as missing and the scanner is reported MISSING with the in-tree path. Only this flag (also the `allow_in_tree_tools` key of `--cli-json-input`) and the environment variable, set to `1`, `true`, `yes` or `on`, turn it on, never a config file, and `ash mcp` never does; see [Tools inside the scanned directory](advanced-usage.md#tools-inside-the-scanned-directory). | Off | `ASH_ALLOW_IN_TREE_TOOLS` | `scan` |
| `--sandbox` | Run every scanner subprocess in an OS-level sandbox: `auto`, `bwrap`, `firejail`, `landlock`, `sandbox-exec` or `off`. A scanner that cannot be sandboxed as requested is reported MISSING. Overrides the `sandbox.mode` config value. Refused with `--mode container` (exit 5), which runs the scanners unsandboxed inside the container. See [Scanner sandboxing](scanner-sandbox.md). | `off` (or `sandbox.mode`) |  | `scan` |
| `--changed-files-only` | Report only findings in files changed between `--base-ref` and HEAD. Scanners still scan every file; findings located in other files are dropped from every report, the summary counts and the exit code. When git is not installed, the source directory is not in a git repository, or the diff fails, ASH logs which of these it was and reports every finding. Not supported with `--mode container`, which refuses it with exit 5 (set through `ASH_CHANGED_FILES_ONLY` too). See [Reporting only changed files](#reporting-only-changed-files). | | `ASH_CHANGED_FILES_ONLY` | `scan` |
| `--color` | Enable/disable colorized output | |  | `scan` |
| `--compact-report` | Produce a shorter markdown report suitable for PR comments. | |  | `scan` |
| `--container-gid` | GID to use for the container user | |  | `scan` |
| `--container-uid` | UID to use for the container user | |  | `scan` |
| `--custom-build-arg` | Custom build arguments to pass to the container build | |  | `scan` |
| `--custom-containerfile` | Path to a custom container definition (e.g. | |  | `scan` |
| `--fail-on-incomplete-scanners` / `--no-fail-on-incomplete-scanners` | Exit 1 when a selected scanner did not complete (`ERROR` or `MISSING`), or a converter could not convert some of its inputs. On by default; see [An incomplete scan is not a clean scan](#an-incomplete-scan-is-not-a-clean-scan). | | `--fail-on-incomplete-scanners` | `scan` |
| `--formats` | The output formats to use (comma-separated). | |  | `scan` |
| `--honor-ignore-files` / `--no-honor-ignore-files` | Whether the `.gitignore` and `.ignore` files in the scanned tree leave files out of ASH's scan set. `--no-honor-ignore-files` scans those files too; ASH's own exclusions such as `.git` still apply. Takes precedence over the `honor_ignore_files` config value, which a config file inside the scanned tree cannot set. The results and summaries record how many files the ignore files excluded; see [Ignore files and the scan set](configuration-guide.md#ignore-files-and-the-scan-set). | Unset: the operator's `honor_ignore_files`, then honored |  | `scan` |
| `--min-severity` | Minimum severity to trigger non-zero exit code: `critical`, `high`, `medium`, `low` or `none`, in any case. `critical` and `high` rank the same. Any other value is a [usage error](#usage-errors). | `low` |  | `scan` |
| `--progress` | Show progress of each job live in the console. Defaults to True. | |  | `scan` |
| `--python-based-plugins-only` / `--all-enabled-plugins` | Exclude execution of any plugins or tools that have depencies external to Python. Also spelled `--python-only` / `--full`, and `--python-based-scanners-only` / `--all-enabled-scanners`; all three name the same option, and the `plugins` spelling is preferred because the option covers converters and reporters too. | |  | `scan` |
| `--runner` | Use the specified OCI runner instead of docker to run the containerized tools | | `OCI_RUNNER` | `scan` |
| `--show-summary` | Show metrics table and results summary | |  | `scan` |
| `--simple` | Simplified output mode with minimal logging | |  | `scan` |
| `--output-dir`         | Path to store scan results. Refused, whatever the sandbox mode, when it, a directory or file ASH writes in it, or a directory inside the scanned tree on the way to it is a symlink; see [Output directory](concepts.md#output-directory). | `.ash/ash_output` | `ASH_OUTPUT_DIR`     | `scan`, `report`                     |
| `--config`, `-c`       | Path to ASH configuration file                             | Discovered        | `ASH_CONFIG`         | `scan`, `config`, `plugin`           |
| `--config-overrides`   | Override configuration values (can be used multiple times) |                   |                      | `scan`, `config`, `plugin`, `report` |
| `--ash-plugin-modules` | List of Python modules to import containing ASH plugins    |                   | `ASH_PLUGIN_MODULES` | `scan`, `plugin`                     |
| `--mode`               | Execution mode: `local`, `precommit`, `container` or `nix`. `precommit` runs only bandit, detect-secrets, checkov, cdk-nag and npm-audit, plus any `--scanners`, with simplified output; in workspace mode it changes only the output. `nix` runs the scan inside `nix develop`, always offline | `local`           | `ASH_MODE`           | `scan`                               |
| `--debug`, `-d`        | Enable debug logging                                       | `False`           | `ASH_DEBUG`          | All commands                         |
| `--verbose`, `-v`      | Enable verbose logging                                     | `False`           | `ASH_VERBOSE`        | All commands                         |
| `--quiet`              | Suppress non-essential output                              | `False`           |                       | All commands                         |
| `--no-color`           | Disable colored output                                     | `False`           |                       | All commands                         |
| `--oci-runner`, `-o`   | OCI runner to use. Unset by default; ASH uses the first of `finch`, `docker`, `nerdctl`, `podman` found on `PATH`                                          | first found          | `OCI_RUNNER`         | `scan` (container mode)              |

### Config Overrides Syntax

The `--config-overrides` parameter allows you to modify configuration values without editing the configuration file:

```bash
# Basic usage
ash --config-overrides 'scanners.bandit.enabled=true'

# Multiple overrides
ash \
  --config-overrides 'scanners.bandit.enabled=true' \
  --config-overrides 'global_settings.severity_threshold=MEDIUM'

# Append to lists
ash --config-overrides 'ash_plugin_modules+=["my_ash_plugins"]'

# Complex values using JSON syntax
ash --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

The key is applied exactly as written, so a key that would name a setting nothing reads is refused, with exit code `3`. That is a key with a dot-separated part that is empty (`a..b`, or a leading or trailing `.`), a part that holds whitespace (a space, a tab, a no-break space), or a part that holds a character that does not print, as Python's `str.isprintable()` decides it. The last covers the zero-width space, the byte order mark and the bidirectional controls, such as U+202E RIGHT-TO-LEFT OVERRIDE and U+2066 LEFT-TO-RIGHT ISOLATE, which can make one key display as another. It also covers the zero-width non-joiner (U+200C), the zero-width joiner (U+200D) and the soft hyphen (U+00AD). Some languages need those in text, but no configuration key holds one. Only the key is checked this way: a value may hold spaces.

### Passing parameters as JSON

`ash scan`, `ash build-image`, `ash report`, and `ash merge` accept `--cli-json-input`, which reads the command's parameters from a JSON object instead of, or as well as, flags. It follows the AWS CLI's `--cli-input-json` convention.

```bash
# Write a template listing every parameter of the command with its default
ash scan --generate-cli-skeleton > scan-params.json

# Run with it. A path, a file:// URI, and - (stdin) are all accepted
ash scan --cli-json-input scan-params.json
ash scan --cli-json-input file://scan-params.json
cat scan-params.json | ash scan --cli-json-input -

# Flags on the command line win over the file
ash scan --cli-json-input file://scan-params.json --strategy sequential
```

```json
{
  "source_dir": "./src",
  "scanners": ["bandit", "semgrep"],
  "strategy": "sequential",
  "offline": true,
  "config_overrides": ["global_settings.severity_threshold=LOW"]
}
```

**Keys.** A key is either the parameter name, which is what `--generate-cli-skeleton` writes (`source_dir`, `output_formats`), or one of the option's long flag spellings (`--source-dir`, `--formats`). The negative half of a boolean pair is not a key: write `"offline": false`, not `"--no-offline": true`. Every parameter the command takes is accepted, and both the accepted keys and the skeleton are read from the command's own option definitions, so a newly added flag is available here without further changes. Use the subcommand form; bare `ash --cli-json-input ...` is rejected as an unknown option.

**Values.** A list parameter takes a JSON array; every other parameter takes a single string, number, or boolean. `null` means "not provided", which is how the skeleton marks a parameter whose default is computed at run time. Each value is converted and checked by the same parameter type the flag uses, so an invalid value fails just as the equivalent flag would, and the error names the JSON key.

**Precedence**, highest first:

1. A flag or positional argument given on the command line.
2. A value in the `--cli-json-input` document.
3. The parameter's environment variable, such as `ASH_SOURCE_DIR`.
4. The parameter's default.

The document ranks above environment variables because it is named on this invocation's command line. A list given on the command line replaces the document's list for that parameter rather than extending it, so `--scanners checkov` with `"scanners": ["bandit"]` in the file runs only `checkov`.

**Interaction with `--config` and `--config-overrides`.** The document is resolved while the command line is parsed, before ASH reads any configuration. It only supplies parameter values: `"config"` in the document is the value of `--config`, and `"config_overrides"` is the list `--config-overrides` would have built. After that, configuration is resolved exactly as it is for flags: the configuration file is loaded, then each override is applied in order. A `--config-overrides` flag on the command line replaces the document's `config_overrides` list as a whole.

**Errors.** The command exits 5 without running when the document cannot be read, is not valid JSON, is not a JSON object, repeats a key, names a key the command does not have (the message lists the valid ones), sets one parameter under two spellings, or holds a value the parameter's type rejects. Exit 5 is the [usage-error code](#usage-errors), the same code an invalid flag produces.

**Security.** The document is parsed as JSON and nothing else. No value is evaluated, and no environment-variable or `~` expansion is applied, which matches how a flag's value is treated once the shell has handed it over. Relative paths in values are relative to the working directory, as they are for flags.

## Core Commands

ASH v3 provides several core commands:

```
ash [command] [options]
```

### Available Commands

| Command           | Description                                                |
|-------------------|------------------------------------------------------------|
| `scan`            | Run security scans on source code (default command)        |
| `merge`           | Recombine the results of a sharded scan into one report     |
| `config`          | Manage ASH configuration                                   |
| `plugin`          | Manage ASH plugins                                         |
| `report`          | Generate reports from scan results                         |
| `dependencies`    | Install dependencies for ASH plugins                       |
| `inspect`         | Inspect and analyze ASH outputs and reports                |
| `build-image`     | Build the ASH container image                              |
| `get-genai-guide` | Write the GenAI Integration Guide for AI assistants        |
| `mcp`             | Start the Model Context Protocol (MCP) server for AI tools |

## Scan Command

The `scan` command is the primary command for running security scans. If no command is specified, ASH defaults to the `scan` command.

```bash
ash [options]
```

### Scan Options

| Option                        | Description                                             | Default               | Environment Variable    |
|-------------------------------|---------------------------------------------------------|-----------------------|-------------------------|
| `--source-dir`                | Path to the directory containing code to scan           | Current directory     | `ASH_SOURCE_DIR`        |
| `--output-dir`                | Path to store scan results                              | `.ash/ash_output`     | `ASH_OUTPUT_DIR`        |
| `--mode`                      | Execution mode: `local`, `precommit`, `container` or `nix`. `precommit` runs only bandit, detect-secrets, checkov, cdk-nag and npm-audit, plus any `--scanners`, with simplified output; in workspace mode it changes only the output. `nix` runs the scan inside `nix develop`, always offline | `local`               | `ASH_MODE`              |
| `--config`, `-c`              | Path to ASH configuration file                          | Discovered from the source directory | `ASH_CONFIG`            |
| `--config-overrides`          | Override configuration values                           |                       |                         |
| `--ash-plugin-modules`        | List of Python modules to import containing ASH plugins |                       | `ASH_PLUGIN_MODULES`    |
| `--scanners`                  | Specific scanner names to run                           | All enabled scanners  | `ASH_SCANNERS`          |
| `--exclude-scanners`          | Specific scanner names to exclude                       | None                  | `ASH_EXCLUDED_SCANNERS` |
| `--output-formats`, `-f`      | Output formats (comma-separated). Run `ash scan --help` for the list this build accepts; the help text is derived from the code, so it cannot go stale. The reporter names are also tabulated in [Output formats](output-formats.md) | The config's `output_formats`, else every enabled reporter |                         |
| `--strategy`                  | Whether to run scanners in parallel or sequential       | `parallel`            |                         |
| `--log-level`                 | Set the log level                                       | `INFO`                |                         |
| `--fail-on-findings`          | Exit with non-zero code if findings are found           | From config           |                         |
| `--ignore-suppressions`       | Ignore all suppression rules and report all findings    | `False`               |                         |
| `--honor-ignore-files/--no-honor-ignore-files` | Whether the scanned tree's `.gitignore` and `.ignore` files leave files out of ASH's scan set. A config file inside the scanned tree cannot set it; see [Ignore files and the scan set](configuration-guide.md#ignore-files-and-the-scan-set) | From operator config, then honored | |
| `--offline`                   | Run in offline mode (container mode only)               | `False`               |                         |
| `--offline-semgrep-rulesets`  | Semgrep rulesets for offline mode                       | `p/ci`                |                         |
| `--build/--no-build`, `-b/-B` | Whether to build the ASH container image                | `True`                |                         |
| `--run/--no-run`, `-r/-R`     | Whether to run the ASH container image                  | `True`                |                         |
| `--build-target`              | Container build target: `non-root` or `ci` (runs as root). CI environment variables do not change it | `non-root` (`ci` on Windows) |                  |
| `--oci-runner`, `-o`          | OCI runner to use. Unset by default; ASH uses the first of `finch`, `docker`, `nerdctl`, `podman` found on `PATH`                                       | first found              | `OCI_RUNNER`            |
| `--python-only/--full`        | Use only Python-based plugins                           | `False`               |                         |
| `--cleanup`                   | Clean up temporary files after scan                     | `False`               |                         |
| `--use-existing`              | Use existing results file                               | `False`               |                         |
| `--phases`                    | Phases to run: `convert`, `scan`, `report`, `inspect`   | `convert,scan,report` |                         |
| `--inspect`                   | After the scan, analyze the SARIF fields in this scan's output directory and write the result to its `analysis/` directory | `False`               |                         |
| `--shard-index`               | Zero-based index of this shard when one scan is split across several executors. Requires `--shard-count` | None | `ASH_SHARD_INDEX` |
| `--shard-count`               | Total number of shards the scan is split across. Requires `--shard-index` | None | `ASH_SHARD_COUNT` |
| `--workspace`                 | Path to a `.code-workspace` file, or `auto` to find the one in the current directory. Mutually exclusive with `--source-dir` | None | `ASH_WORKSPACE` |
| `--workspace-config`          | Path to the workspace policy file. Defaults to `ash-workspace.{yaml,yml,json}` in the workspace root or its `.ash` directory | None | `ASH_WORKSPACE_CONFIG` |
| `--allow-missing-projects`    | Skip workspace projects that are absent or unreadable   | `False`               |                         |
| `--dry-run`                   | Print the resolved workspace plan and exit without scanning | `False`           |                         |
| `--allow-in-tree-tools`       | Let ASH start tools found inside the scanned directory; see Common Parameters | `False` | `ASH_ALLOW_IN_TREE_TOOLS` |

### Running a scan in a container

`--mode container`, the `./ash` wrapper and `Invoke-ASH` in `utils/ash_helpers.ps1` run
the scan inside the ASH image with these bind mounts:

| Mount                     | Host path                                        | Access     |
|---------------------------|--------------------------------------------------|------------|
| `/src`                    | `--source-dir`                                   | read-only  |
| `/out`                    | `--output-dir`                                   | read-write |
| `/ash-config/...`         | `--config` (or `ASH_CONFIG`), when outside `--source-dir` | read-only  |
| `/ash-workspace-config/...` | the workspace policy, when outside the workspace root | read-only  |
| `/ash-env-config/...`     | the file `ASH_CONFIG` names, when outside `--source-dir` | read-only  |

The source is mounted read-only wherever the output directory is, including the default
`.ash/ash_output` inside the source directory: the scan inside the container writes only
to `/out`. An output directory that is the source directory itself, or a directory above
it, would hold the source tree at `/out`, writable, so `--mode container`, `./ash` and
`Invoke-ASH` refuse it with exit 3 before anything is built or mounted (compared by real
path, so a link to the source counts). Use an output directory inside the source or
outside it.

The output directory must not be a symlink or be reached through one, because the scan
inside the container would write wherever the link leads. `--mode container`, `./ash`
and `Invoke-ASH` refuse with exit 3, before the directory is created or mounted, an
output directory that is a symlink, wherever it is, and any symlink between the source
directory and it (a committed `.ash -> /some/host/dir`, for the default
`.ash/ash_output`). `--no-run` is refused too, since the output directory is created
either way. Links at or above the source directory are your own spelling and are not
examined. This is the rule a sandboxed local scan applies (see
[Scanner sandbox](scanner-sandbox.md)).

The config file named with `--config` (or `ASH_CONFIG`) is the one the scan inside the
container reads. One inside `--source-dir` is read through `/src`. One outside it is
mounted read-only under `/ash-config`, together with the files its `extends` chain
names, each where the file that extends it names it (relative to the config's directory,
the parent of `.ash/` for a file in `.ash/`), so the bases resolve inside to the files
the host reads, including a base the host reaches through a link; only those files are
mounted, not the directory. A relative `--config` is resolved against the working
directory on the host, as a local scan resolves it, and the scan inside is given the
file's path in the container, never the path as typed, so it cannot name a different
file under `/src`. The config file the scan inside will use, whether named with
`--config`, named by `ASH_CONFIG`, or found in `--source-dir`, is read on the host the
way a local scan reads it, before anything is built, run, mounted or cleared. One that a
local scan would refuse refuses the run with exit 3 and the same message
(`Invalid configuration: ...`): a file that is missing or empty, a directory or another
file that is not a regular file, unreadable, not UTF-8, not valid YAML, JSON or TOML
(YAML aliases included), or not a valid config, and a name in `--source-dir` that is a
link to nothing. `--config-overrides` are applied to it the same way, so one that does
not parse, or sets a value the config does not accept, refuses the run too. Options of
a scanner or reporter plugin are left to the scan inside,
which loads the plugin from the image. `--mode nix` reads the file the same way before
it enters its shell. `--no-run` builds an image and scans nothing, so its config is not
read. An `extends` entry anywhere in the chain that names its base by absolute path
refuses the run with exit 3 before the container starts: inside the container that path
is not the same file. A `--config` named inside the scanned tree whose real
path, with every link on the way resolved, is outside that tree is refused with exit 3
too, and so is a config file ASH cannot read itself. A config outside `--source-dir`
whose `extends` chain includes a file inside it is refused with exit 3 as well: a
chain is read whole through `/src`, for a config inside `--source-dir`, or mounted
whole from outside it. A file of the chain inside the scanned checkout may extend only
files inside that checkout. Inside the container an `extends` entry is followed as
written, from where the extending file is mounted, so an entry whose written path
leaves the config's directory (`../cfg/base.yaml` from `cfg/ash.yaml`), or that climbs
out with `..` after a link to a directory at another depth, would place its base outside
`/ash-config`: the run is refused with exit 3 before anything is built, naming the
entry. So is a chain where two files would be mounted at one container path, or one
file at a path another file of the chain needs as a directory. A config the scanned
repository wrote keeps the limits a local scan gives it (see
[Settings a repository's config cannot choose](configuration-guide.md#settings-a-repositorys-config-cannot-choose)):
when the config or a file it extends is inside the scanned tree (the git checkout
holding `--source-dir`) or is reached through a symlink that sits in it, but outside
`--source-dir` itself, where the scan inside the container cannot see that, the host
passes it `--config-from-scanned-repository` (`./ash` and `Invoke-ASH` do the same for
the config file, following its path one link at a time as the host does). When only
files the config extends are in the scanned tree, the host marks each of those on its
own (`--config-file-from-scanned-repository`), so the config, as on the host, keeps
the sandbox settings it writes itself and its bases grant nothing. A file inside some
other git checkout (an ops repository beside the scanned one, say), or reached through
a symlink that sits in one, is not the scanned tree's, but it cannot grant either: the
host marks each such file of the `--config` chain and of `ASH_CONFIG`'s chain on its
own (`--config-file-from-another-checkout`; a file already marked as the scanned
tree's keeps that mark alone), and the scan inside limits it as the host does. Such a
file still sets what only restricts: a lowered archive extraction limit, a scanner
option that sends no usage data, and a `network_scanners` list as a limit. The scan
inside reads those from the mounted file, so no value travels in the mark. `./ash` (for
the `--config` file and the `ASH_CONFIG` file) and `Invoke-ASH` (for the `ASH_CONFIG` file)
pass the same mark for the file they mount, on the host's judgment: a `.git` entry that
is a file, a link or a directory holding `HEAD`, at the file's directory or above it,
found from the name as given, from the real path, or from where a link the name goes
through sits (a relative name is read from the physical working directory, and `./ash`
also reads it from the directory `$PWD` names, as the host does). In a directory that
group members or others can write, such an entry
counts only when root, the directory's owner or the user running the script owns it.
A file already marked as the scanned tree's keeps that mark alone. When they cannot make
the judgment (`./ash` needs `ls` to read the owner of a link or the mode of a directory
only in the rare case the shell's own ownership test does not settle it; `Invoke-ASH`
needs `ls` and `id` on the path when its PowerShell runs on a .NET without
`File.GetUnixFileMode`, as PowerShell 7.0 to 7.2 do, and PowerShell 7.3 and later need
neither), they refuse with exit 3 and start nothing. In workspace mode the host marks a
`--config` from another git checkout this way, and the workspace scan inside limits it
as a local workspace scan does. One in the
checkout around the workspace root, or reached through a link there, is refused with
exit 3 before anything is built or mounted: keep `--config`, and every file it
extends, outside every git checkout. A config inside the workspace root is refused
as in a local workspace scan, because the operator's config may not be one of the
workspace's files, and one outside every checkout is the operator's. `./ash` and
`Invoke-ASH` scan one directory and refuse a `--workspace`
passed through to `ash` with exit 3; use `ash --mode container --workspace`. In
workspace mode the policy file the host resolved (`--workspace-config`, or the one found in the workspace
root) is handed to the container the same way, and is refused with exit 3, as a
`--config` is, when it is named inside the workspace's tree but its real path is
outside it. The `./ash` wrapper and `Invoke-ASH`
mount a config from outside the source directory on its own, without the files it
extends, so they refuse one with an `extends` entry with exit 3; use
`ash --mode container` for such a chain. They do not parse the file, so they err toward
refusing: the key followed by `:` or `=` anywhere, line breaks included, and any quoted
key holding a backslash count as an `extends` entry. A program that
calls `run_ash_scan(mode=RunMode.container)` with no `config` gets `ASH_CONFIG`'s file
handed to the container when no config is found in the source directory, which is when
a local scan uses it. For a workspace scan (`workspace_plan`) it is handed over whenever
it is set, as `ash scan --workspace`, which reads `ASH_CONFIG` as `--config`, hands it
over. Whatever names the config, a local scan also reads `ASH_CONFIG`'s file as its
base, the source of the settings a repository-written config may not choose, so the
host refuses that file with exit 3 when it does not load, with a valid `--config` as
well, and hands it to the scan inside: mounted read-only under `/ash-env-config` with
the files it extends, and passed as `--ash-config-from-host`, which the scan inside
reads as `ASH_CONFIG`. Each file of its chain a local scan would count as
repository-written is marked on its own (`--config-file-from-scanned-repository`),
and each one in another git checkout as such (`--config-file-from-another-checkout`).
Nix mode refuses the file on the host the same way, and the scan in the Nix shell
reads `ASH_CONFIG` itself.

A path that would be mounted (the source and output directories, the config file and
the files it extends, the workspace policy) may not contain a comma, a double quote, a
carriage return or a line feed: `--mount` reads its value as comma-separated fields, so
such a path would be read as something else. The same holds for the path a base is
mounted at, which follows the `extends` entry as written and can hold such a character
through the name of a link the entry goes through. The run is refused with exit 3 before
anything is built.

The image should be built from the same ASH as the one on the host. With `--no-build`,
or an `ASH_IMAGE_NAME` image built from an older ASH, the scan inside can reject an
option this ASH passes it, such as `--config-from-scanned-repository` for a config
elsewhere in the scanned checkout, or `--config-file-from-another-checkout` for a
config in another one. It then exits 2 without writing a results file, and
the host refuses with exit 3 and asks for the image to be rebuilt from this ASH.

`Invoke-ASH` refuses by throwing, with `$LASTEXITCODE` set to the code (3 for an
input it refuses, 1 when it finds no OCI runner). It never calls `exit`, so a script
that dot-sources `utils/ash_helpers.ps1` can catch the error and go on, and a session
you type into, or one started with `-NoExit`, stays open. Any other error it raises
leaves `$LASTEXITCODE` non-zero as well. Uncaught, the error ends `pwsh -File` and
`pwsh -Command` with exit 1, as PowerShell does for any uncaught error, whatever the
code. A CI step that needs the code wraps the call, also under
`$ErrorActionPreference = 'Stop'`:

```powershell
$ErrorActionPreference = 'Stop'
. ./utils/ash_helpers.ps1
try {
    Invoke-ASH -SourceDir . -OutputDir ./.ash/ash_output
} catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }
```

The `catch` block writes the error record once and exits with the code. The
`else { 1 }` covers an error raised before `Invoke-ASH` sets one, such as a parameter
it cannot bind. On GitHub Actions, run such a step with `shell: pwsh -File {0}`. The
built-in `shell: pwsh` runs the script as `pwsh -command ". '<script>'"`, which reports
every non-zero `exit` as 1; it also adds `$ErrorActionPreference = 'stop'` before the
script and an `exit $LASTEXITCODE` after it, which `pwsh -File {0}` does not, so set
the first yourself, as above, and end the script with
`if ((Test-Path -LiteralPath variable:\LASTEXITCODE)) { exit $LASTEXITCODE }` to keep
the scan's own exit code. It runs the runner through
`Invoke-Expression`, and passes each path and value it was given by name, so PowerShell
reads a directory named `a$(...)` as that name. Two inputs are still parsed as
PowerShell: the arguments after the named parameters, which are passed through to `ash`
as written, and `OCI_RUNNER_WRAPPER`. A runner given as a path (`-OCIRunner`,
`--oci-runner` or `OCI_RUNNER` naming a file, such as `/opt/podman/bin/podman`) runs
that file in all three entry points; a bare name such as `podman` is looked up on
`PATH`.

The scan inside the container sees the host only through these mounts, and receives only
the environment variables ASH sets for it. So any other value that names a host file
names a path that does not exist in the container: a scanner option such as
`scanners.checkov.options.config_file` or `scanners.trivy-repo.options.ignore_file`, the
same set through `--config-overrides`, or a variable such as `TRIVY_IGNOREFILE` or
`SEMGREP_RULES_CACHE_DIR` in the host's environment. A file in the source directory is
at `/src/<path>` there, but it is the repository's own file, which ASH does not hand to a
tool as its configuration (see
[Settings a repository's config cannot choose](configuration-guide.md#settings-a-repositorys-config-cannot-choose)).
To give the scan inside an operator file of that kind, build it into the image with
`--custom-containerfile` and name its path in the image.

`--ignore-suppressions` is passed to the scan inside the container, which is where
suppressions are applied: the host reads that scan's `ash.sarif` back to compute the
exit code. `--log-level` is passed too, so the log inside the container is kept at the
level asked for. `--min-severity` stays on the host, which applies it to the results it
reads back.

The image stage is the one `--build-target` names; when it is not given, `non-root`, or
`ci` on Windows, where the non-root user cannot write the bind-mounted output. The
`CI`, `IsCI`, `ISCI` and `CODEBUILD_BUILD_ID` variables do not change it;
`--custom-containerfile` builds on `ci`. A `non-root` build is refused when the
container user's UID or GID would be 0, which happens when ASH itself runs as root
(common in CI jobs): pass `--build-target ci` (`-BuildTarget ci` for `Invoke-ASH`).
Another `--container-uid` and `--container-gid` work only when the output directory is
writable by that UID, which a directory ASH created as root is not. In AWS CodeBuild, for
example:

```bash
ash --mode container --build-target ci
```

See [Building your own container image](building-your-own-image.md).

Container mode passes four hidden options, `--config-from-scanned-repository`, `--config-file-from-scanned-repository`, `--config-file-from-another-checkout` and `--ash-config-from-host`, to the scan inside the container so that it applies to a mounted config file the same limits the host judged for it; they are internal, local-mode only (any other scan refuses them with exit 3), and not meant to be set by hand.

### Workspace Mode

A [VS Code workspace file](https://code.visualstudio.com/docs/editor/workspaces) lists several project folders. Passing it to `--workspace` tells ASH to treat each folder as its own project, with its own configuration, rather than as one directory tree:

```json
{
  "folders": [
    { "path": "services/api" },
    { "path": "shared-infra" }
  ]
}
```

Folder paths are relative to the directory holding the workspace file, which becomes the workspace root. Each project gets a key derived from its path below that root — `services/api` becomes `services-api` — and that key is what output paths and per-project attribution use. ASH reads only the `folders` array; the `settings` block is ignored, because ASH configuration belongs in ASH's own config file.

`--workspace` and `--source-dir` cannot be combined. Note that `ASH_SOURCE_DIR` counts as setting `--source-dir`.

Each project uses its own ASH config file. A project that has none uses the file named by `--config` instead, both for the scan and for its verdict, and `--dry-run` shows that file and its threshold; with no `--config` it uses ASH's built-in defaults. The workspace root's own config file is not applied to the other projects: it is the root's config when the root is listed as a project, and otherwise it supplies only the `workspace` settings under Concurrency below.

`--dry-run` resolves and validates the workspace, prints the resulting plan, and exits 0 without scanning anything. It makes the same scanner-selection pre-check the real run makes, so a `--scanners` or `--exclude-scanners` combination the scan would refuse exits 5 here too, with the same message, instead of blessing a command line the real run then refuses. To make that check it loads the workspace's plugin modules, from `--ash-plugin-modules` and from every project's config, as the scan does, so each module's top-level code runs; a module outside ASH's plugin namespace is refused with exit 3, as the scan refuses it, before anything is imported. Without it, the same plan is what gets scanned — resolved once, so what you inspect is what runs.

`ash dependencies install` reads one configuration, that of the directory it runs in, and not each project's. To install the tools the projects' scanners need, name them with `--tool` (for example `ash dependencies install --tool bandit --tool checkov`), or run it in each project's directory.

#### The operator's config

`--config` (or `ASH_CONFIG`) in workspace mode is the operator's config for every project. Every field it sets is final, and a project's own config fills only the fields it leaves unset:

- A project with a config of its own uses that file with the operator's file layered over it. "Sets" means the key is present in the operator's file or in a base it `extends`, whatever its value: `fail_on_findings: true` in the operator's file holds for every project even though `true` is the default.
- The layering follows the [`extends` merge rules](configuration-guide.md#extending-another-configuration), with the operator's file as the child. Mappings merge key by key, so the operator's `scanners.bandit.enabled` and a project's `scanners.bandit.options` both apply. A list the operator sets replaces the project's list whole: an operator `global_settings.suppressions` list drops each project's own suppressions. The operator's file is resolved on its own first, its `extends` and `patch` included, so its `patch` operations change only its own settings and never reach a project's. A setting is merged as ASH reads it, so a project that spells a key another way (`cdk-nag` and `cdk_nag`, or `global-settings` for `global_settings`) does not keep the operator's value from applying.
- A project without a config of its own uses the operator's file alone.
- `--config-overrides` and the CLI flags (`--fail-on-findings`, `--sandbox` and the others) apply after both, so they win over the operator's file and over every project.
- A workspace policy file applies after all of this, as described below.

The file must exist even when every project has its own config, because it is also the trusted base those projects' sandbox settings come from: a `--config` that names no file, and any project config that cannot be loaded, exit 3 at planning, `--dry-run` included.

To leave a field to each project, leave it out of `--config`. `--dry-run` prints an `operator:` line under each project the file was layered over, and the threshold and scanners it prints are the layered result.

Every file the operator's config is built from must be the operator's, because it is final over the workspace. A `--config` inside the workspace's tree, one that `extends` a base inside that tree, or one under the MCP workspace root (a file an MCP client delivered) is refused, with exit code `3`, before any project is resolved. The message names the file and the checkout (or directory) to move it out of. The workspace's tree is the outermost git checkout around the workspace, or the workspace directory itself when it is in no checkout, so a file beside the workspace in the same checkout is refused too. Keep the config, and every base it extends, outside that tree.

This narrows #780's behavior for workspace mode: before, a workspace `--config` inside the checkout around the workspace was used with its sandbox grants dropped and its sandbox mode kept. Single-directory scans are unchanged: an `ASH_CONFIG` inside the scanned checkout still loses its sandbox grants and keeps its sandbox mode.

The scan runs the plan `--dry-run` reports. The plan records a digest of the operator's config and the bases it extends, and a project whose operator config changed after the plan was resolved, or whose plan was resolved without the operator config the scan is given, fails with exit code `3` instead of being scanned with settings the plan did not report.

The settings a repository's config cannot choose ([Settings a repository's config cannot choose](configuration-guide.md#settings-a-repositorys-config-cannot-choose)) are still limited for a project's own file. A value the operator's file sets is the operator's and is kept; a value only the project's file sets is limited as before.

In container mode (`--mode container`), the refusals above are made on the host, before any container starts, because inside the container the operator's file is no longer where it was on the host. Each file the operator's config is built from is then mounted read-only at `/ash-operator-config` in the container, and the scan inside the container is given that path. Only those files are mounted, not the directory they are in. The `--fail-on-findings` and `--fail-on-incomplete-scanners` values given on the command line are forwarded into the container; the values in the operator's file reach it through the mounted file, so they stay layered as above.

In a single-directory scan, `--config` replaces discovery instead: the repository's own config is not read at all.

#### Workspace policy

Each project is judged against its own configuration, so there is nowhere in a project's config to say something about the workspace as a whole. That goes in a workspace policy file, which ASH looks for at `ash-workspace.yaml` (or `.yml`/`.json`) in the workspace root or its `.ash` directory. Having none is not an error.

```yaml
workspace:
  # The LOOSEST threshold any project may use. A stricter project keeps its own.
  max_severity_threshold: MEDIUM
  # Paths are workspace-relative and are rewritten per project.
  suppressions:
    - path: services/api/src/legacy.py
      rule_id: B101
      reason: tracked in TICKET-1
  ignore_paths:
    - path: '**/vendor'
      reason: third-party code
  # Additive: a project cannot be made to run fewer scanners than it enables.
  additional_scanners:
    - bandit
  # Whether findings from scanners added above affect a project's exit code.
  policy_scanners_gate: false
```

The policy file must be a **different file** from any project's ASH config. When the workspace root is itself a project, `.ash/ash.yaml` there is that project's config and keeps meaning exactly that; policy goes in `.ash/ash-workspace.yaml`, or in any file named with `--workspace-config`. Pointing `--workspace-config` at a project's config exits 4 and names the file, because workspace policy governs every project and reading one project's config as policy would apply its settings to its siblings.

`max_severity_threshold` is a ceiling on permissiveness, not on severity. The strictness order is `ALL` (strictest) through `CRITICAL` (loosest), so *raising* this value loosens it. A project's effective threshold is whichever of its own setting and this ceiling is stricter: a project at `CRITICAL` under a `MEDIUM` ceiling is judged at `MEDIUM`, while a project already at `LOW` is left alone. `--dry-run` prints both values for any project the ceiling moved, so you can see what it changed before running a scan.

One limitation is worth knowing before relying on the ceiling. It tightens findings that carry a severity. A finding that carries only a SARIF `error` level is treated as critical and stays actionable at every threshold, so no ceiling excludes it — this is not specific to workspace mode, and `severity_threshold` behaves the same way in a single-project scan. In practice it means the ceiling cannot quieten checkov, which reports no per-finding severity.

Rather than leave that as a caveat to remember, ASH measures it. When the ceiling tightens a project and some of that project's findings were beyond the tightening's reach, the project's entry in `ash_aggregated_results.json` carries `ceiling_unreachable_findings` — a count per scanner:

```json
"ceiling_unreachable_findings": { "checkov": 7 }
```

Read it as a statement about those findings, not about the scanner: seven findings in this project carry no severity, so the ceiling did not change their verdict. It is recomputed on every scan from the findings actually present, so it disappears if a scanner starts reporting severity, and it is absent entirely when the ceiling either did not tighten the project or reached everything it needed to.

Suppressions and ignore paths are written workspace-relative and pushed down into each project's own coordinates, where each matches what it matched at the top level. An ignore path ending in `/` still names a directory (`api/vendor/` becomes `vendor/` in project `api`), and a suppression's trailing `/` stays literal, so it matches no file. A pattern that cannot match inside a project is not applied there, so `services/api/src/legacy.py` silences nothing in `shared-infra`. A pattern with no exact per-project equivalent is refused with exit 4 rather than approximated, because a suppression that matches more than intended hides findings, and an ignore path that does drops files from the scan, with nothing in the output to show what went missing. A pattern with a `.` or empty component (`./api/x.py`, `api//x.py`) is refused the same way: ASH's matcher reads it literally, so it matches no file. `**/vendor/` and `**/vendor/**` reach every project; `*/sub/*.py` is refused, and the error names the pattern and the project.

Scanners in `additional_scanners` that a project already enables run under that project's own configuration and their findings are the project's. Scanners only the policy adds run with default configuration, are reported separately as `origin: workspace-policy`, and do not affect the project's exit code unless `policy_scanners_gate: true`.

#### What each project gets

Each project is scanned in its own scope: its own directory as the scan root, its own configuration (with the fields the operator's `--config` sets taken from that file, see [The operator's config](#the-operators-config)), its own suppressions, and its own severity threshold. Without `--config`, a project's findings and its pass/fail verdict are the same as `ash --source-dir <that project>` would produce. A suppression written in one project's config does not apply to another, even for the same rule at the same relative path.

Output is laid out per project, with a workspace-level roll-up beside it:

```
.ash/ash_output/
  ash_aggregated_results.json      # unified, with per-project attribution
  reports/
    workspace-reports.json         # what every reporter did, and where
    ash.<ext>                       # workspace-level reports (see below)
  projects/<project-key>/
    ash_aggregated_results.json    # this project alone
    reports/ash.<ext>              # this project's own reports
    scanners/<scanner>/<target>/   # raw scanner output
```

The unified `ash_aggregated_results.json` carries a `workspace` block: one entry per project with its threshold, finding counts, verdict and `sarif_run_index`, plus the `skipped_projects` payload. A project's entry lists, in `scanner_reasons`, why each of its `SKIPPED` or `MISSING` scanners did not run, and the error each `ERROR` scanner recorded (a scanner whose constructor raised, for one). The file's `scanner_results` rolls each scanner up to its worst status across projects, and a rolled-up `SKIPPED` or `MISSING` row's `skipped_reason` or `missing_reason` names each project at that status with its reason, as `api: <reason>; web: <reason>`.

Its SARIF holds one `run` per project. Each run declares its own project root under `originalUriBaseIds`, and result paths inside a run stay relative to that root — so a consumer that ingests SARIF against a single repository root, such as GitHub code scanning, still resolves every path correctly. Selecting one run gives you a valid single-root SARIF document for one project. Each result also carries `properties.workspace_project` and `properties.workspace_uri`, the workspace-relative path, for consumers that want one flat coordinate space.

#### Which reports are written where

Not every format can be merged across projects, so each reporter declares what it does with a multi-project scan. Three answers:

| Behaviour | Reporters | What you get |
| --- | --- | --- |
| Merged | `sarif`, `html`, `markdown`, `text`, `csv`, `flat-json`, `yaml`, `junitxml`, `ocsf` | One workspace-level artefact under `reports/`, carrying the project on every finding |
| Per project | `github-ghas`, `gitlab-sast`, `cyclonedx`, `gitlab-cyclonedx`, `spdx`, and the AWS reporters | No workspace-level artefact. The files under `projects/<key>/reports/` are the answer |
| Workspace-scoped | `unused-suppressions` | A workspace-level artefact covering workspace-level state only, not a merge of the projects |

Where the project appears depends on the format: a `workspace_project` column in `csv`, a field of the same name in `flat-json`, a per-project section in `html`, `markdown` and `text`, a `<project>/<scanner>` testsuite name in `junitxml`, and a `workspace_project:<key>` entry in `metadata.labels` for `ocsf`. Single-directory output is unchanged in every case.

A skipped project has no findings, so in the three formats whose output is one record per finding it would have no record at all — indistinguishable from a project that came back clean. Each of those emits one record standing for the project instead, marked in that format's own vocabulary so a finding count can exclude it:

| Format | Where the skipped project appears | How to exclude it from a finding count |
| --- | --- | --- |
| `csv` | A row whose `workspace_row_type` is `skipped-project`. That column is workspace-only, like `workspace_project`, and carries `finding` on every ordinary row | Filter `workspace_row_type == 'finding'`. The row's `severity` cell is also blank, so a severity rollup skips it |
| `junitxml` | A testsuite named after the project, holding one `<skipped type="project-skipped">` test case | Count `<failure>` and `<error>`, which is what CI front ends already do. The suite reports `failures="0" errors="0" skipped="1"` |
| `ocsf` | A record with `status_id` 99 (OCSF's "not mapped — see `status`"), `status` `Skipped`, severity 1 (Informational), an empty `vulnerabilities` array, and an `ash_row_type:workspace_skipped_project` label | Filter on the label or on `status_id`, or sum `vulnerabilities` lengths, which counts this record as zero |

`html`, `markdown` and `text` show the project in their per-project section with its skip reason, and `flat-json` and `yaml` carry the typed `workspace.skipped_projects` payload. The reason is always stated: a `no-changes` skip is a successful optimisation and an `error` skip is a project that was never looked at, and the two must not read the same.

A reporter is per project when merging would be wrong rather than merely unimplemented. `github-ghas` and `gitlab-sast` produce documents their consumers resolve against a single repository root, so a merged one would mis-locate findings. The three SBOM formats describe one deliverable each, and a workspace of independently versioned projects is N SBOMs. The AWS reporters publish side effects, which a second invocation would duplicate.

`reports/workspace-reports.json` accounts for all of them, including the ones that deliberately produced nothing: what each reporter's behaviour is, the path of its workspace-level artefact or `null`, the per-project paths that replace it, which of those are missing, and why a reporter was not considered at all — `disabled`, `not-in-requested-output-formats`, or unsatisfied dependencies. A per-project reporter that ASH's default config leaves off, such as the AWS reporters, is listed with the per-project reports that exist on disk, because each project's own config decided whether it ran. A missing report is never silent.

Reporter enablement at the workspace level comes from ASH's default configuration plus `--output-format`, not from any single project's config, because there is no workspace-level configuration yet. So a project that disables `html` still contributes to the workspace-level `html` report; its own `projects/<key>/reports/` respects its config as usual.

If a reporter declares that it cannot produce a correct workspace-level artefact at all, the scan is refused before anything is scanned, with exit code `4` naming the reporter. No reporter shipped with ASH is in that state. Disable it or narrow `--output-format` to proceed.

#### Changed files and precommit

`--changed-files-only` is evaluated per project, against that project's own git repository, because projects in a workspace are versioned independently. A project with no changed files is skipped and recorded with `skipped_reason: no-changes`, which does not affect the exit code. A project that is not a git repository is scanned in full, with a warning. `--mode precommit` does not select changed files in a workspace, and it does not narrow the scanner set there either: in workspace mode it changes only the output. A refused `--base-ref` (see its row in [Common Parameters](#common-parameters)) stops the whole workspace before any project runs.

#### Concurrency

Set these in the ASH config resolved for the workspace **root** (the file `--config` names, or the one found in the workspace root) — how many projects run at once is not a project's decision. A config file there that cannot be loaded stops the run with exit code 3, as it would stop a single-directory scan:

```yaml
workspace:
  max_parallel_projects: 4   # default: min(4, cpu_count)
  project_timeout: 600       # seconds; default: no limit
```

`max_parallel_projects` bounds how many projects run concurrently. It is an outer bound over each project's own scanner thread pool, not a replacement for it, so the worst-case thread count is the product of the two. Wall clock is roughly `ceil(projects / max_parallel_projects)` times one project's: five projects at the default bound of 4 take two waves. Raise the bound to the project count to get one wave, and accept the larger thread product.

`project_timeout` records a project that overruns as failed and continues with the others; the workspace then exits non-zero. The abandoned worker cannot be interrupted, so it runs to completion in the background and the process will not exit until it does.

#### Container mode

Container mode has one bind mount, so the workspace **root** is mounted at `/src` and each project is `/src/<relative-path>`. This is why every project must sit below the workspace root. `--changed-files-only` is not supported in container mode, as in single-directory mode, and is refused with exit 5.

#### Fail-closed validation

Workspace resolution refuses the whole workspace rather than scanning part of it, because a partial scan exits 0 and the projects that did run supply a passing result for code nothing examined. A workspace is refused when:

- a folder does not exist, or exists but is not readable
- a folder resolves outside the workspace root, or a path contains `..`
- a folder entry is a symlink
- two entries resolve to the same directory, or one is nested inside another
- two entries reduce to the same project key
- the scanners' `tool_version` constraints the plan records are incompatible for the same scanner. A project's own config does not set `tool_version` (it is ignored with a warning), so every project records the operator's value or the scanner's default.
- the `folders` list is empty, or the file is not valid JSON
- the workspace file, the directory holding it, or a folder has a path that is not UTF-8. The plan and the results hold those paths, and both are UTF-8 only, so the workspace is refused before any project's config is read, with the path's bytes that are not UTF-8 written as escapes. Rename the directory, file or folder: container mode does not help, because the workspace is planned on the host

`--allow-missing-projects` opts out of the first item only. Projects skipped that way are recorded in the plan's `skipped_projects` payload with a reason, not just logged. Nothing opts out of the others: they are problems with the definition rather than with the machine, so they are wrong everywhere.

Workspace mode does not introduce a separate exit-code vocabulary; it uses the codes in [Exit Codes](#exit-codes). Every refusal listed above is code `4` — the workspace definition could not be used, so nothing was scanned. That is deliberately distinct from code `2`, which means a scan ran and found issues above the threshold.

What is found before execution starts refuses the whole workspace, and no project runs: the definition problems above, permitted roots, tool versions, plugin sets, scanner selection, and a file git tracks where a project's scan would write (exit `3`, naming the project). A failure during one project's run fails only that project, and the others still run.

When several projects end differently, the code is chosen by how specific the diagnosis is rather than by severity: `3` (a named misconfigured project) outranks `1` (a project that reached no verdict at all, whether from an internal error or a per-project timeout, or one whose scanners did not all complete), which outranks `2` (a project with a verdict that failed). That is the order a single-directory scan uses, so a workspace with one incomplete project exits `1` even when another project has findings; each project's findings are still in the results file and the summaries. The results payload also records `workspace.status` — `completed` or `refused` — and `workspace.refusal_detail`, for consumers reading the file rather than the exit status.

Comments are not supported in the workspace file. VS Code tolerates them; ASH reads strict JSON and reports a commented file as malformed.

### Sharding

`--shard-index` and `--shard-count` split one scan across several CI executors. Both are required together, and the index is zero-based, so a three-way split uses `0`, `1`, and `2`:

```bash
# Run in each of three parallel CI jobs. SHARD_INDEX comes from the job matrix
# and is 0, 1, or 2; every job passes the same --shard-count.
ash --source-dir . --output-dir "./shard-${SHARD_INDEX}" \
  --shard-index "${SHARD_INDEX}" --shard-count 3
```

Each shard scans the whole tree with a disjoint subset of the **scanners**, not a subset of the files. Scanners are handed a directory and most of them walk it themselves, so a file-level split would be honored by roughly a third of them and ignored by the rest: every shard's semgrep would scan the whole repository, and because merging deliberately does not deduplicate, an n-shard run would report every semgrep finding n times. That is a wrong report, not merely a slow one. Partitioning the scanner set instead is honored by every scanner without any scanner knowing that sharding exists.

The partition is a pure function of the scanner names, the index, and the count — names are deduplicated, lowercased, sorted, then dealt round-robin — so executors never coordinate and every shard computes the same partition on its own. It is taken over every *registered* scanner, before the enabled and dependency filters. Partitioning the post-filter set instead would make the split depend on which tools happen to be installed on each runner, so a runner missing semgrep would shift every later scanner onto a different shard than its siblings computed, running some scanners twice and others not at all. As it stands, a tool missing on one runner is reported `MISSING` by the shard that owns it, which is a visible failure rather than a silent gap.

Each shard records the scanners it was assigned in its own `ash_aggregated_results.json`. That record is what `ash merge` verifies coverage from, which is also why merge refuses a results file produced without these flags.

#### Per-shard exit codes are not the verdict

A shard that owned only `syft` and `grype` finds nothing and exits 0. Five such shards mean five green CI jobs and a repository full of critical findings that nobody was told about. The verdict for a sharded run belongs to [`ash merge`](#merge-command), computed over the union. Gate CI on that command, not on per-shard success.

#### What sharding does and does not buy

Balance is by scanner count, not by scanner cost. `semgrep` and `checkov` dominate ASH's runtime, so a shard holding semgrep finishes long after a shard holding syft: wall clock is bounded by the slowest single scanner, and counts above about four buy very little. Nothing models or measures per-scanner cost.

A `--shard-count` above the number of scanners leaves the surplus shards with nothing assigned. They run, produce a valid empty report, and merge correctly, so this is wasteful rather than wrong. It is allowed on purpose, so that a pipeline can parameterize its shard count without knowing how many scanners are registered — ASH ships sixteen built-in scanners, and any scanner plugins you register count too.

#### Interaction with other options

`--exclude-scanners` is carried through rather than replaced. A scanner you excluded stays excluded on every shard, instead of quietly running on whichever shard it happened to land on.

Sharding cannot be combined with `--workspace`, and the combination is refused rather than ignored. Both spread one scan over more compute, but only sharding is recombinable: workspace mode's unified results file is assembled from the per-project payloads and carries none of each project's scan metadata, so a sharded workspace run would write results that merge has no provenance to verify coverage from — and an unverifiable partial scan reads as a clean one. Either scan the workspace whole on one executor, or give each CI job one project via `--source-dir` and shard that.

In container mode both flags are forwarded to the in-container `ash` invocation rather than dropped.

### Reporting only changed files

`--changed-files-only` asks git which files changed between `--base-ref` (default `origin/main`) and HEAD, and reports only the findings located in those files:

```bash
ash --changed-files-only --base-ref origin/main
```

It narrows what is reported, not what is scanned: every scanner still scans all of `--source-dir`, so the scan takes as long as a full one. Findings located in other files are dropped before the summary counts and the reports are written, so they are absent from every report, from the summary counts and from the exit code. Each scanner's own raw output under `scanners/` in the output directory still contains them. Findings with no file location are kept. The results record `metadata.changed_files_only`: `true` when the findings were filtered this way, `false` on a full scan (including the fallback below), so a reader of `ash_aggregated_results.json` can tell a filtered result set from a full one: a finding that is not listed was left out, not fixed.

Only changed files under `--source-dir` count. When git cannot list the changes (not a repository, git missing, or a base ref it cannot resolve), ASH logs a warning and reports everything. When none of the changed files are under `--source-dir`, it reports nothing. In workspace mode each project is compared against its own repository, and a project with no changes is skipped. Container mode does not support the flag and refuses it, exit 5.

### Examples

```bash
# Basic scan in local mode (default)
ash

# Scan with container mode
ash --mode container

# Scan with specific source and output directories
ash --source-dir ./my-project --output-dir ./scan-results

# Scan with configuration overrides
ash --config-overrides 'scanners.bandit.enabled=true' --config-overrides 'global_settings.severity_threshold=MEDIUM'

# Scan with specific output formats
ash --output-formats flat-json,sarif,html,markdown

# Scan in precommit mode (faster)
ash --mode precommit

# Scan with custom plugins
ash --ash-plugin-modules my_ash_plugins

# Inspect the plan for a workspace, without scanning
ash --workspace ./dev.code-workspace --dry-run

# Use the single .code-workspace file in the current directory
ash --workspace auto --dry-run

# Tolerate project folders that have not been cloned on this machine
ash --workspace ./dev.code-workspace --allow-missing-projects --dry-run

# Run shard 0 of a three-way split; run indices 1 and 2 on other executors
ash --shard-index 0 --shard-count 3 --output-dir ./shard-0
```

## Merge Command

The `merge` command recombines the results of a sharded scan into one unified report. Each executor of `ash --shard-index k --shard-count n` writes its own `ash_aggregated_results.json`. This command checks that the shards given reconstruct exactly one whole scan, merges them, writes the unified results file and every requested report format, and exits with the verdict for the union.

```bash
ash merge --results <file-or-dir> [--results ...] --output-dir <dir> [options]
```

### Merge Options

| Option                 | Description                                                                  | Default                                           | Environment Variable |
|------------------------|------------------------------------------------------------------------------|---------------------------------------------------|----------------------|
| `--results`            | A shard's `ash_aggregated_results.json`, or a directory containing one. Repeat once per shard. Required | | |
| `--output-dir`         | Directory to write the merged results and reports to. Required                |                                                   | `ASH_OUTPUT_DIR`     |
| `--output-formats`     | Comma-separated report formats to generate                                    | The scan configuration's `output_formats`, else every enabled reporter |                      |
| `--config`, `-c`       | The operator's config file, the source of the settings a shard's recorded configuration cannot choose (see below) | ASH's defaults                                    | `ASH_CONFIG`         |
| `--config-overrides`   | Configuration overrides as `key.path=value`, applied over the shards' recorded configuration | |                      |
| `--min-severity`       | Minimum severity that counts as actionable for the exit code: `critical`, `high`, `medium`, `low` or `none`; any other value is a usage error | `low`                                             |                      |
| `--fail-on-findings`   | Exit non-zero when the merged report has actionable findings                   | The scan configuration's value, then `True`       |                      |
| `--fail-on-incomplete-scanners` / `--no-fail-on-incomplete-scanners` | Refuse the merge when a shard completed none of the scanners it owned, and exit 1 when any scanner in the union is `ERROR` or `MISSING` | The scan configuration's value, then `True` | |
| `--config`, `-c`       | The operator's configuration file; only it can turn on a reporter that sends findings off the host | None                                              |                      |
| `--log-level`          | Set the log level                                                             | `INFO`                                            |                      |
| `--verbose`, `-v`      | Enable verbose logging                                                        | `False`                                           |                      |
| `--debug`, `-d`        | Enable debug logging                                                          | `False`                                           |                      |
| `--color`              | Enable/disable colorized output                                               | `True`                                            |                      |

`--results` accepts a directory because CI artifact downloads land as directories. A directory is searched for `ash_aggregated_results.json` at `./`, `ash_output/`, and `.ash/ash_output/` in that order, and only then recursively. The recursive search must find exactly one file, so pointing `--results` at a parent holding every shard's artifact directory is refused with a message naming what it found — picking one of several would silently drop shards. Pass one `--results` per shard instead.

The merged report does not depend on the order the shards are listed in. They are sorted by shard index before anything is merged, and the report's identity — its configuration, name, and description — comes from the lowest-indexed shard, because those are properties of the scan rather than of a shard. Converter results are combined across shards instead, so a notebook or archive one shard could not convert still makes the merged report incomplete. So are the records of what each shard left out of ASH's scan set: `metadata.inputs_not_scanned` lists every shard's rows once each, and `metadata.ignore_file_exclusions` says the ignore files were honored only when every shard honored them, with each ignore file's largest count from any shard. When some shards honored them and some did not, it also records how many of the shards did (`honored_scan_count` of `scan_count`), and the summaries say so.

The reporters and severity thresholds come from the scan's own configuration, carried through the shard results, rather than from a config file resolved on the collector host. The collector job need not have the source tree checked out at all, and a config file found there could disagree with the one the shards actually scanned under, which would move the verdict without moving the findings.

#### Settings a shard's recorded configuration cannot choose

A shard's recorded configuration may have been read from a config file inside the scanned tree, so `ash merge` treats it the way a scan treats such a file: every row of [Settings a repository's config cannot choose](configuration-guide.md#settings-a-repositorys-config-cannot-choose) applies to it, and so does the rule for the options a plugin reporter declares in `destination_options`. Which plugin modules are imported, whether ASH's off-host reporters run, where the reporters send findings, and the credentials they use therefore come from the operator at merge time: ASH's defaults, `--config` (or `ASH_CONFIG`), and `--config-overrides`. A value the recorded configuration sets that the operator's does not is replaced by the operator's, and a warning names the setting and the shard's results file.

- `ash_plugin_modules` is stricter than in a scan: `ash merge` imports ASH's built-in plugins and the modules the operator names in `--config` or `--config-overrides`, whether or not the shards recorded them. An entry the shards recorded that the operator does not name is dropped, even an installed module outside the tree, and one warning names it. A config file in the working directory is not the operator's, so its modules are not imported either.
- `enabled` of a reporter that sends findings off the host (the AWS reporters, and a plugin reporter that declares `destination_options`) comes from the operator's configuration, or the reporter's default where that is silent, in both directions, as in a scan: `ash merge` ignores a shard's `enabled: false` with a warning, as it ignores a shard's `enabled: true`.
- `--config-overrides` apply over each shard's recorded configuration before anything reads it, so they reach the reporters, the completion gate and the verdict, and they count as the operator's values for the settings above.
- `--config` supplies the operator's values for those settings, and its `ash_plugin_modules` are the modules the merge loads. It does not otherwise replace the recorded configuration, so a reporter section the shards did not configure is added with `--config-overrides`. A reporter's `enabled` or destination option that `--config` sets for such a section, and that therefore does not apply, is named in a warning with the `--config-overrides` that would add it. As for `ash report`, a `--config` file inside the working directory's tree is not the operator's: the outermost git checkout around the working directory, or the working directory itself when it is in no checkout. Keep the operator's file outside it.
- The sandbox settings and the scanners' own config files are held to the same rules, so the merged results record the operator's values for them. No scanner runs during a merge, so they change nothing else.
- An off-host reporter's `enabled` and destination options (bucket, region, log group, account, model) do not come from `--config` either. The shards do not record which tree was scanned, so the file may be the scanned tree's own `.ash/.ash.yaml`, even outside the working directory and every git checkout. They come from ASH's defaults and `--config-overrides`, and a value `--config` sets for them is ignored with a warning that names the override to pass, as in [`ash report`](#report-options).

The settings the verdict reads still come from the shards, as the verdict follows the scan's own configuration: `fail_on_findings`, `fail_on_incomplete_scanners`, `global_settings.severity_threshold`, `global_settings.suppressions`, `global_settings.ignore_paths`, each scanner's `options.severity_threshold`, `content_db_staleness` and `content_db_staleness_overrides`. One verdict covers the merged scan, so shards whose values for any of these differ after `--config-overrides` are applied are refused with exit code 3, and the error names the setting and each shard's value. `--fail-on-findings`/`--no-fail-on-findings` and `--fail-on-incomplete-scanners`/`--no-fail-on-incomplete-scanners` decide their setting for the merge, so shards that disagree only on a setting whose flag is given are not refused. A value `--config` sets for one of these settings does not apply; a warning names it and the `--config-overrides` key or flag that would.

When the `--config-overrides` one of these warnings suggests has a value with spaces, quotes or other characters a shell interprets, such as a list of suppressions, the warning quotes it for a POSIX shell (bash, zsh, sh) and says so after it. In PowerShell or cmd.exe, quote the same `key=value` the way that shell expects instead.

To keep a shard's reporter settings, pass the same values at merge time. Loading `ash_aws_plugins` makes all four AWS reporters available, and each is off unless the operator's configuration turns it on. For example, to upload the merged report to S3 and to no other AWS service:

```bash
ash merge --results ./shard-0 --results ./shard-1 --output-dir ./ash-merged \
  --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_aws_plugins"]' \
  --config-overrides reporters.s3.enabled=true \
  --config-overrides reporters.s3.options.bucket_name=my-bucket \
  --config-overrides reporters.s3.options.aws_region=us-east-1
```

### What Merge Refuses

Coverage is verified before anything is merged, so a bad set of shards fails without leaving a half-written report behind. A merge is refused when:

- a results file carries no shard provenance, meaning it was not produced by a scan run with `--shard-index` and `--shard-count`
- the shards disagree about the total shard count, which means they came from different runs or the count changed mid-flight
- a shard index is missing, repeated, or outside the declared count
- two shards claim the same scanner, which would count its findings once per shard
- a scanner appears in some shard's results but no shard was assigned it — the executors resolved different scanner sets, so no shard ran it and the union has a hole
- the shard that owned a scanner recorded no result for it, leaving another shard's skip marker as the only trace
- a shard's results record no scan configuration (`"ash_config": null`): the merged verdict, the suppressions applied after merging and the report settings come from the configuration the shards scanned under, so the merge is not run under ASH's defaults instead
- the shards' recorded configurations disagree on a setting the verdict reads, after `--config-overrides` are applied (exit code 3; see [Settings a shard's recorded configuration cannot choose](#settings-a-shards-recorded-configuration-cannot-choose))

With the completeness gate on, which is the default, one more:

- a shard owned at least one scanner and completed none of them — every scanner it was asked to run came back `ERROR`, came back `MISSING`, or produced no entry at all

That is the distributed form of the false-clean exit code, and none of the checks above can see it: they read shard indices and scanner names, never a status. A shard whose every scanner was `MISSING` satisfies all of them, contributes no findings because it ran nothing, and merges into a report that reads as a complete scan of the whole tree. The refusal happens before the merged report is written, so a downstream job that consumes the artifact rather than the exit code cannot pick up a partial report either.

This one check is opt-in while the rest are unconditional. The others describe a set of shards that cannot reconstruct one scan whatever the environment; this one describes an environment — four of the ten default scanners are `MISSING` on a machine without their tools — so refusing by default would break merges that have nothing wrong with them. A shard that owned nothing is never an offender: a shard count above the scanner count leaves surplus shards with an empty assignment, and a shard asked to run nothing cannot have failed to run it.

Merge also warns, without refusing, when a scanner ran on no shard although one job's selection asked for it: the jobs of the matrix were given different `--scanners`, `--exclude-scanners` or config, and the shard that owned the scanner did not select it. Every job records what its selection asks for, so a scanner that no job's selection includes, such as one left out of the same `--scanners` list on every job, is the operator's choice and merges without a warning. Shards from an ASH release that did not record this get the older warning, which names every scanner no shard ran.

An unstamped results file is refused rather than treated as "probably the only shard". A whole unsharded scan and one shard of five are indistinguishable without that record, and guessing would let `ash merge` accept a single scan as a complete merge of a five-way split.

The output directory is checked the way `ash scan` checks it: when it, a directory or file ASH writes in it, or a directory below the current directory on the way to it is a symlink, the merge is refused with exit 3 before anything is written. See [Output directory](concepts.md#output-directory).

The merged output carries no shard provenance of its own; it records `merged_shard_count` and `merged_shard_indices` instead. Copying the base shard's assignment through would make the merged file look like shard 0 of n, so a second `ash merge` over an output directory would accept it and report a whole scan as one fifth of itself.

### Merge Exit Codes

| Code | Meaning                                                                       |
|------|-------------------------------------------------------------------------------|
| 0    | The shards reconstructed one whole scan and the union has no actionable findings |
| 1    | The merge was refused, or a scanner or converter in the union did not complete — the scan's findings are unknown, not absent |
| 2    | The union has findings at or above `--min-severity`                            |
| 3    | The configuration is invalid: `--config` (or `ASH_CONFIG`) names a path that is missing, a directory or unreadable, it or a `--config-overrides` value does not validate, or the shards' recorded configurations disagree on a setting the verdict reads |
| 5    | Usage error: the command line was refused, for example a missing `--output-dir` or `--results`, or a `--results` path that does not exist, and nothing was merged |

Codes 1 and 2 are genuinely different situations. Code 2 means the merge succeeded and the union failed the threshold. Code 1 means no verdict was reached at all, which a CI gate must not read as a clean scan. Code 5 means the command itself was malformed; it never stands for a finding.

### Examples

```bash
# Merge three shards' artifact directories downloaded by a CI collector job
ash merge \
  --results ./artifacts/shard-0 \
  --results ./artifacts/shard-1 \
  --results ./artifacts/shard-2 \
  --output-dir ./ash-merged

# Merge explicit results files and generate only the formats CI consumes
ash merge \
  --results ./shard-0/ash_aggregated_results.json \
  --results ./shard-1/ash_aggregated_results.json \
  --output-dir ./ash-merged \
  --output-formats sarif,markdown

# Fail the collector job only on medium-or-worse findings across the union
ash merge --results ./shard-0 --results ./shard-1 --output-dir ./ash-merged --min-severity medium
```

## Config Command

The `config` command allows you to manage ASH configuration.

```bash
ash config [subcommand] [options]
```

### Config Subcommands

| Subcommand | Description                                                      |
|------------|------------------------------------------------------------------|
| `init`     | Initialize a new configuration file                              |
| `get`      | Display current configuration                                    |
| `update`   | Update configuration values                                      |
| `validate` | Check that a scan accepts the configuration (same loader and model) |
| `lint`     | Lint configuration for issues and optionally auto-fix them       |

### Config Options

| Option               | Description                                     | Default          | Environment Variable |
|----------------------|-------------------------------------------------|------------------|----------------------|
| `--config`, `-c`     | Path to configuration file (every subcommand)   | The config a scan of the current directory would use | `ASH_CONFIG`         |
| `--config-overrides` | Override configuration values (with `get`, `validate`, `validate-plugin-dependencies`) |                  |                      |
| `--source-dir`       | The directory a scan would scan: where the config is discovered, and the tree a config inside it may extend from (with `get`, `lint`, `validate`, `validate-plugin-dependencies`) | Current directory | `ASH_SOURCE_DIR` |
| `--set`              | Set configuration values (with `update`)        |                  |                      |
| `--dry-run`          | Preview changes without writing (with `update`) | `False`          |                      |
| `--force`            | Overwrite the file at the target path (with `init`) | `False`      |                      |
| `--fix`              | Auto-fix common issues (with `lint`)            | `False`          |                      |
| `--fix-unused`       | Comment out unused suppressions (with `lint`)   | `False`          |                      |
| `--non-interactive`  | Skip confirmation prompts (with `lint`)         | `False`          |                      |
| `--output-dir`, `-o` | Path to ASH output directory (with `lint`)      | `.ash/ash_output`|                      |
| `--debug`, `-d`      | Enable debug logging                            | `False`          |                      |
| `--verbose`, `-v`    | Enable verbose logging                          | `False`          |                      |
| `--no-color`         | Disable colored output                          | `False`          |                      |

`get`, `update` and `validate-plugin-dependencies` also accept the file as a
positional argument, as they did before they had `--config`; `--config` is
preferred. A path on the command line takes precedence over `ASH_CONFIG`, as it does
for `ash scan`. A subcommand given a file that is not a valid configuration exits 3,
the exit code `ash scan` gives for an invalid configuration; a file that does not
exist exits 1.

### Examples

```bash
# Initialize a new configuration file (.ashrc.yaml in the current directory)
ash config init

# Replace an existing .ashrc.yaml (or the --config file) with the defaults.
# A project whose config has another name is refused even with --force; name
# the file to reset it: ash config init --config .ash/.ash.yaml --force
# init and wizard write YAML or JSON, and refuse a .toml target.
ash config init --force

# Display current configuration
ash config get

# Display configuration from a specific file
ash config get --config /path/to/config.yaml

# Update configuration
ash config update --set 'scanners.bandit.enabled=true'

# Preview configuration update without writing
ash config update --set 'scanners.bandit.enabled=true' --dry-run

# Validate configuration file
ash config validate

# Validate a specific configuration file
ash config validate --config /path/to/config.yaml

# Validate with verbose output showing all checks
ash config validate --verbose

# Lint configuration for issues
ash config lint

# Lint and auto-fix common issues
ash config lint --fix

# Lint, fix, and comment out unused suppressions
ash config lint --fix --fix-unused

# Non-interactive mode (for pre-commit hooks and CI/CD)
ash config lint --fix --fix-unused --non-interactive

# Lint a specific config file
ash config lint --config path/to/config.yaml
```

### Config Validate Details

`ash config validate` loads the configuration the way a scan loads it and gives the
verdict the scan would give. Without `--config` it checks the file a scan of the
current directory (or of `--source-dir`) would use. The check judges the
environment it runs in: an `ash_plugin_modules` entry no package installed in
this environment provides is refused as a scan run here would refuse it, so a
module that is only installed inside a container image is reported missing by
a check run on the host.

**What it checks:**
- **Loading**: the file must parse (YAML, JSON, or TOML for `.ashrc.toml` and
  `pyproject.toml`; the suffix decides, in upper or lower case), with `${VAR}` and
  `!ENV` references resolved as in a scan, and its `extends`
  chain must resolve, with the same confinement a scan applies: a config inside the
  source directory may extend files anywhere inside it. A file that does not parse is
  invalid (exit 3), and a scan given it refuses it with exit 3 before scanning
  anything.
- **The model**: the result is checked against the `AshConfig` model the JSON schema
  is generated from, with strict types, so a wrong type (`fail_on_findings: banana`),
  a value outside an enum (`severity_threshold: BOGUS`), an unknown key inside a
  section (`global_settings.severity_treshold`) or a suppression without a `reason`
  is an error. Each error names the field, for example
  `Invalid value at 'global_settings.severity_threshold': Input should be 'ALL', 'LOW', 'MEDIUM', 'HIGH' or 'CRITICAL'`.
  So is a key a built-in plugin's section does not declare beside `enabled`. For
  the internal-only fields there (`tool_version`, `install_timeout`, and a
  scanner's `extension`) the error says so,
  `Invalid value at 'scanners.bandit': Value error, Scanner 'bandit' contains internal-only field 'tool_version' - this should not be in user configs; if you meant a version constraint, put it under options.`,
  the message a scan refuses the file with. The hint about `options` appears
  where the plugin declares an option of that name. `ash config lint --fix`
  removes them, except a `tool_version` or `install_timeout` that is neither
  null nor equal to the plugin option's default, which may be a pin you meant.
- **Overrides**: with `--config-overrides`, the overrides are applied as a scan
  given the same `--config-overrides` applies them.
- **Warnings**: things a scan accepts but that are probably mistakes. These are
  printed and do not change the exit code: the internal-only fields a section
  declares (`name`, and a reporter's `extension`), internal-only fields in the
  section of a plugin loaded from `ash_plugin_modules` (checked when a scan loads
  it), the internal `build` section, an unknown top-level key (a scan
  ignores it, so that a config written for another ASH version still loads), a
  duplicated top-level key (YAML keeps the last one), a key written both as its
  documented name and as its field name (`mcp-resource-management` and
  `mcp_resource_management`; a scan reads the first), a missing `project_name`
  (reports then use `ash-scan`), and a path in `ignore_paths` or a suppression that
  names a directory without a `**` glob. A JSON `$schema` key is not a warning, and
  neither is `mcp_resource_management` alone, which a scan reads as
  `mcp-resource-management`. The MCP `validate_config` tool gives the same verdict:
  `valid` is true when a scan accepts the file, and its `errors` list still holds
  these warnings, each with its type.
- **Environment values are not repeated**: an error from the model names the field,
  not the value it holds, and a value read from an environment variable (`!ENV`, or
  `${VAR:default}`) is shown as `<value>` wherever the command would print it,
  including the "Resolved source chain" list, a value quoted with escapes, and the
  `--fix-unused` list. A key read from the environment (a mapping key written as
  `${VAR}`) is hidden the same way. A value shorter than four characters is left as
  it is. The same holds for `ash config lint`, `ash config
  validate-plugin-dependencies`, the refusals of `ash scan` and the error it logs
  (for the file it found or was given, the file `ASH_CONFIG` names, and each project
  of a `--workspace` scan), the messages of `ash config get`, and the MCP
  `validate_config` tool. `ash config get` itself prints a valid configuration with
  each value and key a file read from the environment as the reference the file
  wrote (`${VAR}`, `${VAR:default}` or `!ENV '${VAR}'`, the tag with the
  reference quoted), as a scan's results file records it, and never the value.
  When an `extends` chain fails only because of a base named through an environment
  variable, the error says so without naming the base: a file reached through that
  base (the base itself, or one it extends) is missing, unreadable, or outside the
  directory bases must stay inside.

**Exit Codes:**
- `0`: A scan accepts the configuration (warnings may have been printed)
- `1`: No `--config` was given and no config file was found
- `3`: A scan refuses the configuration (the exit code `ash scan` gives for an
  invalid configuration), or the file cannot be loaded at all: missing, a
  directory or FIFO, unreadable, not UTF-8, not valid YAML, JSON or TOML, or
  using a YAML alias
- `5`: Usage error, such as an unknown option

**Example Output:**

```bash
$ ash config validate
Validating configuration file: .ashrc.yaml

✅ Configuration is valid! A scan accepts it.

$ ash config validate --config bad.yaml
Validating configuration file: bad.yaml

❌ 3 error(s); a scan refuses the configuration because of these:
  1. Invalid value at 'global_settings.severity_threshold': Input should be 'ALL', 'LOW', 'MEDIUM', 'HIGH' or 'CRITICAL'
  2. Invalid value at 'fail_on_findings': Input should be a valid boolean
  3. Invalid value at 'scanners.bandit.enabled': Input should be a valid boolean

❌ Configuration is invalid: a scan refuses it with exit 3. The configuration guide, and the JSON schema at automated_security_helper/schemas/AshConfig.json, give each field's type and allowed values.
```

**Use Cases:**
- Validate configuration before committing to version control
- Debug configuration issues when scans fail
- Verify configuration after manual edits
- CI/CD pipeline checks to ensure valid configuration
- Pre-deployment validation in automated workflows

### Config Lint Details

The `ash config lint` command performs all validation checks plus additional lint checks that can identify and auto-fix common configuration issues:

**Lint Checks:**
- **All validation checks**: Same checks as `ash config validate`. A problem that
  makes a scan refuse the configuration is an error marked `[blocks the scan]`.
  Everything else lint reports is a warning or info, because a scan accepts it.
- **Internal fields**: Detects internal-only fields in plugin sections (e.g., `name`, `extension`, `tool_version` in scanner configs). An error marked `[blocks the scan]` when a built-in plugin's section does not declare the field (`tool_version`, `install_timeout`, a scanner's `extension`), otherwise a warning; `--fix` removes them, except a `tool_version` or `install_timeout` that is neither `null` nor equal to the plugin option's default (any value but `null` for a plugin lint does not load), which it leaves for a hand edit because it may be a pin. A field an `extends` base sets stays an error that is not auto-fixable, since `--fix` edits only the linted file
- **Invalid sections**: Detects internal top-level sections like `build` that shouldn't be in user configs. A warning; `--fix` removes them
- **Legacy plugin and key names**: A snake_case spelling such as `cdk_nag` (the documented key is `cdk-nag`), and both spellings at once, which a scan reads as the documented one. Warnings
- **Missing line_end**: Detects suppressions with `line_start` but no `line_end`
- **Expired suppressions**: Detects suppressions past their expiration date
- **Unused suppressions**: Detects suppressions not matching any findings (requires `--fix-unused`)

**Auto-fix Behavior (`--fix`):**
- Removes internal-only fields from scanner/reporter/converter configs
- Removes invalid top-level sections (e.g., `build`)
- Sets `line_end` equal to `line_start` when missing
- Removes expired suppressions
- Refuses (exit 1) to rewrite a file that reads values from the environment
  (`!ENV`, or `${VAR:default}`), since the rewrite would store what they resolve to
  now; with nothing to fix, such a file gets the exit code `lint` gives it

**Unused Suppression Handling (`--fix-unused`):**
- Comments out unused suppressions instead of removing them
- Adds a dated note explaining why they were commented out
- Preserves suppressions for easy re-activation if needed
- When every entry is commented out, the key is left as `suppressions: []`, so
  the file still loads (a key holding only comments is null, which a scan
  refuses); remove the `[]` when you re-activate an entry
- This is intentionally conservative: a suppression unused locally may still be needed in CI/CD where different scanners are available

**Non-interactive Mode (`--non-interactive` / `--yes` / `-y`):**
- Skips all confirmation prompts
- Useful for pre-commit hooks and CI/CD pipelines
- Warns (but proceeds) when the unused suppressions report is older than 1 hour

**Exit Codes:**
- `0`: A scan accepts the configuration. Warnings and info, such as internal
  fields, the `build` section or a duplicated key, do not change it; nor does
  declining `--fix` at its prompt
- `1`: No `--config` was given and no config file was found, or `--fix` or
  `--fix-unused` refused to rewrite it (a TOML file, a JSON file for
  `--fix-unused`, or a file with environment references when there is something
  to fix)
- `3`: A scan refuses the configuration, as `ash config validate` reports it, the
  `--config` file does not exist or cannot be read, or the file does not parse
  (marked `[blocks the scan]`). With
  `--fix`, the fixes are applied first and the exit code describes the fixed file,
  since removing an internal section can make the configuration valid
- `5`: Usage error, such as an unknown option

**Example Output:**

For a `.ashrc.yaml` whose `bandit` section has `name: bandit`, with a
suppression that sets `line_start: 42` and no `line_end`, and one that expired
on 2024-01-01:

```bash
$ ash config lint
Linting configuration file: /home/user/my-project/.ashrc.yaml

Found 3 issue(s):
  ⚠️  Scanner 'bandit' contains internal-only field 'name' at 'scanners.bandit.name' [auto-fixable]
  ⚠️  Suppression has 'line_start' (42) but missing 'line_end' - it matches any finding that ends at or after line 42, including a multi-line finding that starts before it at 'global_settings.suppressions[0]' [auto-fixable]
  ⚠️  Suppression has expired (expiration: 2024-01-01) at 'global_settings.suppressions[1]' [auto-fixable]

  Warnings: 3

💡 3 issue(s) can be auto-fixed. Run with --fix to apply fixes.

$ ash config lint --fix --non-interactive
Linting configuration file: /home/user/my-project/.ashrc.yaml

Found 3 issue(s):
  ⚠️  Scanner 'bandit' contains internal-only field 'name' at 'scanners.bandit.name' [auto-fixable]
  ⚠️  Suppression has 'line_start' (42) but missing 'line_end' - it matches any finding that ends at or after line 42, including a multi-line finding that starts before it at 'global_settings.suppressions[0]' [auto-fixable]
  ⚠️  Suppression has expired (expiration: 2024-01-01) at 'global_settings.suppressions[1]' [auto-fixable]

  Warnings: 3

🔧 Fixing 3 issue(s):
  • Remove internal field 'name' from scanner 'bandit'
  • Narrow the suppression to line 42 alone by setting line_end = 42
  • Remove expired suppression

✅ Fixed 3 issue(s) in /home/user/my-project/.ashrc.yaml
```

## Plugin Command

The `plugin` command allows you to manage ASH plugins.

```bash
ash plugin [subcommand] [options]
```

### Plugin Subcommands

| Subcommand | Description            |
|------------|------------------------|
| `list`     | List available plugins |

### Plugin Options

| Option                    | Description                            | Default          | Environment Variable |
|---------------------------|----------------------------------------|------------------|----------------------|
| `--include-plugin-config` | Include plugin configuration in output | `False`          |                      |
| `--ash-plugin-modules`    | Additional plugin modules to load      |                  | `ASH_PLUGIN_MODULES` |
| `--config`, `-c`          | Path to configuration file             | Discovered       | `ASH_CONFIG`         |
| `--config-overrides`      | Override configuration values          |                  |                      |
| `--debug`, `-d`           | Enable debug logging                   | `False`          | `ASH_DEBUG`          |
| `--verbose`, `-v`         | Enable verbose logging                 | `False`          | `ASH_VERBOSE`        |
| `--no-color`              | Disable colored output                 | `False`          |                       |

### Examples

```bash
# List all available plugins
ash plugin list

# List plugins with their configuration
ash plugin list --include-plugin-config

# List plugins including custom modules
ash plugin list --ash-plugin-modules my_ash_plugins
```

## Report Command

The `report` command generates reports from scan results.

```bash
ash report [options]
```

With no `--output-dir` and no `ASH_OUTPUT_DIR`, `ash report` reads `.ash/ash_output/ash_aggregated_results.json` under the current directory, where a scan writes it. Given a directory, it reads `ash_aggregated_results.json` from the directory's `.ash/ash_output` subdirectory, its `ash_output` subdirectory or the directory itself, the first of the three it finds. It writes the report to stdout. Log messages and errors go to stderr. When stdout is not a terminal, or with `--no-color`, stdout carries the reporter's output, not re-indented, highlighted or wrapped, so `ash report --format sarif > ash.sarif` produces a SARIF file. It is a fresh rendering of the saved results, not a copy of the file the scan wrote to `reports/`: SARIF can carry fields the saved results default, and CSV, HTML and Markdown carry the time they were rendered. On a terminal with color, JSON is indented and Markdown is rendered, with each link shown as its text and target rather than as a terminal hyperlink (a Markdown report that holds a control character, or text that reads as one of the escapes below, is printed as escaped text, unrendered); `docker run -t` gives the command a terminal: `--no-color` there stops the indenting and rendering, but control characters are still shown escaped, so for the reporter's exact output run the container without `-t`, or redirect stdout to a file inside the container. On a terminal, control characters in the report (which can come from the scanned code, such as escape sequences in a finding's message) are shown as `\xNN`, and Unicode's bidirectional and format controls (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069, the set ASH's console log shows too) as `\uNNNN`, rather than sent to the terminal (as `\u00NN` in JSON formats, indented or not, so the JSON parses to the same document), and the backslashes of text that would read as such an escape are doubled, so `\x1b` on the terminal is always an escaped control character; redirected output is not changed. An invalid configuration exits 3, including an option a plugin loaded from `ash_plugin_modules` does not accept, checked once the plugins are loaded as a scan checks it; an unknown `--format` is refused before the results are read. If no results file is found, the command names the paths it checked and exits 1 without creating anything.

In CI, write the report to a file (`ash report --format markdown > ash-report.md`) or publish the copy the scan wrote to `reports/`, rather than printing it to the job log. A CI log is not a terminal, so the report reaches it unchanged, and the report quotes the scanned code: a line of it that starts with `::` is read by GitHub Actions as a workflow command, and `##[` or `##vso[` by Azure Pipelines. ASH's log and summaries break such commands, writing the colon as `\x3a` or the `#` as `\x23`; `ash report`'s stdout is left as the report.

In CI, don't give ASH a terminal: no `docker run -t`, `script` or `unbuffer` around it. Container mode passes `-t` to the container runner itself when its own output is a terminal and color is on. A terminal gets ASH's output as written. Under GitHub Actions, Azure Pipelines and TeamCity, known by the `GITHUB_ACTIONS`, `TF_BUILD` or `TEAMCITY_VERSION` variable each sets in every job, ASH breaks the commands on a terminal too; under any other runner it can't tell that a terminal is a job log. Container mode and `./ash` pass each of those variables that is set into the container, by name, or, with `OCI_RUNNER_WRAPPER` set, with its value, because a wrapper such as `sudo` need not pass the environment on. Those three are the only variables of your environment that go on the runner's command line with their values; the others there, such as the mount paths, `ASH_DEBUG`, `ASH_OFFLINE` and the terminal size, are ASH's own. Through a wrapper, one of the three holding a newline is refused with exit 3. Running the ASH image yourself with `docker run -t`, pass them the same way, by name (`-e GITHUB_ACTIONS`), or the scan inside writes to its terminal as is.

### Report Options

| Option               | Description                       | Default           | Environment Variable |
|----------------------|-----------------------------------|-------------------|----------------------|
| `--format`           | Report format to generate         | `markdown`        |                      |
| `--output-dir`       | Directory containing scan results. Refused, with exit 3, when it, a directory or file ASH writes in it, or a directory below the current directory on the way to it is a symlink; see [Output directory](concepts.md#output-directory). | `.ash/ash_output` | `ASH_OUTPUT_DIR`     |
| `--config`, `-c`     | Path to configuration file        | Discovered        | `ASH_CONFIG`         |
| `--config-overrides` | Override configuration values     |                   |                      |
| `--log-level`        | Set the log level                 | `INFO`            |                      |
| `--debug`, `-d`      | Enable debug logging              | `False`           | `ASH_DEBUG`          |
| `--verbose`, `-v`    | Enable verbose logging            | `False`           | `ASH_VERBOSE`        |
| `--no-color`         | Disable colored output            | `False`           |                       |

The severity threshold shown for each scanner, and used to count its actionable
findings, comes from the configuration the results record: `global` for
`global_settings.severity_threshold`, `config` for the scanner's own option. When
the results record no configuration (a workspace's combined results, for
example), the threshold is the built-in `MEDIUM` (or `ASH_DEFAULT_SEVERITY_LEVEL`)
and its source is shown as `unavailable`; the configuration of the machine
running `ash report` is not used in its place.

A reporter that sends findings off the host (S3, CloudWatch Logs, Security Hub,
the Bedrock summary) runs from `ash report` only when `--config-overrides`
enables it, and its destination options (bucket, region, log group, account,
model) come from `--config-overrides` too. Stored results do not record which
tree was scanned, so a `--config` file, or the file `ASH_CONFIG` names, may be
the scanned repository's own `.ash/.ash.yaml` even when it is outside the working
directory and every git checkout. Its `enabled` and destination options for those
reporters are ignored with a warning; its other settings still apply. For
example: `ash report --format s3 --config-overrides reporters.s3.enabled=true
--config-overrides reporters.s3.options.bucket_name=my-bucket`.

### Examples

```bash
# Generate a markdown report
ash report --format markdown

# Generate a flat JSON report
ash report --format flat-json

# Generate a report from specific results
ash report --output-dir ./my-scan-results --format html

# Write a SARIF file from saved results
ash report --format sarif > ash.sarif
```

## Dependencies Command

The `dependencies` command installs dependencies for ASH plugins.

```bash
ash dependencies install [options]
```

### Dependencies Options

| Option                | Description                              | Default                      | Environment Variable |
|-----------------------|------------------------------------------|------------------------------|----------------------|
| `--bin-path`, `-b`    | Path to install binaries. A scan finds them there only when `ASH_BIN_PATH` names the same directory; see below | `~/.ash/bin`                 | `ASH_BIN_PATH`       |
| `--plugin-type`, `-t` | Plugin types to install dependencies for: `converter`, `scanner` or `reporter` (repeatable). Any other value exits 2 before anything is resolved or installed, naming the value and the three types | `converter,scanner,reporter` |                      |
| `--tool`, `-T`        | Install dependencies for these plugins only, by name (repeatable). A name no plugin has, or one of a type `--plugin-type` leaves out, exits 2 before anything is installed or downloaded | all plugins |                      |
| `--config`, `-c`      | Path to configuration file               | Discovered                   | `ASH_CONFIG`         |
| `--config-overrides`  | Override configuration values            |                              |                      |
| `--debug`, `-d`       | Enable debug logging                     | `False`                      | `ASH_DEBUG`          |
| `--verbose`, `-v`     | Enable verbose logging                   | `False`                      | `ASH_VERBOSE`        |
| `--no-color`          | Disable colored output                   | `False`                      |                       |

### Examples

```bash
# Install dependencies for all plugin types
ash dependencies install

# Install dependencies for scanners only
ash dependencies install --plugin-type scanner

# Install dependencies to a custom directory, and scan with them
ash dependencies install --bin-path ~/tools/ash-bin
export ASH_BIN_PATH=~/tools/ash-bin
ash scan
```

A `--tool` name that no loaded plugin has is refused with exit 2 and nothing is installed, so a typo cannot report success. With `ASH_DEPENDENCIES_UNKNOWN_TOOLS=skip` (exactly that value), such names are listed as skipped and the known tools are installed; a run that names only unknown tools installs nothing and exits 0. The refusal stands while any plugin failed to load, because the unknown name may be that plugin's. A name that is a plugin of a type `--plugin-type` left out is not unknown: it is refused with exit 2 whether or not the variable is set, and the message names its type. ASH's reusable CI workflow sets the variable only when its caller passes `skip-unknown-tools: true` with `config-ref`, as ASH's own required check does: that check installs an older ASH than the workflow files it runs, so the workflow can ask for a tool that ASH does not have yet.

A `--plugin-type` other than `converter`, `scanner` or `reporter` is refused with exit 2 before anything is resolved or installed, naming the value and the three types.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Every tool a scan here would run is present after the install |
| 1 | For a plugin a scan here would run, or one named with `--tool`: an install command failed, the plugin raised, or its tool is still absent. The panel names each plugin, with a missing program it needs besides its own command in parentheses (`cdk-nag (node)`); npm-audit without npm is named `npm-audit`. A plugin a scan here skips (disabled in the configuration, or not available on this platform) and that was not named with `--tool` exits 0 even when its install command fails or it raises |
| 2 | A `--tool` name matches no plugin, or names a plugin of a type that `--plugin-type` leaves out; or a `--plugin-type` that is none of `converter`, `scanner` and `reporter` was given. ASH names the tool or the type, and nothing was installed or downloaded |
| 3 | The configuration is one a scan refuses, the file `ASH_CONFIG` names included; the scan's refusal is printed and nothing is installed |
| 5 | Any other usage error, such as an unknown option (see [Usage errors](#usage-errors)) |

A tool counts as present when a scan would find it (see below), or, for bandit,
checkov, semgrep and nbconvert, when `uv tool list` lists it, since ASH runs those
with `uv tool run`. cdk-nag runs inside ASH's own Python process, so its tool is
the interpreter running ASH, whether or not a program named `python` is on
`PATH`; it still needs Node.js.

Only the plugins a scan with the same configuration on the same platform would run
decide the exit code, together with every plugin named with `--tool`. A scan skips
a scanner that its configuration disables (`enabled: false`) and one that does not
run on this platform (semgrep on Windows), so the install still runs and reports
theirs, but unless you asked for it with `--tool`, a failed command or a missing
tool there does not fail it. The panel lists them under "Not available on this
platform" (with the reason) and, when one is missing or failed, under "Disabled in
the configuration, not counted". A scanner that only lacks its tool here is
reported MISSING by a scan, and fails the install too: cfn-nag on Windows without
a Ruby DevKit, for example, which has no install path there. To provision only the
scanners you scan with, name them with `--tool`. In a workspace, where each project
has its own configuration and this command reads only the one for the directory it
runs in, name the tools the projects use with `--tool`.

### Where scans look for tools

A scan looks for each program on `PATH`, then in the ASH bin directory
(`ASH_BIN_PATH`, or `~/.ash/bin` when it is unset or blank), then
in the directories of ASH's own environment, where packages installed into it put
their commands: the directory of the Python interpreter running ASH, and that
interpreter's scripts directory, which is a different one on a Windows Python
outside a virtual environment (`python.exe` in the install directory, commands in
its `Scripts\` subdirectory). Last comes `/usr/local/bin` (not on Windows).

Blank means empty, or whitespace in every part of the path, such as ` ` or ` /`
(`/` itself is the root, not blank), and a blank `--bin-path` is the same as none,
so `--bin-path "$TOOLS_DIR"` with `TOOLS_DIR` unset installs into the ASH bin
directory.

A relative `ASH_BIN_PATH`, such as `bin`, is read relative to the working
directory, which is usually the repository being scanned, so a scan does not look
for tools there, and the scanner sandbox does not make it executable. It logs one
warning to `ash.log` that names the value and asks for an absolute path, and when
a scanner is then MISSING the incomplete-scan message names it too. A relative
`--bin-path`, such as `tools` or `.`, is taken against the directory
`ash dependencies install` runs in; the installer creates that directory and
exports it to its own commands as an absolute path.

Keep `ASH_BIN_PATH` outside the repository being scanned. An absolute path inside
it is searched like any other, and under the scanner sandbox it is a directory
tools run from, so a file the repository commits there can run as a tool.

uv is looked for in the other order. ASH runs the uv installed with it, from its
own environment: beside the interpreter, in its scripts directory, or where a
`pip install --prefix`, `--user` or `--target` put the `uv` package. Only when
there is none there does it look for uv on `PATH` and in the directories above.

A scan finds what `--bin-path` installed somewhere else only when `ASH_BIN_PATH`
names that directory for the scan too. Nothing is remembered between runs, so
`ash dependencies install` ends by printing the line that sets it, in absolute
form, for POSIX shells and for PowerShell:

```text
  export ASH_BIN_PATH=/home/me/tools/ash-bin    (POSIX shells)
  $env:ASH_BIN_PATH = '/home/me/tools/ash-bin'    (PowerShell)
```

It prints nothing when a scan in the same environment looks there anyway: the
directory is the (absolute) `ASH_BIN_PATH`, or `~/.ash/bin` with `ASH_BIN_PATH`
unset.

### Python packages

Some plugins need Python packages in ASH's own environment: cdk-nag needs
`aws-cdk-lib`, `cdk-nag` and `constructs`, and the ferret-scan community plugin
needs `ferret-scan`. `ash dependencies install` adds them with the installer that
owns that environment:

- In an environment `uv tool install` created, it runs
  `uv pip install --no-config --python <ASH's interpreter>`. A later
  `uv tool upgrade` or `uv tool install --force` rebuilds that environment without
  them: run `ash dependencies install --tool cdk-nag` again after either one, or
  add `--with` for each package to the `uv tool install` command you install ASH
  with.
- In an environment where pip is importable (pip, pipx, `python -m venv`), it runs
  `<ASH's interpreter> -m pip install`.
- Anywhere else, including `uvx` and a `uv venv` without pip, it runs
  `uv pip install --no-config --python <ASH's interpreter>`. uvx builds a new
  environment when its cache entry is gone or ASH changes; add `--with` for each
  package to the uvx command to keep them.

With neither pip nor uv available, the plugin's row is FAILED and the message says
what to install.

### uv settings

Every uv subcommand except `uv tool` reads `uv.toml` and `pyproject.toml`'s
`[tool.uv]` from the working directory and its parents (`uv pip`, `uv venv`,
`uv python`, `uv run` and the rest). The ones ASH runs itself are `uv pip install`
(above), the dry run that checks a tool found on `PATH`, and `uv cache dir`
(below). It runs the first two with `--no-config`, because the working directory
is usually the repository being scanned and its configuration must not choose what
ASH installs.

An install command a plugin declares gets `UV_NO_CONFIG=1` when it runs uv (as
`uv`, `uv.exe`, `uv.bat`, `uv.cmd`, or `python -m uv` however Python's options
are spelled: `-Im uv`, `-muv` and `-m uv.__main__` count), unless it is a
`uv tool` command or `uvx`. That keeps uv from reading configuration files, and nothing
more: such a command still runs in the working directory, where uv finds the
project and its `.venv` (a `uv pip` command can use a Python interpreter the
repository put there, and `uv run` or `uv sync` creates `.venv` and `uv.lock`
in it). In a plugin, declare `python -I -m uv` rather than `python -m uv`: `-m`
puts the working directory first on `sys.path`, so a declared `python -m uv` run
from the repository runs a `uv.py` the repository carries, and `-I` leaves the
working directory off. `-I` also skips user site-packages, so where uv is
installed only there (`pip install --user uv`), declare `python -P -m uv` instead
(Python 3.11+): `-P` leaves the working directory off and keeps the user site.

For the commands with `--no-config` or `UV_NO_CONFIG=1`, your own and the system
`uv.toml` are not read either; `UV_*` environment variables still apply
(`UV_INDEX_URL`, `UV_EXTRA_INDEX_URL`, `UV_OFFLINE` and the rest), and so does a
file named by `UV_CONFIG_FILE`, which uv reads even with `--no-config`:

```bash
UV_CONFIG_FILE=~/.config/uv/uv.toml ash dependencies install --tool cdk-nag
```

The `uv tool install`, `uv tool run` and `uv tool list` commands ASH runs for
bandit, checkov, semgrep and nbconvert get no flag. uv ignores project files for
`uv tool` commands, so the scanned repository cannot configure them, and they
read your user `uv.toml` (`~/.config/uv/uv.toml`, `%APPDATA%\uv\uv.toml` on
Windows) and the system one (`/etc/uv/uv.toml`), where an index mirror is usually
set. A `cache-dir` there moves their cache. ASH runs `uv cache dir` from the
filesystem root (`/`, or the system drive's root on Windows), where only an
administrator can put a `uv.toml`, and without `UV_PROJECT` or `UV_WORKING_DIR`,
which would send uv to read a `uv.toml` elsewhere. So it names that same cache
and never one that a scanned repository's `uv.toml`, or one in a shared temporary
directory, chose. Give `cache-dir` and `UV_CACHE_DIR` as absolute paths: uv
resolves a relative one against each command's own working directory, so the
cache `uv cache dir` names from `/` is not the one the tools used.

## Inspect Command

The `inspect` command allows you to analyze ASH outputs and reports.

```bash
ash inspect [subcommand] [options]
```

### Inspect Subcommands

| Subcommand     | Description                                    |
|----------------|------------------------------------------------|
| `sarif-fields` | Analyze SARIF fields across different scanners |
| `findings`     | Interactive TUI to explore findings            |

### Inspect Options

| Option            | Description                       | Default           | Environment Variable |
|-------------------|-----------------------------------|-------------------|----------------------|
| `--output-dir`    | Directory containing scan results | `.ash/ash_output` | `ASH_OUTPUT_DIR`     |
| `--config`, `-c`  | Path to configuration file        | Discovered        | `ASH_CONFIG`         |
| `--debug`, `-d`   | Enable debug logging              | `False`           | `ASH_DEBUG`          |
| `--verbose`, `-v` | Enable verbose logging            | `False`           | `ASH_VERBOSE`        |
| `--no-color`      | Disable colored output            | `False`           |                       |

### Examples

```bash
# Analyze SARIF fields
ash inspect sarif-fields

# Explore findings interactively
ash inspect findings
```

## Build-Image Command

The `build-image` command builds the ASH container image and then, unless
`--no-run` is given, scans the current directory with it.

```bash
ash build-image [options]
```

It takes only the options below; any other argument is a
[usage error](#usage-errors). To scan with scan options, such as `--scanners` or
`--min-severity`, use `ash scan --mode container`, which builds the image the same
way and accepts every scan option.

### Build-Image Options

| Option                       | Description                                | Default    | Environment Variable |
|------------------------------|--------------------------------------------|------------|----------------------|
| `--build-target`             | Container build target: `non-root` or `ci` (runs as root). CI environment variables do not change it | `non-root` (`ci` on Windows) |                      |
| `--offline`                  | Build for offline use                      | `False`    |                      |
| `--offline-semgrep-rulesets` | Semgrep rulesets for offline mode          | `p/ci`     |                      |
| `--oci-runner`, `-o`         | OCI runner to use. Unset by default; ASH uses the first of `finch`, `docker`, `nerdctl`, `podman` found on `PATH`                          | first found   | `OCI_RUNNER`         |
| `--debug`, `-d`              | Enable debug logging                       | `False`    | `ASH_DEBUG`          |
| `--verbose`, `-v`            | Enable verbose logging                     | `False`    | `ASH_VERBOSE`        |
| `--no-color`                 | Disable colored output                     | `False`    |                       |

### Examples

```bash
# Build the default image
ash build-image

# Build for CI environments
ash build-image --build-target ci

# Build for offline use
ash build-image --offline --offline-semgrep-rulesets p/ci

# Build using a specific OCI runner
ash build-image --oci-runner podman
```

## Get-GenAI-Guide Command

The `get-genai-guide` command writes the ASH GenAI Integration Guide to a file. The guide tells AI assistants and LLMs how to work with ASH scan results.

```bash
ash get-genai-guide [options]
```

The guide ships with ASH, so the command writes the copy that belongs to the
installed version and needs no network access. Every installation carries one: a
wheel or sdist, an install from a git URL, a clone of the repository (where the
command writes `docs/content/docs/genai-steering-guide.md`), and the container
images that `ash build-image`, `ash scan --mode container`, `./ash` and `Invoke-ASH`
build. A package built from a source tree without `docs/` has none, and there the
command exits 1 and names `--from-github`. `--from-github` downloads the guide from
GitHub instead: the `main` branch's, or that of the branch or release tag `--branch`
names.

### Purpose

This guide provides AI assistants with:
- Instructions on using correct output formats (JSON vs HTML)
- Proper suppression creation with correct YAML syntax
- Working with CycloneDX SBOM for dependency analysis
- Configuration file schema and structure
- Common pitfalls and known issues
- Integration patterns and examples
- Pre-tested jq queries for efficient result querying

### Get-GenAI-Guide Options

| Option            | Description                                | Default              |
|-------------------|--------------------------------------------|----------------------|
| `--output`, `-o`  | Output path for the GenAI integration guide | `ash-genai-guide.md` |
| `--from-github`   | Download the guide from GitHub instead of writing the installed copy | off |
| `--branch`, `-b`  | Branch or tag to download from with `--from-github` | `main` |

### Examples

```bash
# Write to the default location (ash-genai-guide.md)
ash get-genai-guide

# Write to another location
ash get-genai-guide -o /path/to/guide.md

# Write to the current directory under another name
ash get-genai-guide --output genai-integration.md
```

### Installation for AI Coding Tools

**For Kiro (Global - Recommended)**:
```bash
# Install globally for all Kiro workspaces
mkdir -p ~/.kiro/steering
ash get-genai-guide -o ~/.kiro/steering/ash-integration.md

# Kiro will automatically load this as steering context
```

**For Kiro (Project-Specific)**:
```bash
# Install for current project only
mkdir -p .kiro/steering
ash get-genai-guide -o .kiro/steering/ash-integration.md
```

**For Cline (VS Code)**:
```bash
# Add to project root for Cline to reference
ash get-genai-guide -o .cline/ash-guide.md

# Or add to VS Code workspace settings
mkdir -p .vscode
ash get-genai-guide -o .vscode/ash-integration-guide.md
```

**For Claude Desktop / MCP Clients**:
```bash
# Save to a dedicated documentation folder
mkdir -p ~/Documents/ai-guides
ash get-genai-guide -o ~/Documents/ai-guides/ash-integration.md

# Then reference in your prompts:
# "Please read the ASH integration guide at ~/Documents/ai-guides/ash-integration.md"
```

**For Amazon Q CLI**:
```bash
# Add to project documentation
mkdir -p docs/ai-guides
ash get-genai-guide -o docs/ai-guides/ash-integration.md

# Reference in .q/config if supported
```

**For Cursor**:
```bash
# Add to .cursorrules or project docs
ash get-genai-guide -o .cursor/ash-guide.md

# Or add to project root
ash get-genai-guide -o ASH_INTEGRATION_GUIDE.md
```

### Use Cases

**For Users:**
- Download and provide to AI assistants as context
- Share with team members using AI coding tools
- Include in documentation for AI-assisted workflows

**For AI Assistants:**
- Learn correct ASH result processing patterns
- Avoid common mistakes (parsing HTML, incorrect suppressions)
- Use efficient queries and proper data formats
- Understand ASH configuration and suppression syntax

### Guide Contents

The guide includes:
- Quick reference for key files and locations
- Critical rules for GenAI tools
- File structure and output directory layout
- Working with `ash_aggregated_results.json`
- Working with CycloneDX SBOM
- Configuration file schema
- Creating suppressions properly
- Common pitfalls and solutions
- Integration patterns (CI/CD, analysis, reporting)
- MCP server integration guidelines
- Scanner-specific notes
- Performance optimization tips
- Troubleshooting guide

For more information, see the [GenAI Integration Guide](genai-steering-guide.md) documentation.

## MCP Command

The `mcp` command starts the Model Context Protocol (MCP) server, which enables AI assistants to interact with ASH programmatically.

```bash
ash mcp
```

### Purpose

The MCP server provides a standardized interface for AI assistants to:
- Run security scans programmatically
- Retrieve scan results with filtering options
- Monitor scan progress in real-time
- Manage multiple concurrent scans
- Access scan result files and paths

A scan started through the MCP server never runs a tool from inside the scanned or
delivered directory: `ASH_ALLOW_IN_TREE_TOOLS` and `--allow-in-tree-tools` are not
honored by `ash mcp`. See
[Tools inside the scanned directory](advanced-usage.md#tools-inside-the-scanned-directory).

### MCP Server Features

- **Real-time Progress Tracking**: Monitor scan progress with streaming updates
- **Background Scanning**: Start scans and continue other work while they run
- **Multiple Scan Management**: Handle concurrent scans with unique identifiers
- **Comprehensive Error Handling**: Detailed error messages and recovery suggestions
- **Configuration Support**: Full support for ASH configuration files and environment variables
- **Result Filtering**: Filter results by severity, scanner, or response size

### MCP Options

| Option                                      | Description                                                                        | Default                |
|---------------------------------------------|------------------------------------------------------------------------------------|------------------------|
| `--transport`                               | Transport to serve on: `stdio`, `streamable-http`, or `sse`                         | `stdio`                |
| `--host`                                    | Host to bind for HTTP transports                                                    | `127.0.0.1`            |
| `--port`                                    | Port to bind for HTTP transports                                                    | `8000`                 |
| `--mount-path`                              | HTTP path the transport listens on. With `--transport sse`, an unchanged default becomes `/sse` | `/mcp`     |
| `--auth-header-name`                        | Required HTTP header name for single-tenant auth. Must be set with `--auth-header-value` | None              |
| `--auth-header-value`                       | Expected value of `--auth-header-name`                                              | None                   |
| `--stateless-http` / `--no-stateless-http`  | Handle each streamable-HTTP request independently instead of binding it to a server-held session | `--no-stateless-http` |
| `--trust-upstream-session-id`               | Stateless streamable-HTTP only: a platform in front of ASH issues and authenticates `Mcp-Session-Id`, so the header names the caller's session | `False` |
| `--allowed-host`                            | Host header value to accept. Repeatable. Required with a non-loopback `--host` unless `--trust-upstream-host-check` is given | None |
| `--session-workspace-ttl`                   | Seconds a session workspace may go unused before it is removed. HTTP transports only | `86400` |
| `--trust-upstream-host-check`               | A proxy or platform in front of ASH checks Host and Origin, so ASH checks neither. HTTP transports only; not with `--allowed-host` | `False` |
| `--profile`                                 | Register a config profile as `NAME=path/to/ash.yaml`. Repeatable. Each file is loaded and validated at startup, and one that fails stops the server with exit 3. See [Config profiles](mcp/streamable-http.md#config-profiles) | None |
| `--log-level`                               | Set the log level                                                                   | `INFO`                 |
| `--verbose` / `--no-verbose`, `-v`          | Enable verbose logging                                                              | `--no-verbose`         |
| `--debug` / `--no-debug`, `-d`              | Enable debug logging                                                                | `--no-debug`           |
| `--quiet` / `--no-quiet`                    | Hide all log output                                                                 | `--no-quiet`           |
| `--color` / `--no-color`                    | Enable/disable colorized output                                                     | `--color`              |

Setting `--auth-header-name` without `--auth-header-value`, or the reverse, is rejected: partial auth configuration would look configured and enforce nothing.

`--profile` is the only way a profile is registered. Clients see the names with the `list_profiles` tool and bind one to their session with `select_profile`; a bound profile supplies the config for every later call in that session that names none. A profile file that does not load, has an unknown top-level key, or repeats a name stops the server from starting, with exit code 3. See [Config profiles](mcp/streamable-http.md#config-profiles).

Everything this command writes goes to stderr. On the `stdio` transport stdout is the JSON-RPC channel, so one human-readable line there makes the client fail to parse the stream.

### Session Handling and Host Allowlisting

`--stateless-http` makes the server handle each request on its own instead of binding it to a session the server is holding. Two situations require it: a load balancer that may route consecutive requests from one client to different replicas, where the next request reaches a replica that never saw the session; and managed runtimes that inject their own `Mcp-Session-Id`, which a stateful server refuses as a session it did not issue. The difference is observable — given a session id the server never issued, a stateful server answers `404` and a stateless one answers `200`.

A stateless server issues no session, so by default its callers have no session identity: the `Mcp-Session-Id` they send is client-chosen and is ignored, and the tools that need a session (source delivery, `select_profile`, the scan registry tools) refuse with `error_type: session_identity_required`. Pass `--trust-upstream-session-id` when a platform in front of ASH issues and authenticates that header, as Bedrock AgentCore Runtime does; the header then names the caller's session. See [Session identity](mcp/streamable-http.md#session-identity).

The flag is only valid with `--transport streamable-http`, and passing it on another transport is refused rather than ignored. `stdio` has a single implicit session and `sse` holds an open connection per client, so neither has a session to make stateless; silently dropping the flag would leave you running a stateful server and finding out only when a request landed on the wrong replica in production. `--no-stateless-http` is indistinguishable from the default, so it is accepted on every transport.

`--allowed-host` is repeatable and names the Host header values the server will accept. The MCP SDK enables DNS-rebinding protection automatically when the bind address is `127.0.0.1`, `localhost` or `::1`; bind anywhere else and that autodetect leaves protection off, so the server would answer any Host and any Origin. ASH refuses that: a non-loopback `--host` without `--allowed-host` exits 5, a [usage error](#usage-errors), with an error naming `--allowed-host` and `--trust-upstream-host-check`. `--allowed-host` keeps protection on for a non-loopback bind, because supplying it replaces the SDK's autodetect with an explicit allowlist. That is the right posture behind a proxy whose hostname you know:

```bash
ash mcp --transport streamable-http --host 0.0.0.0 --port 8000 \
  --stateless-http \
  --allowed-host ash-mcp.internal.example.com
```

On a loopback bind without `--allowed-host`, ASH accepts only the server's own origin: Host `127.0.0.1`, `localhost` or `[::1]` with the `--port` it is bound to, and those as `http://` origins. The SDK's own check would accept them on any port. On `--port 80` the names are accepted without the port as well, as clients write them. `--port 0` lets the system choose: ASH binds first and accepts the port it got, which the startup message prints.

The `Origin` allowlist is left empty rather than mirroring the host list. `Origin` is a browser-supplied header, and an MCP server reached through a proxy has no reason to trust one.

`--trust-upstream-host-check` is the explicit alternative when a proxy or platform in front of ASH checks Host and Origin and cannot give ASH a fixed list of names, as on Bedrock AgentCore Runtime. With it ASH checks neither header. It is refused together with `--allowed-host`, which says the opposite, and on stdio.

### Usage

The MCP server is typically configured in AI assistant clients (Amazon Q CLI, Claude Desktop, Cline) rather than run directly. See the [MCP Server Guide](mcp-server-guide.md) for detailed setup instructions.

### Configuration Example

For Amazon Q CLI (`~/.aws/amazonq/mcp.json`):
```json
{
  "mcpServers": {
    "ash": {
      "command": "uvx",
      "args": [
        "--from=git+https://github.com/awslabs/automated-security-helper@v3.7.0",
        "ash",
        "mcp"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

For more information, see:
- [MCP Server Guide](mcp-server-guide.md)
- [MCP Tools Reference](MCP-TOOLS-REFERENCE.md)
- [MCP Filtering Guide](MCP-FILTERING-GUIDE.md)
- [Using ASH with MCP Tutorial](../tutorials/using-ash-with-mcp.md)

## Additional Environment Variables

ASH supports additional environment variables that don't directly map to command-line parameters:

| Variable              | Description                                                          | Default                                      |
|-----------------------|----------------------------------------------------------------------|----------------------------------------------|
| `ASH_IMAGE_NAME`      | Name of the ASH container image                                      | `automated-security-helper:<build-target>`    |
| `OCI_RUNNER`          | OCI runner to use instead of auto-detection                          | first of `finch`, `docker`, `nerdctl`, `podman` on `PATH` |
| `OCI_RUNNER_WRAPPER`  | Command prefix to wrap the OCI runner invocation                     |                                              |
| `ASH_OFFLINE`         | Run in offline mode                                                  |                                              |
| `ASH_DEBUG`           | Enable debug logging                                                 |                                              |
| `ASH_DEBUG_SHOW_LOCALS` | Show each frame's local variables in a traceback. They can include secrets; see below | unset |
| `ASH_VERBOSE`         | Enable verbose logging                                               |                                              |
| `ASH_BASE_IMAGE_OVERRIDE` | Registry to fetch the Dockerfile's base image from                   | unset (the Dockerfile's own `ARG BASE_IMAGE`) |
| `ASH_BASE_OCI_LAYOUT` | Verified OCI layout to build the base image from, with no registry call | unset |
| `ASH_ALLOW_IN_TREE_TOOLS` | Let ASH start tools found inside the scanned directory, as `--allow-in-tree-tools` does: `1`, `true`, `yes` or `on`. Ignored by `ash mcp` | unset |

### `ASH_DEBUG_SHOW_LOCALS`

Set to `YES`, `1` or `TRUE`, a traceback in the console log, and the one printed for an
uncaught error, lists each frame's local variables. It is for debugging on your own
machine. Those variables can include secrets from the config and from the environment,
so never set it in CI or anywhere the output is shared. On a CI runner ASH ignores it:
when `GITHUB_ACTIONS`, `TF_BUILD`, `AZURE_PIPELINES`, `TEAMCITY_VERSION`, `JENKINS_URL`,
`CODEBUILD_BUILD_ID`, `GITLAB_CI`, `BUILDKITE`, `CIRCLECI`, `TRAVIS`, `APPVEYOR`,
`BITBUCKET_BUILD_NUMBER` or `bamboo_buildKey` is set, to any value, an empty one
included, or `CI` is set to anything but `0` or
`false` (`true`, `1`, ...), no locals are shown, and the scan logs one warning saying
the variable was ignored. A developer whose shell exports `CI=1` gets no locals either.

### `ASH_BASE_IMAGE_OVERRIDE`

When set, this replaces the Dockerfile's `ARG BASE_IMAGE` default for the duration of the
build, as `--build-arg BASE_IMAGE=<value>`. Every build entrypoint honours it: the Python CLI
(`ash build-image` and `ash scan --mode container`), the `./ash` shell entrypoint, and
`Invoke-ASH` in `utils/ash_helpers.ps1`.

It exists for one reason. ECR Public meters anonymous pulls by monthly data volume as well as
by rate, and a CI runner drawing from a shared egress pool can find that volume already spent
by someone else. ASH's CI pre-pulls the base image and, when ECR Public refuses, sources it
from Docker Hub instead, then sets this variable to the Docker Hub reference so the build asks
the registry that actually answered. Tagging the fallback image locally under the ECR name is
not sufficient: `nerdctl`, `finch`, and `docker buildx` on a `docker-container` driver all
resolve `FROM` against the registry and never consult the local image store.

Set it yourself if you mirror the base image into a registry of your own. A digest-suffixed
reference is accepted and recommended:

```bash
export ASH_BASE_IMAGE_OVERRIDE="my-registry.example.com/python@sha256:<digest>"
ash build-image
```

An explicit `--custom-build-arg BASE_IMAGE=...` takes precedence over this variable.

### `ASH_BASE_OCI_LAYOUT`

`<layout dir>@sha256:<manifest digest>`: an OCI image layout holding the Dockerfile's base
image, and the digest of the manifest for this machine's architecture inside it. ASH's CI sets
it after restoring the base image from the Actions cache and verifying every blob against the
Dockerfile's `ARG BASE_IMAGE_DIGEST`, so that a warm CI run makes no registry call for the base
image at all. You do not normally set it yourself.

What each entrypoint does with it depends on the builder:

| Builder | What ASH passes |
|---|---|
| `docker buildx build` (docker-container builder) | `--build-context ash-base-image=oci-layout://<dir>@<digest>` and `--build-arg BASE_IMAGE=ash-base-image` |
| `nerdctl`, `finch` | `--build-context ash-base-image=oci-layout://<dir>`, `--build-arg BASE_IMAGE=ash-base-image` and `--pull=false` |
| plain `docker build`, `podman` | nothing: these read the base image from their local image store, where the CI step placed it |

A value that is not `<dir>@sha256:<64 hex>` stops the build with an error rather than being
ignored. When it applies, it takes the place of `ASH_BASE_IMAGE_OVERRIDE`; an explicit
`--custom-build-arg BASE_IMAGE=...` still takes precedence over both.

## Exit Codes

Every `ash` command exits with one of these codes. `--help` exits 0, as does
`--version` on `ash` and `ash scan`.

| Code | Meaning | Returned by |
|------|---------|-------------|
| 0    | Success. For a scan or a merge: no actionable findings at or above the threshold | every command |
| 1    | The command failed, or the scan is incomplete: a selected scanner is `ERROR` or `MISSING`, a rule could not be evaluated, a content database is stale, or a merge was refused. Also a scan run on the host (local, precommit or nix mode) of a directory whose path is not UTF-8, refused before it writes anything | every command (any unexpected error exits 1) |
| 2    | Actionable findings at or above the threshold | `ash`, `ash scan`, `ash merge`, `ash build-image` |
| 3    | Invalid configuration or refused input, including, for the `ash config` commands, a named config file that does not exist or cannot be read, and a configured `ash_plugin_modules` entry that fails to import (or, for the checks, one no installed package provides). Also, in container mode, a directory to scan or an output directory whose path holds a comma, a double quote or a line break, or is not UTF-8, refused before any container runtime call (`--no-run`, which mounts nothing, is not refused); `./ash` refuses such a path with 3 too | `ash`, `ash scan`, `ash build-image`, `ash report`, `ash merge`, `ash dependencies install`, `ash plugin list`, `ash config validate`, `lint`, `get`, `update` and `validate-plugin-dependencies`, `ash mcp` |
| 4    | Workspace definition or policy error; nothing was scanned | `ash` and `ash scan` in workspace mode, or given a workspace-only option without `--workspace` |
| 5    | Usage error: the command line was refused and nothing ran, including a `--source-dir` that does not exist, is not a directory or cannot be entered, and an `--output-dir` that is a file, cannot be created, cannot be entered or cannot be written (see [Usage errors](#usage-errors)) | every command, `./ash` and `Invoke-ASH` |
| 130  | Stopped with Ctrl-C | every command, at any point: while the CLI loads, while the command runs, and while it reports an unexpected error |

Code 4 is distinct from code 2 on purpose. Code 2 means a scan ran and found
issues; code 4 means the workspace definition could not be used and no project
was scanned at all.

### Container and nix mode

In container and nix mode ASH runs a second ASH, the inner run, and computes the
exit code from the results it writes. It reads those results back only when the
inner run recorded that it completed, with the ID the outer process gave it
(`ASH_OUTER_RUN_ID`). Otherwise the exit code is `1`, whatever the inner run's own
status was, and the error says the inner run did not complete and names the
results file. A container image built from an ASH older than the one running the
scan records no completion, so a `--no-build` run of such an image, or an image
built with `--ash-revision-to-install` naming an older release, exits `1` this way;
rebuild the image from this ASH. When the inner run refused its reports, the exit
code is `1` with the inner run's own message. A container status that is not a
verdict (`3`, `4`, or the runner's own, such as `125` or `137`) is returned as is,
without reading any results back.

`ash mcp` also exits 2 when the server stops on a scanner error, and `ash dependencies install` for a `--tool` it cannot select or a `--plugin-type` that is none of the three. In container mode
(and with `ash build-image`), a status the container runtime reports, such as 125
for a container that could not start or 137 for one that was killed, is passed
through unchanged.

A scan stopped with Ctrl-C exits 130 in every mode: local, container and Nix. It
prints that it was interrupted, and no completion line, results table or verdict. In
container and Nix mode the interrupt is passed on to the container runtime or the
Nix shell, which has 5 seconds to stop before it is killed. A second Ctrl-C during
those 5 seconds kills it at once. On Windows the console passes a Ctrl-C to the
runtime as well, since the two share it; when ASH is attached to no console, it ends
the runtime at once instead. `ash build-image` stopped with Ctrl-C also exits 130 and
says it was interrupted. Every other command stopped with Ctrl-C while it runs exits
130 too. Stopped while the CLI loads, before the command runs, or while it reports
an unexpected error, any command exits 130 as well and prints nothing more: neither
the error nor a traceback of the interrupt. A shell
script that runs `ash` in a loop sees 130 as an exit status, not as an interrupt,
and goes on to the next iteration unless it checks for it, for example with
`ash scan ... || [ $? -ne 130 ] || break`.

The `./ash` wrapper script in the repository exits 3 when it refuses its own
arguments or environment, before it builds or runs anything: no container runner
found or an `OCI_RUNNER` of only whitespace, an option given without a value or with
an empty or blank one, a `--source-dir` or `--output-dir` whose path holds a newline, a carriage
return, a comma or a double quote (a runtime reads `--mount` as CSV, so it cannot
take any of them; a relative `--output-dir` counts the working directory's path,
and is refused before it is created) or bytes that are not UTF-8, an
`ASH_IMAGE_NAME` that
starts with `-` or holds a character other than A-Z, a-z, 0-9 and `. _ : / @ -`, a
`--build-target` that starts with `-` or holds one other than A-Z, a-z, 0-9 and
`. _ -`, a `--workspace` or `--workspace-config` (the wrapper scans one directory, so
run `ash --mode container --workspace <file>` instead), when it builds the image,
an `ASH_BASE_IMAGE_OVERRIDE` held to the same characters as an image name or a
malformed `ASH_BASE_OCI_LAYOUT`, or, with `OCI_RUNNER_WRAPPER` set, a
`GITHUB_ACTIONS`, `TF_BUILD` or `TEAMCITY_VERSION` that holds a newline. A registry named by a bracketed IPv6 literal, such as
`[::1]:5000`, is refused as well, since `[` and `]` are not among the image-name
characters; name the registry by a host name instead. Those characters are the same in every locale, and
`Invoke-ASH` holds an image name and `ASH_BASE_IMAGE_OVERRIDE` to them as well, with the
same message; it reads `ASH_BASE_IMAGE_OVERRIDE` when it starts, even with `-NoBuild`.
`ash scan --mode container` holds `ASH_IMAGE_NAME` to them too, with the same message
and exit 3, before it builds or runs anything; an empty one names the default image.
When it builds, it holds `ASH_BASE_IMAGE_OVERRIDE` to them as well, with the wrappers'
message and exit 3, before the build starts: a value of only whitespace is refused,
and only an empty one is unset. Both refusals write a tab, a newline or a carriage
return in the value as `\x09`, `\x0a` or `\x0d`, so each stays on one line.
With `--no-run`, which only builds the image, the two directories are neither checked
nor created and the runner variables are not read, so those refusals do not apply. The
exceptions to exit 3 are the usage errors `ash` itself refuses with 5, refused with 5
and the text `ash scan` gives: an explicit `--sandbox` other than `off`, as
`ash scan --mode container --sandbox` refuses it, even next to a `--workspace`,
whichever comes first; a `--source-dir` that does not exist, is not a directory, or
cannot be entered; and an `--output-dir` that is a file, cannot be created, or
cannot be entered or written. A command line
that reaches `ash` inside the container is refused there with 5, as above. The other
two wrappers follow the same rule: `utils/ash_helpers.sh` returns 3 when it cannot
find the checkout, and `Invoke-ASH` in `utils/ash_helpers.ps1` sets `$LASTEXITCODE`
to 3 and throws for each refusal its help lists, or to 5 for the same usage errors.
PowerShell's own errors in reading Invoke-ASH's parameters, such as a parameter given
no value, are not Invoke-ASH refusals; its help gives the catch form that turns them
into exit 1.

### Usage errors

ASH exits 5 when something on the command line is wrong. It refuses before any scanner
runs, and writes no report. Exactly these exit 5:

- An unknown command or option, or an argument the command does not take, for any
  command. `ash scan --fail-on-finding` (for `--fail-on-findings`) is refused rather
  than run without the gate it names.
- An option given to `ash` before a subcommand that does not take it, as in
  `ash --source-dir src report`. An option the subcommand does take is passed to it,
  as though written right after the subcommand name, so `ash --output-dir out report`
  reads `out`. An option set through its environment variable, such as
  `ASH_SOURCE_DIR`, is not affected.
- A missing required option, such as `ash merge` without `--output-dir` or
  `--results`.
- A value an option does not accept: a value outside its choices (`--mode`,
  `--strategy`, `--output-formats`, `--build-target`, `--min-severity`,
  `ash mcp --transport`), or a
  number that is not one (`--shard-index first`).
- A name ASH does not know: a `--scanners` list that names no registered scanner,
  in a single scan or a workspace scan; an `ash report --format` that no reporter
  answers to, whether or not there are results to report. Two selections exit 2
  instead: an `ash dependencies install` `--tool` name that it has no plugin for,
  or whose plugin type `--plugin-type` leaves out, and a `--plugin-type` that is
  none of `converter`, `scanner` and `reporter`.
- Options that cannot be combined: `--shard-index` without `--shard-count` or the
  reverse, a `--shard-index` outside `0` to `--shard-count` minus one, either with
  `--workspace`, a `--scanners` list that `--exclude-scanners` cancels out, and
  `ash mcp`'s `--stateless-http` without `--transport streamable-http`,
  `--auth-header-name` without `--auth-header-value` or the reverse, `--quiet`
  with `--verbose` or `--debug`, a non-loopback `--host` with neither
  `--allowed-host` nor `--trust-upstream-host-check`, `--allowed-host` together
  with `--trust-upstream-host-check`, and `--trust-upstream-host-check` on a
  loopback `--host` or on `--transport stdio`.
- A path that names nothing usable: a `--source-dir` (or `ASH_SOURCE_DIR`) that does
  not exist, is not a directory, or cannot be entered, for `ash scan` and the
  `ash config` commands that take it; an `ash scan --output-dir` that is a file,
  cannot be created, or is there but cannot be entered or written; an
  `ash merge --results` that does not exist or is neither a file nor a directory; and
  a `--cli-json-input` file that cannot be read, along with a document in it that ASH
  cannot use. A missing `--output-dir` is not refused: it is created.

  The directory refusals read the same from `ash`, `./ash`, `Invoke-ASH` and the MCP
  server's scan tools, which name the case and the path as given, and no option:
  `Source directory does not exist: <path>`, `Source directory is not a directory:
  <path>`, `Source directory cannot be entered: <path>`, `Output directory is not
  a directory: <path>`, `Output directory cannot be entered: <path>`,
  `Output directory cannot be created: <path> (<reason>)` and `Output directory
  cannot be written: <path> (<reason>)`, whose reason is the system's own text for
  the error, such as `Not a directory` for a file on the way to it, `Permission
  denied` or `Read-only file system`. Whether an output directory that is there can
  be written is found by making a file in it, under a name of its own, and deleting
  it, before anything else is written there; the permission bits alone miss ACLs and
  read-only mounts. The wrappers put `ERROR: ` before them. A source directory
  cannot be entered when its entries cannot be both listed and opened (it lacks
  read or search permission), and also when it is under a directory that cannot be
  searched, whether or not it is there: the system denies such a path, which is not
  the same as not finding it.

These are not usage errors, because the command line is right and what it asks for
is not there yet, or the problem is the machine's. They exit 1: `--use-existing`
when the output directory holds no results, `ash report` when it holds none, an
`ash merge --results` directory holding no results file or more than one, and
`--mode nix` on a machine without Nix. So do `ash config validate`, `lint`, `update`
and `validate-plugin-dependencies` given no `--config` in a directory with no config
file.

A config path that names no readable file is not a usage error either: it names the
configuration to use, and that configuration cannot be used. `ash config validate`,
`lint`, `get`, `update` and `validate-plugin-dependencies` exit 3 for a `--config`,
an `ASH_CONFIG` or a path argument that does not exist, is a directory, or cannot be
read, as they do for a file a scan refuses. So do `ash scan` and `ash report` for an
`ASH_CONFIG` or a `--config` that does not exist, and `ash config validate`, `lint`
and `get` checking another file while `ASH_CONFIG` names a file that does not
exist, since a scan with that environment refuses it. An empty `ASH_CONFIG` counts
as unset; one of only whitespace is refused.

Usage errors have a code of their own because click, the library ASH's command line
is built on, exits 2 for them, and 2 is ASH's code for actionable findings: a CI gate
would read a mistyped flag as a scan that found problems. Workspace-mode refusals
keep code 4, including `--dry-run` or `--workspace-config` without `--workspace` and
`--workspace` combined with `--source-dir`.

Container mode and `--mode nix` run a second ASH, inside the image or the Nix shell.
When that inner ASH exits 3, 4 or 5 before scanning, the outer `ash` exits with the
same code and names its meaning.

### An incomplete scan is not a clean scan

Zero findings has two causes and they are not the same answer: nothing was wrong,
or nothing was checked. The exit code used to be derived from finding counts
alone, so both produced 0. A machine without cfn-nag, grype and syft installed
reported those three as `MISSING` and exited 0, indistinguishable from a run where
all ten scanners ran clean.

ASH now exits 1 for that case and prints which scanners did not run:

```console
$ ash scan
ERROR    Scan incomplete: cfn-nag (MISSING), grype (MISSING), syft (MISSING)
```

Two statuses count as incomplete:

- `ERROR` — the scanner ran and failed: its tool exited with a code the scanner
  does not accept, its results could not be read, or its content database does
  not exist. Whatever results file the tool left is not graded.
- `MISSING` — the scanner's dependencies were unavailable, so it never ran.

`SKIPPED` does not. A skipped scanner is one you did not select, which is also
how sharding divides work between executors: each shard excludes the scanners its
siblings own, and those land as `SKIPPED`. Gating on `SKIPPED` would fail every
shard of a healthy sharded scan. A scanner with nothing to scan in the project is
`SKIPPED` as well, whether or not its tool is installed: cdk-nag and cfn-nag with no
CloudFormation template among the scanned files, npm-audit with no lockfile beside a
`package.json`. With files to scan and no tool, it is `MISSING`.

A run in which every scanner is `SKIPPED` still exits 1, because it scanned
nothing. A scanner with nothing of its kind to scan is `SKIPPED` too, so this is
also what happens when no selected scanner had a file to scan: a scan whose config
ignores every file, or `--scanners bandit` on a tree with no Python file. The
error says so:

```console
$ ash scan --scanners detect-secrets
ERROR    No selected scanner had a file to scan: detect-secrets was SKIPPED with nothing to scan, so this run has shown the target to be neither clean nor dirty. The config's global_settings.ignore_paths ('**') leaves every path it matches out of what the scanners read, which can leave them nothing to scan; narrow it to have those files scanned. To accept a run that scanned nothing, set fail_on_incomplete_scanners: false or pass --no-fail-on-incomplete-scanners.
```

The `ignore_paths` sentence appears only when the config sets `ignore_paths`. A run
whose scanners were all `SKIPPED` for another reason, such as `--scanners` naming
a scanner this platform does not support, reports `Scan ran no scanners` with the
list of scanners and their statuses.

`ash merge` reaches the same verdict over the union of its shards. With
`--no-fail-on-incomplete-scanners` such a run exits 0.

Converters count too. A notebook nbconvert could not convert (it exited non-zero,
timed out or wrote no output) and a `.zip`, `.tar` or `.gz` file that is not an
archive Python can read are recorded under `converter_results.<name>.failed_inputs`,
and the scan exits 1 naming the converter and the files:

```console
ERROR (1) Exiting because conversion was incomplete: 1 converter(s) did not process the files they were given
  jupyter: could not convert 1 input: notebooks/report.ipynb
```

Other errors are recorded too, as `<Type>: <message>`. A converter that crashed, and
one whose tool is missing while it had inputs, also make the scan incomplete. A `.gz`
that is one compressed file rather than a tarball, such as `data.json.gz`, is
decompressed and scanned, and is a failed input only when it cannot be decompressed.
`ash merge` combines every shard's failed inputs, and
workspace mode reports them per project in `incomplete_converters`. When a scanner is
incomplete as well, the message names the scanners only; the converter failures are
then in `ash.log` and in the results file.

Narrowing a run selects rather than fails. `--scanners bandit`,
`--exclude-scanners grype` and `--python-only` record the scanners you left out as
`SKIPPED`, so they do not trip the gate. That was not always true of `--scanners`: the scan phase used
to validate a scanner's dependencies before checking whether it had been selected,
so on a host without cfn-nag, grype and syft a `--scanners bandit` run reported
those three `MISSING` while the six left-out scanners whose tools were present
reported `SKIPPED` — the status depended on whether the tool happened to be
installed rather than on what you asked for.

A scanner that scanned no file is not `PASSED`. semgrep, opengrep and bandit record
how many files they scanned. When their exclusions left out every file there was to
scan (semgrep's and opengrep's `--exclude` patterns, or Python files bandit was not
told to exclude but did not scan), the scanner is `ERROR` and the message gives the
count; when there was nothing to scan, it is `SKIPPED`.

Two more things worth knowing:

- It takes precedence over `--fail-on-findings`. A run with both actionable
  findings and an incomplete scanner exits 1, not 2, because clearing the
  findings that were reported would not make the scan complete.
- It is independent of `--fail-on-findings` in the other direction too:
  `fail_on_findings: false` still reports an incomplete scan, since it says
  nothing about whether the scanners ran.

`--no-fail-on-incomplete-scanners` (config: `fail_on_incomplete_scanners: false`)
accepts a partial scan's exit code. Reach for it last. If a tool cannot be
installed on a platform, excluding its scanner is the better answer: the run then
records `SKIPPED` and the report says which scanners were not part of it, where
`false` returns to a 0 that carries no such information.

`ash merge` uses the same vocabulary over the union of a sharded run: `0` clean,
`1` the merge was refused so the union's findings are unknown, `2` findings at or
above the threshold, `5` a usage error. See [Merge Exit Codes](#merge-exit-codes). A shard's own exit
code is not the verdict for a sharded run — see [Sharding](#sharding).

Workspace mode applies the gate per project, so `ash --workspace` and
`ash --source-dir <one project>` agree about whether that project's scan happened.
A project that completed with a scanner at `ERROR` or `MISSING` is reported with
`scan_incomplete: true` and the scanner named in `incomplete_scanners`, and the run
exits `1`. A scanner at `ERROR` only because its content database is stale is named
in `stale_content_databases` instead, as a single scan's results name it. A project
whose conversion was incomplete (a converter that crashed, one
that could not convert some of its inputs, a converter tool that was absent with
inputs to convert, or an archive refused for an extraction limit) is reported the
same way, with the converter and the reason in `incomplete_converters`, exactly as
`ash --source-dir <project>` fails on it; the MCP workspace tools report the same
rows in each project's `incomplete_converters`.
`--no-fail-on-incomplete-scanners` applies per project as well, and it
clears only the verdict: `incomplete_scanners` and `incomplete_converters` still
name what did not run, because turning the gate off accepts the risk rather than
asserting the scan was complete. Each project's `inputs_not_scanned` names the
inputs its scanners found and did not scan (an offline npm-audit's lockfiles), with
workspace-relative paths, and the merged summaries and the console list them.

An incomplete project outranks findings, as in a single-project scan: a workspace
where project A is incomplete and project B has actionable findings exits `1`, not
`2`. B's findings are still in the results file (`exceeds_threshold` and the
counts) and in every summary, so a gate that has to block on findings whatever else
happened should read them there. Exit `4` is unaffected, because it means no
project was attempted at all.

### A scan against a stale database is not a clean scan

A vulnerability database only describes the advisories published before it was
built. Measured with grype 0.111.0 under ASH's offline settings, a database built
10 days earlier scanned with exit 0 and no warning. ASH now reads each content
database's own build time after its scanner runs and exits 1 when it is past the
declared bound (grype 120h, trivy 24h, the offline semgrep and opengrep rulesets
30 days). In an image built with `OFFLINE=YES`, a stale trivy database warns instead;
see [Failing on a stale content database](configuration-guide.md#failing-on-a-stale-content-database):

```console
$ ash scan --offline
ERROR    Content database grype-db (grype) is stale: built 2026-09-21T13:13:21Z,
         10d 0h old, past its 120h bound (grype's own bound); age read from `built`
         in `grype db status -o json`. The scan fails: ...
```

This does not depend on `--fail-on-incomplete-scanners`, and it takes precedence
over `--fail-on-findings` the same way. `--allow-stale-content-db` (config:
`content_db_staleness: warn`) lets the scan pass and records the warning in the
summary reports, the SARIF and `ash.flat.json` instead. Workspace mode applies it
per project, reporting the project `scan_incomplete: true`. See
[Failing on a stale content database](configuration-guide.md#failing-on-a-stale-content-database)
for the bounds, where each comes from, and how to refresh each database.
