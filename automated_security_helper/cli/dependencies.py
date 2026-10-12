# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CLI command for installing dependencies for ASH plugins."""

import logging
import os
import platform
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Dict, List, Optional, Sequence

import typer

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form.
from rich import print  # noqa: A004
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import (
    ASH_BIN_PATH,
    ASH_CONFIG_SOURCES_DESCRIPTION,
    ASH_WORK_DIR_NAME,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import (
    PluginModuleError,
    load_plugins,
)
from automated_security_helper.utils.download_utils import (
    pinned_install_already_satisfied,
)
from automated_security_helper.utils.log import get_logger
from automated_security_helper.utils.process_env import set_environ, snapshot_environ
from automated_security_helper.utils.python_child import (
    empty_directory,
    python_child,
    runs_module_or_code,
)
from automated_security_helper.utils.subprocess_utils import (
    clear_find_executable_cache,
    find_executable,
)

dependencies_app = typer.Typer(
    name="dependencies",
    help="Install dependencies for ASH plugins",
    pretty_exceptions_enable=True,
)

console = Console()
# Deprecation warnings go to stderr so a script that parses this command's stdout
# is not handed a line it has never seen.
err_console = Console(stderr=True)

# Exit codes. Distinct values so a caller can tell "you asked for a tool that does
# not exist" from "the install ran and something failed".
EXIT_OK = 0
EXIT_INSTALL_FAILED = 1
EXIT_BAD_SELECTION = 2
# The code every ASH command uses for a configuration that cannot be used.
EXIT_INVALID_CONFIG = 3

# Set to exactly `skip`, a `--tool` name that no plugin of this ASH has, of any type,
# is named and skipped rather than refused. ASH's own required check sets it, because
# it installs ASH from an older commit than the workflow that asks for the tools: a
# tool that ASH has no plugin for is not run by it either, so the scan needs nothing
# from that tool. Unset, the refusal stands, which is what catches a typo.
UNKNOWN_TOOLS_SETTING = "ASH_DEPENDENCIES_UNKNOWN_TOOLS"

# The plugin registry's kinds, which --plugin-type selects among.
PLUGIN_KINDS = ("converter", "scanner", "reporter")


def _plugin_kind(plugin_type: str) -> str:
    """The registry kind a --plugin-type value selects; anything else means scanner."""
    return plugin_type if plugin_type in ("converter", "reporter") else "scanner"


# `--tool` names that stopped working when this command began building each plugin
# from its own config section (#766), mapped to the config key that replaced them.
#
# Before #766 a plugin's selectable name was its default config's `name`, or its
# class name when the plugin was built without a config. The archive converter was
# the only bundled plugin in the second group, so it was selected as
# `ArchiveConverter`; it is now `archive`, like its config key. Every other bundled
# converter, scanner and reporter, including those in ash_aws_plugins and the
# community modules, kept its name: the two commits' `Available:` lists were
# compared for each plugin type with every bundled plugin module loaded.
#
# The old spelling keeps working so that scripts and docs written against it do not
# start exiting 2, and it warns so they can move to the new key.
DEPRECATED_TOOL_ALIASES: dict[str, str] = {
    "ArchiveConverter": "archive",
}


def _resolve_tool_aliases(tools: List[str]) -> dict[str, str]:
    """Map each requested `--tool` name to the plugin name to select it by.

    A deprecated alias maps to its replacement and prints one warning to stderr per
    alias, however many times it was passed. Every other name maps to itself, so an
    unknown name is still refused by the caller exactly as before.
    """
    resolved: dict[str, str] = {}
    for tool in tools:
        if tool in resolved:
            continue
        replacement = DEPRECATED_TOOL_ALIASES.get(tool)
        if replacement is None:
            resolved[tool] = tool
            continue
        err_console.print(
            f"[bold yellow]Deprecated:[/bold yellow] --tool {escape(tool)} is "
            f"deprecated; use --tool {escape(replacement)} instead.",
            highlight=False,
        )
        resolved[tool] = replacement
    return resolved


@dataclass
class PluginInstallOutcome:
    """What actually happened for one plugin, as counts rather than impressions.

    The reason this type exists at all: the previous implementation tracked a
    single `exit_code` and printed "All dependencies installed successfully!"
    whenever it stayed 0 -- which it did when every plugin returned an empty
    command list. Three of ASH's scanners were in exactly that state, so the
    installer's happiest output was also its report for having installed nothing.
    """

    name: str
    plugin_type: str
    command: Optional[str] = None
    commands_attempted: int = 0
    commands_succeeded: int = 0
    commands_failed: int = 0
    commands_skipped_empty: int = 0
    # Pinned installs not run because a byte-identical copy of the pinned binary was
    # already present; see download_utils.find_verified_pinned_executable.
    commands_satisfied: int = 0
    errors: List[str] = field(default_factory=list)
    executable: Optional[str] = None

    @property
    def declared_no_commands(self) -> bool:
        """No usable install command was declared for this platform/arch.

        Excludes plugins that raised while producing their commands. Those have an
        unknown install path rather than no install path, and reporting a crash as
        "no install path on this platform" is the wrong diagnosis in the one
        function whose whole purpose is to report accurately.
        """
        return (
            self.commands_attempted == 0
            and self.commands_satisfied == 0
            and not self.errors
        )

    @property
    def needs_external_tool(self) -> bool:
        """Whether this plugin runs an external executable at all.

        Python-only converters and reporters do not, so a sweep that demanded an
        executable for every plugin would report failures for plugins that were
        never going to have one.
        """
        return bool(self.command)

    @property
    def status(self) -> str:
        if self.errors or self.commands_failed:
            return "FAILED"
        if self.commands_succeeded:
            return "INSTALLED" if self.executable else "INSTALLED (not on PATH)"
        if self.commands_satisfied:
            return "VERIFIED PRESENT" if self.executable else "VERIFIED (not on PATH)"
        if not self.needs_external_tool:
            return "PYTHON-ONLY"
        if self.executable:
            return "ALREADY PRESENT"
        return "NO INSTALL PATH"


def get_platform() -> str:
    """Get the current platform name."""
    system = platform.system().lower()
    if system in ["linux", "darwin", "windows"]:
        return system
    else:
        return "unknown"


def get_architecture() -> str:
    """Get the current architecture."""
    arch = platform.machine().lower()
    if arch in ("x86_64", "amd64"):
        return "amd64"
    elif arch in ("aarch64", "arm64"):
        return "arm64"
    else:
        return "unknown"


#: uv options that come before the subcommand and take a value (uv 0.12).
_UV_OPTIONS_WITH_A_VALUE = frozenset(
    {
        "--allow-insecure-host",
        "--cache-dir",
        "--color",
        "--config-file",
        "--directory",
        "--project",
        "--python-preference",
    }
)


def uv_child_overrides(argv: Sequence[str]) -> Dict[str, str]:
    """The environment a uv command needs to find no project or ``.venv`` near it.

    Measured with uv 0.12.22: ``uv pip`` and ``uv run`` run the python of a ``.venv``
    in the directory they start in or any parent, and ``uv run`` builds a project it
    finds there, running the project's build backend. The empty start directory
    keeps uv out of the scanned tree only while the system's temporary directory is
    outside it, so a uv command also gets:

    - ``UV_NO_PROJECT=1``, unless it names a ``--project`` itself;
    - ``UV_PYTHON`` set to ASH's interpreter, unless it names one (``--python``,
      ``-p``, ``--system``) or the operator set ``UV_PYTHON`` or
      ``UV_SYSTEM_PYTHON``.

    ``uv tool`` commands and ``uvx`` get nothing: they read neither, and an
    interpreter there would change which Python the tool's environment is built on.
    Neither does ``UV_NO_CONFIG`` help, which only stops uv reading ``uv.toml``.
    """
    if not argv:
        return {}
    name = re.split(r"[\\/]", argv[0])[-1].lower().removesuffix(".exe")
    if name != "uv":
        return {}
    rest = list(argv[1:])
    subcommand = None
    index = 0
    while index < len(rest):
        arg = rest[index]
        if arg in _UV_OPTIONS_WITH_A_VALUE:
            index += 2
            continue
        if not arg.startswith("-"):
            subcommand = arg
            break
        index += 1
    if subcommand in (None, "tool"):
        return {}
    overrides: Dict[str, str] = {}
    if not any(a == "--project" or a.startswith("--project=") for a in rest):
        overrides["UV_NO_PROJECT"] = "1"
    names_interpreter = any(
        a in ("--python", "-p", "--system") or a.startswith("--python=") for a in rest
    )
    operator_chose = os.environ.get("UV_PYTHON") or os.environ.get("UV_SYSTEM_PYTHON")
    if not names_interpreter and not operator_chose:
        overrides["UV_PYTHON"] = sys.executable
    return overrides


def run_command(args: List[str], shell: bool = False):
    """Run a command and return the exit code.

    Every command starts in an empty directory of its own, not the current
    directory, which this command treats as the source tree. Run from there, a
    package manager read the repository's settings: npm its ``.npmrc``, ``gem
    install -g`` its Gemfile, Bundler its ``.bundle/config``. The user's own
    settings still apply. A command that starts ASH's interpreter with ``-m`` or
    ``-c`` (``python -m pip install``, the pinned-tool install script) also gets
    ``-P`` where Python has it, so it imports no ``pip/`` or
    ``automated_security_helper/`` from where it starts; see
    ``utils/python_child.py``. A uv command also gets the environment
    :func:`uv_child_overrides` gives it.
    """
    from automated_security_helper.utils.subprocess_utils import run_command as run_cmd

    try:
        if not shell and runs_module_or_code(args):
            with python_child(*args[1:]) as child:
                result = run_cmd(  # nosec B603 - argv list built by plugins, no shell
                    args=child.argv,
                    cwd=child.cwd,
                    check=False,
                    log_level=logging.INFO,
                )
        else:
            overrides = {} if shell else uv_child_overrides(args)
            with empty_directory() as start:
                result = run_cmd(  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
                    args=args,
                    cwd=start,
                    env={**snapshot_environ(), **overrides} if overrides else None,
                    shell=shell,
                    check=False,
                    log_level=logging.INFO,
                )
        # The child's output is not markup. pip alone prints `[notice]` lines and
        # echoes extras such as `ash[sarif,toml]`, which rich would otherwise
        # consume as tags and delete from the log.
        print(escape(result.stdout))
        print(escape(result.stderr))
        return result.returncode
    except Exception as e:
        print(
            f"[bold red]Error running command {escape(' '.join(args))}: "
            f"{escape(str(e))}[/bold red]"
        )
        return 1


@dependencies_app.command(name="install")
def install_dependencies(
    bin_path: Optional[Path] = typer.Option(
        # As the docs write it, and expanded below. The default used to be
        # core.constants.ASH_BIN_PATH, the absolute home directory (or the
        # variable's value) read at import, so the help said where this machine's
        # home was and wrapped differently on every machine. typer reads
        # ASH_BIN_PATH itself through envvar, and the help says so.
        "~/.ash/bin",
        "--bin-path",
        "-b",
        help="Path to install binaries to.",
        envvar="ASH_BIN_PATH",
    ),
    plugin_types: List[str] = typer.Option(
        ["converter", "scanner", "reporter"],
        "--plugin-type",
        "-t",
        help="Plugin types to install dependencies for",
    ),
    tools: Annotated[
        List[str],
        typer.Option(
            "--tool",
            "-T",
            help=(
                "Install dependencies for these tools only, by plugin name "
                "(repeatable, e.g. '--tool grype --tool syft'). An unknown name is "
                "an error rather than a no-op."
            ),
        ),
    ] = [],
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    config_overrides: Annotated[
        List[str],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2')",
        ),
    ] = [],
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
) -> int:
    """Install dependencies for ASH plugins.

    This command installs all required dependencies for the specified plugin types.
    By default, it installs dependencies for all plugin types (converter, scanner, reporter).

    Binary tools will be installed to the specified bin path (defaults to ~/.ash/bin).
    """
    # Set up logging
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )

    # Use provided bin path or default if bin_path was null. expanduser for the
    # default's "~", and for a "~" a shell left unexpanded.
    target_bin_path = Path(bin_path).expanduser() if bin_path else ASH_BIN_PATH
    # Create target_bin_path directory if it doesn't exist
    target_bin_path.mkdir(parents=True, exist_ok=True)
    # Exported absolute, because the install commands that read it back do not all
    # start in this directory: a Python one starts in an empty directory of its own.
    target_bin_path = target_bin_path.absolute()
    # Set the ASH_BIN_PATH environment variable to override the default
    set_environ("ASH_BIN_PATH", str(target_bin_path))

    console.print(
        Panel(
            f"[bold green]Installing ASH dependencies[/bold green]\n"
            f"[cyan]Target bin path:[/cyan] {escape(str(target_bin_path))}\n"
            f"[cyan]Plugin types:[/cyan] {escape(', '.join(plugin_types))}",
            title="ASH Dependency Installer",
            expand=False,
        )
    )

    print("Getting platform and architecture")
    platform_name = get_platform()
    arch = get_architecture()

    print(
        f"Installing dependencies for platform: {platform_name}, architecture: {arch}"
    )

    source_dir = Path.cwd()
    output_dir = source_dir.joinpath(".ash", "ash_output")
    work_dir = output_dir.joinpath(ASH_WORK_DIR_NAME)
    # config_path is what makes --config/ASH_CONFIG mean anything here. Omitting it
    # made the option accept a path and then quietly ignore it, so
    # `ash dependencies install --config .ash/.ash_community_plugins.yaml` resolved
    # the default config instead and installed dependencies for the wrong set of
    # plugins.
    try:
        resolved_config = resolve_config(
            config_path=config,
            source_dir=source_dir,
            config_overrides=config_overrides,
        )
    except ASHConfigValidationError as e:
        # Installing for the built-in plugin set instead would report success for
        # a config whose own plugins got nothing.
        print(f"[red]Invalid configuration: {escape(str(e))}[/red]")
        raise typer.Exit(EXIT_INVALID_CONFIG)

    # Import the plugin modules the config names before enumerating anything.
    #
    # `--config` previously resolved the config's *values* and stopped there. The
    # scanners a config adds through `ash_plugin_modules` were never imported, so
    # their plugin classes never registered, so
    # `ash dependencies install --config .ash/.ash_community_plugins.yaml` installed
    # dependencies for the built-in set and reported success -- and trivy, snyk and
    # ferret had to be installed by hand in CI before the scan.
    #
    # load_plugins is what the scan path already uses for this. Calling it here means
    # a config that adds scanners also adds their dependencies, and `--tool
    # trivy-repo` resolves instead of being rejected as an unknown name.
    try:
        load_plugins(
            PluginContext(
                source_dir=source_dir,
                output_dir=output_dir,
                work_dir=work_dir,
                config=resolved_config,
            )
        )
    except PluginModuleError as e:
        # A plugin module outside the plugin namespace, or one that does not
        # import: refused before anything is installed, with a scan's
        # invalid-configuration code.
        print(f"[red]Invalid configuration: {escape(str(e))}[/red]")
        raise typer.Exit(3)

    def discover(plugin_type: str, warn: bool = True):
        """The plugins of one type, each built from its own section of the config."""
        found: List[tuple] = []
        failed: List[PluginInstallOutcome] = []
        plugin_module_input = _plugin_kind(plugin_type)
        for plugin_class in ash_plugin_manager.plugin_modules(plugin_module_input):
            try:
                # The plugin's own section of the resolved config, looked up the way
                # the scan path looks it up (ExecutionEngine.get_scanner). Without
                # it every plugin was built from its defaults, so a
                # `--config-overrides scanners.semgrep.options.tool_version===X`
                # reached resolved_config and stopped there: the scanner installed
                # its default range, and the image carried whatever release PyPI
                # had that day instead of the version its license entry records.
                plugin_instance: PluginBase = plugin_class(
                    context=PluginContext(
                        source_dir=source_dir,
                        output_dir=output_dir,
                        work_dir=work_dir,
                        config=resolved_config,
                    ),
                    config=resolved_config.get_plugin_config(
                        plugin_type=plugin_module_input,
                        plugin_name=plugin_config_key(plugin_class),
                    ),
                )
                # `name` exists on every plugin config but is not always populated,
                # and getattr's default only fires when the attribute is absent --
                # so a config carrying name=None used to yield None here and sorting
                # the discovered names raised TypeError.
                plugin_name = (
                    getattr(plugin_instance.config, "name", None)
                    or plugin_class.__name__
                )
                found.append((plugin_type, plugin_name, plugin_instance))
            except Exception as e:
                # Reported as a warning here and weighed by the verdict later, because
                # whether it is fatal depends on the run: a --tool run answers only for
                # what it was asked about, so an unrelated plugin that will not
                # construct is information rather than this run's failure.
                if warn:
                    print(
                        f"[bold yellow]Plugin {escape(plugin_class.__name__)} could "
                        f"not be loaded: {escape(str(e))}[/bold yellow]",
                    )
                # Held aside rather than added to `outcomes` directly. `outcomes` is
                # what the verdict is computed from, and a plugin that failed to
                # construct is unrelated to a `--tool` request for a different one --
                # so folding it in unconditionally made
                # `ash dependencies install --tool trivy-repo` exit 1 because some
                # other community plugin would not import, and name that other plugin
                # in the failure panel.
                failed.append(
                    PluginInstallOutcome(
                        name=plugin_class.__name__,
                        plugin_type=plugin_type,
                        errors=[str(e)],
                    )
                )
        return found, failed

    outcomes: List[PluginInstallOutcome] = []
    construction_failures: List[PluginInstallOutcome] = []
    discovered: List[tuple] = []
    for plugin_type in plugin_types:
        found, failed = discover(plugin_type)
        discovered += found
        construction_failures += failed

    # --tool selection. Validated against the names actually discovered rather than
    # a hardcoded list, so it cannot drift from the plugin registry. An unknown name
    # is refused: silently installing nothing for `--tool gryp` would be a typo that
    # reports success, which is the class of bug this whole change is about.
    #
    # Deprecated aliases are resolved first, so `--tool ArchiveConverter` selects,
    # installs and is judged exactly as `--tool archive` is. An unknown name is still
    # reported in the spelling the caller typed.
    tool_resolution = _resolve_tool_aliases(tools)
    requested_names = list(dict.fromkeys(tool_resolution.values()))
    if tools:
        available = sorted({name for _, name, _ in discovered})
        unknown = [
            typed
            for typed, resolved_name in tool_resolution.items()
            if resolved_name not in available
        ]
        # A name missing from the selected types may still be a plugin of a type that
        # --plugin-type left out. That name is not unknown to this ASH, so it is never
        # skipped as unknown, and the refusal says which type it is.
        selected_kinds = {_plugin_kind(t) for t in plugin_types}
        elsewhere: dict = {}
        lookup_failures: List[PluginInstallOutcome] = []
        if unknown:
            for kind in PLUGIN_KINDS:
                if kind in selected_kinds:
                    continue
                found, failed = discover(kind, warn=False)
                lookup_failures += failed
                names = {name for _, name, _ in found}
                for typed in unknown:
                    if tool_resolution[typed] in names:
                        elsewhere.setdefault(typed, []).append(kind)
        if elsewhere:
            # Every name the request got wrong, not only those of another type, so one
            # run shows all of them.
            nowhere = sorted(t for t in unknown if t not in elsewhere)
            console.print(
                Panel(
                    "[bold red]Not of the selected plugin type "
                    f"(--plugin-type {escape(' '.join(plugin_types))}):[/bold red]\n"
                    + "\n".join(
                        f"{escape(typed)} is a {escape(' and '.join(kinds))} plugin"
                        for typed, kinds in sorted(elsewhere.items())
                    )
                    + "\nAdd its --plugin-type, or leave --plugin-type out."
                    + (
                        "\n[bold red]Unknown tool(s):[/bold red] "
                        + escape(", ".join(nowhere))
                        if nowhere
                        else ""
                    ),
                    title="Nothing installed",
                    expand=False,
                )
            )
            raise typer.Exit(EXIT_BAD_SELECTION)
        # Exactly `skip`, as the docs say: not a value that only strips to it.
        skip_unknown = os.environ.get(UNKNOWN_TOOLS_SETTING, "") == "skip"
        if (
            unknown
            and skip_unknown
            and not construction_failures
            and not lookup_failures
        ):
            # Named, not silent: the reader sees which requested tools this ASH lacks.
            # Not when a plugin failed to load, of any type: the unknown name could be
            # that plugin's, and skipping it would skip a tool this ASH does have.
            console.print(
                Panel(
                    "[yellow]Not known to this ASH (no converter, scanner or reporter "
                    "plugin has these names), so not installed:[/yellow] "
                    f"{escape(', '.join(sorted(unknown)))}\n"
                    f"{UNKNOWN_TOOLS_SETTING}=skip is set, and nothing this ASH runs "
                    "needs a tool it has no plugin for.",
                    title="Skipped",
                    expand=False,
                )
            )
            requested_names = [name for name in requested_names if name in available]
            if not requested_names:
                print(
                    "Nothing to install: none of the requested tools is known to this ASH."
                )
                raise typer.Exit(EXIT_OK)
            unknown = []
        if unknown:
            # A plugin that failed to construct has no config, so its declared name is
            # unknowable here -- only its class name is. Rather than claim a match that
            # cannot be established, say that some plugins failed to load, so a
            # requested name missing for that reason is not misreported as a typo.
            failed_to_load = construction_failures + lookup_failures
            broken_note = (
                ""
                if not failed_to_load
                else (
                    "\n[yellow]Note:[/yellow] "
                    f"{len(failed_to_load)} plugin(s) failed to load and are "
                    "absent from that list: "
                    + escape(", ".join(sorted(o.name for o in failed_to_load)))
                )
            )
            console.print(
                Panel(
                    f"[bold red]Unknown tool(s): "
                    f"{escape(', '.join(sorted(unknown)))}[/bold red]\n"
                    f"[cyan]Available:[/cyan] {escape(', '.join(available))}"
                    f"{broken_note}",
                    title="Nothing installed",
                    expand=False,
                )
            )
            raise typer.Exit(EXIT_BAD_SELECTION)
        selected = [entry for entry in discovered if entry[1] in requested_names]
    else:
        # Only a run that was not narrowed to specific tools answers for every
        # plugin, so construction failures count against the verdict only here.
        outcomes.extend(construction_failures)
        selected = discovered

    for plugin_type, plugin_name, plugin_instance in selected:
        outcome = PluginInstallOutcome(
            name=plugin_name,
            plugin_type=plugin_type,
            command=getattr(plugin_instance, "command", None),
        )
        outcomes.append(outcome)

        print(
            f"Installing dependencies for {escape(plugin_type)} plugin: "
            f"{escape(plugin_name)}"
        )
        try:
            commands = plugin_instance.get_installation_commands(platform_name, arch)
        except Exception as e:
            print(
                f"[bold red]Error getting installation commands for plugin "
                f"{escape(plugin_name)}: {escape(str(e))}[/bold red]"
            )
            outcome.errors.append(str(e))
            continue

        for cmd in commands:
            # An empty argv is not a command. These reached run_command before this
            # change, failed, and pushed the run's exit code to 1 -- which then went
            # nowhere, because the returned code was discarded. Skipping them and
            # counting them separately keeps a declared-but-empty entry from
            # masquerading as an attempt.
            if not cmd:
                print(
                    f"[yellow]Skipping an empty install command declared by "
                    f"{escape(plugin_name)}[/yellow]"
                )
                outcome.commands_skipped_empty += 1
                continue

            # Fix for opengrep download command
            if (
                len(cmd) > 2
                and cmd[0] == sys.executable
                and cmd[1] == "-c"
                and "opengrep" in cmd[2]
            ):
                # Fix the Python command by properly importing Path
                cmd = [sys.executable, "-c", "from pathlib import Path; " + cmd[2]]

            # A pinned binary that is already on disk, byte for byte, is not
            # installed a second time. The image installs syft, grype and trivy into
            # /usr/local/bin before this runs, and this used to write another copy of
            # each into the bin path -- twice, once per image stage. Decided by the
            # bytes, never the name: a same-named binary that does not hash to the
            # pinned executable digest is installed over as before.
            present = pinned_install_already_satisfied(cmd)
            if present is not None:
                print(
                    f"Already present: {escape(present.tool)} "
                    f"{escape(present.version)} at {escape(str(present.path))} matches "
                    f"the pinned SHA256 {present.sha256}; not installing a second copy"
                )
                outcome.commands_satisfied += 1
                continue

            # An argv routinely carries brackets -- `pip install ash[sarif,toml]` --
            # and rich would read `[sarif,toml]` as a tag and drop it from the line.
            print(f"Running command: {escape(' '.join(cmd))}")
            outcome.commands_attempted += 1
            cmd_exit_code = run_command(cmd)
            if cmd_exit_code != 0:
                print(f"Command failed with exit code: {cmd_exit_code}")
                outcome.commands_failed += 1
            else:
                print(f"Command succeeded with exit code: {cmd_exit_code}")
                outcome.commands_succeeded += 1

    # Post-install sweep. find_executable memoizes negative results, so a lookup
    # made before the install would answer for the world as it was and report a tool
    # ASH just installed as absent.
    clear_find_executable_cache()
    for outcome in outcomes:
        if outcome.needs_external_tool:
            outcome.executable = find_executable(outcome.command)

    return _report_and_exit(outcomes, requested_tools=requested_names)


def _report_and_exit(
    outcomes: List[PluginInstallOutcome], requested_tools: List[str]
) -> int:
    """Print the tally and derive the verdict from it.

    The verdict is computed from counts, never assumed. Three things fail a run:

    1. Any install command exited non-zero, or a plugin raised.
    2. Nothing was attempted **and** a needed tool is still absent. A run in which
       every command list was empty installed nothing, and reporting that as
       success is what let three scanners stay absent from ASH's own CI while the
       installer said it had finished. The second half of the condition matters:
       attempting nothing because everything is already present is a no-op, and
       failing it would turn `--tool npm-audit` on a machine with node into a false
       alarm.
    3. A tool named explicitly with --tool is not on PATH afterwards. Asking for a
       specific tool and getting a clean exit without it is the same failure in
       miniature. Restricted to plugins that actually run an external binary, since
       a reporter has no executable to find.

    Tools with no install path on this platform are reported by name and do not
    fail the run on their own when they are already present. That is a real
    constraint rather than a malfunction -- npm-audit needs a Node runtime ASH does
    not install, cfn-nag needs RubyGems, and grype and trivy publish no
    windows/arm64 build -- and it is named in the output rather than left for the
    reader to infer from silence.
    """
    table = Table(title="Dependency installation results")
    table.add_column("Plugin")
    table.add_column("Type")
    table.add_column("Tool")
    table.add_column("Cmds", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Status")
    table.add_column("Resolved to")

    for outcome in sorted(outcomes, key=lambda o: (o.plugin_type, o.name)):
        # Python-only plugins are the bulk of the list and say nothing useful here.
        if outcome.status == "PYTHON-ONLY" and not outcome.commands_attempted:
            continue
        # Table cells are markup too; a resolved path or plugin name is not.
        table.add_row(
            escape(outcome.name),
            escape(outcome.plugin_type),
            escape(outcome.command or "-"),
            str(outcome.commands_attempted),
            str(outcome.commands_failed),
            escape(outcome.status),
            escape(outcome.executable or "-"),
        )
    console.print(table)

    commands_attempted = sum(o.commands_attempted for o in outcomes)
    commands_failed = sum(o.commands_failed for o in outcomes)
    plugins_with_errors = [o.name for o in outcomes if o.errors]
    verified = sorted(
        o.name for o in outcomes if o.needs_external_tool and o.executable
    )
    # Named whether or not the tool happens to be present. "npm is on PATH" and
    # "ASH cannot install npm" are different facts, and a reader planning a CI image
    # needs the second one even when the first is currently true.
    unprovisionable = sorted(
        o.name for o in outcomes if o.needs_external_tool and o.declared_no_commands
    )
    missing_after_install = sorted(
        o.name
        for o in outcomes
        if o.needs_external_tool
        and not o.executable
        and (o.commands_attempted or o.commands_satisfied)
    )
    already_verified = sorted(o.name for o in outcomes if o.commands_satisfied)

    # An external tool that is needed, has no install path here, and is not present.
    # This is what makes "nothing was installed" a failure rather than a no-op: the
    # run installed nothing *and* something it needs is still missing.
    still_missing = sorted(
        o.name
        for o in outcomes
        if o.needs_external_tool and not o.executable and o.declared_no_commands
    )

    reasons: List[str] = []
    if commands_failed:
        reasons.append(f"{commands_failed} install command(s) failed")
    if plugins_with_errors:
        reasons.append(f"plugin error(s): {', '.join(sorted(plugins_with_errors))}")
    if commands_attempted == 0 and still_missing:
        # Deliberately conditioned on something actually being absent. A run that
        # attempts nothing because everything it needs is already present is a no-op,
        # not a failure -- `--tool npm-audit` on a machine with node is the case, and
        # failing it would be a false alarm. But a run that attempts nothing while a
        # needed tool is missing is exactly the state grype, syft and cfn-nag were in
        # on every CI runner, and that must not read as success.
        reasons.append(
            "no install commands were run and these are still absent: "
            + ", ".join(still_missing)
        )
    unsatisfied_requests = sorted(
        o.name
        for o in outcomes
        # needs_external_tool is required: `executable` is only ever populated for
        # plugins that have a command, so without it every Python-only plugin named
        # with --tool (any reporter, or the archive converter) failed the run for
        # lacking a binary it was never going to have.
        if requested_tools
        and o.name in requested_tools
        and o.needs_external_tool
        and not o.executable
    )
    if unsatisfied_requests:
        reasons.append(
            f"requested tool(s) still not on PATH: {', '.join(unsatisfied_requests)}"
        )

    verified_names = f" -- {escape(', '.join(verified))}" if verified else ""
    summary = [
        f"[cyan]Commands run:[/cyan] {commands_attempted} ({commands_failed} failed)",
        f"[cyan]Tools verified on PATH:[/cyan] {len(verified)}{verified_names}",
    ]
    # Only printed when it happened, so a run with nothing pre-installed reads
    # exactly as it did before verified-present tools were recognized.
    if already_verified:
        summary.append(
            f"[cyan]Already present, verified against the pinned digest:[/cyan] "
            f"{len(already_verified)} -- {escape(', '.join(already_verified))}"
        )
    if unprovisionable:
        summary.append(
            f"[yellow]No install path on this platform:[/yellow] "
            f"{escape(', '.join(unprovisionable))}"
        )
    if missing_after_install:
        summary.append(
            f"[yellow]Install ran but tool not found on PATH:[/yellow] "
            f"{escape(', '.join(missing_after_install))}"
        )

    if reasons:
        console.print(
            Panel(
                "\n".join(summary)
                + "\n\n[bold red]"
                + escape("; ".join(reasons))
                + "[/bold red]",
                title="Installation Incomplete",
                expand=False,
            )
        )
        raise typer.Exit(EXIT_INSTALL_FAILED)

    console.print(
        Panel(
            "\n".join(summary),
            title="Installation Complete",
            expand=False,
        )
    )
    return EXIT_OK
