# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CLI command for installing dependencies for ASH plugins."""

import contextvars
import logging
import os
import platform
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PureWindowsPath
from typing import Annotated, Any, Iterable, List, Optional, Tuple

import typer

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form. It is utils/console.py's print, not rich's:
# its console checks each line it writes off a terminal, so none reads as a CI command.
from automated_security_helper.utils.console import ash_console, print  # noqa: A004
from automated_security_helper.utils.console import global_console
from automated_security_helper.utils.ui_theme import rich_theme
from rich.panel import Panel
from rich.table import Table

from automated_security_helper.base.plugin_base import CustomCommand, PluginBase
from automated_security_helper.base.plugin_config import (
    declared_plugin_name,
    plugin_config_key,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    plugin_explains_its_own_refusal,
    plugin_missing_dependency_reason,
)
from automated_security_helper.config.named_config import (
    refuse_a_named_config_that_does_not_exist,
)
from automated_security_helper.config.plugin_option_check import (
    refuse_unknown_options_of_registered,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import (
    ASH_BIN_PATH,
    ASH_CONFIG_SOURCES_DESCRIPTION,
    ASH_EXIT_BAD_SELECTION,
    ASH_EXIT_USAGE_ERROR,
    ASH_WORK_DIR_NAME,
    ash_bin_path_from_environment,
    home_bin_path,
    is_anchored,
    is_blank_bin_path,
    usable_home,
)
from automated_security_helper.core.exceptions import (
    ASHConfigFileNotFoundError,
    ASHConfigValidationError,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import (
    PluginModuleError,
    PluginModuleNamespaceError,
    load_plugins,
    plugin_module_fix,
)
from automated_security_helper.utils.download_utils import (
    NO_BIN_DIRECTORY,
    pinned_install_already_satisfied,
)
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    get_logger,
    show_debug_locals,
)

# Not rich.markup.escape, which shows a trailing backslash twice or lets it escape
# the next tag; see escape_markup.
from automated_security_helper.utils.log import escape_markup as escape
from automated_security_helper.utils.process_env import set_environ, snapshot_environ
from automated_security_helper.utils.python_child import (
    empty_directory,
    python_child,
    runs_module_or_code,
    uv_child_overrides,
)
from automated_security_helper.utils.python_installer import environment_rebuild_note
from automated_security_helper.utils.redacted_model import value_tuple
from automated_security_helper.utils.subprocess_utils import (
    clear_find_executable_cache,
    find_executable_for_scan,
    shown_arguments,
)
from automated_security_helper.utils.uv_tool_runner import UV_NO_CONFIG

#: How long one install command may run. A package manager or a download that
#: stalls held the whole installer for ever: with no timeout, run_command waited on
#: it indefinitely. A command that reaches this limit fails like any other failed
#: command, naming the limit in its error line.
INSTALL_COMMAND_TIMEOUT_SECONDS = 3600.0

dependencies_app = typer.Typer(
    name="dependencies",
    help="Install dependencies for ASH plugins",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    # As the other command apps: typer's default shows every frame's locals, and
    # this module's frames hold the values the configuration read from the
    # environment, which every line it prints is redacted with (utils/log.py).
    pretty_exceptions_show_locals=show_debug_locals(),
)

console = ash_console(theme=rich_theme())
# Deprecation warnings go to stderr so a script that parses this command's stdout
# is not handed a line it has never seen.
err_console = ash_console(stderr=True, theme=rich_theme())

# Exit codes. Distinct values so a caller can tell "you asked for a tool that does
# not exist" from "the install ran and something failed". A --tool this command
# cannot select (a name no plugin has, or a plugin of a type --plugin-type leaves out),
# and a --plugin-type that is none of PLUGIN_KINDS, exit ASH_EXIT_BAD_SELECTION, 2,
# the code the CLI reference documents for them; the command's other usage errors,
# such as an unknown option, exit 5 like every command's.
EXIT_OK = 0
EXIT_INSTALL_FAILED = 1
EXIT_BAD_SELECTION = ASH_EXIT_BAD_SELECTION
# The code every ASH command uses for a configuration that cannot be used.
EXIT_INVALID_CONFIG = 3

#: The values the run's configuration read from the environment, while the
#: install commands run: every line run_command prints or logs about a child
#: (its argv, its output, the error it raised) is redacted with them, as the
#: scan's runner redacts its own lines (subprocess_utils._SPAWN_VALUES). A
#: context variable rather than an argument: run_command keeps the two-argument
#: shape its callers and their stand-ins have, and the values belong to the whole
#: install, not to one child.
_INSTALL_VALUES: contextvars.ContextVar[Tuple[str, ...]] = contextvars.ContextVar(
    "ash_install_values", default=()
)

# Set to exactly `skip`, a `--tool` name that no plugin of this ASH has, of any type,
# is named and skipped rather than refused. ASH's own required check sets it, because
# it installs ASH from an older commit than the workflow that asks for the tools: a
# tool that ASH has no plugin for is not run by it either, so the scan needs nothing
# from that tool. Unset, the refusal stands, which is what catches a typo.
UNKNOWN_TOOLS_SETTING = "ASH_DEPENDENCIES_UNKNOWN_TOOLS"

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

#: The plugin types --plugin-type selects, each the plugin manager's own name for
#: that kind of plugin.
PLUGIN_KINDS = ("converter", "scanner", "reporter")


def _plugin_kind(plugin_type: str) -> str:
    """The registry kind a --plugin-type value selects.

    install_dependencies refuses a value that is not one of PLUGIN_KINDS before
    anything is selected, so a value reaching here is one of them; any other is a
    programming error, not a kind to guess.
    """
    if plugin_type not in PLUGIN_KINDS:
        raise ValueError(f"not a plugin type: {plugin_type!r}")
    return plugin_type


def _selection_key(name: str) -> str:
    """The key a plugin name is selected by: lower-cased and stripped.

    The scan selects its scanners by this key (core.phases.scan_phase), so
    ``--tool Bandit`` and ``--tool " bandit "`` select the plugin the scan would
    rather than reading as tools this ASH lacks, which
    ``ASH_DEPENDENCIES_UNKNOWN_TOOLS=skip`` would then skip with exit 0.
    """
    return name.lower().strip()


class AmbiguousToolName(ValueError):
    """A ``--tool`` name selects more than one plugin by the scan's key and none
    by its exact spelling: ``--tool SEMGREP`` with plugins ``Semgrep`` and
    ``semgrep``. Neither is the caller's choice, so the caller refuses it,
    naming both (:func:`_canonical_tool_names`)."""

    def __init__(self, name: str, matches: List[str]):
        self.name = name
        self.matches = list(matches)
        super().__init__(
            f"--tool {name} names more than one plugin: {', '.join(self.matches)}"
        )


def _canonical_tool_name(resolved_name: str, available: Iterable[str]) -> str:
    """The name in ``available`` that ``resolved_name`` selects.

    The name itself when it is there as typed, so a plugin whose name differs
    from another's only in case or blanks is still selected by its exact
    spelling; else the one name with the same selection key
    (:func:`_selection_key`), the scan's match; else ``resolved_name`` as it is,
    for the caller to refuse as unknown.

    Two names with that key and neither spelled as typed raise
    :class:`AmbiguousToolName` rather than picking one. The scan picks neither
    either: two scanners whose names differ only in case share one selection
    key, and it runs the first and refuses the second as a name already carried
    (core.phases.scan_phase, ``_record_duplicate_scanner_name``), so which plugin
    an installer picked would be an accident of registry order. One name declared
    by two plugin classes is one name here: the caller passes a list, and a name
    listed twice matched itself twice and was refused as ambiguous with itself.
    """
    names = list(dict.fromkeys(available))
    if resolved_name in names:
        return resolved_name
    key = _selection_key(resolved_name)
    matches = [name for name in names if _selection_key(name) == key]
    if len(matches) > 1:
        raise AmbiguousToolName(resolved_name, matches)
    if matches:
        return matches[0]
    return resolved_name


def _deprecated_aliases_by_key() -> dict[str, str]:
    """The deprecated aliases by their selection key, so an alias is matched as a
    plugin name is: ``archiveconverter`` and ``" ArchiveConverter"`` resolve too.

    Read from :data:`DEPRECATED_TOOL_ALIASES` at each call, not once at import:
    the table is the one thing that resolves an alias, and a test that empties it
    expects the old name refused as unknown, which a copy taken at import kept
    resolving.
    """
    return {
        _selection_key(alias): replacement
        for alias, replacement in DEPRECATED_TOOL_ALIASES.items()
    }


def _resolve_tool_aliases(tools: List[str]) -> dict[str, str]:
    """Map each requested `--tool` name to the plugin name to select it by.

    A deprecated alias, in any case or with blanks around it, maps to its
    replacement and prints one warning to stderr per alias, however many times it
    was passed. Every other name maps to itself, so an unknown name is still
    refused by the caller exactly as before.
    """
    resolved: dict[str, str] = {}
    aliases_by_key = _deprecated_aliases_by_key()
    # Aliases match by selection key, so two spellings of one alias are one alias:
    # warned once, by key, not once per spelling.
    warned: set[str] = set()
    for tool in tools:
        if tool in resolved:
            continue
        key = _selection_key(tool)
        replacement = aliases_by_key.get(key)
        if replacement is None:
            resolved[tool] = tool.strip()
            continue
        if key not in warned:
            warned.add(key)
            err_console.print(
                f"[bold yellow]Deprecated:[/bold yellow] --tool {escape(tool)} is "
                f"deprecated; use --tool {escape(replacement)} instead.",
                highlight=False,
            )
        resolved[tool] = replacement
    return resolved


def _is_under_tilde(bin_path: str, pure: type = PurePath) -> bool:
    """Whether ``bin_path`` is ``~`` or starts with the component ``~``.

    The rule pathlib's own ``expanduser`` applies: the first path component, read
    with the platform's separators (``pure``), is exactly ``~``. So on POSIX
    ``~\\x`` is one component, not home: it goes to ``expanduser``, which reads
    ``\\x`` as a user name and refuses it, and the caller refuses the option.
    """
    return pure(bin_path).parts[:1] == ("~",)


def _bin_path_under_home(bin_path: str, home: Path, pure: type = PurePath) -> Path:
    """``bin_path``, whose first component is ``~`` (:func:`_is_under_tilde`),
    under ``home``.

    Joined component by component, never as the text after ``~/``: ``~//.ash/bin``
    has the components of ``~/.ash/bin``, while its text after ``~/`` is the
    absolute ``/.ash/bin``, which ``Path.joinpath`` would take whole, dropping
    ``home`` and putting the install at the filesystem's root. ``pure`` is the
    path flavor the components are read with (the platform's by default).
    """
    return home.joinpath(*pure(bin_path).parts[1:])


def _canonical_tool_names(
    tool_resolution: dict[str, str], known: Iterable[str], strict: bool = True
) -> dict[str, str]:
    """Each requested name mapped to the plugin name it selects among ``known``
    (:func:`_canonical_tool_name`: as typed first, then by the scan's selection
    key). A name no plugin has stays as resolved, so the caller still refuses it.
    Compared as typed, `--tool Grype` was refused as unknown, and with
    ASH_DEPENDENCIES_UNKNOWN_TOOLS=skip it skipped a tool the scan then ran.

    A name that selects two plugins by key and neither exactly is refused here,
    exit 2, naming both and the spelling that would select one: the scan refuses
    such a pair too (:func:`_canonical_tool_name`), and installing for the first
    the registry happened to list would be a silent choice.

    With ``strict`` false, ``known`` is only part of the plugins' names (a plugin
    whose name is known only by building it is not in it), so a name that is
    ambiguous among them is kept as resolved and not refused: the complete list
    decides, in a later call made from the same resolved names."""
    names = list(known)
    canonical: dict[str, str] = {}
    for typed, resolved_name in tool_resolution.items():
        try:
            canonical[typed] = _canonical_tool_name(resolved_name, names)
        except AmbiguousToolName as e:
            if not strict:
                canonical[typed] = resolved_name
                continue
            console.print(
                Panel(
                    f"[bold red]Ambiguous tool: {escape(e.name)}[/bold red]\n"
                    f"[cyan]Names more than one plugin:[/cyan] "
                    f"{escape(', '.join(e.matches))}\n"
                    "Their names differ only in case or blanks, which the scan "
                    "refuses too (two scanners cannot share one name). Select one "
                    "by its exact spelling.",
                    title="Nothing installed",
                    expand=False,
                )
            )
            raise typer.Exit(EXIT_BAD_SELECTION)
    return canonical


def _requested_classes(candidates: Iterable[tuple], requested_names: List[str]) -> set:
    """The plugin classes a ``--tool`` run builds, for the option check: each
    candidate whose declared name is one of the resolved names, exactly, and each
    whose name is known only by building it (declared ``None``).

    Exactly, not by selection key: the names were resolved to the plugins' own
    spellings already (:func:`_canonical_tool_names`), so matching by key here
    put a plugin that differs from a requested one only in case back into the
    check, and ``--tool semgrep`` exited 3 over a bad option in the ``Semgrep``
    section of a plugin this run never builds.
    """
    return {
        candidate[2]
        for candidate in candidates
        if candidate[3] is None or candidate[3] in requested_names
    }


def _refuse_a_named_config_that_does_not_exist(config: Optional[str]) -> None:
    """Exit 3 when ``--config`` names a file that is not there.

    ``resolve_config`` answers a named path that does not exist with the default
    configuration and a warning. For this command that is not a harmless fallback:
    it would install the dependencies of the built-in plugin set, none of which the
    named file chose. A scan and ``ash report`` refuse the path before resolving
    anything, in these words, and so does this command, before it creates a
    directory or starts a process.

    The rule, and what it leaves to ``resolve_config``, is
    ``config.named_config.refuse_a_named_config_that_does_not_exist``, shared with
    ``ash plugin list``; this prints its refusal in the command's own format.
    """
    try:
        refuse_a_named_config_that_does_not_exist(config)
    except ASHConfigFileNotFoundError as e:
        print(f"[red]Invalid configuration: {escape(error_text(e))}[/red]")
        raise typer.Exit(EXIT_INVALID_CONFIG)


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
    # Run through `uv tool run`, so present when uv lists it even with uv's tool
    # bin directory off PATH.
    uv_managed: bool = False
    # Programs the plugin needs besides `command` that ASH does not install
    # (cdk-nag: node), and those of them the post-install sweep did not find.
    external_executables: Tuple[str, ...] = ()
    missing_executables: List[str] = field(default_factory=list)
    # The plugin's own dependency check -- the resolution a scan uses -- can
    # start the tool. Asked only for a plugin that declares its check can start
    # the tool off PATH (``resolves_tool_off_path``), is not run through uv,
    # and whose tool the PATH lookup does not find; see _scan_can_run.
    runnable_by_scan: bool = False
    # The check's answer where it was asked and answered; None where it was
    # not asked, and None where it raised (a crash is not an answer). A False
    # is said on the tool's failure line, beside the PATH.
    check_answer: Optional[bool] = None
    # The plugin's own reason for that False, read the way the scan's MISSING
    # row reads it, redacted with the environment values and with the home
    # directory as "~"; see _refusal_reason. Named apart from the plugin's
    # missing_dependency_reason() hook, whose raw text can carry an
    # environment value: this field is the text that may be shown.
    shown_refusal_reason: Optional[str] = None
    # The plugin runs inside ASH's own interpreter (cdk-nag), so its command is
    # sys.executable whatever ``command`` says; see _resolved_executable.
    runs_in_ash_interpreter: bool = False
    # Set when a scan with this configuration on this platform would not run the
    # plugin; see _scan_skip. Such a plugin's install is still run and reported,
    # but it does not decide the exit code.
    unsupported_platform: Optional[str] = None
    disabled_by_config: bool = False
    # Named with --tool: an explicit request, judged whether or not a scan here
    # would run the plugin, and reported so (see status).
    requested: bool = False
    # The plugin that produced this outcome, for the post-install sweep. On the
    # outcome itself, not in a side table keyed by name: two plugin modules can
    # ship plugins of the same name, and each outcome is judged by the plugin
    # that produced it. Not part of the outcome's value: two outcomes that
    # counted the same things read equal, and a printed outcome stays counts.
    plugin: Any = field(default=None, repr=False, compare=False)

    @property
    def needed(self) -> bool:
        """Whether a scan here would run this plugin, so its outcome counts."""
        return self.unsupported_platform is None and not self.disabled_by_config

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
    def is_absent(self) -> bool:
        """A program this plugin needs is not there after the install.

        A program the plugin needs besides its command (``external_executables``)
        counts whether or not the plugin has a command of its own: a plugin with
        no command whose program was missing never failed the install.
        """
        if self.missing_executables:
            return True
        return self.needs_external_tool and (
            not self.executable and not self.runnable_by_scan
        )

    @property
    def status(self) -> str:
        if self.errors or self.commands_failed:
            return "FAILED"
        # A tool named with --tool is counted (see _report_and_exit), so its row
        # says what is wrong with it, not that a scan would skip it: "DISABLED IN
        # CONFIG" beside a run that failed for its absence read as two stories.
        if self.is_absent and not self.requested:
            if self.unsupported_platform is not None:
                return "NOT AVAILABLE ON THIS PLATFORM"
            if self.disabled_by_config:
                return "DISABLED IN CONFIG"
        if self.missing_executables:
            return f"{self._status()} ({', '.join(self.missing_executables)} not found)"
        return self._status()

    def _status(self) -> str:
        if self.commands_succeeded:
            if not self.needs_external_tool:
                # Nothing to look for on PATH: the install put a Python package
                # in place, and "not on PATH" said something was missing.
                return "INSTALLED"
            if self.executable:
                return "INSTALLED"
            if self.runnable_by_scan:
                return "INSTALLED (a scan can run it)"
            return "INSTALLED (not on PATH)"
        if self.commands_satisfied:
            if self.executable:
                return "VERIFIED PRESENT"
            if self.runnable_by_scan:
                return "VERIFIED (a scan can run it)"
            return "VERIFIED (not on PATH)"
        if not self.needs_external_tool:
            return "PYTHON-ONLY"
        if self.executable:
            return "ALREADY PRESENT"
        # One story: "NO INSTALL PATH" beside the summary's "a scan can run
        # them" read as a contradiction, and the reader's question is whether a
        # scan has the tool, which this answers.
        if self.runnable_by_scan:
            return "RUNNABLE BY SCAN"
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


def _declared_install_name(
    plugin_class: type, plugin_type: str, resolved_config
) -> Optional[str]:
    """The name ``--tool`` selects ``plugin_class`` by, read without building it.

    A built plugin is selected by its config's ``name``: the ``name`` in its
    section of the resolved config, or the default its config class declares.
    Both are readable from the class and the config. None when the class declares
    no config class with a name, so the caller builds that plugin to find out.
    """
    declared = declared_plugin_name(plugin_class)
    if not declared:
        return None
    try:
        section = resolved_config.get_plugin_config(
            plugin_type=plugin_type, plugin_name=plugin_config_key(plugin_class)
        )
    except Exception:
        # The declared name is the answer when the section cannot be read.
        section = None
    configured = (
        section.get("name")
        if isinstance(section, dict)
        else getattr(section, "name", None)
    )
    return configured if isinstance(configured, str) and configured else declared


def _refuse_unknown_tools(
    tool_resolution: dict[str, str],
    available: List[str],
    construction_failures: List[PluginInstallOutcome],
) -> None:
    """Exit with EXIT_BAD_SELECTION if a requested name is not in ``available``."""
    unknown = [
        typed
        for typed, resolved_name in tool_resolution.items()
        if resolved_name not in available
    ]
    if not unknown:
        return
    # A plugin that failed to construct before its name was known has no config to
    # read a name from -- only its class name is known. Rather than claim a match
    # that cannot be established, say that some plugins failed to load, so a
    # requested name missing for that reason is not misreported as a typo.
    broken_note = (
        ""
        if not construction_failures
        else (
            "\n[yellow]Note:[/yellow] "
            f"{len(construction_failures)} plugin(s) failed to load and are "
            "absent from that list: "
            + escape(", ".join(sorted(o.name for o in construction_failures)))
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


def _scan_skip(plugin_instance) -> Tuple[Optional[str], bool]:
    """Whether a scan here would skip this plugin: (platform reason, disabled).

    The scan phase's own two tests, read from the same plugin: a plugin whose
    configuration says ``enabled: false`` is not selected, and a scanner whose
    ``unsupported_platform_reason`` gives a reason is SKIPPED. Either way the scan
    never looks for its tool, so its absence cannot fail the scan and does not fail
    the install. A scanner that only lacks its tool here (cfn-nag on Windows
    without a Ruby DevKit, npm-audit without npm) is MISSING in a scan and is
    still needed.
    """
    config = getattr(plugin_instance, "config", None)
    disabled = getattr(config, "enabled", True) is False
    declare = getattr(plugin_instance, "unsupported_platform_reason", None)
    reason = declare() if callable(declare) else None
    return (reason if isinstance(reason, str) and reason else None), disabled


def _ash_environment_install(cmd: List[str]) -> List[str]:
    """The requirements ``cmd`` installs into ASH's own environment, if it does."""
    if cmd[:4] == [sys.executable, "-m", "pip", "install"]:
        return list(cmd[4:])
    if cmd[:6] == ["uv", "pip", "install", UV_NO_CONFIG, "--python", sys.executable]:
        return list(cmd[6:])
    return []


#: uv's global options that take a value (uv 0.12), so the subcommand is found
#: after them. An option missing here makes its value read as the subcommand, which
#: is "tool" only if the value is, so the mistake sets UV_NO_CONFIG rather than
#: leaving it out.
_UV_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--allow-insecure-host",
        "--cache-dir",
        "--color",
        "--config-file",
        "--directory",
        "--project",
        # Both take a value; missing, `uv --python-preference managed tool ...`
        # read "managed" as the subcommand and lost the user's uv.toml.
        "--python-fetch",
        "--python-preference",
    }
)


#: Python's long option that takes a value, skipped on the way to ``-m uv``.
_PYTHON_LONG_OPTIONS_WITH_VALUES = frozenset({"--check-hash-based-pycs"})
#: Python's single-letter options that take a value: the rest of the argument, or
#: the next argument when nothing follows the letter. -c and -m end the options.
_PYTHON_LETTERS_WITH_VALUES = frozenset("cmWX")
#: The modules that run uv: ``python -m uv`` and ``python -m uv.__main__``.
_UV_MODULES = frozenset({"uv", "uv.__main__"})


def _uv_arguments(args: List[str]) -> Optional[List[str]]:
    """uv's own arguments in ``args``, or None when ``args`` does not run uv.

    ``uv ...`` gives everything after the program; ``<python> [options] -m uv ...``
    everything after the module. Any program followed by ``-m uv`` counts: setting
    UV_NO_CONFIG on a command that turns out not to be Python costs nothing.
    """
    # PureWindowsPath splits on either separator, whatever the host.
    name = PureWindowsPath(str(args[0])).name.lower()
    for suffix in (".exe", ".bat", ".cmd"):
        name = name.removesuffix(suffix)
    if name == "uv":
        return list(args[1:])
    return _python_module_arguments(list(args[1:]))


def _python_module_arguments(options: List[str]) -> Optional[List[str]]:
    """What follows ``-m uv`` in a Python command line's ``options``, or None.

    Read the way CPython reads its own options: single-letter ones cluster
    (``-Im uv``, ``-IXutf8``), and a letter that takes a value (-c, -m, -W, -X)
    takes the rest of its argument (``-muv``) or, when nothing follows it, the next
    argument. -c, a script, ``-`` or ``--`` means no module runs; -m with any
    module but uv's means another one does.
    """
    index = 0
    while index < len(options):
        arg = options[index]
        if arg in _PYTHON_LONG_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if arg in ("-", "--") or not arg.startswith("-"):
            return None
        if arg.startswith("--"):
            index += 1
            continue
        for position in range(1, len(arg)):
            letter = arg[position]
            if letter not in _PYTHON_LETTERS_WITH_VALUES:
                continue
            value: Optional[str] = arg[position + 1 :]
            if not value:
                index += 1
                value = options[index] if index < len(options) else None
            if letter == "c":
                return None
            if letter == "m":
                return options[index + 1 :] if value in _UV_MODULES else None
            break  # -W or -X took the rest of this argument or the next one.
        index += 1
    return None


def _uv_reads_project_config(args: List[str], shell: bool) -> bool:
    """Whether ``args`` runs a uv subcommand that reads the project's uv config.

    Every uv subcommand but ``uv tool`` reads ``uv.toml`` and ``pyproject.toml``'s
    ``[tool.uv]`` from the working directory and its parents (measured with uv
    0.12: ``uv pip``, ``uv cache``, ``uv venv``, ``uv python`` and ``uv run`` do),
    so the answer is "not ``uv tool``": a subcommand this does not know is treated
    as one that reads it. The program is uv by its file name (``uv``, or on Windows
    ``uv.exe``, ``uv.bat`` or ``uv.cmd``, the names ``find_executable`` tries, in
    any directory), or it is a Python interpreter running ``-m uv``. The
    subcommand is uv's first argument that is neither an option nor an option's
    value. ``uvx`` is ``uv tool run``. A shell command is not parsed.
    """
    if shell or not args:
        return False
    uv_args = _uv_arguments(args)
    if uv_args is None:
        return False
    rest = iter(uv_args)
    for arg in rest:
        if arg in _UV_GLOBAL_OPTIONS_WITH_VALUES:
            next(rest, None)
            continue
        if arg.startswith("-"):
            continue
        return arg != "tool"
    return True


def _shown_command(args: Iterable[Any], values: Iterable[str]) -> str:
    """The argv on one line as this command shows it: each element as text,
    without the values the configuration read from the environment.

    A plugin declares its argv; one that puts a Path, or a number, in it is
    shown, and then fails in the child's spawn, instead of ``' '.join`` raising
    TypeError over the whole install run.

    Built as the runner builds its own "Running command" log line
    (``subprocess_utils.run_command``): ``shown_arguments`` writes each
    ``--config-overrides`` value as its key, and ``value_tuple`` reads the values
    as one value each, so the two lines about one child cannot drift apart.
    """
    shown = " ".join(map(str, shown_arguments(list(args))))
    return text_without_values(shown, value_tuple(values))


def run_command(args: List[str], shell: bool = False):
    """Run a command and return the exit code.

    What this prints about the child (its output, the error its spawn raised)
    is redacted with the install's environment values (``_INSTALL_VALUES``),
    and the runner's own log lines are passed the same values.

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
    from automated_security_helper.utils.subprocess_utils import run_succeeded
    from automated_security_helper.utils.uv_tool_runner import find_uv_or_none

    values = _INSTALL_VALUES.get()
    if shell and isinstance(args, (list, tuple)) and len(args) != 1:
        # One command line for the shell is one string. Several words under
        # shell=True have no reading that is safe: POSIX runs the first word as
        # the script and the rest as its $0, $1, ..., and a space join hands the
        # shell the words to read again, so `["bash", "-c", "cd d && make"]`
        # would run `bash -c cd d` and then `make` in the wrong directory, and a
        # Windows path with a space would lose the quoting list2cmdline gives it.
        # No words at all is no line either: handed on as `[]`, the runner would
        # have nothing to run under a shell.
        # Not run, and counted as a failed command; the plugin declares the line.
        if args:
            print(
                "[bold red]Not run: a command declared with shell=True is one "
                f"command line for the shell, and this one is {len(args)} "
                f"separate words: {escape(_shown_command(args, values))}. Declare "
                "the whole line as one string.[/bold red]"
            )
        else:
            print(
                "[bold red]Not run: a command declared with shell=True is one "
                "command line for the shell, and this one has no words. Declare "
                "the whole line as one string.[/bold red]"
            )
        return 1
    if args and not shell and args[0] == "uv":
        # Plugins declare their uv installs as `uv ...`. Resolved like any other
        # program name, that found only a uv on PATH or in the ASH bin directory,
        # never the one installed with ASH beside its interpreter.
        args = [find_uv_or_none() or "uv", *args[1:]]

    env = None
    if _uv_reads_project_config(args, shell):
        # The --no-config of uv_tool_runner.UV_NO_CONFIG, for a declared uv command
        # that reads the scanned repository's uv.toml, whatever its spelling or
        # argument order. uv tool commands, which ignore project files, keep the
        # user's and the system uv.toml.
        env = snapshot_environ()
        env["UV_NO_CONFIG"] = "1"
    # The uv child's own overrides (UV_PYTHON, UV_NO_PROJECT) for every spelling
    # of a uv command, `<ASH python> -m uv ...` included: applied to the plain
    # `uv ...` spelling only, a `-m uv` install resolved against another
    # interpreter and the working directory's project.
    uv_args = None if shell or not args else _uv_arguments(args)
    overrides = {} if uv_args is None else uv_child_overrides(["uv", *uv_args])
    if overrides:
        # The declared command's UV_NO_CONFIG environment, when one was built
        # above, extended with the uv child's own overrides.
        env = {**(env if env is not None else snapshot_environ()), **overrides}
    try:
        if not shell and runs_module_or_code(args):
            with python_child(*args[1:]) as child:
                result = run_cmd(  # nosec B603 - argv list built by plugins, no shell
                    args=child.argv,
                    cwd=child.cwd,
                    env=env,
                    check=False,
                    log_level=logging.INFO,
                    values=values,
                    timeout=INSTALL_COMMAND_TIMEOUT_SECONDS,
                )
        else:
            # A CustomCommand declared shell=True is one shell command line, and
            # its one string is handed to the shell as written. Handed to Popen as
            # a list with shell=True, POSIX runs `sh -c` on the first word alone
            # and passes the rest as $0, $1, ...; a list of several words is
            # refused above, since joining it would have the shell read the words
            # again, whatever quoting each carried.
            is_one_line = shell and isinstance(args, (list, tuple)) and len(args) == 1
            command = args[0] if is_one_line else args
            with empty_directory() as start:
                result = run_cmd(  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
                    args=command,
                    cwd=start,
                    env=env,
                    shell=shell,
                    check=False,
                    log_level=logging.INFO,
                    values=values,
                    timeout=INSTALL_COMMAND_TIMEOUT_SECONDS,
                )
        # The child's output is not markup. pip alone prints `[notice]` lines and
        # echoes extras such as `ash[sarif,toml]`, which rich would otherwise
        # consume as tags and delete from the log. A child that echoes a value
        # the configuration read from the environment (a token in a URL it was
        # given, say) does not print it here.
        print(escape(text_without_values(result.stdout, values)))
        print(escape(text_without_values(result.stderr, values)))
        if not run_succeeded(result):
            # A run whose output ASH could not record, or one ASH stopped, failed
            # whatever its code says, and may have no code: the answer is a
            # non-zero number either way.
            code = result.returncode
            return code if isinstance(code, int) and code != 0 else 1
        return result.returncode
    except Exception as e:
        print(
            f"[bold red]Error running command {escape(_shown_command(args, values))}: "
            f"{escape(error_text(e, values))}[/bold red]"
        )
        return 1


@dependencies_app.command(name="install")
def install_dependencies(
    # A str, not a Path: Typer makes "" Path(""), whose str() is ".", the same as
    # an explicit ".", so `--bin-path "$UNSET_VAR"` installed into the working
    # directory. A blank value (is_blank_bin_path) is no value, and so is the
    # default when there is no bin directory (ASH_BIN_PATH None).
    bin_path: Optional[str] = typer.Option(
        str(ASH_BIN_PATH) if ASH_BIN_PATH is not None else None,
        "--bin-path",
        "-b",
        help="Path to install binaries to.",
        envvar="ASH_BIN_PATH",
        # The default is resolved from $HOME (or $ASH_BIN_PATH) at import, so the
        # help shows "~/.ash/bin" and not that path, which would put one machine's
        # home directory into every rendering. "[env var: ASH_BIN_PATH]" says what
        # overrides it.
        show_default="~/.ash/bin",
        # Named as the Path option it was, not as Typer's <str>.
        metavar="<path>",
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
    if not color:
        # --no-color reached the logger only; the panels, the table and the
        # print() lines, written through these consoles, stayed colored.
        for sink in (console, err_console, global_console()):
            sink.no_color = True

    # An unknown --plugin-type is refused first, before anything is resolved,
    # probed or installed, with an unknown --tool's code, naming the value and the
    # types there are. Read as a scanner type, `--plugin-type nosuch` would install
    # every scanner's tool, and offline wait on uv resolving them.
    unknown_types = [
        value for value in dict.fromkeys(plugin_types) if value not in PLUGIN_KINDS
    ]
    if unknown_types:
        console.print(
            Panel(
                "[bold red]Unknown plugin type(s): "
                f"{escape(', '.join(unknown_types))}[/bold red]\n"
                f"[cyan]Plugin types:[/cyan] {escape(', '.join(PLUGIN_KINDS))}",
                title="Nothing installed",
                expand=False,
            )
        )
        raise typer.Exit(EXIT_BAD_SELECTION)
    # A repeated value selects its kind once: `--plugin-type scanner --plugin-type
    # scanner` built and installed every scanner twice.
    plugin_types = list(dict.fromkeys(plugin_types))

    # A named config file that is not there is refused before the bin directory is
    # made, the environment is changed or any plugin is resolved: resolve_config
    # would answer it with the default configuration, and the installs that follow
    # would be for a configuration other than the one named.
    _refuse_a_named_config_that_does_not_exist(config)

    # Read before set_environ below overwrites it: a --bin-path that came from the
    # environment already reaches every scan that inherits it. Blank is unset.
    bin_path_from_environment = ash_bin_path_from_environment()
    # The default when no bin path was given, or a blank one, from the option or
    # from a whitespace-only ASH_BIN_PATH that click passes through as given.
    target_bin_path: Optional[Path]
    if is_blank_bin_path(bin_path):
        target_bin_path = ASH_BIN_PATH
    elif _is_under_tilde(bin_path):
        # A "~" a shell left unexpanded (a quoted --bin-path, or ASH_BIN_PATH set
        # to it) is expanded from the home directory only when there is a usable
        # one (usable_home), as ~/.ash/bin is. Path.expanduser takes HOME as given:
        # an empty HOME made ~/.ash/bin the filesystem's /.ash/bin, and a relative
        # HOME put it under the working directory, the scanned repository.
        home = usable_home()
        target_bin_path = None if home is None else _bin_path_under_home(bin_path, home)
    else:
        # expanduser's own RuntimeError for a "~user" with no such user is a
        # refusal too, not a traceback.
        try:
            target_bin_path = Path(bin_path).expanduser()
        except (RuntimeError, OSError, ValueError) as e:
            print(
                f"[red]--bin-path {escape(str(bin_path))} cannot be expanded: "
                f"{escape(error_text(e))}[/red]"
            )
            raise typer.Exit(EXIT_INVALID_CONFIG)
    if target_bin_path is None:
        # No --bin-path, no ASH_BIN_PATH and no usable home for ~/.ash/bin, or a
        # bin path under "~" with no usable home: nowhere to install. Refused
        # before anything is installed or created, with a scan's
        # invalid-configuration code, as an unusable --config is.
        print(f"[red]{escape(NO_BIN_DIRECTORY)}[/red]")
        raise typer.Exit(EXIT_INVALID_CONFIG)
    # The working directory is the source tree this command installs for. Deleted
    # or unmounted under the shell, Path.cwd() raised FileNotFoundError after the
    # panel was printed; it is the usage error a scan gives such a directory.
    # Checked before the bin path is made absolute: os.path.abspath reads the
    # working directory for a relative path, so a relative --bin-path or
    # ASH_BIN_PATH under a deleted directory raised the same error out of the
    # command, with the failed-install code, before this check was reached.
    try:
        source_dir = Path.cwd()
    except OSError:
        print(
            "[red]Source directory does not exist: the current directory was "
            "deleted or unmounted. Change to a directory that exists.[/red]"
        )
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)

    # Exported absolute, for the install's own commands and the sweep below: tool
    # lookup does not search a relative ASH_BIN_PATH
    # (subprocess_utils.find_executable). The panel shows the value as given. The
    # directory itself is made just before the installs run (below), after every
    # refusal of this command's own.
    absolute_bin_path = Path(os.path.abspath(target_bin_path))
    set_environ("ASH_BIN_PATH", str(absolute_bin_path))

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
        print(f"[red]Invalid configuration: {escape(error_text(e))}[/red]")
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
    # The values and keys the config read from the environment, for each failure
    # below: a plugin's own error can name one, and a key the file read from the
    # environment is the variable's value by then.
    environment_values = resolved_config._environment_values

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
    except PluginModuleNamespaceError as e:
        # The config names something that is not a plugin module. Installing for
        # the built-in set instead would report success for a config whose own
        # plugins got nothing. In the install's own closing words: the scan's
        # say nothing was scanned and name options this command does not have.
        message = e.shown_with(
            "Nothing was imported and nothing was installed. Rename the package "
            "or name the packages inside it, or remove the entry from the "
            "config file or --config-overrides."
        )
        print(f"[red]Invalid configuration: {escape(message)}[/red]")
        raise typer.Exit(EXIT_INVALID_CONFIG)
    except PluginModuleError as e:
        # A configured module could not be loaded; the fix clause follows the
        # loss's stage (plugin_module_fix).
        message = e.shown_with(
            f"Nothing was installed. {plugin_module_fix(e)}, or remove "
            "the entry from the config file or --config-overrides."
        )
        print(f"[red]Invalid configuration: {escape(message)}[/red]")
        raise typer.Exit(EXIT_INVALID_CONFIG)
    except ASHConfigValidationError as e:
        # Any other refusal plugin loading raises is still an invalid
        # configuration: the arms above name the module refusals only to pick
        # their closing words, and this one keeps the type's documented exit
        # code instead of a traceback. Redacted with the run's values, like
        # every other failure printed below: the anticipated-by-nobody arm is
        # exactly where an unredacted value is likeliest.
        print(
            "[red]Invalid configuration: "
            f"{escape(error_text(e, environment_values))}[/red]"
        )
        raise typer.Exit(EXIT_INVALID_CONFIG)
    outcomes: List[PluginInstallOutcome] = []
    construction_failures: List[PluginInstallOutcome] = []
    discovered: List[tuple] = []
    # Each failed plugin's outcome by the name it is selected with, where that name
    # is known without building it; see _declared_install_name. A list per name:
    # two plugin classes can declare one name, and a dict that kept one outcome per
    # name reported only the last failure.
    failures_by_name: dict[str, List[PluginInstallOutcome]] = {}

    def discover(plugin_type: str, warn: bool = True, classes=None):
        """The plugins of one type, each built from its own section of the config.

        The install's own selection is lazy (candidates and build below); this
        builds a whole kind at once, or only ``classes`` of it, and the --tool
        check uses it quietly to ask whether a requested name belongs to a kind
        --plugin-type left out, without recording that kind's failures against
        this run's outcome.
        """
        found: List[tuple] = []
        failed: List[PluginInstallOutcome] = []
        plugin_module_input = _plugin_kind(plugin_type)
        for plugin_class in (
            ash_plugin_manager.plugin_modules(plugin_module_input)
            if classes is None
            else classes
        ):
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
                        f"not be loaded: "
                        f"{escape(error_text(e, environment_values))}[/bold yellow]",
                    )
                failed.append(
                    PluginInstallOutcome(
                        name=plugin_class.__name__,
                        plugin_type=plugin_type,
                        errors=[error_text(e, environment_values)],
                    )
                )
        return found, failed

    candidates: List[tuple] = []
    for plugin_type in plugin_types:
        plugin_module_input = _plugin_kind(plugin_type)
        for plugin_class in ash_plugin_manager.plugin_modules(plugin_module_input):
            candidates.append(
                (
                    plugin_type,
                    plugin_module_input,
                    plugin_class,
                    _declared_install_name(
                        plugin_class, plugin_module_input, resolved_config
                    ),
                )
            )

    # Deprecated aliases are resolved first, so `--tool ArchiveConverter` selects,
    # installs and is judged exactly as `--tool archive` is (see below); then each
    # name takes the spelling of the plugin it matches without regard to case, as
    # the scan matches names (_canonical_tool_names).
    #
    # The alias-resolved names are kept (`aliased`): this first pass sees only the
    # names plugins declare, so with a plugin whose name is known only by building
    # it, it is a provisional reading for the option check below, and the check
    # of the --tool names is made again, from `aliased`, once those plugins are
    # built. Started from this pass's output, that check took a spelling that
    # exactly names a built-only plugin for the declared twin it had been
    # rewritten to, chose silently between two plugins, and refused a spelling
    # that exactly names a built-only plugin.
    aliased = _resolve_tool_aliases(tools)
    tool_resolution = _canonical_tool_names(
        aliased,
        [candidate[3] for candidate in candidates if candidate[3]],
        strict=all(candidate[3] for candidate in candidates),
    )
    requested_names = list(dict.fromkeys(tool_resolution.values()))

    # Before any plugin is built, as the scan engine and ash report check: an
    # unknown or refused option of a plugin loaded from ash_plugin_modules makes
    # the configuration one a scan refuses, so it is refused here too, exit 3,
    # and the refusal names no value or key read from the environment. Left to
    # the plugin's own model, it would be refused mid-build and the run would show
    # it as a FAILED row. Only the plugins this run builds: the kinds
    # --plugin-type names and, with --tool, the plugins requested and each plugin
    # whose name is known only by building it, which a --tool run builds to learn
    # it. Another plugin's problem is reported at info, as an unrelated plugin is
    # here.
    built_kinds = {candidate[1] for candidate in candidates}
    requested_classes = _requested_classes(candidates, requested_names)

    def builds(plugin_module_input: str, plugin_class: type) -> bool:
        if plugin_module_input not in built_kinds:
            return False
        return not tools or plugin_class in requested_classes

    try:
        refuse_unknown_options_of_registered(
            resolved_config, ash_plugin_manager, builds=builds
        )
    except ASHConfigValidationError as e:
        print(f"[red]Invalid configuration: {escape(error_text(e))}[/red]")
        raise typer.Exit(EXIT_INVALID_CONFIG)

    def build(plugin_type, plugin_module_input, plugin_class, declared_name) -> None:
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
                getattr(plugin_instance.config, "name", None) or plugin_class.__name__
            )
            discovered.append((plugin_type, plugin_name, plugin_instance))
        except Exception as e:
            # Reported as a warning here and weighed by the verdict later, because
            # whether it is fatal depends on the run: a --tool run answers only for
            # what it was asked about, so an unrelated plugin that will not
            # construct is information rather than this run's failure.
            print(
                f"[bold yellow]Plugin {escape(plugin_class.__name__)} could not "
                f"be loaded: {escape(error_text(e, environment_values))}"
                "[/bold yellow]",
            )
            # Held aside rather than added to `outcomes` directly. `outcomes` is
            # what the verdict is computed from, and a plugin that failed to
            # construct is unrelated to a `--tool` request for a different one --
            # so folding it in unconditionally made
            # `ash dependencies install --tool trivy-repo` exit 1 because some
            # other community plugin would not import, and name that other plugin
            # in the failure panel.
            # A plugin its configuration disables is one a scan never runs, so
            # its error does not decide a full run's exit code (the documented
            # rule, PluginInstallOutcome.needed); read from its section, since
            # the built plugin that would have said so does not exist.
            failure = PluginInstallOutcome(
                name=plugin_class.__name__,
                plugin_type=plugin_type,
                errors=[error_text(e, environment_values)],
                disabled_by_config=_section_disables(
                    resolved_config, plugin_module_input, plugin_class
                ),
            )
            construction_failures.append(failure)
            if declared_name:
                failures_by_name.setdefault(declared_name, []).append(failure)

    # --tool selection. Validated against the names the plugins answer to rather than
    # a hardcoded list, so it cannot drift from the plugin registry. An unknown name
    # is refused: silently installing nothing for `--tool gryp` would be a typo that
    # reports success, which is the class of bug this whole change is about.
    #
    # Refused before any plugin is built. Building bandit, checkov, semgrep and the
    # jupyter converter probes their version with `uv tool run --from <req> <tool>
    # --version`, which downloads each tool's environment, so `--tool <typo>` used
    # to download about 312 MB and then refuse the name. The names come from each
    # plugin's config class and its section of the resolved config; only a plugin
    # whose name cannot be read that way (no config class declaring one) is built
    # to learn it, and after the check only the requested plugins are built.
    #
    # The aliases were resolved above (tool_resolution). An unknown name is still
    # reported in the spelling the caller typed.
    if tools:
        for candidate in candidates:
            if candidate[3] is None:
                build(*candidate)
        available = sorted(
            {candidate[3] for candidate in candidates if candidate[3]}
            | {name for _, name, _ in discovered}
        )
        # Matched as typed first, then by the key the scan selects scanners with
        # (_selection_key, _canonical_tool_name), so a name typed in another
        # case, or with blanks around it, selects the plugin it names and is
        # installed under the plugin's own spelling, while a plugin whose name
        # differs from another's only in case is still selected by its exact
        # spelling, and a name that selects two plugins by key is refused. An
        # unknown name is still reported as the caller typed it.
        tool_resolution = _canonical_tool_names(aliased, available)
        requested_names = list(dict.fromkeys(tool_resolution.values()))
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
                # Read, not built: the names come from each plugin's config class
                # and its section of the resolved config, as the selected kinds'
                # candidates do above. discover() of a whole kind constructs every
                # plugin of it, and bandit, checkov, semgrep and the jupyter
                # converter probe their version while constructed, with `uv tool
                # run --from <req> <tool> --version`, which resolves and downloads
                # each tool's environment: `--plugin-type reporter --tool grype`
                # downloaded the scanners and converters to say grype is a
                # scanner. Only a plugin that declares no name is built to learn
                # it, quietly, as the selected kinds' unnamed plugins are.
                names = set()
                unnamed = []
                for plugin_class in ash_plugin_manager.plugin_modules(kind):
                    declared = _declared_install_name(
                        plugin_class, kind, resolved_config
                    )
                    if declared is None:
                        unnamed.append(plugin_class)
                    else:
                        names.add(declared)
                if unnamed:
                    found, failed = discover(kind, warn=False, classes=unnamed)
                    lookup_failures += failed
                    names |= {name for _, name, _ in found}
                keys = {_selection_key(name) for name in names}
                for typed in unknown:
                    if _selection_key(tool_resolution[typed]) in keys:
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
            # Out of the run's scope entirely, so the post-build check below does
            # not refuse the names this run just skipped.
            tool_resolution = {
                typed: name
                for typed, name in tool_resolution.items()
                if name in available
            }
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
            # A community scanner that ships with ASH is not a typo when its module
            # is simply not loaded: say which module to add.
            from automated_security_helper.core.community_scanners import (
                community_module_for,
            )

            community = {
                name: module
                for name in unknown
                if (module := community_module_for(name))
            }
            community_note = "".join(
                f"\n[yellow]{escape(name)}[/yellow] is a community plugin scanner: "
                + escape(
                    f"load {module} with --config (ash_plugin_modules) or "
                    f'--config-overrides "ash_plugin_modules+=[{module}]".'
                )
                for name, module in sorted(community.items())
            )
            console.print(
                Panel(
                    f"[bold red]Unknown tool(s): "
                    f"{escape(', '.join(sorted(unknown)))}[/bold red]\n"
                    f"[cyan]Available:[/cyan] {escape(', '.join(available))}"
                    f"{community_note}{broken_note}",
                    title="Nothing installed",
                    expand=False,
                )
            )
            raise typer.Exit(EXIT_BAD_SELECTION)
        # Only the requested plugins: building the others would run their version
        # probes, and `--tool grype` would download semgrep, checkov and bandit.
        for candidate in candidates:
            if candidate[3] is not None and candidate[3] in requested_names:
                build(*candidate)
        # A requested plugin that exists but would not build is this run's failure,
        # named, rather than an unknown name: every failure of that name, since
        # two plugin classes can declare one.
        for name in requested_names:
            for failure in failures_by_name.get(name, []):
                # Recorded on the outcome itself: it is named by its class
                # (``CfnNagScanner``) and the request by the declared name
                # (``cfn-nag``), so the tally's name match never found it, and a
                # requested plugin its section disables read as not counted, exit
                # 0, "Installation Complete".
                failure.requested = True
                outcomes.append(failure)
        # Only reachable if a plugin's built name differs from the one read from its
        # config, which no bundled plugin does; refused rather than reported as
        # installed.
        built_names = {name for _, name, _ in discovered} | set(failures_by_name)
        _refuse_unknown_tools(
            {
                typed: name
                for typed, name in tool_resolution.items()
                if name not in built_names
            },
            sorted(name for _, name, _ in discovered),
            construction_failures,
        )
        selected = [entry for entry in discovered if entry[1] in requested_names]
    else:
        for candidate in candidates:
            build(*candidate)
        # Only a run that was not narrowed to specific tools answers for every
        # plugin, so construction failures count against the verdict only here.
        outcomes.extend(construction_failures)
        selected = discovered

    # The bin directory is made here, after every refusal above (a --config that is
    # not there, a configuration a scan refuses, a plugin module that does not
    # load, an unknown --tool or --plugin-type): made first, a refused run that
    # printed "Nothing installed" had still created it. A regular file at the
    # path, a file as a parent or a parent this user cannot write is a refusal
    # with the invalid-configuration code, as an unusable --config is, where it
    # was a traceback with the failed-install code.
    try:
        absolute_bin_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(
            f"[red]The bin directory {escape(str(target_bin_path))} cannot be "
            f"created: {escape(error_text(e))}. Name a directory with --bin-path "
            "(or ASH_BIN_PATH) that can be made.[/red]"
        )
        raise typer.Exit(EXIT_INVALID_CONFIG)

    ash_environment_requirements: List[str] = []
    # For run_command's lines about each child; reset once the installs are done.
    # Through the one normalizer every redaction reads values with, so a lone
    # string is one value, never its characters.
    install_values = _INSTALL_VALUES.set(value_tuple(environment_values))
    try:
        for plugin_type, plugin_name, plugin_instance in selected:
            outcome = PluginInstallOutcome(
                name=plugin_name,
                plugin_type=plugin_type,
                command=getattr(plugin_instance, "command", None),
                uv_managed=getattr(plugin_instance, "use_uv_tool", False) is True,
                external_executables=tuple(
                    getattr(plugin_instance, "external_executables", ()) or ()
                ),
                runs_in_ash_interpreter=getattr(
                    plugin_instance, "runs_in_ash_interpreter", False
                )
                is True,
                requested=plugin_name in requested_names,
                plugin=plugin_instance,
            )
            outcomes.append(outcome)

            print(
                f"Installing dependencies for {escape(plugin_type)} plugin: "
                f"{escape(plugin_name)}"
            )
            try:
                outcome.unsupported_platform, outcome.disabled_by_config = _scan_skip(
                    plugin_instance
                )
            except Exception as e:
                # Counted as needed, and failing, since it is unknown that a scan
                # would skip it; its install still runs.
                print(
                    f"[bold red]ASH could not tell whether a scan runs "
                    f"{escape(plugin_name)} here: "
                    f"{escape(error_text(e, environment_values))}[/bold red]"
                )
                outcome.errors.append(error_text(e, environment_values))
            try:
                # Read whole, and checked, inside the try: a list that is None, an
                # iterable that raises while iterated, or an argv with an element
                # that is not text aborted the whole run with a traceback before
                # the results table, outside the per-plugin error isolation.
                commands = _well_formed_commands(
                    plugin_instance.get_installation_commands(platform_name, arch)
                )
            except Exception as e:
                print(
                    f"[bold red]Error getting installation commands for plugin "
                    f"{escape(plugin_name)}: "
                    f"{escape(error_text(e, environment_values))}[/bold red]"
                )
                outcome.errors.append(error_text(e, environment_values))
                continue

            for cmd, shell in commands:
                # An empty argv is not a command. These reached run_command before
                # this change, failed, and pushed the run's exit code to 1 -- which
                # then went nowhere, because the returned code was discarded.
                # Skipping them and counting them separately keeps a
                # declared-but-empty entry from masquerading as an attempt.
                if not cmd:
                    print(
                        f"[yellow]Skipping an empty install command declared by "
                        f"{escape(plugin_name)}[/yellow]"
                    )
                    outcome.commands_skipped_empty += 1
                    continue

                if not shell:
                    cmd = _with_path_imported(cmd)

                # A pinned binary that is already on disk, byte for byte, is not
                # installed a second time. The image installs syft, grype and trivy
                # into /usr/local/bin before this runs, and this used to write
                # another copy of each into the bin path -- twice, once per image
                # stage. Decided by the bytes, never the name: a same-named binary
                # that does not hash to the pinned executable digest is installed
                # over as before.
                present = pinned_install_already_satisfied(cmd)
                if present is not None:
                    print(
                        f"Already present: {escape(present.tool)} "
                        f"{escape(present.version)} at {escape(str(present.path))} "
                        f"matches the pinned SHA256 {present.sha256}; not installing "
                        "a second copy"
                    )
                    outcome.commands_satisfied += 1
                    continue

                # An argv routinely carries brackets -- `pip install ash[sarif,toml]`
                # -- and rich would read `[sarif,toml]` as a tag and drop it from the
                # line. On one line, unfolded, so it can be copied; it carries the
                # absolute bin directory, whose length differs from machine to
                # machine. Shown as run_command shows it: without the values the
                # configuration read from the environment, and whatever the plugin
                # put in its argv.
                console.print(
                    "Running command: "
                    f"{escape(_shown_command(cmd, environment_values))}",
                    soft_wrap=True,
                )
                outcome.commands_attempted += 1
                # A CustomCommand declared with shell=True runs through the shell,
                # as declared; the flag was dropped before the installer saw it.
                cmd_exit_code = (
                    run_command(cmd, shell=shell) if shell else run_command(cmd)
                )
                if cmd_exit_code != 0:
                    print(f"Command failed with exit code: {cmd_exit_code}")
                    outcome.commands_failed += 1
                else:
                    print(f"Command succeeded with exit code: {cmd_exit_code}")
                    outcome.commands_succeeded += 1
                    ash_environment_requirements.extend(_ash_environment_install(cmd))
    finally:
        # Whatever escapes the loop (a plugin helper raising, an interrupt), the
        # values are reset: an in-process caller (a test runner, an embedding
        # host) would otherwise redact its next run with this run's values.
        _INSTALL_VALUES.reset(install_values)

    # Said once, after the installs, for packages added to ASH's own environment
    # when the tool that owns it removes them again later (uv tool upgrade, a
    # rebuilt uvx environment).
    rebuild_note = (
        environment_rebuild_note(ash_environment_requirements)
        if ash_environment_requirements
        else None
    )
    if rebuild_note:
        print(f"[yellow]Note:[/yellow] {escape(rebuild_note)}")

    # Post-install sweep. Forget the paths found before the install, so each tool
    # is looked up again now that it is installed.
    clear_find_executable_cache()
    for outcome in outcomes:
        # Looked up as a scan of this tree looks a tool up (find_executable_for_scan
        # with the source tree as its root): a copy found only inside the working
        # directory, the tree this command treats as the source, is refused there,
        # and the plain lookup reported it installed while the scan refused it.
        # Programs the plugin needs besides its command are looked up for every
        # plugin that names any, a plugin with no command included.
        outcome.missing_executables = [
            name
            for name in outcome.external_executables
            if not find_executable_for_scan(name, source_dir)
        ]
        if outcome.needs_external_tool:
            outcome.executable = _resolved_executable(outcome, source_dir)
            if outcome.executable is None and outcome.uv_managed:
                outcome.executable = _uv_tool_executable(outcome.command)
            # Last, and only for a plugin the verdict counts (see
            # _report_and_exit) that declares its check can start the tool off
            # PATH: the plugin's own check, the one a scan runs. A tool run
            # through `uv tool run` is judged by uv's listing alone: that is
            # what uv can start without installing, and its own check installs
            # what uv does not list. A plugin without the declaration is judged
            # by the lookups above: most checks are the same PATH lookup the
            # sweep just made, so asking them can only answer True for a tool
            # nothing here can start. An outcome with a failed command or an
            # error keeps its exit-1 verdict unasked: the answer stopped
            # mattering, and a check with an install path can cost its full
            # install timeout.
            instance = outcome.plugin
            if (
                outcome.executable is None
                and not outcome.uv_managed
                and _declares_off_path_resolution(instance)
                and not outcome.commands_failed
                and not outcome.errors
                and (outcome.needed or outcome.name in requested_names)
            ):
                # Said, the way each install command is shown with "Running
                # command:": the check is this verdict's only evidence for the
                # tool, and it is the plugin's own code.
                console.print(
                    f"Asking {escape(outcome.name)}'s own dependency check "
                    "whether a scan can run its tool (it declares "
                    "resolves_tool_off_path)",
                    soft_wrap=True,
                )
                # The reason for a refusal is asked in the check's own scope.
                answer, reason = _ask_the_check(
                    instance, outcome.name, reason_values=environment_values
                )
                outcome.runnable_by_scan = bool(answer)
                # None means the check raised: not an answer, so the verdict
                # keeps its plain wording and quotes no refusal reason.
                outcome.check_answer = answer
                outcome.shown_refusal_reason = reason

    try:
        return _report_and_exit(outcomes, requested_tools=requested_names)
    finally:
        # Last, whether or not the run failed: what did install went there.
        hint = _bin_path_hint(target_bin_path, bin_path_from_environment)
        if hint:
            console.print(hint, highlight=False, soft_wrap=True)


#: The characters PowerShell ends a single-quoted string on, each written twice to
#: stand for itself: the ASCII quote and the four typographic single quotes.
_POWERSHELL_SINGLE_QUOTES = ("'", "\u2018", "\u2019", "\u201a", "\u201b")


def _bin_path_hint(target: Path, from_environment: Optional[str]) -> Optional[str]:
    """How to make later scans look in ``target``, or None when they already do.

    A scan searches the ASH bin directory, which is ``ASH_BIN_PATH`` when it is set
    and ``~/.ash/bin`` when it is not (an empty or blank value is unset), and no other
    directory ``--bin-path`` named. None when ``target`` is what a scan with this
    environment searches anyway: the absolute ``ASH_BIN_PATH`` itself, however it
    is spelled, or ``~/.ash/bin`` with ``ASH_BIN_PATH`` unset. A relative
    ``ASH_BIN_PATH`` gets the hint, since it names another directory as soon as a
    scan runs somewhere else. The directory is given absolutely for the same reason.
    With no usable home directory there is no ``~/.ash/bin`` a scan searches
    (``core.constants.home_bin_path``), so the hint is given.
    """
    directory = Path(os.path.abspath(target))
    if is_blank_bin_path(from_environment):
        default = home_bin_path()
        if default is not None and directory == Path(os.path.abspath(default)):
            return None
    # is_blank_bin_path is True for None, so this branch always has a string; the
    # check says so to the type checker, which cannot see through the helper.
    # Anchored, as the lookup requires (subprocess_utils.find_executable): on
    # Windows before Python 3.13 isabs accepts a drive-less "\\tools", which the
    # lookup does not search, so the hint is owed for it.
    elif (
        from_environment is not None
        and is_anchored(from_environment)
        and Path(os.path.abspath(from_environment)) == directory
    ):
        return None
    text = str(directory)
    powershell = text
    for quote in _POWERSHELL_SINGLE_QUOTES:
        powershell = powershell.replace(quote, quote * 2)
    return (
        f"[yellow]Note:[/yellow] this install's bin directory is {escape(text)}. "
        "A scan looks for tools there only when ASH_BIN_PATH names it:\n"
        f"  export ASH_BIN_PATH={escape(shlex.quote(text))}    (POSIX shells)\n"
        f"  $env:ASH_BIN_PATH = '{escape(powershell)}'    (PowerShell)"
    )


def _resolved_executable(
    outcome: PluginInstallOutcome, source_dir: Path
) -> Optional[str]:
    """What runs ``outcome.command`` here, or None when the sweep finds nothing.

    A plugin that runs inside ASH's interpreter is run by ``sys.executable``, which
    is present by definition; looking its "python" up on PATH would report cdk-nag
    absent wherever the interpreter is called only ``python3``. Only an absolute
    ``sys.executable`` counts (an embedded interpreter may have an empty or
    relative one); otherwise the name is looked up as a scan of ``source_dir``
    looks it up, so a copy found only inside that tree is not reported installed.
    """
    if outcome.runs_in_ash_interpreter and os.path.isabs(sys.executable or ""):
        return sys.executable
    return find_executable_for_scan(outcome.command, source_dir)


def _section_disables(resolved_config, plugin_type: str, plugin_class: type) -> bool:
    """Whether the plugin's own section of the resolved config says ``enabled:
    false``, read without building the plugin; False when it cannot be read."""
    try:
        section = resolved_config.get_plugin_config(
            plugin_type=plugin_type, plugin_name=plugin_config_key(plugin_class)
        )
    except Exception:
        return False
    enabled = (
        section.get("enabled", True)
        if isinstance(section, dict)
        else getattr(section, "enabled", True)
    )
    return enabled is False


def _with_path_imported(cmd: List[str]) -> List[str]:
    """The opengrep download command with ``Path`` imported, else ``cmd`` as is.

    The fix for that command's ``-c`` script: ``from pathlib import Path`` is
    prepended as a line of its own, so a script that starts with a compound
    statement still parses, and the script's own arguments (``sys.argv``) are
    kept, where the rewrite rebuilt the command from its first three elements and
    joined the import with ``;``. A script that imports Path itself, or that
    starts with a ``__future__`` import (which must come first), is left as
    declared.
    """
    if not (
        len(cmd) > 2
        and cmd[0] == sys.executable
        and cmd[1] == "-c"
        and "opengrep" in cmd[2]
        and "from pathlib import Path" not in cmd[2]
        and "__future__" not in cmd[2]
    ):
        return cmd
    return [sys.executable, "-c", "from pathlib import Path\n" + cmd[2], *cmd[3:]]


def _well_formed_commands(declared: Any) -> List[Tuple[List[str], bool]]:
    """The install commands a plugin declared, each as (argv, shell), checked.

    ``get_installation_commands`` returns a list of argv lists; a
    :class:`CustomCommand` carries its own ``shell`` flag and is run as declared.
    None, a value that is not iterable, an entry that is neither an argv nor a
    CustomCommand, and an argv element that is not text are each a ValueError or
    TypeError naming the entry, which the caller records against that plugin
    alone: iterated bare, each aborted the whole run with a traceback.

    A path object (``os.PathLike``) is text to this check: subprocess accepts one
    as an argv element, and a plugin that builds its command from a ``Path`` is
    run as it would be by hand. It is taken as its ``os.fspath`` text, so the
    runner and the "Running command" line see one shape.
    """
    if declared is None:
        raise ValueError("get_installation_commands returned None, not a list")
    commands: List[Tuple[List[str], bool]] = []
    for position, entry in enumerate(declared):
        if isinstance(entry, CustomCommand):
            argv, shell = list(entry.args), bool(entry.shell)
        elif isinstance(entry, (list, tuple)):
            argv, shell = list(entry), False
        else:
            raise TypeError(
                f"install command {position} is {type(entry).__name__}, not a list "
                "of arguments"
            )
        text_argv: List[str] = []
        for item in argv:
            if isinstance(item, os.PathLike):
                item = os.fspath(item)
            if not isinstance(item, str):
                raise TypeError(
                    f"install command {position} holds {type(item).__name__}, not text"
                )
            text_argv.append(item)
        commands.append((text_argv, shell))
    return commands


def _uv_tool_executable(command: str) -> Optional[str]:
    """Where uv installed ``command`` as a tool, or None if uv does not list it.

    bandit, checkov, semgrep and the jupyter converter run through
    ``uv tool run``, which works with uv's tool bin directory off PATH, so for
    them "installed" is what ``uv tool list`` says, not what PATH finds.
    """
    from automated_security_helper.utils.uv_tool_runner import get_uv_tool_runner

    runner = get_uv_tool_runner()
    try:
        if not (runner.is_uv_available() and runner.is_tool_installed(command)):
            return None
    except Exception:
        return None
    return f"uv tool {command}"


def _declares_off_path_resolution(plugin_instance: Optional[Any]) -> bool:
    """Whether the plugin declares its dependency check can start its tool off PATH.

    Only ``resolves_tool_off_path is True`` declares it: a plugin without the
    attribute, or with any other value, is judged by the lookups alone. A
    plugin whose declaration raises is undeclared too, so one plugin's property
    cannot stop the sweep, and the verdict, for every other. The exception's
    type is logged at DEBUG, without its message.
    """
    if plugin_instance is None:
        return False
    try:
        return getattr(plugin_instance, "resolves_tool_off_path", False) is True
    except Exception as e:
        ASH_LOGGER.debug(
            f"{type(e).__name__} reading a plugin's resolves_tool_off_path; it "
            "counts as undeclared"
        )
        return False


def _scan_can_run(
    plugin_instance: Optional[Any], name: Optional[str] = None
) -> Optional[bool]:
    """Whether the plugin's own dependency check can start its tool.

    This is the resolution a scan uses (``validate_plugin_dependencies``), so the
    verdict and the scan agree about what counts as present: a plugin can start a
    tool the PATH lookup does not find. Asked only for a plugin that declares
    ``resolves_tool_off_path``: most checks are the same PATH lookup the sweep
    just made, and an undeclared plugin keeps the plain verdict, so a requested
    tool that is absent everywhere keeps exit 1. Not asked for a tool run
    through ``uv tool run``, whose presence is uv's listing
    (``_uv_tool_executable``). A check that raises returns None, not False: an
    installer cannot treat a crash as a tool, but a crash is not an answer
    either, so the verdict keeps its plain "still not on PATH" wording instead
    of quoting a refusal the check never gave. The crash is said, named by
    plugin and by the exception's type, and no more: the message can carry
    whatever the check read (a path, a configuration value), and this verdict
    shows none of it.

    The check runs inside ``plugin_probe_scope``, the sandbox scope ScanPhase
    asks it in, so for these off-PATH tools -- the only ones the sweep asks the
    check about -- the two agree under a sandbox too: a sandbox the host cannot
    provide refuses the check's probes, and the scan does not run the scanner
    (a backend named explicitly records an ERROR naming the backend; ``auto``
    with no working backend records MISSING). A check that starts no probe
    (detect-secrets reads its library in-process) agrees through the scope's
    other channel: an unavailable backend is recorded as the plugin's
    ``dependency_unavailable_reason`` (``_record_probe_refusal``), the field
    such a check reads first, so it answers False too. Outside the scope, the
    same probe ran unsandboxed and answered True for a tool no scan here can
    run. A tool
    the PATH lookup finds never reaches this function: the lookup reports it,
    and its scanner answers for itself at scan time.

    It also runs in check-only mode (``checking_only``), the way the scanner
    inventory asks it: the question is "can a scan run this tool now", and an
    answer that needs a network install isn't that. Inside it, a check's own
    install step is skipped and every ``uv tool run`` probe runs ``--offline``,
    so answering costs no install and no download.
    """
    return _ask_the_check(plugin_instance, name)[0]


def _ask_the_check(
    plugin_instance: Optional[Any],
    name: Optional[str] = None,
    reason_values: Optional[Iterable[str]] = None,
) -> Tuple[Optional[bool], Optional[str]]:
    """``_scan_can_run``'s answer, and with ``reason_values`` the reason for a
    refusal (``_refusal_reason``, redacted with them).

    The reason is plugin code too (``missing_dependency_reason()``, and the
    plugin's ``_environment_values()``), so it is asked in the same scope as
    the check, check-only and the probe's sandbox scope: an override that
    probes installs nothing and downloads nothing here either.
    """
    from automated_security_helper.utils.sandbox.scope import plugin_probe_scope
    from automated_security_helper.utils.terminal_text import shown_not_obeyed
    from automated_security_helper.utils.uv_tool_runner import checking_only

    if plugin_instance is None:
        return False, None
    try:
        with (
            checking_only(),
            plugin_probe_scope(
                plugin_instance, getattr(plugin_instance, "context", None)
            ),
        ):
            answer = bool(plugin_instance.validate_plugin_dependencies())
            if answer or reason_values is None:
                return answer, None
            # The check said no. Reading its reason is plugin code too, and a
            # read that raises leaves that answer as it is, with no reason.
            try:
                reason = _refusal_reason(plugin_instance, reason_values)
            except Exception as e:  # noqa: BLE001 -- the check's no stands
                ASH_LOGGER.debug(
                    f"{name or type(plugin_instance).__name__}'s refusal reason "
                    f"could not be read ({type(e).__name__})"
                )
                reason = None
            return False, reason
    except Exception as e:
        shown = name or type(plugin_instance).__name__
        # The type's name is escaped like the plugin's: type() can give a class
        # any name, and one holding a closing tag would make this print raise.
        console.print(
            f"[yellow]{escape(shown)}'s own dependency check failed "
            f"({escape(type(e).__name__)}); the verdict counts the tool as not "
            "found[/yellow]",
            soft_wrap=True,
        )
        # The record reaches ash.log and, with --debug, any console handler, so
        # the names' terminal controls are shown as escapes here too.
        ASH_LOGGER.debug(
            shown_not_obeyed(f"{shown}'s dependency check raised {type(e).__name__}")
        )
        return None, None


def _refusal_reason(instance: Any, values: Iterable[str]) -> Optional[str]:
    """The plugin's own reason its check said no, or None.

    Named apart from ``scan_phase._missing_dependency_reason``, which always
    gives a reason: this one gives the plugin's words or nothing. They are read
    the way the scan's MISSING row reads them: the plugin's
    ``missing_dependency_reason()`` through the one reader of that hook
    (``base.scanner_plugin.plugin_missing_dependency_reason``), redacted and
    with the home directory written as ``~``. A reason can quote a configured
    path or value. It is redacted with the values the row redacts with
    (``utils.error_text.plugin_environment_values``): ``values``, the ones the
    run's configuration read from the environment, and the plugin's own
    ``_environment_values()`` where it offers them. A plugin whose hook gives
    no text gets no reason here, where the row would add a generic one: this
    line already says the check refused.

    Only the plugin's own words are quoted
    (``base.scanner_plugin.plugin_explains_its_own_refusal``): a reason its
    check recorded, or text its hook gives other than the base hook's generic
    answer. That answer -- usually the tool not found on PATH, "install it with
    `ash dependencies install`" -- would send the user back to this command
    from its own failure panel, and blame PATH for a check that refused. It
    gets no reason here, from the base hook or from an override that falls
    back to it.
    """
    from automated_security_helper.utils.error_text import (
        plugin_environment_values,
        text_without_values,
    )
    from automated_security_helper.utils.get_shortest_name import home_as_tilde

    values = plugin_environment_values(instance, values)
    reason = plugin_missing_dependency_reason(
        instance, values, when_it_raises="quoting no reason"
    )
    if reason is None or not plugin_explains_its_own_refusal(instance, reason):
        return None
    return home_as_tilde(text_without_values(reason, values))


def _found_in_uv_listing(outcome: PluginInstallOutcome) -> bool:
    """Whether the sweep found the tool only in uv's listing (_uv_tool_executable),
    which says uv can start it, not that it is on PATH."""
    return outcome.uv_managed and (outcome.executable or "").startswith("uv tool ")


def _report_and_exit(
    outcomes: List[PluginInstallOutcome], requested_tools: List[str]
) -> int:
    """Print the tally and derive the verdict from it.

    The verdict is computed from counts, never assumed. Two things fail a run:

    1. Any install command exited non-zero, or a plugin raised.
    2. A tool the selection needs is absent after the install: its command is not
       found, or a program it needs besides its command (``external_executables``,
       cdk-nag's node) is not, in a full run as with --tool. So a full run that
       installs grype and syft and leaves npm-audit without npm, or cfn-nag's gem
       without ``cfn_nag_scan``, fails, not reporting "Installation Complete"
       before a scan reports those scanners MISSING. Judged by ``is_absent``: a
       plugin with a command of its own, or one that names a program it needs
       besides (``external_executables``) with or without a command; a reporter
       that names neither has nothing to find. Present means
       found by ``find_executable``, or, for a tool run through ``uv tool run``,
       listed by uv, or, for a plugin that declares its check can start the
       tool off PATH, started by that check, the resolution a scan uses
       (``_scan_can_run``).

    Tools with no install path on this platform are reported by name whether or
    not they are present. Present, they do not fail the run: npm-audit needs a Node
    runtime ASH does not install, cfn-nag needs RubyGems, and grype and trivy
    publish no windows/arm64 build, and a machine that already has the tool is in
    the state the installer exists to produce. Absent, they fail it like any other
    absent tool, naming it, so the reader can install it or exclude the scanner.

    Both rules apply only to plugins a scan with this configuration on this
    platform would run (``PluginInstallOutcome.needed``, see ``_scan_skip``), and
    to every plugin named with ``--tool``. A scanner the configuration disables,
    or one that declares the platform unsupported (semgrep on Windows), is not
    looked for by a scan, so unless it was requested its failed install command,
    its error or its absence is reported and does not fail the run. The verdict
    agrees with the scan: what would be MISSING fails here, what would be
    SKIPPED does not.
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
            escape(
                outcome.executable
                or ("its own dependency check" if outcome.runnable_by_scan else "-")
            ),
        )
    console.print(table)

    commands_attempted = sum(o.commands_attempted for o in outcomes)
    commands_failed = sum(o.commands_failed for o in outcomes)

    # Only these decide the verdict; see the docstring. A tool named with --tool
    # always counts: it is an explicit request, and its failure is this run's.
    # Decided once, here: the request recorded on the outcome by the build (a
    # construction failure is named by its class, never by the declared name the
    # request used), or the declared name itself for an outcome made elsewhere.
    def asked(o: PluginInstallOutcome) -> bool:
        return o.requested or o.name in requested_tools

    needed = [o for o in outcomes if o.needed or asked(o)]
    needed_failed = sum(o.commands_failed for o in needed)
    plugins_with_errors = [o.name for o in needed if o.errors]
    # "Verified on PATH" counts a tool the lookup found (ASH's own interpreter
    # for a plugin that runs inside it); a tool known only from uv's listing is
    # not on PATH and is counted on its own line below.
    verified = sorted(
        o.name
        for o in outcomes
        if o.needs_external_tool
        and o.executable
        and not o.missing_executables
        and not _found_in_uv_listing(o)
    )
    uv_listed = sorted(
        o.name
        for o in outcomes
        if o.needs_external_tool
        and _found_in_uv_listing(o)
        and not o.missing_executables
    )
    # Named whether or not the tool happens to be present. "npm is on PATH" and
    # "ASH cannot install npm" are different facts, and a reader planning a CI image
    # needs the second one even when the first is currently true.
    unprovisionable = sorted(
        o.name for o in outcomes if o.needs_external_tool and o.declared_no_commands
    )
    # Not a tool the run just said a scan can run: that one is named under
    # "Not on PATH; a scan can run them", and listing it here too told the
    # reader two stories about one tool.
    missing_after_install = sorted(
        o.name
        for o in outcomes
        if o.needs_external_tool
        and not o.executable
        and not o.runnable_by_scan
        and (o.commands_attempted or o.commands_satisfied)
    )
    already_verified = sorted(o.name for o in outcomes if o.commands_satisfied)
    # Informational, never a failure: off PATH, and started by the resolution a
    # scan uses.
    runnable_off_path = sorted(
        o.name
        for o in outcomes
        if o.needs_external_tool and not o.executable and o.runnable_by_scan
    )

    def label(outcome: PluginInstallOutcome) -> str:
        if outcome.missing_executables:
            return f"{outcome.name} ({', '.join(outcome.missing_executables)})"
        return outcome.name

    absent = sorted((o for o in needed if o.is_absent), key=lambda o: o.name)
    # An absent tool whose own check was asked and said no gets one line that
    # says both: the tool is not on PATH (putting it there makes this sweep
    # find it), and the check, asked in check-only mode, did not find a tool to
    # start. Check-only skips the check's install step, so a scan, which
    # installs, can still answer otherwise.
    check_refused = [o for o in absent if o.check_answer is False]
    path_absent = [o for o in absent if o.check_answer is not False]
    requested_absent = [label(o) for o in path_absent if asked(o)]
    other_absent = [label(o) for o in path_absent if not asked(o)]
    not_available = sorted(
        (o for o in outcomes if o.unsupported_platform is not None),
        key=lambda o: o.name,
    )
    # Named only where it changed the verdict, so a run on Windows does not list
    # every scanner the default configuration turns off there. A requested tool is
    # counted (see `needed`), so it is never one of these.
    disabled_uncounted = sorted(
        o.name
        for o in outcomes
        if o.disabled_by_config
        and o.unsupported_platform is None
        and not asked(o)
        and (o.is_absent or o.commands_failed or o.errors)
    )

    reasons: List[str] = []
    if needed_failed:
        reasons.append(f"{needed_failed} install command(s) failed")
    if plugins_with_errors:
        reasons.append(f"plugin error(s): {', '.join(sorted(plugins_with_errors))}")
    if commands_attempted == 0 and other_absent:
        # The state grype, syft and cfn-nag were in on every CI runner: nothing
        # installed and something needed missing. A requested tool is named by
        # the requested clause below alone, not in both.
        reasons.append(
            "no install commands were run and these are still absent: "
            + ", ".join(other_absent)
        )
    elif other_absent:
        reasons.append(
            "needed tool(s) still absent after install: " + ", ".join(other_absent)
        )
    if requested_absent:
        reasons.append(
            f"requested tool(s) still not on PATH: {', '.join(requested_absent)}"
        )
    for refused in check_refused:
        reasons.append(
            f"{label(refused)}: not on PATH, and its own dependency check "
            "(asked in check-only mode) did not find a tool to start"
            + (
                f": {refused.shown_refusal_reason}"
                if refused.shown_refusal_reason
                else ""
            )
        )
    missing_programs = [label(o) for o in absent if o.missing_executables]

    verified_names = f" -- {escape(', '.join(verified))}" if verified else ""
    summary = [
        f"[cyan]Commands run:[/cyan] {commands_attempted} ({commands_failed} failed)",
        f"[cyan]Tools verified on PATH:[/cyan] {len(verified)}{verified_names}",
    ]
    if uv_listed:
        summary.append(
            f"[cyan]Tools uv manages, in its listing (not on PATH):[/cyan] "
            f"{len(uv_listed)} -- {escape(', '.join(uv_listed))}"
        )
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
    if runnable_off_path:
        summary.append(
            f"[cyan]Not on PATH; a scan can run them:[/cyan] "
            f"{escape(', '.join(runnable_off_path))}"
        )
    if missing_programs:
        summary.append(
            f"[yellow]Programs ASH does not install, not found:[/yellow] "
            f"{escape(', '.join(missing_programs))}"
        )
    if not_available:
        summary.append(
            "[yellow]Not available on this platform:[/yellow] "
            + escape(
                ", ".join(f"{o.name} ({o.unsupported_platform})" for o in not_available)
            )
        )
    if disabled_uncounted:
        summary.append(
            "[yellow]Disabled in the configuration, not counted:[/yellow] "
            + escape(", ".join(disabled_uncounted))
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
