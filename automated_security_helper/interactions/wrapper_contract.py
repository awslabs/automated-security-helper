# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the two host wrappers must agree with the ``ash`` CLI about.

``./ash`` (bash) and ``utils/ash_helpers.ps1`` (``Invoke-ASH``) exist for hosts with no
Python, so neither can ask the CLI anything at run time. Each carries written-out
tables of the CLI's own surface: the subcommand names, which root options take a
value, which subcommands take the options the wrapper adds, which commands read stdin
(`./ash` only: `Invoke-ASH` never keeps the container's stdin open), the order in which
OCI runners are looked for, the CI runner markers passed into the container, the image
build targets, the image-name pattern and the refusal and usage-error exit codes.
Those tables are the part of the two wrappers that drifts when the CLI changes.
Every field of the contract is rendered into a block of at least one wrapper and read
by that wrapper's own control flow; a field no block renders does not belong here.

This module is the one place that computes them. It reads the real typer app and the
constants container mode itself uses, never a hand-kept copy, and
``scripts/generate_wrapper_tables.py`` renders the result into marked blocks inside
the two wrappers. It is data only: importing it, or calling :func:`contract`, changes
no behavior anywhere.

What stays hand-written in the wrappers is control flow (mount assembly, refusal
order, the checkout judgment); the agreement suites under ``tests/unit`` hold those
to the Python implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

# The directory refusals both wrappers quote. ``directory_refusals`` owns the texts and
# the codes that name each refusal; they are re-exported here so the wrapper contract
# has one import for everything the wrappers must agree on, and nothing is copied.
from automated_security_helper.utils.directory_refusals import (  # noqa: F401
    REFUSED_CANNOT_BE_CREATED,
    REFUSED_CANNOT_BE_ENTERED,
    REFUSED_CANNOT_BE_WRITTEN,
    REFUSED_NOT_A_DIRECTORY,
    REFUSED_NOT_A_VALID_PATH,
    output_dir_invalid_path,
    output_dir_refusal,
    output_dir_unmakeable,
    output_dir_unwritable,
    source_dir_refusal,
)


#: The options a wrapper adds, or reads, in front of the subcommand's own arguments,
#: in the order the wrappers list them. Which subcommands take each is read from the
#: real commands; this list says only which options the wrappers care about. An option
#: a wrapper must NOT forward is deliberately absent.
WRAPPER_FORWARDED_OPTIONS: tuple[str, ...] = (
    "--quiet",
    "--no-color",
    "--progress",
    "--no-progress",
    "--show-summary",
    "--no-show-summary",
    "--fail-on-findings",
    "--no-fail-on-findings",
    "--verbose",
    "--debug",
    "--offline",
    "--config",
    "--scanners",
    "--exclude-scanners",
    "--ignore-suppressions",
)

#: The subcommands whose own ``-o`` is not the container runtime's. ``scan`` and
#: ``build-image`` are the container-mode commands, where the wrapper reads ``-o`` as
#: the runner; every other command's ``-o`` is its own and is forwarded.
CONTAINER_MODE_SUBCOMMANDS: tuple[str, ...] = ("scan", "build-image", "container")

#: The subcommands that are groups handing the options typed before them to one of
#: their commands (AshTyperGroup._options_for_subcommand), so `./ash --quiet container
#: build` passes `--quiet` on to `build`: such a group takes what that command takes.
OPTION_ROUTING_GROUPS: dict[str, str] = {"container": "build"}

#: The commands that read the caller's stdin, each as the words that name it from the
#: root down (`config`, `lint`). A wrapper keeps the container's stdin open for a run of
#: one of these and for a run given `--cli-json-input -`, and for no other run: -i on a
#: command that reads nothing makes the container take the caller's input, so a
#: `while read` loop that runs `./ash` ended after one line. Every entry is a command,
#: never a group, because a group holds commands that read and commands that do not:
#: `ash config lint` and `ash config wizard` ask before they change a file and the rest
#: of `config` never reads stdin, and `ash results inspect findings` is a terminal app
#: while `ash results report` reads nothing. One command mounted at two paths, as the
#: findings view is (the deprecated top-level `inspect` and `results inspect`), is one
#: entry per path. Whether a command reads stdin is a property of its code, so the list
#: is written out, and `_stdin_readers` refuses a path that names no command or names
#: a group. tests/unit/test_ash_bash_entrypoint_subcommand_args.py reads each command's
#: code and fails when a command reads stdin and is not listed here, or is listed and
#: does not.
STDIN_READING_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("config", "lint"),
    ("config", "wizard"),
    ("inspect", "findings"),
    ("mcp",),
    ("results", "inspect", "findings"),
)


def _options(command: Any) -> set[str]:
    found: set[str] = set()
    for param in command.params:
        found.update(getattr(param, "opts", None) or [])
        found.update(getattr(param, "secondary_opts", None) or [])
    return found


def _taken_options(name: str, command: Any) -> set[str]:
    """The options the subcommand *name* takes when the wrapper hands it one: its own,
    or for a group in OPTION_ROUTING_GROUPS those of the command the options go to."""
    leaf = OPTION_ROUTING_GROUPS.get(name)
    if leaf is not None:
        return _options(command.commands[leaf])
    return _options(command)


def _tree_options(command: Any) -> set[str]:
    """The options of a command and of every command nested under it."""
    found = _options(command)
    for sub in (getattr(command, "commands", None) or {}).values():
        found |= _tree_options(sub)
    return found


def _stdin_readers(
    root: Any, declared: tuple[tuple[str, ...], ...]
) -> tuple[tuple[str, ...], ...]:
    """The declared stdin-reading commands, sorted, each checked against the real tree.

    A path that names no command (a renamed or removed one) or names a group is an
    error here, so a stale entry stops the generator and the contract's own users
    instead of being rendered into a wrapper."""
    for words in declared:
        command = root
        for word in words:
            subcommands = getattr(command, "commands", None) or {}
            if word not in subcommands:
                raise ValueError(
                    f"STDIN_READING_COMMANDS lists `ash {' '.join(words)}`, but the "
                    f"ash CLI has no command `{word}` there"
                )
            command = subcommands[word]
        if getattr(command, "commands", None):
            raise ValueError(
                f"STDIN_READING_COMMANDS lists `ash {' '.join(words)}`, which is a "
                "group: list the commands under it that read stdin"
            )
    return tuple(sorted(declared))


@dataclass(frozen=True)
class WrapperContract:
    """The tables the wrappers carry, as the CLI and container mode define them."""

    #: Every subcommand of the root command, in the CLI's own order.
    subcommands: tuple[str, ...]
    #: The subcommands that take ``--sandbox``.
    sandbox_subcommands: tuple[str, ...]
    #: The root options that take a value, long spellings then short, sorted.
    root_value_options: tuple[str, ...]
    #: For each wrapper-forwarded option, the subcommands that declare it, in order.
    option_subcommands: tuple[tuple[str, tuple[str, ...]], ...]
    #: Subcommands whose own ``-o`` is forwarded instead of read as the runner.
    dash_o_subcommands: tuple[str, ...]
    #: The commands that read the caller's stdin, each as the words that name it, sorted.
    stdin_readers: tuple[tuple[str, ...], ...]
    #: The order OCI runners are looked for when none is named.
    runner_order: tuple[str, ...]
    #: The image stages a wrapper accepts for its build-target parameter.
    build_targets: tuple[str, ...]
    #: The characters an image name may hold, as a regular expression.
    image_name_pattern: str
    #: Exit codes: refusal (also the code for no runner found), and usage error.
    refusal_exit: int
    usage_error_exit: int
    #: The runner markers that are passed into the container by name.
    ci_runner_markers: tuple[str, ...]

    def takers(self, option: str) -> tuple[str, ...]:
        for name, subcommands in self.option_subcommands:
            if name == option:
                return subcommands
        raise KeyError(option)


@lru_cache(maxsize=1)
def contract() -> WrapperContract:
    """Compute the contract from the real typer app and container-mode constants."""
    import typer.main

    from automated_security_helper.cli.main import app
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
    from automated_security_helper.core.enums import BuildTarget
    from automated_security_helper.interactions import run_ash_container as rac

    root: Any = typer.main.get_command(app)
    commands = dict(root.commands)
    subcommands = tuple(commands)

    forwarded = []
    for option in WRAPPER_FORWARDED_OPTIONS:
        takers = tuple(
            name
            for name, command in commands.items()
            if option in _taken_options(name, command)
        )
        forwarded.append((option, takers))

    value_options = sorted(
        spelling
        for param in root.params
        if param.param_type_name == "option" and not param.is_flag and not param.count
        for spelling in param.opts
    )

    return WrapperContract(
        subcommands=subcommands,
        sandbox_subcommands=tuple(
            name
            for name, command in commands.items()
            if "--sandbox" in _options(command)
        ),
        root_value_options=tuple(value_options),
        option_subcommands=tuple(forwarded),
        dash_o_subcommands=tuple(
            name
            for name, command in commands.items()
            if name not in CONTAINER_MODE_SUBCOMMANDS and "-o" in _tree_options(command)
        ),
        stdin_readers=_stdin_readers(root, STDIN_READING_COMMANDS),
        runner_order=tuple(rac._OCI_RUNNER_CANDIDATES),
        build_targets=tuple(sorted(target.value for target in BuildTarget)),
        image_name_pattern=rac._IMAGE_NAME_PATTERN.pattern,
        refusal_exit=rac._WRAPPER_REFUSAL_EXIT,
        usage_error_exit=ASH_EXIT_USAGE_ERROR,
        ci_runner_markers=tuple(rac.RUNNER_MARKERS_ON_ARGV),
    )
