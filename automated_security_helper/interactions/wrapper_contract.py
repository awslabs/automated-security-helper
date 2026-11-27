# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the host wrapper must agree with the ``ashx`` CLI about.

``utils/ash_helpers.ps1`` (``Invoke-ASH``) exists for hosts with no Python, so it
cannot ask the CLI anything at run time. It carries written-out tables of the CLI's own
surface: the subcommand names, which root options take a value, which commands take
the options the wrapper adds and the groups whose words name those commands
(``results report``), the order in which OCI runners are looked for, the CI
runner markers passed into the container, the image build targets, the image-name
pattern and the refusal and usage-error exit codes. Those tables are the part of the
wrapper that drifts when the CLI changes. Every field of the contract is rendered into
a block of the wrapper and read by its own control flow; a field no block renders does
not belong here. v4 removed the second wrapper, the ``./ash`` bash script, and with it
the one table only that script read: the subcommands whose own ``-o`` it forwarded
instead of taking it as the OCI runner.

This module is the one place that computes them. It reads the real typer app and the
constants container mode itself uses, never a hand-kept copy, and
``scripts/generate_wrapper_tables.py`` renders the result into marked blocks inside
the wrapper. It is data only: importing it, or calling :func:`contract`, changes no
behavior anywhere.

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

#: The subcommands that are groups whose own commands take the options a wrapper adds.
#: The group takes none of them itself (`ashx container --quiet build` is a usage
#: error), so a wrapper puts them after the command the group's words name: `container
#: build`, `results report`, `results inspect findings`. `ashx --quiet container build`
#: hands the root's `--quiet` to `build` the same way (AshTyperGroup
#: ._options_for_subcommand). Under the other groups (config, dependencies, plugin,
#: suppress, express) the options a wrapper adds go to no command.
OPTION_ROUTING_GROUPS: tuple[str, ...] = ("results", "container")


def _options(command: Any) -> set[str]:
    found: set[str] = set()
    for param in command.params:
        found.update(getattr(param, "opts", None) or [])
        found.update(getattr(param, "secondary_opts", None) or [])
    return found


def _commands_under(words: str, command: Any) -> list[tuple[str, Any]]:
    """The command *words* names, or, for a group, every command under it (nested
    groups included), each with the words that name it from the root, in CLI order."""
    subcommands = getattr(command, "commands", None)
    if not subcommands:
        return [(words, command)]
    return [
        found
        for name, subcommand in subcommands.items()
        for found in _commands_under(f"{words} {name}", subcommand)
    ]


def _groups_under(words: str, command: Any) -> list[tuple[str, tuple[str, ...]]]:
    """The group *words* names and each group under it, with the names of its own
    commands, in CLI order: how far a command's words go (`results`, then `inspect`,
    then `findings`)."""
    subcommands = getattr(command, "commands", None)
    if not subcommands:
        return []
    found = [(words, tuple(subcommands))]
    for name, subcommand in subcommands.items():
        found += _groups_under(f"{words} {name}", subcommand)
    return found


def _receivers(name: str, command: Any) -> list[tuple[str, Any]]:
    """The commands a wrapper hands its options to under the subcommand *name*, each
    with its words: *name* itself, or every command under a group in
    OPTION_ROUTING_GROUPS."""
    if name in OPTION_ROUTING_GROUPS:
        return _commands_under(name, command)
    return [(name, command)]


@dataclass(frozen=True)
class WrapperContract:
    """The tables the wrappers carry, as the CLI and container mode define them."""

    #: Every subcommand of the root command, in the CLI's own order.
    subcommands: tuple[str, ...]
    #: The subcommands that take ``--sandbox``.
    sandbox_subcommands: tuple[str, ...]
    #: The root options that take a value, long spellings then short, sorted.
    root_value_options: tuple[str, ...]
    #: For each wrapper-forwarded option, the commands that declare it, in order: a
    #: subcommand by its name, a command under a group in OPTION_ROUTING_GROUPS by its
    #: words (`results report`).
    option_subcommands: tuple[tuple[str, tuple[str, ...]], ...]
    #: The groups in OPTION_ROUTING_GROUPS and the groups under them, each with the
    #: names of its own commands, in the CLI's order.
    routed_groups: tuple[tuple[str, tuple[str, ...]], ...]
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

    receivers = [
        receiver
        for name, command in commands.items()
        for receiver in _receivers(name, command)
    ]
    forwarded = []
    for option in WRAPPER_FORWARDED_OPTIONS:
        takers = tuple(
            words for words, command in receivers if option in _options(command)
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
        routed_groups=tuple(
            group
            for name, command in commands.items()
            if name in OPTION_ROUTING_GROUPS
            for group in _groups_under(name, command)
        ),
        runner_order=tuple(rac._OCI_RUNNER_CANDIDATES),
        build_targets=tuple(sorted(target.value for target in BuildTarget)),
        image_name_pattern=rac._IMAGE_NAME_PATTERN.pattern,
        refusal_exit=rac._WRAPPER_REFUSAL_EXIT,
        usage_error_exit=ASH_EXIT_USAGE_ERROR,
        ci_runner_markers=tuple(rac.RUNNER_MARKERS_ON_ARGV),
    )
