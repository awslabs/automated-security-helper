# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the two host wrappers must agree with the ``ash`` CLI about.

``./ash`` (bash) and ``utils/ash_helpers.ps1`` (``Invoke-ASH``) exist for hosts with no
Python, so neither can ask the CLI anything at run time. Each carries written-out
tables of the CLI's own surface: the subcommand names, which root options take a
value, which subcommands take the options the wrapper adds, the order in which OCI
runners are looked for, the CI runner markers passed into the container, the image
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

#: The subcommands that are groups handing the options typed before them to one of
#: their commands (AshTyperGroup._options_for_subcommand), so `./ash --quiet container
#: build` passes `--quiet` on to `build`: such a group takes what that command takes.
OPTION_ROUTING_GROUPS: dict[str, str] = {"container": "build"}


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
    # No table of the subcommands whose own ``-o`` is forwarded instead of read as the
    # runner: the root ``./ash`` script was the one wrapper that read ``-o`` itself, and
    # it is gone, so a field computed for it would be rendered nowhere.
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
        runner_order=tuple(rac._OCI_RUNNER_CANDIDATES),
        build_targets=tuple(sorted(target.value for target in BuildTarget)),
        image_name_pattern=rac._IMAGE_NAME_PATTERN.pattern,
        refusal_exit=rac._WRAPPER_REFUSAL_EXIT,
        usage_error_exit=ASH_EXIT_USAGE_ERROR,
        ci_runner_markers=tuple(rac.RUNNER_MARKERS_ON_ARGV),
    )
