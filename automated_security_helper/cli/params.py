# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading where a command's parameter values came from, shared by the commands."""

from typing import Annotated, Any

import typer


#: The ``--color/--no-color`` option every command shares, declared once.
#:
#: The leading whitespace in ``"  /-C"`` is load-bearing. It is how click
#: disambiguates a short form for the OFF side of a boolean flag. Without it the
#: decl is taken as a literal option named ``/-C`` and ``-C`` is rejected with
#: "No such option", silently and at runtime only.
#:
#: ``-C`` rather than ``-c`` because ``-c`` is ``--config`` on most of these
#: commands. The deleted root bash script used ``-c`` for ``--no-color``, so an old
#: invocation consumes the next argument as a config path; see
#: docs/content/docs/cli-reference.md.
#:
def color_option(default: Any = ..., **extra: Any) -> Any:
    """The shared ``--color/--no-color`` option, with *extra* typer arguments.

    ``scan`` passes ``rich_help_panel``; the ``mcp`` wrapper, which declares its
    default in the option, passes ``True``; every other command takes
    :data:`ColorOption`.
    """
    return typer.Option(
        default,
        "--color/--no-color",
        "  /-C",
        help="Enable/disable colorized output",
        **extra,
    )


#: Use as ``color: ColorOption = True``.
ColorOption = Annotated[bool, color_option()]


def from_environment(ctx: typer.Context, param: str) -> bool:
    """Whether click took *param*'s value from its ``envvar``.

    Compared by the source's name, not against ``click.core.ParameterSource``: the
    source typer's context reports can be an enum of a click copy other than the one
    imported here, which an ``is`` or ``==`` against this module's enum never matches.
    """
    return getattr(ctx.get_parameter_source(param), "name", None) == "ENVIRONMENT"


def from_command_line(ctx: typer.Context, param: str) -> bool:
    """Whether *param*'s value was typed on the command line.

    Compared by the source's name, as :func:`from_environment` does, for the same
    reason. A value from the ``envvar``, from the option's default, from the default
    map or from a prompt is not typed, so it is not "COMMANDLINE".
    """
    return getattr(ctx.get_parameter_source(param), "name", None) == "COMMANDLINE"
