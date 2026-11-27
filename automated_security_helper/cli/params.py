# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading where a command's parameter values came from, shared by the commands."""

import typer


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
