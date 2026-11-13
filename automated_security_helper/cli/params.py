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
