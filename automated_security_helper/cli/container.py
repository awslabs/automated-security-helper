# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash container``: the commands that work with the ASH container image.

``ash container build`` is the command ``ash build-image`` was named in 3.8.
"""

import typer

from automated_security_helper.cli.help_text import BUILD_HELP
from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.cli.json_input import CliJsonInputCommand

container_app = typer.Typer(
    name="container",
    help="Work with the ASH container image.",
    no_args_is_help=True,
)
container_app.command(
    name="build",
    cls=CliJsonInputCommand,
    no_args_is_help=False,
    help=BUILD_HELP,
)(build_ash_image_cli_command)
