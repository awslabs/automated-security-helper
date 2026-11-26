# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash container``: the commands that work with the ASH container image.

``ash container build`` is the command ``ash build-image`` was named in 3.8.
"""

import typer

from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.cli.json_input import CliJsonInputCommand

BUILD_HELP = """Builds the ASH container image, then scans the current directory with it unless --no-run is given.

It takes only the options below. To scan with scan options, run `ash scan fs --mode container`, which builds the image the same way and accepts every scan option.
"""

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
