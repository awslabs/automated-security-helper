# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import typer
from automated_security_helper.cli.config import config_app
from automated_security_helper.cli.image import image_build
from automated_security_helper.cli.inspect import inspect_app
from automated_security_helper.cli.plugin import plugin_app
from automated_security_helper.cli.run import run


app = typer.Typer(
    name="ash",
    help="AWS Labs - Automated Security Helper",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
    in ["YES", "1", "TRUE"],
)

app.callback(invoke_without_command=True)(run)
app.command(no_args_is_help=False, name="run")(run)

app.command(
    name="image",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help="""Builds the ASH container image then runs a scan with it.

Any additional arguments passed will be forwarded to ASH inside the container image when starting the scan.
""",
)(image_build)


app.add_typer(config_app, name="config")
app.add_typer(inspect_app, name="inspect")
app.add_typer(plugin_app, name="plugin")

if __name__ == "__main__":
    app()
