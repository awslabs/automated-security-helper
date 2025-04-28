# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import typer
from automated_security_helper.cli.config import config_app
from automated_security_helper.cli.image import image_app
from automated_security_helper.cli.inspect import inspect_app
from automated_security_helper.cli.run import run


app = typer.Typer(
    name="ash",
    help="AWS Labs - Automated Security Helper",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=True,
)

app.callback(invoke_without_command=True)(run)
app.command(no_args_is_help=False, name="run")(run)


app.add_typer(config_app, name="config")
app.add_typer(image_app, name="image")
app.add_typer(inspect_app, name="inspect")

if __name__ == "__main__":
    app()
