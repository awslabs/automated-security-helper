# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash results``: the commands that read, compare and combine saved scan results.

``report``, ``diff``, ``trend``, ``merge`` and ``inspect`` each work on results a
scan already wrote and run no scan, so they sit under one noun instead of beside
``scan`` at the top level. The group only registers the existing implementations
(``report_command``, ``diff_command``, ``trend_command``, ``merge_command`` and
``inspect_app``); no command body lives here.

The old top-level spellings (``ash report`` and the rest) keep working through
4.0 with a stderr deprecation warning and are removed in 4.1; the warning is
emitted by ``AshRootTyperGroup`` in :mod:`automated_security_helper.cli.main`.
"""

import typer

from automated_security_helper.cli.diff import diff_command
from automated_security_helper.cli.inspect import inspect_app
from automated_security_helper.cli.json_input import CliJsonInputCommand
from automated_security_helper.cli.main import MERGE_COMMAND_HELP
from automated_security_helper.cli.merge import merge_command
from automated_security_helper.cli.report import report_command
from automated_security_helper.cli.trend import trend_command
from automated_security_helper.utils.log import show_debug_locals

results_app = typer.Typer(
    name="results",
    help=(
        "Read, compare and combine the results of saved ASH scans: report, diff, "
        "trend, merge and inspect. None of them runs a scan."
    ),
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    # Not on a CI runner: locals can hold secrets (utils/log.py).
    pretty_exceptions_show_locals=show_debug_locals(),
)

results_app.command(name="report", cls=CliJsonInputCommand)(report_command)
results_app.command(name="diff", cls=CliJsonInputCommand)(diff_command)
results_app.command(name="trend", cls=CliJsonInputCommand)(trend_command)
results_app.command(name="merge", cls=CliJsonInputCommand, help=MERGE_COMMAND_HELP)(
    merge_command
)
results_app.add_typer(inspect_app, name="inspect")


if __name__ == "__main__":
    from automated_security_helper.cli.entrypoint import run_module_app

    run_module_app(results_app)
