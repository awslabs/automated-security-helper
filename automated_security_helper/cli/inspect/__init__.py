# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH outputs and reports.
"""

import typer

from automated_security_helper.cli.inspect.inspect_findings_app import findings_command
from automated_security_helper.utils.log import show_debug_locals
from automated_security_helper.utils.sarif_field_analysis import analyze_sarif_fields

inspect_app = typer.Typer(
    name="inspect",
    help="Inspect and analyze ASH outputs and reports",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    # Not on a CI runner: locals can hold secrets (utils/log.py).
    pretty_exceptions_show_locals=show_debug_locals(),
)

inspect_app.command(
    name="sarif-fields",
    help="""
The `inspect sarif-fields` command analyzes SARIF reports to understand field usage
across different scanners and ensure fields are preserved during aggregation.

This command:
1. Extracts field paths from the original SARIF reports
2. Identifies which scanners populate which fields and their data types
3. Compares fields between original scanner reports and the aggregated report
4. Generates a comprehensive HTML report showing field presence and mapping information
5. Outputs field data in both JSON and CSV formats for further analysis
""",
)(analyze_sarif_fields)
inspect_app.command(
    name="findings",
    help="""
The `inspect findings` command provides an interactive TUI to explore the findings
and identify actions to quickly take.

A finding's code is the code snippet the results hold, wherever the results file is.
For a finding with none, its lines are read from its file only when the results
file sits in <root>/.ash/ash_output, and only from a regular file inside <root>
(a hard link inside the tree counts as a file in it, as it does for the scanners);
otherwise the detail view says "(source not shown)".
""",
)(findings_command)


if __name__ == "__main__":
    from automated_security_helper.cli.entrypoint import run_module_app

    run_module_app(inspect_app)
