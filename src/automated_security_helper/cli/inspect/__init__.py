# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH outputs and reports.
"""

import os
import typer

from automated_security_helper.cli.inspect.sarif_fields import analyze_sarif_fields

inspect_app = typer.Typer(
    name="inspect",
    help="Inspect and analyze ASH outputs and reports",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
    in ["YES", "1", "TRUE"],
)

inspect_app.command(
    name="sarif-fields",
    help="""
The `inspect sarif-fields` command analyzes SARIF reports to understand field usage across different scanners and ensure fields are preserved during aggregation.

This command:
1. Extracts field paths from the original SARIF reports
2. Identifies which scanners populate which fields and their data types
3. Compares fields between original scanner reports and the aggregated report
4. Generates a comprehensive HTML report showing field presence and mapping information
5. Outputs field data in both JSON and CSV formats for further analysis
""",
)(analyze_sarif_fields)


if __name__ == "__main__":
    inspect_app()
