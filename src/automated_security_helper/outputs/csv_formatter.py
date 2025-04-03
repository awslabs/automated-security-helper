# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import csv
from io import StringIO

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.outputs.interfaces import IOutputFormatter


class CSVFormatter(IOutputFormatter):
    """Formats results as CSV."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model as CSV string."""
        output = StringIO()
        writer = csv.writer(output)

        # Write headers
        writer.writerow(["Finding ID", "Severity", "Description", "Location"])

        # TODO: Implement CSV row writing based on findings

        return output.getvalue()
