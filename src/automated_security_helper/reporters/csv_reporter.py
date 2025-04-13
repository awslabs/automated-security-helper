# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import csv
from io import StringIO
from typing import Any


class CSVReporter:
    """Formats results as CSV."""

    def format(self, model: Any) -> str:
        """Format ASH model as CSV string."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")
        output = StringIO()
        writer = csv.writer(output)

        # Write headers
        writer.writerow(["Finding ID", "Severity", "Description", "Location"])

        # TODO: Implement CSV row writing based on findings

        return output.getvalue()
