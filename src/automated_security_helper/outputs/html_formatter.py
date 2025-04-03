# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import html

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.outputs.interfaces import IOutputFormatter


class HTMLFormatter(IOutputFormatter):
    """Formats results as HTML."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model as HTML string."""
        # Basic HTML template
        template = """
        <!DOCTYPE html>
        <html>
        <head><title>ASH Results</title></head>
        <body>
            <h1>Security Scan Results</h1>
            <h2>Findings</h2>
            {findings}
            <h2>Metadata</h2>
            {metadata}
        </body>
        </html>
        """

        # TODO: Implement detailed HTML formatting
        return template.format(
            findings=html.escape(str(model.findings)),
            metadata=html.escape(str(model.metadata)),
        )
