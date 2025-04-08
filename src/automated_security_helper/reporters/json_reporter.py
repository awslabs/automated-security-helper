# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.interfaces import IOutputReporter


class JSONReporter(IOutputReporter):
    """Formats results as JSON."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model as JSON string."""
        return model.model_dump_json(indent=2, serialize_as_any=True)
