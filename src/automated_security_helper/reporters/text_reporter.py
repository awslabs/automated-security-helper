# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.interfaces import IOutputReporter


class TextReporter(IOutputReporter):
    """Formats results as text."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model as text string."""
        # TODO - Replace with aggregated_results.txt simulator
        return yaml.dump(model.model_dump(), indent=2)
