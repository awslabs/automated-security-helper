# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.interfaces import IOutputReporter


class ASFFReporter(IOutputReporter):
    """Formats results as Amazon Security Finding Format (ASFF)."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model in Amazon Security Finding Format (ASFF)."""
        # TODO - Replace with ASFF adapter
        return yaml.dump(model.model_dump(), indent=2)
