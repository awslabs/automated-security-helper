# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.interfaces import IOutputReporter


class SPDXReporter(IOutputReporter):
    """Formats results as SPDX."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model in SPDX."""
        # TODO - Replace with SPDX adapter
        return yaml.dump(model.model_dump(), indent=2)
