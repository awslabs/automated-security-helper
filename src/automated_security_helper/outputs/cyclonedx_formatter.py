# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.outputs.interfaces import IOutputFormatter


class CycloneDXFormatter(IOutputFormatter):
    """Formats results as CycloneDX."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model in CycloneDX."""
        # TODO - Replace with CycloneDX adapter
        return yaml.dump(model.model_dump(), indent=2)
