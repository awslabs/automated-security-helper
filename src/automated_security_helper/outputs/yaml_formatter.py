# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.outputs.interfaces import IOutputFormatter


class YAMLFormatter(IOutputFormatter):
    """Formats results as YAML."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model as YAML string."""
        return yaml.dump(model.model_dump(), indent=2)
