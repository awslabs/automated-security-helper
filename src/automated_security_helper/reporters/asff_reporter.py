# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any
import yaml


class ASFFReporter:
    """Formats results as Amazon Security Finding Format (ASFF)."""

    def format(self, model: Any) -> str:
        """Format ASH model in Amazon Security Finding Format (ASFF)."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")
        # TODO - Replace with ASFF adapter
        return yaml.dump(model.model_dump(), indent=2)
