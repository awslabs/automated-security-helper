# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any


class SARIFReporter:
    """Formats results as SARIF."""

    def format(self, model: Any) -> str:
        """Format ASH model in SARIF."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")
        return model.sarif.model_dump_json()
