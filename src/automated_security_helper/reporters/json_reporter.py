# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any
import json


class JSONReporter:
    """Formats results as JSON."""

    def format(self, model: Any) -> str:
        """Format ASH model as JSON string."""
        if hasattr(model, "__dict__") and model.__dict__:
            return json.dumps(model.__dict__, default=str)
