# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class JSONReporterConfigOptions(ReporterOptionsBase):
    pass


class JSONReporterConfig(ReporterPluginConfigBase):
    name: Literal["json"] = "json"
    extension: str = "json"
    enabled: bool = True


class JSONReporter(ReporterPluginBase[JSONReporterConfig]):
    """Formats results as JSON."""

    def format(self, model: Any) -> str:
        """Format ASH model as JSON string."""
        if hasattr(model, "__dict__") and model.__dict__:
            return json.dumps(model.__dict__, default=str)
