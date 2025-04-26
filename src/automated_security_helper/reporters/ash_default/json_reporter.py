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
    extension: str = "flat.json"
    enabled: bool = True
    options: JSONReporterConfigOptions = JSONReporterConfigOptions()


class JSONReporter(ReporterPluginBase[JSONReporterConfig]):
    """Formats results as JSON."""

    def report(self, model: Any) -> str:
        """Format ASH model as JSON string."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        flat_vulns = model.to_flat_vulnerabilities()
        return json.dumps(
            [
                vuln.model_dump(exclude_none=True, exclude_unset=True, mode="json")
                for vuln in flat_vulns
            ],
            indent=2,
        )
