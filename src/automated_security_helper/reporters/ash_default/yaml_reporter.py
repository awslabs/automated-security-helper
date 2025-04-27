# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import yaml
from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class YAMLReporterConfigOptions(ReporterOptionsBase):
    pass


class YAMLReporterConfig(ReporterPluginConfigBase):
    name: Literal["yaml"] = "yaml"
    extension: str = "yaml"
    enabled: bool = False
    options: YAMLReporterConfigOptions = YAMLReporterConfigOptions()


class YAMLReporter(ReporterPluginBase[YAMLReporterConfig]):
    """Formats results as YAML."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = YAMLReporterConfig()
        return super().model_post_init(context)

    def report(self, model: Any) -> str:
        """Format ASH model as YAML string."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")
        return yaml.dump(model.model_dump(by_alias=True), indent=2)
