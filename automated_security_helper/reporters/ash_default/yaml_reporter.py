# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import yaml
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class YAMLReporterConfigOptions(ReporterOptionsBase):
    pass


class YAMLReporterConfig(ReporterPluginConfigBase):
    name: Literal["yaml"] = "yaml"
    extension: str = "yaml"
    enabled: bool = False
    options: YAMLReporterConfigOptions = YAMLReporterConfigOptions()


@ash_reporter_plugin
class YamlReporter(ReporterPluginBase[YAMLReporterConfig]):
    """Formats results as YAML."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = YAMLReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "ASHARPModel") -> str:
        """Format ASH model as YAML string."""

        return yaml.dump(model.model_dump(by_alias=True), indent=2)
