# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml
from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class SPDXReporterConfigOptions(ReporterOptionsBase):
    pass


class TextReporterConfig(ReporterPluginConfigBase):
    name: Literal["text"] = "text"
    extension: str = "txt"
    enabled: bool = True


class TextReporter(ReporterPluginBase[TextReporterConfig]):
    """Formats results as text."""

    def format(self, model: Any) -> str:
        """Format ASH model as text string."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        return yaml.dump(model.model_dump(), indent=2)
