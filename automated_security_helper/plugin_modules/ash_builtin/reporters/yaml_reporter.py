# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import yaml
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
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
    """Formats results as YAML.

    Workspace mode: one merged artefact, and the field the RFC asks for needs no
    code. This reporter dumps the whole model, so it already carries the
    ``workspace`` block, every SARIF run, and ``properties.workspace_project`` on
    every finding. The declaration is what makes that a *stated* behaviour rather
    than a coincidence, and ``tests/unit/workspace/test_workspace_reporting.py``
    holds it -- a future change that dropped ``workspace`` from the dump, or
    narrowed it to one run, would fail there rather than passing quietly.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = YAMLReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as YAML string."""

        return yaml.dump(model.model_dump(by_alias=True), indent=2)
