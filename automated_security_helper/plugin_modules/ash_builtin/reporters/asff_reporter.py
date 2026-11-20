# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import re
from pathlib import PureWindowsPath
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, field_validator

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.finding_identity import relative_path

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class AsffReporterOptions(ReporterOptionsBase):
    account_id: str | None = Field(
        default=None, description="Twelve-digit AWS account ID for the findings."
    )
    aws_region: str | None = Field(
        default=None, description="AWS Region for the findings product ARN."
    )
    findings_scope: str | None = Field(
        default=None,
        max_length=1024,
        description="Stable identifier for the scanned target.",
    )
    scan_root: str | None = Field(
        default=None,
        description="Absolute original scan root for normalizing finding paths.",
    )

    @field_validator("account_id", mode="before")
    @classmethod
    def account_from_int(cls, value: Any) -> Any:
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        if (
            isinstance(value, str)
            and len(value) == 14
            and value[0] == value[-1]
            and value[0] in "\"'"
        ):
            return value[1:-1]
        return value


class AsffReporterConfig(ReporterPluginConfigBase):
    name: Literal["asff"] = "asff"
    extension: str = "asff.json"
    enabled: bool = False
    options: AsffReporterOptions = Field(default_factory=AsffReporterOptions)


def _absolute(value: str | None) -> bool:
    return bool(
        value and (value.startswith("/") or PureWindowsPath(value).is_absolute())
    )


@ash_reporter_plugin
class AsffReporter(ReporterPluginBase[AsffReporterConfig]):
    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = AsffReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
            AsffFormatter,
            _scan_scope,
            _unique_by_id,
        )

        config = self.config
        if not isinstance(config, AsffReporterConfig):
            raise ValueError("Invalid reporters.asff configuration")
        options = config.options
        if not options.account_id or not re.fullmatch(r"[0-9]{12}", options.account_id):
            raise ValueError(
                "asff requires a 12-digit reporters.asff.options.account_id"
            )
        if not options.aws_region or not options.aws_region.strip():
            raise ValueError("asff requires reporters.asff.options.aws_region")
        if not options.findings_scope or not options.findings_scope.strip():
            raise ValueError("asff requires reporters.asff.options.findings_scope")
        if model.workspace is not None:
            raise ValueError(
                "asff exports one project at a time. Set --output-dir to a "
                "project's directory under the workspace output."
            )
        root = options.scan_root
        if root is not None and not _absolute(root):
            raise ValueError("reporters.asff.options.scan_root must be absolute")
        if root is None:
            source = getattr(model.metadata, "scan_source", None)
            root = source if isinstance(source, str) and _absolute(source) else None
        results = model.sarif.get_all_results() if model.sarif else []
        if not results:
            return json.dumps({"Findings": []})
        if root is None:
            for result in results:
                flat = FlatVulnerability.from_sarif_result(result, "unknown", "UNKNOWN")
                path = relative_path(flat.file_path)
                if _absolute(path):
                    raise ValueError(
                        "asff requires an absolute reporters.asff.options.scan_root for absolute finding paths"
                    )
        scope = _scan_scope(model)
        formatter = AsffFormatter(
            options.findings_scope.strip(), scope, root, offline=True
        )
        findings = formatter.build_asff_findings(
            model, account_id=options.account_id, region=options.aws_region.strip()
        )
        return json.dumps({"Findings": _unique_by_id(findings)[0]})
