# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import re
from pathlib import PureWindowsPath
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, field_validator, model_validator

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_formatter import (
    AsffFormatter,
    _scan_scope,
    _unique_by_id,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.finding_identity import relative_path
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class AsffReporterOptions(ReporterOptionsBase):
    # ``aws_account_id`` is the spelling an earlier ASFF reporter's options used
    # (and that results files written then still carry); ``account_id`` is
    # canonical and what the Security Hub reporter calls the same option.
    account_id: str | None = Field(
        default=None,
        description="Twelve-digit AWS account ID for the findings.",
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

    @model_validator(mode="before")
    @classmethod
    def _earlier_account_spelling(cls, data: Any) -> Any:
        """Read ``aws_account_id`` as ``account_id``, which wins when it is set.

        Done here rather than with a ``validation_alias``: the type checker's
        pydantic plugin rejects a required dynamic alias, and a section built from
        the defaults carries ``account_id: null`` with an override of
        ``aws_account_id`` merged next to it, where an alias would take the null.
        """
        if isinstance(data, dict) and "aws_account_id" in data:
            data = dict(data)
            earlier = data.pop("aws_account_id")
            if data.get("account_id") is None:
                data["account_id"] = earlier
        return data

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
        paths = [
            relative_path(
                FlatVulnerability.from_sarif_result(
                    result, "unknown", "UNKNOWN"
                ).file_path
            )
            for result in results
        ]
        absolute = [path for path in paths if _absolute(path)]
        if root is None:
            if absolute:
                raise ValueError(
                    "asff requires an absolute reporters.asff.options.scan_root for absolute finding paths"
                )
        elif absolute and all(
            _absolute(relative_path(path, root, resolve_root=False))
            for path in absolute
        ):
            ASH_LOGGER.warning(
                f"asff: the scan root {root!r} is not a prefix of any of the "
                f"{len(absolute)} absolute finding paths, so the exported finding "
                "Ids and resource Ids carry those paths as recorded, which are "
                "specific to the machine that scanned. They will not equal the Ids "
                "an import from the scan's own checkout gives. Set "
                "reporters.asff.options.scan_root to the scan root as the results "
                "recorded it; a root recorded through a symbolic link needs the "
                "resolved spelling."
            )
        scope = _scan_scope(model)
        formatter = AsffFormatter(
            options.findings_scope.strip(), scope, root, offline=True
        )
        findings = formatter.build_asff_findings(
            model, account_id=options.account_id, region=options.aws_region.strip()
        )
        return json.dumps({"Findings": _unique_by_id(findings)[0]})
