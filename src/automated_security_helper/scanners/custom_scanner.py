# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the generic security scanner implementation.

This security scanner depends on a valid ScannerPluginConfig to be provided in the
`build.custom_scanners` section of an ASHConfig instance or ASH configuration YAML/JSON file.
"""

from importlib.metadata import version
import json
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Dict

from pydantic import Field
from automated_security_helper.base.options import BaseScannerOptions
from automated_security_helper.core.constants import SCANNER_TYPES
from automated_security_helper.base.scanner import ScannerBaseConfig
from automated_security_helper.base.types import ToolArgs
from automated_security_helper.models.core import (
    Location,
)
from automated_security_helper.models.iac_scan import (
    IaCVulnerability,
    CheckResultType,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPlugin,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    Artifact,
    ArtifactLocation,
    Invocation,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename


class CustomScannerConfigOptions(BaseScannerOptions):
    pass


class CustomScannerConfig(ScannerBaseConfig):
    """Custom scanner configuration."""

    name: str = "custom"
    enabled: bool = True
    type: SCANNER_TYPES = "CUSTOM"
    options: Annotated[
        CustomScannerConfigOptions, Field(description="Configure custom scanner")
    ] = CustomScannerConfigOptions()


class CustomScanner(ScannerPlugin[CustomScannerConfig]):
    """CustomScanner provides an interface for custom scanners using known formats."""

    command: str | None = None

    def model_post_init(self, context):
        if self.config is None:
            self.config = CustomScannerConfig()
        self.tool_type = "CUSTOM"
        self.tool_version = version("checkov")
        self.args = ToolArgs()
        super().model_post_init(context)

    def _create_finding_from_check(
        self, result: Dict[str, Any], check_type: CheckResultType
    ) -> IaCVulnerability:
        """Create an IaCVulnerability from a check result."""
        finding_id = "/".join(
            [
                item
                for item in [
                    result.get("check_id", None),
                    result.get("repo_file_path", None),
                    result.get("resource", None),
                    result.get("resource_address", None),
                ]
                if item
            ]
        )

        # Extract location information from the result
        file_path = result.get("file_path", "")
        file_line_range = result.get("file_line_range", [0, 0])
        location = Location(
            path=file_path,
            start_line=file_line_range[0] if file_line_range else 0,
            end_line=file_line_range[1] if file_line_range else 0,
        )

        return IaCVulnerability(
            id=finding_id,
            title=result.get("check_name", "Unknown Check"),
            description=result.get("check_name", ""),
            location=location,
            resource_name=result.get("resource", ""),
            resource_type=(
                result.get("resource", "").split(".")[0]
                if result.get("resource", "")
                else None
            ),
            rule_id=result.get("check_id", ""),
            check_result_type=check_type,
            violation_details={
                "check_class": result.get("check_class", ""),
                "guideline": result.get("guideline", ""),
                "evaluated_keys": result.get("check_result", {}).get(
                    "evaluated_keys", []
                ),
                "result_details": result.get("check_result", {}).get("result", ""),
                "bc_category": result.get("bc_category", ""),
            },
        )

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        return True

    def scan(
        self,
        target: Path,
        config: Any | CustomScannerConfig | None = None,
    ) -> SarifReport:
        """Execute Checkov scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        if self.command is None:
            # ASH_LOGGER.warning(f"({(config is not None and config.name) or self.config.name or self.__class__.__name__}) No command specified for custom scanner. Config provided: {config}")
            return
        try:
            self._pre_scan(
                target=target,
                options=self.config.options,
            )
        except ScannerError as exc:
            raise exc
        ASH_LOGGER.debug(f"self.config: {self.config}")
        ASH_LOGGER.debug(f"config: {config}")

        scanner_name = self.config.name
        try:
            normalized_file_name = get_normalized_filename(str_to_normalize=target)
            target_results_dir = Path(self.results_dir).joinpath(normalized_file_name)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            results_file.parent.mkdir(exist_ok=True, parents=True)
            final_args = self._resolve_arguments(
                target=target,
                # We want to use the parent here, not the results_file, as Checkov is expecting the output
                # directory and not the file name.
                results_file=target_results_dir,
            )
            self._run_subprocess(final_args)

            # Parse JSON output
            scanner_results = json.loads("".join(self.output))
            results = scanner_results.get("results", {})
            ASH_LOGGER.debug(f"({scanner_name}) Found {len(results)} results")

            self._post_scan(target=target)

            tool = Tool(
                driver=ToolComponent(
                    name=scanner_name,
                    version=get_ash_version(),
                    informationUri="XXXXXXXXXXXXXXXXXXX",
                )
            )
            # Create and return report
            return SarifReport(
                runs=[
                    Run(
                        tool=tool,
                        artifacts=[
                            Artifact(
                                location=ArtifactLocation(
                                    uri=target.as_posix(),
                                )
                            )
                        ],
                        invocations=[
                            Invocation(
                                commandLine=final_args[0],
                                arguments=final_args[1:],
                                startTimeUtc=self.start_time,
                                endTimeUtc=self.end_time,
                                executionSuccessful=True,
                                exitCode=self.exit_code,
                                exitCodeDescription="\n".join(self.errors),
                                workingDirectory=ArtifactLocation(
                                    uri=target.as_posix(),
                                ),
                                properties=PropertyBag(
                                    tool=tool,
                                ),
                            )
                        ],
                        results=[
                            Result(
                                ruleId=result.get("check_id", ""),
                                message=Message(
                                    text=result.get("check_name", ""),
                                ),
                                locations=[
                                    Location(
                                        physicalLocation=PhysicalLocation(
                                            artifactLocation=ArtifactLocation(
                                                uri=result.get("file_path", ""),
                                                index=0,
                                            ),
                                            region=Region(
                                                startLine=result.get(
                                                    "file_line_range", [0, 0]
                                                )[0],
                                                endLine=result.get(
                                                    "file_line_range", [0, 0]
                                                )[1],
                                            ),
                                        )
                                    )
                                ],
                            )
                            for result in results
                        ],
                    )
                ],
                properties=PropertyBag(
                    tool=Tool(
                        driver=ToolComponent(
                            name=scanner_name,
                            version=self.tool_version,
                            informationUri="XXXXXXXXXXXXXXXXXXX",
                        )
                    ),
                    timestamp=datetime.now().isoformat(),
                    projectRoot=ArtifactLocation(
                        uri=target.as_posix(),
                    ),
                    ashVersion=get_ash_version(),
                    scannerConfig=self.config.model_dump(),
                    scannerResults=scanner_results,
                    scannerErrors=[
                        Message(
                            text=error,
                        )
                        for error in self.errors
                    ],
                ),
            )

        except Exception as e:
            # Check if there are useful error details
            error_output = "".join(self.errors)
            if error_output.strip() != "":
                raise ScannerError(
                    f"{scanner_name} scan failed: {str(e)}. Additional error output: {error_output}"
                )
            else:
                raise ScannerError(f"{scanner_name} scan failed: {str(e)}.")
