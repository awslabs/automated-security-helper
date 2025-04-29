# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the generic security scanner implementation.

This security scanner depends on a valid ScannerPluginConfig to be provided in the
`build.custom_scanners` section of an AshConfig instance or ASH configuration YAML/JSON file.
"""

import json
from datetime import datetime
from pathlib import Path
import shutil
from typing import Annotated, Any, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.core.constants import (
    ASH_DOCS_URL,
    ASH_REPO_URL,
    SCANNER_TYPES,
)
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    Artifact,
    ArtifactLocation,
    Invocation,
    Location,
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
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER


class CustomScannerConfigOptions(ScannerOptionsBase):
    pass


class CustomScannerConfig(ScannerPluginConfigBase):
    """Custom scanner configuration."""

    name: str = "custom"
    enabled: bool = True
    type: SCANNER_TYPES = "CUSTOM"
    options: Annotated[
        CustomScannerConfigOptions, Field(description="Configure custom scanner")
    ] = CustomScannerConfigOptions()


# Do not uncomment this decorator, this class should be extended and will
# intentionally throw an error if registering as-is.
# @ash_scanner_plugin
class CustomScanner(ScannerPluginBase[CustomScannerConfig]):
    """CustomScanner provides an interface for custom scanners using known formats."""

    command: str | None = None

    def model_post_init(self, context):
        if self.command is None:
            raise ScannerError(
                f"({self.config.name or self.__class__.__name__}) Command not provided for custom scanner! If this is a Python based scanner, set the command property to `python` in your scanner properties to resolve this error."
            )
        if self.config is None:
            self.config = CustomScannerConfig()
        self.args = ToolArgs()
        super().model_post_init(context)

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        return shutil.which(self.command) is not None

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
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
                target_type=target_type,
                config=config,
            )
        except ScannerError as exc:
            raise exc
        ASH_LOGGER.debug(f"self.config: {self.config}")
        ASH_LOGGER.debug(f"config: {config}")

        scanner_name = self.config.name
        try:
            target_results_dir = self.results_dir.joinpath(target_type)
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
            try:
                scanner_results = json.loads("".join(self.output))
                results = scanner_results.get("results", {})
            except json.JSONDecodeError:
                # If the output is not valid JSON, create an empty result structure
                scanner_results = {"results": []}
                results = []

            ASH_LOGGER.debug(f"({scanner_name}) Found {len(results)} results")

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            tool = Tool(
                driver=ToolComponent(
                    name=scanner_name,
                    version=get_ash_version(),
                    informationUri=ASH_DOCS_URL,
                    downloadUri=ASH_REPO_URL,
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
                                    uri=get_shortest_name(input=target),
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
                                    uri=get_shortest_name(input=target),
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
                                                index=1,
                                            ),
                                            region=Region(
                                                startLine=result.get(
                                                    "file_line_range", [1, 1]
                                                )[0],
                                                endLine=result.get(
                                                    "file_line_range", [1, 1]
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
                    tool=tool,
                    timestamp=datetime.now().isoformat(),
                    projectRoot=ArtifactLocation(
                        uri=get_shortest_name(input=target),
                    ),
                    ashVersion=get_ash_version(),
                    scannerConfig=self.config.model_dump(by_alias=True),
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
                raise ScannerError(f"{scanner_name} scan failed: {str(e)}")
