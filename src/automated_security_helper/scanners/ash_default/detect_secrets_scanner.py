"""Module containing the detect-secrets security scanner implementation."""

from importlib.metadata import version
import json
from pathlib import Path
import re
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Invocation,
    Kind,
    Level,
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
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename

from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings
from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class


class DetectSecretsScannerConfigOptions(ScannerOptionsBase):
    baseline_file: Annotated[
        Path | str | None,
        Field(
            description="Path to detect-secrets baseline file, relative to current source directory. Defaults to searching for `.secrets.baseline` in the root of the source directory. The settings from the baseline will be overwritten if scan_settings is provided.",
        ),
    ] = None
    scan_settings: Annotated[
        dict[str, List[dict[str, str]]],
        Field(
            description="Settings to use with detect-secrets. Refer to the detect-secrets documentation for formatting information. By default, all plugins will be used and no filters are configured. scan_settings takes precedence over baseline_file",
        ),
    ] = {}


class DetectSecretsScannerConfig(ScannerPluginConfigBase):
    name: Literal["detect-secrets"] = "detect-secrets"
    enabled: bool = True
    options: Annotated[
        DetectSecretsScannerConfigOptions,
        Field(description="Configure detect-secrets scanner"),
    ] = DetectSecretsScannerConfigOptions()


class DetectSecretsScanner(ScannerPluginBase[DetectSecretsScannerConfig]):
    """DetectSecretsScanner implements SECRET scanning using detect-secrets."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = DetectSecretsScannerConfig()
        self.command = "detect-secrets"
        self.tool_version = version("detect-secrets")
        super().model_post_init(context)

        self._secrets_collection = SecretsCollection()

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # detect-secrets is a dependency of this Python module, if the Python import got
        # this far then we know we're in a valid runtime for this scanner.
        return True

    def _process_config_options(self):
        # Check detect-secrets baseline path
        possible_baseline_paths = [
            item
            for item in [
                self.config.options.baseline_file,
                ".secrets.baseline",
            ]
            if item is not None
        ]
        ASH_LOGGER.debug(f"Possible baseline file paths: {possible_baseline_paths}")

        # Look through each baseline file path to see if it exists and configure
        # the scan settings according to the first baseline file found
        for baseline_path in possible_baseline_paths:
            ASH_LOGGER.verbose(
                f"Checking for detect-secrets config @ {Path(baseline_path).absolute()}"
            )
            if bool(self.config.options.scan_settings):
                pass
            elif Path(baseline_path).absolute().exists():
                abs_baseline_path = Path(baseline_path).absolute()
                with open(abs_baseline_path, "r") as f:
                    self.config.options.scan_settings = json.load(f)
                    f.close()
                ASH_LOGGER.verbose(
                    f"Custom settings identified: {self.config.options.scan_settings}"
                )
                break

        # If no existing baseline is identified then use all detect-secrets plugins
        # This is the same as using the default_settings function provided by detect-secrets
        if not bool(self.config.options.scan_settings):
            self.config.options.scan_settings = {
                "plugins_used": [
                    {"name": plugin_type.__name__}
                    for plugin_type in get_mapping_from_secret_type_to_class().values()
                ],
            }
            ASH_LOGGER.debug(
                f"Default settings identified: {self.config.options.scan_settings}"
            )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        config: DetectSecretsScannerConfig | None = None,
    ) -> SarifReport:
        """Execute detect-secrets scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        try:
            self._pre_scan(
                target=target,
                config=config,
            )
        except ScannerError as exc:
            raise exc
        ASH_LOGGER.debug(f"self.config: {self.config}")
        ASH_LOGGER.debug(f"config: {config}")

        try:
            # Set up target path for scan results for target path
            normalized_file_name = get_normalized_filename(str_to_normalize=target)
            target_results_dir = Path(self.results_dir).joinpath(normalized_file_name)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            results_file.parent.mkdir(exist_ok=True, parents=True)
            self._resolve_arguments(target=target, results_file=target_results_dir)

            # Find all files to scan from the scan set
            scannable = scan_set(
                source=self.source_dir,
                output=self.output_dir,
            )
            ASH_LOGGER.debug(
                f"Found {len(scannable)} files in scan set to scan with detect-secrets"
            )
            with transient_settings(self.config.options.scan_settings) as settings:
                ASH_LOGGER.debug(f"Settings: {settings}")
                self._secrets_collection.scan_files(*scannable)

            self._post_scan(target=target)

            # Populate the Results list with findings from the scan
            results: List[Result] = []
            for filename, detections in self._secrets_collection.data.items():
                for finding in detections:
                    rule_id = re.sub(
                        pattern=r"\W+", repl="-", string=finding.type
                    ).upper()
                    results.append(
                        Result(
                            # Adjust as needed to capture findings from scanner as
                            # SARIF Result objects. Reference the current CDK Nag
                            # Scanner/Wrapper for examples on custom SARIF structure.
                            ruleId=f"SECRET-{rule_id}",
                            properties=PropertyBag(
                                tags=[
                                    "detect-secrets",
                                    "secret",
                                    "security",
                                ],
                            ),
                            level=Level.error,
                            kind=Kind.fail,
                            message=Message(
                                text=f"Secret of type '{finding.type}' detected in file '{filename}' at line {finding.line_number}"
                            ),
                            locations=[
                                Location(
                                    id=1,
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri=get_shortest_name(input=filename),
                                        ),
                                        region=Region(
                                            startLine=finding.line_number,
                                            endLine=finding.line_number,
                                            snippet=ArtifactContent(
                                                text=f"Secret of type {finding.type} detected"
                                            ),
                                        ),
                                    ),
                                )
                            ],
                        )
                    )
            sarif_tool: Tool = Tool(
                driver=ToolComponent(
                    name="detect-secrets",
                    fullName="yelp/detect-secrets",
                    organization="Yelp",
                    version=self.tool_version,
                    informationUri="https://github.com/Yelp/detect-secrets",
                    downloadUri="https://github.com/Yelp/detect-secrets",
                    rules=[],
                )
            )
            sarif_invocation: Invocation = Invocation(
                commandLine="ash-detect-secrets-scanner",
                arguments=[
                    "--target",
                    get_shortest_name(input=target),
                    "--scanner",
                ],
                startTimeUtc=self.start_time,
                endTimeUtc=self.end_time,
                executionSuccessful=True,
                exitCode=self.exit_code,
                exitCodeDescription="\n".join(self.errors),
                workingDirectory=ArtifactLocation(
                    uri=get_shortest_name(input=target),
                ),
                properties=PropertyBag(
                    tool=sarif_tool,
                ),
            )
            sarif_report = SarifReport(
                runs=[
                    Run(
                        tool=sarif_tool,
                        invocations=[sarif_invocation],
                        results=results,
                    )
                ]
            )
            with open(results_file, "w") as fp:
                report_str = sarif_report.model_dump_json()
                fp.write(report_str)

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"{self.__class__.__name__} failed: {str(e)}")


if __name__ == "__main__":
    scanner = DetectSecretsScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath("ash_output"),
    )
    scanner.scan(target=Path.cwd())
