"""Module containing the Checkov security scanner implementation."""

from importlib.metadata import version
import json
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable


CheckFrameworks = Literal[
    "all",
    "ansible",
    "argo_workflows",
    "arm",
    "azure_pipelines",
    "bicep",
    "bitbucket_pipelines",
    "cdk",
    "circleci_pipelines",
    "cloudformation",
    "dockerfile",
    "github_configuration",
    "github_actions",
    "gitlab_configuration",
    "gitlab_ci",
    "bitbucket_configuration",
    "helm",
    "json",
    "yaml",
    "kubernetes",
    "kustomize",
    "openapi",
    "sca_package",
    "sca_image",
    "secrets",
    "serverless",
    "terraform",
    "terraform_json",
    "terraform_plan",
    "sast",
    "sast_python",
    "sast_java",
    "sast_javascript",
    "sast_typescript",
    "sast_golang",
    "3d_policy",
]


class CheckovScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Checkov configuration file, relative to current source directory. Defaults to searching for `.checkov.yaml` and `.checkov.yml` in the root of the source directory.",
        ),
    ] = None
    skip_path: Annotated[
        List[IgnorePathWithReason],
        Field(
            description='Path (file or directory) to skip, using regular expression logic, relative to current working directory. Word boundaries are not implicit; i.e., specifying "dir1" will skip any directory or subdirectory named "dir1". Ignored with -f. Can be specified multiple times.',
        ),
    ] = []
    additional_formats: Annotated[
        List[
            Literal[
                "cli",
                "csv",
                "cyclonedx",
                "cyclonedx_json",
                "json",
                "junitxml",
                "github_failed_only",
                "gitlab_sast",
                "sarif",
                "spdx",
            ]
        ],
        Field(
            description="List of additional formats to output. Defaults to including CycloneDX JSON"
        ),
    ] = ["cyclonedx_json"]
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, disabling policy downloads",
        ),
    ] = False
    frameworks: Annotated[
        List[CheckFrameworks],
        Field(
            description="Specific frameworks to include with Checkov. Defaults to `all`."
        ),
    ] = ["all"]
    skip_frameworks: Annotated[
        List[CheckFrameworks],
        Field(
            description="Specific frameworks to exclude with Checkov. Defaults to none."
        ),
    ] = []


class CheckovScannerConfig(ScannerPluginConfigBase):
    name: Literal["checkov"] = "checkov"
    enabled: bool = True
    options: Annotated[
        CheckovScannerConfigOptions, Field(description="Configure Checkov scanner")
    ] = CheckovScannerConfigOptions()


@ash_scanner_plugin
class CheckovScanner(ScannerPluginBase[CheckovScannerConfig]):
    """CheckovScanner implements IaC scanning using Checkov."""

    check_conf: str = "NOT_PROVIDED"

    def model_post_init(self, context):
        if self.config is None:
            self.config = CheckovScannerConfig()
        self.command = "checkov"
        self.tool_type = "IAC"
        self.tool_version = version("checkov")
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="sarif",
            output_arg="--output-file-path",
            scan_path_arg="--directory",
            extra_args=[
                # ToolExtraArg(key="--skip-framework", value="cloudformation"),
            ],
        )
        super().model_post_init(context)

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # Checkov is a dependency this Python module, if the Python import got
        # this far then we know we're in a valid runtime for this scanner.
        found = find_executable(self.command)
        return found is not None

    def _process_config_options(self):
        # Checkov config path
        possible_config_paths = [
            item
            for item in [
                self.config.options.config_file,
                ".checkov.yaml",
                ".ash/.checkov.yaml",
                ".checkov.yml",
                ".ash/.checkov.yml",
            ]
            if item is not None
        ]

        for conf_path in possible_config_paths:
            if Path(conf_path).exists():
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--config-file",
                        value=get_shortest_name(input=conf_path),
                    )
                )
                break

        # Add offline mode if enabled
        if self.config.options.offline:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--no-download",
                    value="",
                )
            )
            ASH_LOGGER.info(
                "Running Checkov in offline mode - policy downloads disabled"
            )

        for item in self.config.options.additional_formats:
            self.args.extra_args.append(ToolExtraArg(key="--output", value=item))
        for item in self.config.options.frameworks:
            self.args.extra_args.append(ToolExtraArg(key="--framework", value=item))
        for item in self.config.options.skip_frameworks:
            self.args.extra_args.append(
                ToolExtraArg(key="--skip-framework", value=item)
            )
        for item in self.config.options.skip_path:
            ASH_LOGGER.debug(
                f"Path '{item.path}' excluded from {self.config.name} scan for reason: {item.reason}"
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--skip-path",
                    value=item.path,
                )
            )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: CheckovScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute Checkov scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._scanner_log(
                message,
                target_type=target_type,
                level=20,
                append_to_stream="stderr",  # This will add the message to self.errors
            )
            return True

        try:
            validated = self._pre_scan(
                target=target,
                target_type=target_type,
                config=config,
            )
            if not validated:
                return False
        except ScannerError as exc:
            raise exc

        if not self.dependencies_satisfied:
            # Logging of this has been done in the central self._pre_scan() method.
            return False

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            results_file.parent.mkdir(exist_ok=True, parents=True)

            # Extend the skip-paths args with the global exclusion list
            # self.config.options.skip_path.extend(global_ignore_paths)
            final_args = self._resolve_arguments(
                target=target,
                # We want to use the parent here, not the results_file, as Checkov is expecting the output
                # directory and not the file name.
                results_file=target_results_dir,
            )
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
            )

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            checkov_results = {}
            Path(results_file).parent.mkdir(exist_ok=True, parents=True)
            with open(results_file, mode="r", encoding="utf-8") as f:
                checkov_results = json.load(f)
            try:
                sarif_report: SarifReport = SarifReport.model_validate(checkov_results)
                sarif_report.runs[0].invocations = [
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
                            tool=sarif_report.runs[0].tool,
                        ),
                    )
                ]
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}"
                )
                sarif_report = checkov_results

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Checkov scan failed: {str(e)}")
