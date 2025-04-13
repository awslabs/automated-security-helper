"""Module containing the Checkov security scanner implementation."""

from importlib.metadata import version
import json
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import BaseScannerOptions
from automated_security_helper.base.scanner import ScannerBaseConfig
from automated_security_helper.base.types import ToolArgs
from automated_security_helper.models.core import (
    ToolExtraArg,
)
from automated_security_helper.base.plugin import (
    ScannerPlugin,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.static_analysis import (
    StaticAnalysisReport,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename


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


class CheckovScannerConfigOptions(BaseScannerOptions):
    config_file: Annotated[
        str,
        Field(
            description="Path to Checkov configuration file, relative to current source directory. Defaults to searching for `.checkov.yaml` and `.checkov.yml` in the root of the source directory.",
        ),
    ] = "NOT_PROVIDED"
    skip_path: Annotated[
        List[str],
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
    frameworks: Annotated[
        List[CheckFrameworks],
        Field(
            description="Specific frameworks to include with Checkov. Defaults to `all`."
        ),
    ] = ["all"]


class CheckovScannerConfig(ScannerBaseConfig):
    name: Literal["checkov"] = "checkov"
    enabled: bool = True
    options: Annotated[
        CheckovScannerConfigOptions, Field(description="Configure Checkov scanner")
    ] = CheckovScannerConfigOptions()


class CheckovScanner(ScannerPlugin[CheckovScannerConfig]):
    """CheckovScanner implements IaC scanning using Checkov."""

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
        return True

    def _process_config_options(self):
        # Bandit config path
        possible_config_paths = [
            item
            for item in [
                self.config.options.config_file,
                ".checkov.yaml",
                ".checkov.yml",
            ]
            if item is not None
        ]

        for conf_path in possible_config_paths:
            if Path(conf_path).exists():
                self.args.extra_args.extend(
                    [
                        "--config-file",
                        Path(conf_path).absolute().relative_to(Path.cwd()).as_posix(),
                    ]
                )
                break

        for item in self.config.options.additional_formats:
            self.args.extra_args.append(ToolExtraArg(key="--output", value=item))
        for item in self.config.options.skip_path:
            self.args.extra_args.append(ToolExtraArg(key="--skip-path", value=item))
        for item in self.config.options.frameworks:
            self.args.extra_args.append(ToolExtraArg(key="--framework", value=item))

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        config: CheckovScannerConfig | None = None,
    ) -> StaticAnalysisReport:
        """Execute Checkov scan and return results.

        Args:
            target: Path to scan

        Returns:
            StaticAnalysisReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        try:
            self._pre_scan(
                target=target,
                options=self.config.options,
            )
        except ScannerError as exc:
            raise exc
        ASH_LOGGER.debug(f"self.config: {self.config}")
        ASH_LOGGER.debug(f"config: {config}")

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
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
            )

            self._post_scan(target=target)

            checkov_results = {}
            Path(results_file).parent.mkdir(exist_ok=True, parents=True)
            with open(results_file, "r") as f:
                checkov_results = json.load(f)
            try:
                sarif_report = SarifReport.model_validate(checkov_results)
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
                            uri=target.as_posix(),
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
