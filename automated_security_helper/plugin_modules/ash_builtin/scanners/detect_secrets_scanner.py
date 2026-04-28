"""Module containing the detect-secrets security scanner implementation."""

import fnmatch
from importlib.metadata import version
import json
import multiprocessing
from pathlib import Path
import re
import sys
from typing import Annotated, Any, Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.constants import KNOWN_LOCKFILE_NAMES
from automated_security_helper.plugins.decorators import ash_scanner_plugin
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
from automated_security_helper.models.core import IgnorePathWithReason

from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings
from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class


class DetectSecretsScanSettingsPluginsUsed(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str | None = None
    limit: float | None = None
    keyword_exclude: str | None = None


class DetectSecretsScanSettingsFiltersUsed(BaseModel):
    model_config = ConfigDict(extra="allow")
    path: str | None = None
    min_level: int | None = None
    keyword_exclude: str | None = None


class DetectSecretsScanSettingsResults(BaseModel):
    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: Dict[str, List[Any]] = {}


class DetectSecretsScanSettings(BaseModel):
    model_config = ConfigDict(extra="allow")
    version: str | None = None
    generated_at: str | None = None
    plugins_used: List[DetectSecretsScanSettingsPluginsUsed] = []
    filters_used: List[DetectSecretsScanSettingsFiltersUsed] = []
    results: DetectSecretsScanSettingsResults = DetectSecretsScanSettingsResults()


class DetectSecretsScannerConfigOptions(ScannerOptionsBase):
    baseline_file: Annotated[
        Path | str | None,
        Field(
            description="Path to detect-secrets baseline file, relative to current source directory. Defaults to searching for `.secrets.baseline` in the root of the source directory. The settings from the baseline will be overwritten if scan_settings is provided.",
        ),
    ] = None
    scan_settings: Annotated[
        DetectSecretsScanSettings,
        Field(
            description="Settings to use with detect-secrets. Refer to the detect-secrets documentation for formatting information. By default, all plugins will be used and no filters are configured. scan_settings takes precedence over baseline_file",
        ),
    ] = DetectSecretsScanSettings()


class DetectSecretsScannerConfig(ScannerPluginConfigBase):
    name: Literal["detect-secrets"] = "detect-secrets"
    enabled: bool = True
    options: Annotated[
        DetectSecretsScannerConfigOptions,
        Field(description="Configure detect-secrets scanner"),
    ] = DetectSecretsScannerConfigOptions()


@ash_scanner_plugin
class DetectSecretsScanner(ScannerPluginBase[DetectSecretsScannerConfig]):
    """DetectSecretsScanner implements SECRET scanning using detect-secrets."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = DetectSecretsScannerConfig()
        self.command = "detect-secrets"
        self.tool_type = "SECRETS"
        self.tool_version = version("detect-secrets")
        self._secrets_collection = SecretsCollection()
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # detect-secrets is a dependency of this Python module and we interact with it
        # purely through Python. If the Python import got this far then we know we're
        # in a valid runtime for this scanner.
        return True

    def _process_config_options(self):
        # Check detect-secrets baseline path
        possible_baseline_paths = [
            item
            for item in [
                self.config.options.baseline_file,
                ".ash/.secrets.baseline",
                ".secrets.baseline",
            ]
            if item is not None
        ]
        ASH_LOGGER.debug(f"Possible baseline file paths: {possible_baseline_paths}")

        # Look through each baseline file path to see if it exists and configure
        # the scan settings according to the first baseline file found
        for baseline_path in possible_baseline_paths:
            ASH_LOGGER.debug(
                f"Checking for detect-secrets config @ {Path(baseline_path).absolute()}"
            )
            if Path(baseline_path).absolute().exists():
                ASH_LOGGER.debug(
                    f"Identified detect-secrets config @ {Path(baseline_path).absolute()}"
                )

                self.config.options.baseline_file = Path(baseline_path)
                break

        # If a baseline file was found, load its plugins_used and filters_used
        # into scan_settings so they are applied during scanning.
        # SecretsCollection.load_from_baseline() only loads results, not settings,
        # so we must propagate the baseline's configuration explicitly.
        if self.config.options.baseline_file is not None:
            try:
                with open(Path(self.config.options.baseline_file).absolute(), "r") as f:
                    baseline_data = json.load(f)

                # Only apply baseline settings if scan_settings was not explicitly
                # configured by the user (i.e. still at defaults)
                if (
                    self.config.options.scan_settings.version is None
                    and len(self.config.options.scan_settings.plugins_used) == 0
                ):
                    # Load plugins from baseline
                    if "plugins_used" in baseline_data:
                        self.config.options.scan_settings.plugins_used = [
                            DetectSecretsScanSettingsPluginsUsed(**plugin)
                            for plugin in baseline_data["plugins_used"]
                        ]
                    # Load filters from baseline (includes should_exclude_file, etc.)
                    if "filters_used" in baseline_data:
                        self.config.options.scan_settings.filters_used = [
                            DetectSecretsScanSettingsFiltersUsed(**f)
                            for f in baseline_data["filters_used"]
                        ]
                    ASH_LOGGER.debug(
                        f"Loaded settings from baseline: "
                        f"{len(self.config.options.scan_settings.plugins_used)} plugins, "
                        f"{len(self.config.options.scan_settings.filters_used)} filters"
                    )
            except (json.JSONDecodeError, OSError) as e:
                ASH_LOGGER.warning(
                    f"Failed to read baseline file settings: {e}. "
                    f"Falling back to default settings."
                )

        # If no existing baseline is identified then use all detect-secrets plugins
        # This is the same as using the default_settings function provided by detect-secrets
        if (
            self.config.options.scan_settings.version is None
            and len(self.config.options.scan_settings.plugins_used) == 0
        ):
            self.config.options.scan_settings = DetectSecretsScanSettings(
                plugins_used=[
                    DetectSecretsScanSettingsPluginsUsed(name=plugin_type.__name__)
                    for plugin_type in get_mapping_from_secret_type_to_class().values()
                ],
            )
            settings = self.config.options.scan_settings.model_dump(
                exclude_defaults=True, exclude_none=True, exclude_unset=True
            )
            ASH_LOGGER.debug(f"Default settings identified: {settings}")

        return super()._process_config_options()

    @staticmethod
    def _get_baseline_exclude_patterns(
        scan_settings_dict: Dict[str, Any],
    ) -> List[re.Pattern]:
        """Extract file exclusion regex patterns from scan settings filters.

        Looks for detect_secrets.filters.regex.should_exclude_file entries
        in the filters_used configuration and compiles their patterns.

        Returns:
            List of compiled regex patterns for file exclusion.
        """
        patterns = []
        for filter_config in scan_settings_dict.get("filters_used", []):
            if filter_config.get("path") == (
                "detect_secrets.filters.regex.should_exclude_file"
            ):
                raw_patterns = filter_config.get("pattern", [])
                if isinstance(raw_patterns, str):
                    raw_patterns = [raw_patterns]
                for p in raw_patterns:
                    try:
                        patterns.append(re.compile(p))
                    except re.error as e:
                        ASH_LOGGER.warning(
                            f"Invalid exclude pattern '{p}' in baseline: {e}"
                        )
        return patterns

    @staticmethod
    def _apply_file_exclusions(
        files: List[str],
        exclude_patterns: List[re.Pattern],
    ) -> List[str]:
        """Filter out files matching any of the exclude patterns.

        Args:
            files: List of file paths to filter.
            exclude_patterns: Compiled regex patterns to match against.

        Returns:
            Filtered list of file paths.
        """
        if not exclude_patterns:
            return files
        return [
            f
            for f in files
            if not any(pattern.search(f) for pattern in exclude_patterns)
        ]

    @staticmethod
    def _ensure_fork_multiprocessing() -> None:
        """Ensure multiprocessing uses 'fork' start method on Linux.

        detect-secrets' scan_files() uses multiprocessing.Pool internally.
        On macOS with Python 3.13+, the default start method is 'spawn',
        which causes recursive process creation (fork bomb) when called
        outside of 'if __name__ == "__main__"' guard.

        On Linux containers (CodeBuild, Docker), 'fork' is the default and
        works correctly, but we set it explicitly to be safe in case the
        default changes in future Python versions.
        """
        if sys.platform == "linux":
            try:
                multiprocessing.set_start_method("fork", force=True)
            except RuntimeError:
                # Already set — this is fine
                pass

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: DetectSecretsScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute detect-secrets scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        tool_component = ToolComponent(
            name="detect-secrets",
            version=self.tool_version,
            informationUri="https://github.com/yelp/detect-secrets",
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine=self.command,
                            executionSuccessful=True,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=20,
                append_to_stream="stderr",  # This will add the message to self.errors
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return sarif_report

        try:
            validated = self._pre_scan(
                target=target,
                target_type=target_type,
                config=config,
            )
            if not validated:
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return False
        except ScannerError as exc:
            raise exc

        if not self.dependencies_satisfied:
            # Logging of this has been done in the central self._pre_scan() method.
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        ASH_LOGGER.debug(f"self.config: {self.config}")
        ASH_LOGGER.debug(f"config: {config}")

        try:
            self._secrets_collection = SecretsCollection()
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            results_file.parent.mkdir(exist_ok=True, parents=True)
            self._resolve_arguments(target=target, results_file=target_results_dir)

            if (
                target_type == "source"
                and self.config.options.baseline_file is not None
            ):
                with open(self.config.options.baseline_file, "r") as f:
                    self._secrets_collection = SecretsCollection.load_from_baseline(
                        baseline=json.load(f),
                    )

                self._secrets_collection.root = Path(target).absolute()
            # Find all files to scan from the scan set
            scannable = [
                str(item)
                for item in (
                    [item for item in self.context.work_dir.glob("**/*.*")]
                    if target_type == "converted"
                    else scan_set(
                        source=self.context.source_dir,
                        output=self.context.output_dir,
                    )
                )
                if Path(item).name not in [*KNOWN_LOCKFILE_NAMES]
                and "/.ash/" not in str(item)
            ]

            # Build the scan_settings dict for transient_settings, ensuring
            # filters_used from the baseline are included so detect-secrets
            # can apply should_exclude_file and other filters during scanning.
            scan_settings_dict = self.config.options.scan_settings.model_dump(
                exclude_defaults=True, exclude_none=True, exclude_unset=True
            )
            # model_dump with exclude_defaults drops empty lists, but we need
            # filters_used to be present if the baseline defined any filters,
            # so that transient_settings -> configure_settings_from_baseline
            # actually configures them.
            if (
                len(self.config.options.scan_settings.filters_used) > 0
                and "filters_used" not in scan_settings_dict
            ):
                scan_settings_dict["filters_used"] = [
                    f.model_dump(exclude_none=True)
                    for f in self.config.options.scan_settings.filters_used
                ]

            # Apply exclude file patterns from baseline filters to the scan set
            # BEFORE passing files to detect-secrets. This prevents unnecessary
            # file I/O and entropy calculations on excluded files, which is
            # critical for performance on large repos (e.g. 400+ JSON test files).
            exclude_patterns = self._get_baseline_exclude_patterns(scan_settings_dict)
            if exclude_patterns:
                pre_filter_count = len(scannable)
                scannable = self._apply_file_exclusions(scannable, exclude_patterns)
                excluded_count = pre_filter_count - len(scannable)
                if excluded_count > 0:
                    self._plugin_log(
                        f"Excluded {excluded_count} files from detect-secrets scan "
                        f"based on baseline exclude patterns",
                        level=15,
                        target_type=target_type,
                    )

            if global_ignore_paths:
                original_count = len(scannable)
                scannable = [
                    file_path
                    for file_path in scannable
                    if not any(
                        fnmatch.fnmatch(file_path, ignore_path.path)
                        or fnmatch.fnmatch(Path(file_path).name, ignore_path.path)
                        or file_path.endswith(ignore_path.path)
                        for ignore_path in global_ignore_paths
                    )
                ]
                if original_count != len(scannable):
                    ASH_LOGGER.debug(
                        f"Filtered {original_count - len(scannable)} files using global_ignore_paths"
                    )

            if len(scannable) == 0:
                message = f"There were no scannable files found in target '{target}'"
                self._plugin_log(
                    message,
                    target_type=target_type,
                    level=20,
                    append_to_stream="stderr",  # This will add the message to self.errors
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return sarif_report

            self._plugin_log(
                f"Found {len(scannable)} files in scan set to scan with detect-secrets",
                level=15,
                target_type=target_type,
            )

            # Ensure multiprocessing uses 'fork' start method to avoid spawn-related
            # issues in containerized environments (CodeBuild, Docker) where 'spawn'
            # can cause recursive process creation and significant overhead.
            self._ensure_fork_multiprocessing()

            with transient_settings(scan_settings_dict) as settings:
                ASH_LOGGER.debug(f"Settings: {settings}")
                self._secrets_collection.scan_files(*scannable)

            self._post_scan(
                target=target,
                target_type=target_type,
            )

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
                                    f"tool_name::{self.config.name}",
                                    f"tool_type::{self.tool_type or 'UNKNOWN'}",
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
                version="2.1.0",
                runs=[
                    Run(
                        tool=sarif_tool,
                        invocations=[sarif_invocation],
                        results=results,
                    )
                ],
            )
            with open(results_file, mode="w", encoding="utf-8") as fp:
                report_str = sarif_report.model_dump_json(
                    exclude_none=True,
                    exclude_unset=True,
                )
                fp.write(report_str)

            # Set exit code to 0 when no findings are found
            if len(results) == 0:
                self.exit_code = 0

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"{self.__class__.__name__} failed: {str(e)}")


if __name__ == "__main__":
    scanner = DetectSecretsScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
    )
    scanner.scan(target=Path.cwd())
