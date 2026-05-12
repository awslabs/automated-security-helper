from datetime import datetime, timezone
import json
import logging
import re
import shlex
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import ArtifactLocation, Invocation, SarifReport
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable

from pydantic import Field
from typing import Annotated, Any, ClassVar, Generic, List, Literal, Optional, Set, Tuple, TypeVar
from abc import abstractmethod

# Pattern for valid CLI flag keys: one or two leading dashes followed by
# a letter, then alphanumerics/underscores/hyphens.
_VALID_FLAG_KEY_PATTERN = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_\-]*$")
from pathlib import Path


class ScannerPluginConfigBase(PluginConfigBase):
    options: Annotated[ScannerOptionsBase, Field(description="Scanner options")] = (
        ScannerOptionsBase()
    )


T = TypeVar("T", bound=ScannerPluginConfigBase)


class ScannerPluginBase(PluginBase, Generic[T]):
    """Base class for all scanner plugins.

    Plugin implementations
    """

    config: T | ScannerPluginConfigBase | None = None
    dependencies_satisfied: bool = False

    tool_type: ScannerToolType = ScannerToolType.UNKNOWN
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.UNKNOWN

    command: Annotated[
        str | None,
        Field(
            description="The command to invoke the scanner, typically the binary or path to a script"
        ),
    ] = None
    subcommands: Annotated[
        List[str],
        Field(
            description="Subcommands to include when invoking the scanner, e.g. ['scan'] is needed as the subcommand for 'semgrep' as Semgrep supports multiple subcommands, but we are specifically interested in running a scan."
        ),
    ] = []
    args: Annotated[
        ToolArgs,
        Field(
            description="Specialized arguments to pass to the scanner command. Includes an `extra_args` field which accepts a dictionary of arbitrary arguments to pass to the scanner. These are not configurable at scan time."
        ),
    ] = ToolArgs()

    results_file: Annotated[
        Path | None,
        Field(
            description="The path to the results file, if any. This is set by the scanner plugin after the scan is complete."
        ),
    ] = None

    use_uv_tool: Annotated[
        bool,
        Field(
            description="Flag to indicate whether this scanner should use UV tool execution instead of direct command execution"
        ),
    ] = False

    uv_tool_install_commands: Annotated[
        List[str],
        Field(
            description="List of UV tool install commands to execute for this scanner"
        ),
    ] = []

    def model_post_init(self, context):
        if self.config is None:
            raise ScannerError(
                f"Unable to initialize {self.__class__.__name__}! Configuration is empty."
            )

        # Use context if provided, otherwise fall back to instance attributes
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        ASH_LOGGER.trace(f"Using provided context for {self.__class__.__name__}")

        # Set up results directory based on output directory
        self.results_dir = self.context.output_dir.joinpath("scanners").joinpath(
            self.config.name
        )

        self._process_config_options()

        ASH_LOGGER.trace(
            f"Scanner {self.config.name} initialized with source_dir={self.context.source_dir}, output_dir={self.context.output_dir}"
        )
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Check whether the scanner's command is available on PATH.

        Subclasses with more complex requirements (UV tool management,
        version checks, non-standard binaries) should override this.
        """
        found = find_executable(self.command)
        return found is not None

    def _process_config_options(self) -> None:
        """By default, returns False to indicate that the scanner did not perform any
        configuration option processing.

        Override this method if you need to process custom options before
        arguments are resolved!

        This method is called at the start of `self._resolve_arguments(target)` before
        `self.args.extra_args` is processed. Use this method to populate additional
        argument key/value pairs where needed.
        """
        pass

    def _resolve_arguments(
        self, target: str | Path, results_file: str | Path | None = None
    ) -> List[str]:
        """Resolve any configured options into command line arguments.

        Args:
            target: Target to scan

        Returns:
            List[str]: Arguments to pass to scanner
        """

        # # Process configuration options to populate extra_args
        # self._process_config_options()

        args = [
            self.command,
            *self.subcommands,
            self.args.format_arg,
            self.args.format_arg_value,
        ]

        for tool_extra_arg in self.args.extra_args:
            if not _VALID_FLAG_KEY_PATTERN.match(tool_extra_arg.key):
                ASH_LOGGER.warning(
                    f"Skipping extra arg with invalid key: {tool_extra_arg.key!r}. "
                    "Keys must match pattern: -<letter> or --<letter>[alphanumeric_-]*"
                )
                continue
            args.append(tool_extra_arg.key)
            args.append(tool_extra_arg.value)

        args.extend(
            [
                self.args.scan_path_arg,
                Path(target).as_posix(),
                self.args.output_arg,
                (
                    Path(results_file).as_posix()
                    if results_file is not None
                    else (
                        Path(self.results_file).as_posix()
                        if self.results_file is not None
                        else None
                    )
                ),
            ]
        )
        return [item for item in args if item is not None and str(item).strip() != ""]

    def _pre_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        config: Optional[ScannerPluginConfigBase] = None,
        *args,
        **kwargs,
    ) -> bool:
        """Perform pre-scan setup.

        Args:
            target: Target to scan
            options: Optional scanner-specific options
        """
        self.start_time = datetime.now(timezone.utc)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.dependencies_satisfied = self.validate_plugin_dependencies()

        if not self.dependencies_satisfied:
            self._plugin_log(
                "Scanner is missing dependencies and will be skipped.",
                target_type=target_type,
                level=logging.WARNING,
                append_to_stream="stderr",
            )
            return False

        self._plugin_log(
            "Starting scan",
            target_type=target_type,
            level=logging.INFO,
        )
        self._plugin_log(
            f"self.config: {self.config}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        if config is not None:
            if hasattr(config, "model_dump") and callable(config.model_dump):
                config = config.model_dump(by_alias=True)
            self.config = self.config.__class__.model_validate(config)
        self._plugin_log(
            f"config: {config}",
            target_type=target_type,
            level=logging.DEBUG,
        )

        if not Path(target).exists():
            raise ScannerError(
                f"([yellow]{self.config.name or self.__class__.__name__}[/yellow] @ [magenta]{target_type}[/magenta]) Target {target} does not exist!"
            )

        # Ensure all required directories exist
        self.context.work_dir.mkdir(parents=True, exist_ok=True)
        if self.results_dir:
            self.results_dir.mkdir(parents=True, exist_ok=True)

        # Log the paths being used
        self._plugin_log(
            f"Using source_dir: {self.context.source_dir}",
            f"Using output_dir: {self.context.output_dir}",
            f"Using work_dir: {self.context.work_dir}",
            f"Using results_dir: {self.results_dir}",
            target_type=target_type,
            level=logging.DEBUG,
        )

        return True

    def _post_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
    ) -> None:
        """Perform pre-scan setup.

        Args:
            target: Target to scan
            options: Optional scanner-specific options
        """
        self.end_time = datetime.now(timezone.utc)
        if not self.start_time:
            self.start_time = self.end_time

        # ec_color = "bold green" if self.exit_code == 0 else "bold red"
        self._plugin_log(
            f"Scan completed in {(self.end_time - self.start_time).total_seconds()} seconds",
            # f"Scan completed in {(self.end_time - self.start_time).total_seconds()} seconds with an exit code of [{ec_color}]{self.exit_code}[/{ec_color}]",
            target_type=target_type,
            level=logging.INFO,
        )

    # Exit codes considered "successful". Grype uses {0, 2}; the default set
    # works for bandit/checkov/etc. Override on subclasses where the scanner
    # has a different convention.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}

    # Log level used for the empty-target preamble message. Defaults to INFO;
    # bandit overrides to VERBOSE since python-only repos commonly trip it.
    empty_target_log_level: ClassVar[int] = logging.INFO

    def _invocation_extras(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: "Path",
    ) -> dict:
        """Return additional Invocation kwargs (e.g. ``properties``).

        Default returns an empty dict. Override to attach scanner-specific
        Invocation fields like a PropertyBag. Called from ``_inject_invocation``.
        """
        return {}

    def _inject_invocation(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: "Path",
        success_codes: Optional[Set[int]] = None,
    ) -> None:
        """Populate runs[0].invocations with timing, exit-code, and command info.

        Also attaches per-result and tool-driver ``scanner_details`` via
        :func:`attach_scanner_details` so consumers that read
        ``result.properties.scanner_details.tool_invocation`` continue to
        see the command line, arguments, working directory, and exit code
        for migrated scanners. Without this, the un-migrated scanners
        (ferret/snyk/trivy) populate per-result details inside their own
        ``scan()`` while migrated scanners would only have the run-level
        ``invocations[0]`` — see DA r7 #3.

        No-op when sarif_report.runs is empty (avoids IndexError on empty reports).
        """
        if success_codes is None:
            success_codes = self.success_exit_codes
        if not sarif_report.runs:
            return
        working_dir = ArtifactLocation(uri=get_shortest_name(input=target))  # type: ignore[call-arg]
        extras = self._invocation_extras(sarif_report, final_args, target)
        command_line = (
            shlex.join(str(a) for a in final_args) if final_args else ""
        )
        sarif_report.runs[0].invocations = [
            Invocation(  # type: ignore[call-arg]
                commandLine=command_line,
                arguments=final_args[1:],
                startTimeUtc=self.start_time,
                endTimeUtc=self.end_time,
                executionSuccessful=(self.exit_code in success_codes),
                exitCode=self.exit_code,
                exitCodeDescription="\n".join(self.errors) if self.errors else "",
                workingDirectory=working_dir,
                **extras,
            )
        ]
        # Mirror the un-migrated scanner pattern: attach per-result and
        # tool-driver scanner_details so downstream consumers (and the
        # ScanResultProcessor's own attach pass) see the same shape they
        # saw before the template-method refactor (DA r7 #3).
        from automated_security_helper.utils.sarif_utils import (
            attach_scanner_details as _attach_scanner_details,
        )

        scanner_name = (
            str(self.config.name)
            if self.config is not None and getattr(self.config, "name", None)
            else self.__class__.__name__
        )
        _attach_scanner_details(
            sarif_report=sarif_report,
            scanner_name=scanner_name,
            scanner_version=getattr(self, "tool_version", None),
            invocation_details={
                "command_line": command_line,
                "arguments": final_args[1:] if final_args else [],
                "working_directory": get_shortest_name(input=target),
                "exit_code": self.exit_code,
                "start_time": self.start_time.isoformat()
                if self.start_time is not None
                else None,
                "end_time": self.end_time.isoformat()
                if self.end_time is not None
                else None,
            },
        )

    def _read_results_file(self, results_file: "Path") -> Optional[dict]:
        """Read and parse the scanner results file as JSON.

        Default reads the file as JSON. Subclasses may override to add
        empty-file detection or alternative parsing. Return None to signal
        an empty/missing result that should be replaced with the default
        empty SARIF report (see ``_handle_empty_results``).
        """
        with open(results_file, mode="r", encoding="utf-8") as fh:
            content = fh.read()
        if not content or content.strip() == "":
            return None
        return json.loads(content)

    def _handle_empty_results(self) -> SarifReport:
        """Return a SARIF report representing an empty/missing scanner result.

        Default returns an empty SARIF 2.1.0 report with no runs. Override
        if a scanner needs richer empty-state handling.
        """
        return SarifReport(  # type: ignore[call-arg]
            version="2.1.0",
            runs=[],
        )

    def _ensure_runs(self, sarif_report: SarifReport) -> None:
        """Ensure ``sarif_report.runs`` is non-empty before invocation injection.

        Default no-op. Override (e.g. Grype) to synthesize a fallback Run
        when the scanner produces a SARIF report with zero runs but the
        template still needs to attach an invocation.
        """
        return None

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: "Path",
    ) -> SarifReport:
        """Apply scanner-specific tweaks to a SARIF report after invocation injection.

        Default returns the report unchanged. Override to normalize URIs,
        mask secrets, attach scanner details, etc.
        """
        return sarif_report

    @abstractmethod
    def _execute_scan(
        self,
        target: "Path",
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], "Path", Optional[dict]]:
        """Run the scanner tool and return (final_args, results_file, subprocess_env).

        Abstract template-method hook. Subclasses that use the default
        `scan()` template MUST implement this with real tool-invocation
        logic. Subclasses that override `scan()` directly (e.g. Python-API
        scanners, file-iterating scanners) must still satisfy the abstract
        contract — provide a one-line stub that raises NotImplementedError
        so ABC can verify the interface at class-definition time and the
        stub is never reached at runtime.

        Returns:
            (final_args, results_file, subprocess_env) where subprocess_env is
            a dict merged with os.environ (or None to inherit the parent env).
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement _execute_scan() "
            "or override scan() directly."
        )

    def scan(
        self,
        target: "Path",
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: "T | ScannerPluginConfigBase | None" = None,
        *args,
        **kwargs,
    ) -> Any | SarifReport | CycloneDXReport:
        """Template scan: preamble → _execute_scan → read result → inject invocation → postamble.

        Subclasses with bespoke logic (file-iteration, Python-API scanners) should
        override this method directly and leave _execute_scan unimplemented.
        """
        if global_ignore_paths is None:
            global_ignore_paths = []

        if not target.exists() or not any(target.iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=self.empty_target_log_level,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(target=target, target_type=target_type)
            return False

        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        try:
            final_args, results_file, subprocess_env = self._execute_scan(
                target=target,
                target_type=target_type,
                global_ignore_paths=global_ignore_paths,
            )

            self._run_subprocess(
                command=final_args,
                results_dir=results_file.parent,
                env=subprocess_env,
            )

            self._post_scan(target=target, target_type=target_type)

            raw = self._read_results_file(results_file)
            if raw is None:
                # Empty result file: defer to _handle_empty_results so
                # subclasses can log or build a richer fallback report.
                error_msg = (
                    f"{self.__class__.__name__} results file is empty "
                    f"(exit code: {self.exit_code}). "
                )
                if self.errors:
                    error_msg += f"Stderr: {' '.join(self.errors)}"
                else:
                    error_msg += "No stderr output captured."
                ASH_LOGGER.warning(error_msg)
                return self._handle_empty_results()

            try:
                sarif_report: SarifReport = SarifReport.model_validate(raw)
                self._ensure_runs(sarif_report)
                self._inject_invocation(sarif_report, final_args, target)
                sarif_report = self._post_process_sarif(
                    sarif_report, final_args, target
                )
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to parse {self.__class__.__name__} results as SARIF: {e}"
                )
                sarif_report = raw  # type: ignore[assignment]

            return sarif_report

        except Exception as e:
            raise ScannerError(f"{self.__class__.__name__} scan failed: {e}")

    ### Methods that require implementation by plugins.
    def validate_plugin(self) -> bool:
        """Validate scanner configuration and requirements."""
        # Use enhanced validation that includes pre-installed tool detection
        validation_result = self._validate_tool_availability_with_pre_installed()

        # Log validation details
        if validation_result["available"]:
            self._plugin_log(
                f"Tool validation successful via {validation_result['validation_method']}",
                level=logging.INFO,
            )

            # Log any warnings
            for warning in validation_result.get("warnings", []):
                self._plugin_log(warning, level=logging.WARNING)

            self.dependencies_satisfied = True
            return True
        else:
            # Log validation errors
            for error in validation_result.get("errors", []):
                self._plugin_log(error, level=logging.ERROR)

            # Provide helpful offline mode message if applicable
            if self._is_offline_mode() and self.use_uv_tool:
                self._plugin_log(
                    f"Offline mode is enabled (ASH_OFFLINE=true) but tool '{self.command}' is not available. "
                    f"In offline mode, tools must be pre-installed. Please install '{self.command}' manually or disable offline mode.",
                    level=logging.ERROR,
                )

            self.dependencies_satisfied = False
            return False

    def safe_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: T | ScannerPluginConfigBase | None = None,
        *args,
        **kwargs,
    ) -> Any | SarifReport | CycloneDXReport:
        """
        Safely execute scanner against a target with comprehensive error handling.

        This is a wrapper around the scan method that catches exceptions and returns
        a structured error response instead of propagating exceptions.

        Args:
            target: Target to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore globally
            config: Scanner configuration
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Dict containing scan results or error information
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        try:
            return self.scan(
                target=target,
                target_type=target_type,
                global_ignore_paths=global_ignore_paths,
                config=config,
                *args,
                **kwargs,
            )
        except Exception as e:
            # Include stack trace for debugging
            import traceback

            stack_trace = traceback.format_exc()

            error_msg = f"{self.__class__.__name__} scanner failed: {str(e)}"
            ASH_LOGGER.error(error_msg)
            ASH_LOGGER.debug(f"Stack trace for scanner failure:\n{stack_trace}")

            # Add error to scanner's error list
            self.errors.append(error_msg)

            # Return structured error response
            return {
                "scanner": self.__class__.__name__,
                "error": str(e),
                "status": "failed",
                "findings": [],
                "errors": [error_msg, *self.errors],
                "output": self.output,
                "stack_trace": stack_trace,
            }
