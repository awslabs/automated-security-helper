from datetime import datetime, timezone
import logging
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER

from pydantic import Field
from typing import Annotated, Any, Generic, List, Literal, Optional, TypeVar
from abc import abstractmethod
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

    @abstractmethod
    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: T | ScannerPluginConfigBase | None = None,
        *args,
        **kwargs,
    ) -> Any | SarifReport | CycloneDXReport:
        """Execute scanner against a target.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Any | SarifReport | CycloneDxReport: Full scan results

        Raises:
            ScannerError: if scanning failed for any reason
        """
        pass

    def safe_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
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
