"""Module containing the Checkov security scanner implementation."""

import logging
import os
import re
from pathlib import Path
from typing import Annotated, ClassVar, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS, is_offline_mode
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command


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


# Characters a --skip-path value can carry through checkov without changing what
# it matches or breaking the regex checkov's terraform module finder builds from
# it. See CheckovScanner._output_dir_skip_pattern.
_CHECKOV_SAFE_SKIP_PATH = re.compile(r"^[\w./:-]+$")


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
            default_factory=is_offline_mode,
        ),
    ]
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
    skip_ash_output_dir: Annotated[
        bool,
        Field(
            description=(
                "Skip ASH's own output directory when it sits inside the scanned "
                "directory, so Checkov does not parse ASH's previous reports. "
                "Defaults to true; set to false to scan it anyway. Has no effect "
                "on Windows, where Checkov's --skip-path matching is unreliable."
            ),
        ),
    ] = True
    tool_version: Annotated[
        str | None,
        Field(
            description=(
                "Version constraint for checkov installation, in pip requirement "
                "syntax. Leave unset to use the scanner's own default constraint."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class CheckovScannerConfig(ScannerPluginConfigBase):
    name: Literal["checkov"] = "checkov"
    enabled: bool = True
    options: Annotated[
        CheckovScannerConfigOptions, Field(description="Configure Checkov scanner")
    ] = CheckovScannerConfigOptions()


@ash_scanner_plugin
class CheckovScanner(ScannerPluginBase[CheckovScannerConfig]):
    """CheckovScanner implements IaC scanning using Checkov."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS
    check_conf: str = "NOT_PROVIDED"

    def model_post_init(self, context):
        if self.config is None:
            self.config = CheckovScannerConfig()
        self.command = "checkov"
        self.use_uv_tool = True  # Enable UV tool execution
        self.tool_type = ScannerToolType.IAC

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # Update tool version detection to work with explicit installation
        self.tool_version = self._get_uv_tool_version("checkov")
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="sarif",
            output_arg="--output-file-path",
            scan_path_arg="--directory",
            extra_args=[],
        )
        super().model_post_init(context)

    def _get_tool_version_constraint(self) -> str | None:
        """Get version constraint for checkov installation.

        Returns:
            The configured ``tool_version`` constraint if set, otherwise the
            default returned below. The literal is deliberately stated once, in
            the return statement, rather than repeated here where it could drift.
        """
        # Use configured tool version if provided, otherwise use default
        if self.config and self.config.options.tool_version:
            return self.config.options.tool_version

        # Use checkov-specific version constraint - checkov 3.2.0+ has improved stability
        # and better SARIF support, but avoid 4.x for now due to potential breaking changes
        return ">=3.2.0,<4.0.0"

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        if not self._validate_uv_tool_availability():
            # UV missing — defer to consolidated resolver for direct binary.
            if get_uv_tool_command(self.command) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            return False

        # For UV tool-based scanners, attempt explicit installation if needed
        if self.use_uv_tool:
            # Check if tool is already available (UV-installed or pre-installed)
            installation_info = self._get_tool_installation_info()

            if installation_info.get("available"):
                # Runs a verified binary on PATH directly instead of re-resolving
                # through uv, and fails offline with the missing extras named (#520).
                return self._select_tool_execution(installation_info)

            # Tool not available, attempt installation
            self._plugin_log(
                "Checkov not found via UV tool, attempting explicit installation..."
            )

            # Attempt explicit tool installation with configured timeout
            timeout = self.config.options.install_timeout if self.config else 300
            if self._install_uv_tool(timeout=timeout):
                self._plugin_log("Successfully installed checkov via UV tool")
                self.dependencies_satisfied = True
                return True

            self._plugin_log(
                "UV tool installation failed for checkov, falling back to consolidated resolver",
                level=logging.WARNING,
            )

        # Final fallback: consolidated UV-or-direct-binary resolver.
        return get_uv_tool_command(self.command) is not None

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

        # Resolve config candidates against source_dir, not the process working
        # directory, and hand checkov an absolute path.
        #
        # The subprocess runs with cwd=context.source_dir (see
        # PluginBase._run_subprocess), so probing with a bare Path(...).exists()
        # asked a different question than the one checkov would answer: it tested
        # the directory ASH happens to be invoked from. When that directory was
        # ASH's own checkout, the probe matched ASH's ".ash/.checkov.yaml" and
        # passed it through get_shortest_name, which relativises against the
        # process cwd. checkov then could not open it, wrote no SARIF, and the
        # scanner reported ERROR with zero findings.
        #
        # This used to line up by accident: the pre-decomposition run_ash_scan
        # chdir'd the whole process into source_dir, so process cwd and subprocess
        # cwd were the same directory. Resolving explicitly keeps the behaviour
        # correct without a global chdir, which also matters for scanning several
        # projects in one process.
        source_dir = Path(self.context.source_dir)
        for conf_path in possible_config_paths:
            candidate = Path(conf_path)
            if not candidate.is_absolute():
                candidate = source_dir / candidate
            if candidate.exists():
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--config-file",
                        value=candidate.resolve().as_posix(),
                    )
                )
                break

        # Add offline mode if enabled
        if self.config.options.offline:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--skip-download",
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

        for item in KNOWN_IGNORE_PATHS:
            self.args.extra_args.append(
                ToolExtraArg(key=f"--skip-path={item}", value=None)
            )

        for item in self.config.options.skip_path:
            ASH_LOGGER.debug(
                f"Path '{item.path}' excluded from {self.config.name} scan for reason: {item.reason}"
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key=f"--skip-path={item.path}",
                    value=None,
                )
            )

        return super()._process_config_options()

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ):
        """Resolve final argv and results path for Checkov.

        Checkov writes results into a directory and chooses the filename;
        we point ``--output-file-path`` at the parent dir but read
        ``results_sarif.sarif`` from inside it.
        """
        target_results_dir = self.results_dir.joinpath(target_type)
        results_file = target_results_dir.joinpath("results_sarif.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)

        # Added for this resolution only and then removed, as bandit does with its
        # excluded paths: the pattern depends on the target, and extra_args
        # persists across scan() calls.
        original_extra_args = list(self.args.extra_args)
        output_skip = self._output_dir_skip_pattern(target)
        if output_skip is not None:
            self.args.extra_args.append(
                ToolExtraArg(key="--skip-path", value=output_skip)
            )
        try:
            final_args = self._resolve_arguments(
                target=target,
                # We want to use the parent here, not the results_file, as Checkov is expecting the output
                # directory and not the file name.
                results_file=target_results_dir,
            )
        finally:
            self.args.extra_args = original_extra_args
        return final_args, results_file, None

    def _output_dir_skip_pattern(self, target: Path) -> str | None:
        """A ``--skip-path`` value matching ASH's output directory under ``target``.

        Why: Checkov is given the whole directory, and ``--framework all``
        includes parsers (openapi, generic JSON/YAML) that read report files. A
        report it cannot read can stall the run until the scan timeout kills it
        (#628). Checkov already skips hidden directories, so the default
        ``.ash/ash_output`` was safe, but ``--output-dir`` pointed at a visible
        directory inside the source -- common in CI -- was scanned.

        Checkov tests each value both as a regex (``re.search``) and as a
        substring against ``os.path.join(root, name)``, where ``root`` comes from
        walking the ``--directory`` value as given. So the value is the output
        directory spelled from that same string, with a trailing ``/`` so ``out``
        does not also skip ``outer/``.

        Deliberately not ``re.escape``d or anchored with a group. Checkov's
        terraform module finder builds one regex out of every ``--skip-path``
        character by character (``'|'.join(f"({excluded_paths})")`` in
        ``module_finder.py``), so a ``(`` or ``)`` in any value fails the whole
        terraform scan with "unbalanced parenthesis" -- measured against checkov
        3.x when an escaped, grouped pattern was tried first. For the same reason a
        path containing anything beyond word characters, ``.``, ``/``, ``:`` and
        ``-`` is not emitted at all; the warning names ``skip_path`` instead.
        Nothing is emitted on Windows, where checkov's walked paths use ``\\``.
        """
        options = getattr(self.config, "options", None)
        if not getattr(options, "skip_ash_output_dir", True):
            return None
        scanner_name = getattr(self.config, "name", "checkov")
        relative = self._output_dir_inside(target)
        if relative is None:
            return None
        if os.sep != "/":
            # checkov joins walked paths with os.sep, so on Windows the value
            # would have to carry backslashes, which are regex escapes to the
            # re.search half of its match and to the module finder's joined
            # regex. checkov documents --skip-path as unreliable on Windows
            # (the TODO in filter_ignored_paths); leave the previous behavior.
            ASH_LOGGER.debug(
                f"Not excluding ASH's output directory from {scanner_name} on "
                "Windows; add it to scanners.checkov.options.skip_path if needed."
            )
            return None
        output_path = f"{Path(target).as_posix()}/{relative.as_posix()}/"
        if not _CHECKOV_SAFE_SKIP_PATH.match(output_path):
            ASH_LOGGER.warning(
                f"Not excluding ASH's output directory {output_path} from "
                f"{scanner_name}: the path has characters checkov cannot take "
                "in --skip-path. Add it to scanners.checkov.options.skip_path, or "
                "move --output-dir outside the source directory."
            )
            return None
        ASH_LOGGER.debug(
            f"Path '{output_path}' excluded from {scanner_name} scan for "
            "reason: ASH output directory"
        )
        return output_path
