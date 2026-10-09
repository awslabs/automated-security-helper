"""Module containing the Checkov security scanner implementation."""

import logging
import os
import re
import json
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Optional, Sequence
from urllib.parse import quote, unquote

from pydantic import Field, PrivateAttr
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.config.path_trust import (
    cwd_outside_scanned_tree,
    honored_path,
    resolved_path,
)
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
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
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
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


def checkov_repo_file_path(file_path: str, cwd: str) -> str:
    """The ``repo_file_path`` checkov records for ``file_path`` when run in ``cwd``.

    A copy of ``checkov.common.output.record.Record._determine_repo_file_path``
    (checkov 3.3.26) with the working directory as a parameter: ``"/" +`` the path
    relative to the working directory, separators made ``/``, and every ``/..``
    removed, or the path without its drive when the drive differs. checkov puts
    this, without the leading ``/`` and URL-quoted, in each SARIF result's URI.
    tests/unit/plugin_modules/ash_builtin/test_checkov_repo_file_path.py pins the
    shape and the integration test compares it with checkov's output.
    """
    path = Path(file_path)
    if Path(cwd).drive == path.drive:
        return f"/{os.path.relpath(path, cwd)}".replace("\\", "/").replace("/..", "")
    return f"/{'/'.join(path.parts[1:])}"


def rewrite_checkov_paths(
    document: Any,
    *,
    ran_in: str,
    source_dir: str,
    scanned_dirs: Sequence[str] = (),
) -> None:
    """Make the paths in a checkov SARIF or JSON report read as if run in source_dir.

    ASH runs checkov from the filesystem root (``CheckovScanner._subprocess_cwd``),
    so the paths checkov writes relative to its working directory are absolute
    paths without the leading ``/``. They are recomputed here with the source
    directory as the working directory, which is what checkov wrote when ASH ran
    it there, so findings and the suppressions that match their paths are
    unchanged. The JSON report's ``file_abs_path`` is used as is. A SARIF URI is
    matched against how checkov writes each of ``scanned_dirs`` (the target and
    the source directory) from ``ran_in``, because checkov's ``/..`` removal also
    changes an ancestor directory whose name starts with ``..``; a URI that
    matches none is joined to ``ran_in``.
    """
    cwd = os.path.realpath(source_dir)
    prefixes = [
        (checkov_repo_file_path(root, ran_in).rstrip("/"), root)
        for root in scanned_dirs
    ]

    def _absolute(uri: str) -> str:
        written = "/" + unquote(uri)
        for prefix, root in prefixes:
            if written.startswith(prefix + "/"):
                return os.path.join(root, written[len(prefix) + 1 :])
        return os.path.join(ran_in, unquote(uri))

    def _uri(uri: str) -> str:
        return quote(checkov_repo_file_path(_absolute(uri), cwd).lstrip("/"))

    def _locations(items: Any) -> None:
        for location in items or []:
            artifact = (location.get("physicalLocation") or {}).get("artifactLocation")
            if isinstance(artifact, dict) and isinstance(artifact.get("uri"), str):
                artifact["uri"] = _uri(artifact["uri"])

    if isinstance(document, dict) and "runs" in document:
        for run in document.get("runs") or []:
            for result in run.get("results") or []:
                _locations(result.get("locations"))
                _locations(result.get("relatedLocations"))
            for artifact in run.get("artifacts") or []:
                location = artifact.get("location")
                if isinstance(location, dict) and isinstance(location.get("uri"), str):
                    location["uri"] = _uri(location["uri"])
        return

    reports = document if isinstance(document, list) else [document]
    for report in reports:
        results = report.get("results") if isinstance(report, dict) else None
        for records in (results or {}).values():
            for record in records if isinstance(records, list) else []:
                if isinstance(record, dict) and isinstance(
                    record.get("file_abs_path"), str
                ):
                    record["repo_file_path"] = checkov_repo_file_path(
                        record["file_abs_path"], cwd
                    )


def _directory_as_one_token(argv: List[str]) -> List[str]:
    """``--directory <path>`` as the single token ``--directory=<path>``.

    checkov also reads ``.checkov.yaml`` from the directory it scans, found by
    looking for a ``-d`` or ``--directory`` token followed by a path
    (``get_default_config_paths``). Passed as one token, the same option names no
    such pair, so a config file in the scanned directory is not read. Checked
    against the checkov ASH installs.
    """
    out: List[str] = []
    index = 0
    while index < len(argv):
        if argv[index] in ("--directory", "-d") and index + 1 < len(argv):
            out.append(f"--directory={argv[index + 1]}")
            index += 2
            continue
        out.append(argv[index])
        index += 1
    return out


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
            description="Run in offline mode, disabling policy downloads. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
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
        tool_version_constraint("scanners.checkov.options.tool_version"),
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

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        env_prefixes=("CHECKOV_",)
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS
    check_conf: str = "NOT_PROVIDED"

    # The absolute target of the scan in progress, set by _execute_scan and read
    # when the results are rewritten (see rewrite_checkov_paths).
    _checkov_target: Optional[Path] = PrivateAttr(default=None)

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
        for index, conf_path in enumerate(possible_config_paths):
            configured = index == 0 and self.config.options.config_file is not None
            if not resolved_path(conf_path, source_dir).exists():
                continue
            # A config file inside the scanned tree is not passed to checkov; see
            # config/path_trust.py. The path passed is the one that was checked.
            candidate = honored_path(
                conf_path,
                source_dir=source_dir,
                config=getattr(self.context, "config", None),
                key="scanners.checkov.options.config_file"
                if configured
                else f"checkov config file {conf_path}",
            )
            if candidate is not None:
                self.args.extra_args.append(
                    ToolExtraArg(key="--config-file", value=candidate.as_posix())
                )
                break

        # Add offline mode if enabled
        if self._scanner_offline():
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
        # Absolute, because checkov runs from the filesystem root
        # (_subprocess_cwd), where a relative path names something else.
        target = Path(os.path.abspath(target))
        self._checkov_target = target
        target_results_dir = Path(
            os.path.abspath(self.results_dir.joinpath(target_type))
        )
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
        return _directory_as_one_token(final_args), results_file, None

    def _subprocess_cwd(self, results_dir: Path) -> Path | None:
        """Run checkov from the filesystem root, outside the scanned tree.

        checkov reads ``.checkov.yaml`` and ``.checkov.yml`` from its working
        directory as default config files, whatever ``--config-file`` says
        (``checkov.common.util.config_utils.get_default_config_paths``), so the
        source directory is not usable. A directory under the results directory
        is not either: when the output directory is inside the source directory,
        checkov's paths relative to it drop their ``..`` components and can no
        longer be told apart. Every path relative to the root is absolute, so
        ``rewrite_checkov_paths`` recovers the source-relative form exactly.
        """
        return cwd_outside_scanned_tree(
            self._scanned_target(),
            results_dir=results_dir,
            source_dir=self.context.source_dir,
            config=getattr(self.context, "config", None),
        )

    def _scanned_target(self) -> Path:
        """The target of the scan in progress, or the source directory."""
        return self._checkov_target or Path(os.path.abspath(self.context.source_dir))

    def _read_results_file(self, results_file: Path) -> Optional[dict[str, Any]]:
        """Read checkov's SARIF with its paths made relative to the source directory.

        The JSON report, written when ``additional_formats`` asks for it, is
        rewritten the same way so it matches. CycloneDX carries no such path.
        """
        target = self._scanned_target()
        ran_in = Path(target).anchor
        source_dir = os.path.abspath(self.context.source_dir)
        scanned_dirs = [target.as_posix(), Path(source_dir).as_posix()]
        json_report = Path(results_file).parent / "results_json.json"
        if json_report.is_file():
            try:
                with open(json_report, encoding="utf-8") as handle:
                    document = json.load(handle)
                rewrite_checkov_paths(
                    document,
                    ran_in=ran_in,
                    source_dir=source_dir,
                    scanned_dirs=scanned_dirs,
                )
                with open_for_write(json_report) as handle:
                    json.dump(document, handle, indent=4)
            except (OSError, ValueError) as error:
                ASH_LOGGER.debug(f"Could not rewrite paths in {json_report}: {error}")
        raw = super()._read_results_file(results_file)
        if raw is not None:
            rewrite_checkov_paths(
                raw, ran_in=ran_in, source_dir=source_dir, scanned_dirs=scanned_dirs
            )
        return raw

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
