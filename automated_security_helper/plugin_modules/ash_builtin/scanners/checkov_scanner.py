"""Module containing the Checkov security scanner implementation."""

import logging
import os
import json
import re
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Iterable,
    List,
    Literal,
    Optional,
    Sequence,
)
from urllib.parse import quote, unquote

from pydantic import Field, PrivateAttr
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.config.path_trust import (
    cwd_outside_scanned_tree,
    derived_roots,
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
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.get_scan_set import file_links_leaving_tree
from automated_security_helper.utils.link_exclusions import (
    ignored_entries,
    walked_files,
)
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.scanned_tree import REASON_LINK_LEAVES_TREE
from automated_security_helper.utils.suppression_matcher import active_ignore_paths
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


# Characters an output directory's path cannot hold for ASH to pass it to checkov
# as --skip-path, escaped or not: they can break the regex checkov's terraform
# module finder builds from every --skip-path value. See
# CheckovScanner._output_dir_skip_patterns.
_CHECKOV_UNSAFE_SKIP_PATH_CHARS = frozenset("()")


def _module_finder_compiles(values: List[str]) -> bool:
    """Whether checkov's terraform module finder can compile its regex over
    ``values``, the ``--skip-path`` values in the order checkov is given them.

    checkov 3.3.26 builds it as ``re.compile('|'.join(f"({excluded_paths})"))``
    (``checkov/terraform/module_loading/module_finder.py``): the list's text, joined
    one character at a time. When that fails to compile, checkov's whole terraform
    scan fails, so a value that makes it fail cannot be given.
    """
    if not values:
        return True
    try:
        re.compile("|".join(f"({list(values)})"))
    except re.error:
        return False
    return True


def _link_named_in_refusal(target: Path) -> str:
    """The link a refusal of ``target`` names: one whose path holds a parenthesis,
    the likely cause, or else the first."""
    links = file_links_leaving_tree(target)
    with_parenthesis = [link for link in links if "(" in link or ")" in link]
    return (with_parenthesis or links)[0]


def _given_skip_paths(extra_args: List[ToolExtraArg]) -> List[str]:
    """The ``--skip-path`` values already in ``extra_args``, in order: the known
    ignore paths and the operator's ``skip_path``."""
    values = []
    for arg in extra_args:
        key = str(arg.key)
        if key.startswith("--skip-path="):
            values.append(key[len("--skip-path=") :])
        elif key == "--skip-path" and arg.value is not None:
            values.append(str(arg.value))
    return values


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


def _source_relative_path(file_path: str, cwd: str) -> str:
    """The path ASH writes for ``file_path``: checkov's shape, with the name kept.

    The same ``"/" +`` relative path with every ``/..`` removed, or the path
    without its drive when the drive differs, as :func:`checkov_repo_file_path`.
    But a backslash becomes ``/`` only where it is a separator, on Windows.
    checkov's own conversion rewrites every one, which on POSIX turned the file
    ``a\\b.tf`` into ``a/b.tf``, a path that names no file. That copy is kept
    exact because the prefixes it rebuilds have to match what checkov wrote.
    """
    path = Path(file_path)
    if Path(cwd).drive == path.drive:
        relative = os.path.relpath(path, cwd)
        if "\\" in (os.sep, os.altsep):
            relative = relative.replace("\\", "/")
        return f"/{relative}".replace("/..", "")
    return f"/{'/'.join(path.parts[1:])}"


def rewrite_checkov_paths(
    document: Any,
    *,
    ran_in: str,
    source_dir: str,
    scanned_dirs: Sequence[str] = (),
    scanned_files: Optional[Callable[[], Iterable[str]]] = None,
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

    checkov also writes every backslash as ``/``, so on POSIX its path for the
    file ``a\\b.tf`` is ``a/b.tf``. When the path rebuilt from a URI does not
    exist, *scanned_files* (the scan set) is read, once, and a file checkov
    spells exactly that way, and the only one, is used instead. When both
    ``a\\b.tf`` and ``a/b.tf`` exist, checkov's path names an existing file and
    is kept: its output cannot tell the two apart.
    """
    cwd = os.path.realpath(source_dir)
    prefixes = [
        (checkov_repo_file_path(root, ran_in).rstrip("/"), root)
        for root in scanned_dirs
    ]
    # checkov's spelling of each scanned file, to that file; None where two
    # files share a spelling. Built on the first URI that names nothing.
    by_checkov_spelling: Optional[dict[str, Optional[str]]] = None

    def _recovered(written: str) -> Optional[str]:
        nonlocal by_checkov_spelling
        if scanned_files is None:
            return None
        if by_checkov_spelling is None:
            by_checkov_spelling = {}
            for name in scanned_files():
                absolute = os.path.abspath(name)
                spelling = checkov_repo_file_path(absolute, ran_in)
                by_checkov_spelling[spelling] = (
                    None if spelling in by_checkov_spelling else absolute
                )
        return by_checkov_spelling.get(written)

    def _absolute(uri: str) -> str:
        written = "/" + unquote(uri)
        joined = next(
            (
                os.path.join(root, written[len(prefix) + 1 :])
                for prefix, root in prefixes
                if written.startswith(prefix + "/")
            ),
            None,
        )
        if joined is None:
            joined = os.path.join(ran_in, unquote(uri))
        if not os.path.lexists(joined):
            return _recovered(written) or joined
        return joined

    def _uri(uri: str) -> str:
        return quote(_source_relative_path(_absolute(uri), cwd).lstrip("/"))

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
                    record["repo_file_path"] = _source_relative_path(
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
            description="Path to Checkov configuration file. A relative path is taken from the directory of the config file that sets it, or from the working directory for --config-overrides, not from the source directory. Defaults to searching for `.checkov.yaml` and `.checkov.yml` in the root of the source directory.",
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
                "Tell Checkov to skip ASH's own output directories inside the "
                "scanned directory (this run's output directory and "
                ".ash/ash_output), so it does not parse ASH's previous reports. "
                "Defaults to true; set to false to let Checkov read them. Either "
                "way ASH drops the findings located there after the scan. Has no "
                "effect on Windows, where Checkov's --skip-path matching is "
                "unreliable."
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

    #: checkov is a Python package ASH runs through uv. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True

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

        # Deferred until the dependency check asks
        # (resolve_deferred_tool_version), so construction runs nothing.
        self.defer_tool_version_probe("checkov")
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
        # First, while use_uv_tool still says what construction set: the
        # tool-version probe, which construction leaves to this point.
        self.resolve_deferred_tool_version()
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
        context_config = getattr(self.context, "config", None)
        for index, conf_path in enumerate(possible_config_paths):
            configured = index == 0 and self.config.options.config_file is not None
            if not resolved_path(conf_path, source_dir).exists():
                if configured:
                    # A configured file that does not exist takes no discovered
                    # replacement (config/path_trust.py, "Configured tool inputs
                    # that are refused or missing").
                    ASH_LOGGER.warning(
                        text_without_values(
                            f"Configured checkov config file does not exist: "
                            f"{conf_path}. Checkov will run without a config "
                            "file; no config file is discovered from the "
                            "scanned tree in its place.",
                            self._environment_values(),
                        )
                    )
                    break
                continue
            # A config file inside the scanned tree is not passed to checkov, and
            # neither is one the scan derived from the repository (under the
            # output or work directory) unless the operator's own configuration
            # names it; see config/path_trust.py. A candidate found by name is
            # the checkout's, never the operator's. The path passed is the one
            # that was checked.
            if configured:
                from automated_security_helper.config.operator_only_options import (
                    operator_wrote_value,
                )

                operator_written = operator_wrote_value(
                    context_config,
                    "scanner",
                    "checkov",
                    ("options", "config_file"),
                    conf_path,
                    config_from_context=self._config_from_context,
                )
            else:
                operator_written = False
            candidate = honored_path(
                conf_path,
                source_dir=source_dir,
                config=context_config,
                key="scanners.checkov.options.config_file"
                if configured
                else f"checkov config file {conf_path}",
                derived_dirs=derived_roots(self.context),
                operator_written=operator_written,
            )
            if candidate is not None:
                self.args.extra_args.append(
                    ToolExtraArg(key="--config-file", value=candidate.as_posix())
                )
                break
            if configured:
                # Refused: the configured value takes no discovered
                # replacement; checkov runs without a config file.
                ASH_LOGGER.warning(
                    "Configured checkov config file was not used because it "
                    "is repository-influenced. Checkov will run without a "
                    "config file; no config file is discovered from the "
                    "scanned tree in its place."
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

        for item in active_ignore_paths(
            self.config.options.skip_path, where="scanners.checkov.options.skip_path"
        ):
            # NO_MARKUP: the path and the reason are the config's text, and a
            # "[/" in either is a closing Rich tag that raises instead of printing.
            # Redacted: a configured value can come from the environment, and
            # ash.log keeps DEBUG lines under --debug.
            ASH_LOGGER.debug(
                text_without_values(
                    f"Path '{item.path}' excluded from {self.config.name} scan "
                    f"for reason: {item.reason}",
                    self._environment_values(),
                ),
                extra=NO_MARKUP,
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
        # persists across scan() calls. A new list: the one extra_args holds is
        # put back as it was, unchanged.
        original_extra_args = self.args.extra_args
        given = _given_skip_paths(original_extra_args)
        skips = list(self._output_dir_skip_patterns(target))
        links = self._link_skip_patterns(target)
        # checkov's terraform module finder compiles one regex over every value
        # (_module_finder_compiles), and fails the whole terraform scan when it
        # cannot. A link has to be left out, so a target whose link values break
        # it is not scanned; an ignored path is only left out of --skip-path, as
        # ASH drops checkov's findings there anyway.
        if links and not _module_finder_compiles([*given, *skips, *links]):
            raise ScannerError(
                f"Not running checkov on {Path(target).as_posix()}: "
                f"{_link_named_in_refusal(target)!r}: {REASON_LINK_LEAVES_TREE}, "
                "and the --skip-path values that would leave such links out fail "
                "checkov's terraform scan, so checkov would read the file it points at."
            )
        skips.extend(links)
        for value in self._ignore_skip_patterns(target, global_ignore_paths):
            if _module_finder_compiles([*given, *skips, value]):
                skips.append(value)
                continue
            ASH_LOGGER.debug(
                f"Not passing ignored path {value!r} to checkov --skip-path: with it, "
                "checkov's terraform module finder cannot compile its regex. ASH "
                "drops checkov's findings there.",
                extra=NO_MARKUP,
            )
        self.args.extra_args = [
            *original_extra_args,
            *(ToolExtraArg(key="--skip-path", value=skip) for skip in skips),
        ]
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

    def _ignore_skip_patterns(
        self, target: Path, global_ignore_paths: List[IgnorePathWithReason] | None
    ) -> List[str]:
        """One ``--skip-path`` for each path the global ignore paths ignore.

        The paths come from ``ignored_entries``, which matches each pattern as ASH
        does when it drops findings. A file is written as a link's path is
        (``_link_skip_patterns``): anchored at both ends, so it matches that file
        alone. A directory whose every file is ignored is anchored at the start and
        ends with ``/``, so it matches every path below it and not a sibling that
        shares its name's start. ``_execute_scan`` leaves out of ``--skip-path`` a
        value that would make checkov's terraform module finder fail to compile its
        regex (``_module_finder_compiles``); checkov then reads that path, and ASH
        drops its findings. None on Windows, where checkov's walked paths are not
        ``/``-joined.
        """
        if os.sep != "/" or not global_ignore_paths:
            return []
        files, _ = walked_files(target)
        entries = ignored_entries(
            target, self.context.source_dir, global_ignore_paths, files
        )
        root = Path(target).as_posix()
        escaped_dot = "\\."
        patterns = []
        for entry in entries:
            literal = re.escape(f"{root}/{entry}").replace(escaped_dot, "[.]")
            patterns.append("^" + literal + ("" if entry.endswith("/") else "$"))
        return patterns

    def _link_skip_patterns(self, target: Path) -> List[str]:
        """One ``--skip-path`` for each link to a file whose target leaves ``target``.

        checkov 3.3.26 reads a link to a file in directory mode, relative or
        absolute, and reports it at the link's path (measured), so a link the
        repository committed would have checkov read a file outside the scanned tree.
        The links come from ``file_links_leaving_tree``, which walks as checkov
        does: it does not descend links to directories, and it ignores ignore files.

        Built here, for links ASH found, and kept apart from the operator's
        ``skip_path`` values, which are passed as they are: each is the link's path
        as checkov walks it (the ``--directory`` value joined with the link's path
        below it), ``re.escape``d and anchored at both ends, so it matches that path
        and no other -- ``a/main.tf`` does not also skip ``a/main.tf.json``. checkov
        applies a value with ``re.search`` and as a substring, and the substring
        test cannot match a path either, since the value starts with ``^``. Escaped
        values with parentheses, brackets, braces, spaces, commas, quotes and
        ``? * + | $ ^ #`` were measured against checkov 3.3.26, including the regex
        its Terraform module finder builds from every value: each skipped exactly
        its own link.

        Every dot is ``[.]``, not ``\\.``: checkov's secrets runner, with
        --enable-secret-scan-all-files (or CKV_SECRETS_SCAN_ENABLE_ALL), compiles
        each value after replacing ``.terraform`` with ``\\.terraform``
        (``checkov/secrets/utils.py`` ``filter_excluded_paths``), which would turn
        an escaped ``\\.terraform`` into ``\\\\.terraform``, and that matches no path.

        checkov's terraform module finder joins every ``--skip-path`` into one
        regex a character at a time (``_module_finder_compiles``), and the ``]`` of
        a ``[.]`` can turn a later unmatched parenthesis into an open group of that
        regex: measured with checkov 3.3.26's expression, the values for ``x.tf``
        and ``a(b.tf`` together fail to compile, and with them the whole terraform
        scan, while ``x.tf`` and ``l (1).tf`` compile. ``_execute_scan`` refuses
        the target when the values do not compile.

        Raises:
            ScannerError: When there is such a link and checkov's walked paths use
                a separator other than ``/`` (Windows), where the values cannot
                match them. checkov is then not run on ``target``, rather than read
                the file the link points at.
        """
        links = file_links_leaving_tree(target)
        if not links:
            return []
        if os.sep != "/":
            raise ScannerError(
                f"Not running checkov on {Path(target).as_posix()}: {links[0]!r}: "
                f"{REASON_LINK_LEAVES_TREE}, and checkov's --skip-path cannot leave "
                "out a single file on this platform, so checkov would read the file "
                "it points at."
            )
        root = Path(target).as_posix()
        # Every dot as "[.]", not "\.": checkov's secrets runner, with
        # --enable-secret-scan-all-files (or CKV_SECRETS_SCAN_ENABLE_ALL), compiles
        # each value after replacing ".terraform" with "\.terraform"
        # (checkov/secrets/utils.py filter_excluded_paths), which would turn an
        # escaped "\.terraform" into "\\.terraform", and that matches no path.
        escaped_dot = "\\."
        return [
            "^" + re.escape(f"{root}/{relative}").replace(escaped_dot, "[.]") + "$"
            for relative in links
        ]

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
                ASH_LOGGER.debug(
                    f"Could not rewrite paths in {json_report}: {error}",
                    extra=NO_MARKUP,
                )
        raw = super()._read_results_file(results_file)
        if raw is not None:
            rewrite_checkov_paths(
                raw,
                ran_in=ran_in,
                source_dir=source_dir,
                scanned_dirs=scanned_dirs,
                scanned_files=self._scan_set,
            )
        return raw

    def _scan_set(self) -> List[str]:
        """The run's scan set, for names checkov rewrote (see rewrite_checkov_paths)."""
        from automated_security_helper.utils.scan_output_dirs import scan_set_of

        return scan_set_of(self.context)

    def _output_dir_skip_patterns(self, target: Path) -> List[str]:
        """``--skip-path`` values matching each ASH output directory under ``target``.

        Why: Checkov is given the whole directory, and ``--framework all``
        includes parsers (openapi, generic JSON/YAML) that read report files. A
        report it cannot read can stall the run until the scan timeout kills it
        (#628). Checkov already skips hidden directories, so the default
        ``.ash/ash_output`` was safe, but ``--output-dir`` pointed at a visible
        directory inside the source -- common in CI -- was scanned, and so was the
        ``.ash/ash_output`` of an earlier run when ``--output-dir`` moved this one.

        Checkov tests each value both as a regex (``re.search``) and as a
        substring against ``os.path.join(root, name)``, where ``root`` comes from
        walking the ``--directory`` value as given. So each value is an output
        directory spelled from that same string, with a trailing ``/`` so ``out``
        does not also skip ``outer/``, and ``re.escape``d
        (``utils/scan_output_dirs.escape_for_pattern``): unescaped, ``out.1/``
        also skipped ``outx1/``, ``out+1/`` also skipped ``out1/`` and
        ``outt1/``, and ``out|q/`` skipped every directory. Measured by calling
        checkov 3.3.26's ``filter_ignored_paths`` the way its runners walk a tree.

        Not anchored or grouped, and a path holding ``(`` or ``)`` is not emitted
        at all; the warning names ``skip_path`` instead. Checkov's terraform
        module finder joins every ``--skip-path`` value into one regex a character
        at a time (``'|'.join(f"({excluded_paths})")`` in ``module_finder.py``),
        which separates each escape from the character it escapes. Measured on
        3.3.26 with every printable character in an escaped value: none breaks
        that regex alone, a ``]`` followed by an unmatched parenthesis does, and
        so does an unmatched parenthesis after a user ``skip_path`` holding
        ``]``; it then fails the whole terraform scan. ASH leaves out every path
        with a parenthesis instead of working out whether it is matched.

        A path holding ``.terraform`` matches nothing in the secrets runner, which
        rewrites ``.terraform`` in each value to ``\\.terraform`` and so turns the
        escape into a literal backslash (measured on 3.3.26; the bicep and
        terraform-json runners apply the same rewrite). Those runners then read the
        directory, and ASH drops their findings there.

        Nothing is emitted on Windows, where checkov's walked paths use ``\\``.
        Findings checkov reports there anyway are dropped after the scan.
        """
        from automated_security_helper.utils.scan_output_dirs import (
            PatternSyntax,
            escape_for_pattern,
        )

        options = getattr(self.config, "options", None)
        if not getattr(options, "skip_ash_output_dir", True):
            return []
        scanner_name = getattr(self.config, "name", "checkov")
        relatives = self._ash_output_dirs_inside(target)
        if not relatives:
            return []
        if os.sep != "/":
            # checkov joins walked paths with os.sep, so on Windows the value
            # would have to carry backslashes, which are regex escapes to the
            # re.search half of its match and to the module finder's joined
            # regex. checkov documents --skip-path as unreliable on Windows
            # (the TODO in filter_ignored_paths); leave the previous behavior.
            ASH_LOGGER.debug(
                f"Not excluding ASH's output directories from {scanner_name} on "
                "Windows; add them to scanners.checkov.options.skip_path if needed."
            )
            return []
        patterns = []
        for relative in relatives:
            output_path = f"{Path(target).as_posix()}/{relative.as_posix()}/"
            if _CHECKOV_UNSAFE_SKIP_PATH_CHARS & set(output_path):
                ASH_LOGGER.warning(
                    f"Not excluding ASH's output directory {output_path} from "
                    f"{scanner_name}: the path has characters checkov cannot take "
                    "in --skip-path. Add it to scanners.checkov.options.skip_path, "
                    "or move --output-dir outside the source directory.",
                    extra=NO_MARKUP,
                )
                continue
            ASH_LOGGER.debug(
                f"Path '{output_path}' excluded from {scanner_name} scan for "
                "reason: ASH output directory",
                extra=NO_MARKUP,
            )
            patterns.append(escape_for_pattern(output_path, PatternSyntax.REGEX))
        return patterns
