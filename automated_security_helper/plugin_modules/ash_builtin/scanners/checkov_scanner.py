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

import yaml
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
from automated_security_helper.utils.sandbox.fs_guard import open_for_atomic_write
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


def _known_ignore_skip_pattern(entry: str) -> str:
    """The ``--skip-path`` value for one ``KNOWN_IGNORE_PATHS`` directory name.

    checkov applies each value with ``re.search`` and as a substring against the
    walked path (``filter_ignored_paths``), so the bare ``venv/`` skipped every
    file under any directory whose name merely ends in ``venv`` (``devenv/``,
    ``prevenv/``), and ``node_modules/`` every file under ``old_node_modules/``.
    Anchored to a path component instead: ``(^|/)venv/`` matches ``venv/`` as a
    whole directory name at any depth and nothing else, and the substring half
    of checkov's test cannot match a real path either. Every dot is ``[.]``, not
    ``\\.``, for the reason ``_link_skip_patterns`` gives. The group is balanced,
    so the regex checkov's terraform module finder builds from every value still
    compiles (``_module_finder_compiles``).
    """
    name = entry.strip("/")
    return "(^|/)" + re.escape(name).replace("\\.", "[.]") + "/"


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


def _link_named_in_refusal(target: Path, links: Optional[List[str]] = None) -> str:
    """The link a refusal of ``target`` names: one whose path holds a parenthesis,
    the likely cause, or else the first.

    ``links`` is the list the caller already walked (``file_links_leaving_tree``),
    so the tree is not walked a second time for the message; without it the walk
    runs here. An empty list (the links are gone, or the caller had none) names
    no link rather than failing on an empty index.
    """
    if links is None:
        links = file_links_leaving_tree(target)
    with_parenthesis = [link for link in links if "(" in link or ")" in link]
    chosen = with_parenthesis or links
    return chosen[0] if chosen else "a link that leaves the scanned tree"


def _under_a_known_ignore_path(relative: str) -> bool:
    """Whether ``relative`` (``/``-joined, below the target) lies under a directory
    ``KNOWN_IGNORE_PATHS`` names, which checkov is already told to skip whole
    (``_known_ignore_skip_pattern``), so a link there needs no value of its own."""
    names = {entry.strip("/") for entry in KNOWN_IGNORE_PATHS}
    return any(part in names for part in relative.split("/")[:-1])


def _skip_path_root(target: Path) -> str:
    """``target`` as the start of a ``--skip-path`` value: without a trailing ``/``,
    so the filesystem root does not become ``//``, a path checkov never walks."""
    return Path(target).as_posix().rstrip("/")


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

    The same ``"/" +`` relative path, or the path without its drive when the
    drive differs, as :func:`checkov_repo_file_path`, with two differences. A
    backslash becomes ``/`` only where it is a separator, on Windows: checkov's
    own conversion rewrites every one, which on POSIX turned the file ``a\\b.tf``
    into ``a/b.tf``, a path that names no file. And the ``..`` components are
    kept: checkov removes every ``/..``, which turned a file outside ``cwd``
    (``../elsewhere/x.tf``) into ``elsewhere/x.tf``, a path that reads as
    inside it and names nothing there. That copy is kept exact because the
    prefixes it rebuilds have to match what checkov wrote; this one is what ASH
    reports.
    """
    path = Path(file_path)
    if Path(cwd).drive == path.drive:
        relative = os.path.relpath(path, cwd)
        if "\\" in (os.sep, os.altsep):
            relative = relative.replace("\\", "/")
        return f"/{relative}"
    return f"/{'/'.join(path.parts[1:])}"


def _within(path: str, root: str) -> bool:
    """Whether ``path`` is ``root`` or below it, both absolute, as spelled."""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # another drive, on Windows
        return False


#: The most characters the ``--skip-path`` values for globally ignored paths may
#: take together. Every ignored file that is not under a wholly ignored directory
#: is its own value, so a large ignore set could exceed the argument-list limit
#: (checkov cannot start) or multiply checkov's per-directory filtering until the
#: scan timeout. Past the budget the rest are left out: ASH drops checkov's
#: findings under an ignored path anyway.
_IGNORE_SKIP_PATH_CHAR_BUDGET = 100_000


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
    given = os.path.abspath(source_dir)
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
            try:
                names = list(scanned_files())
            except (OSError, ValueError, RuntimeError) as error:
                # The scan set is a convenience here (a name checkov respelled);
                # a set that cannot be read must not fail the whole report. The
                # URI then keeps checkov's form, as one with no match does.
                ASH_LOGGER.debug(
                    f"Could not read the scan set to recover checkov's paths: {error}",
                    extra=NO_MARKUP,
                )
                names = []
            for name in names:
                absolute = os.path.abspath(name)
                spelling = checkov_repo_file_path(absolute, ran_in)
                by_checkov_spelling[spelling] = (
                    None if spelling in by_checkov_spelling else absolute
                )
        return by_checkov_spelling.get(written)

    def _absolute(uri: str) -> str:
        # surrogateescape both ways: checkov writes the bytes of a name that is
        # not UTF-8 percent-encoded, and the default decoding replaced them with
        # U+FFFD, a path that names no file and could never be re-encoded to the
        # bytes checkov wrote.
        written = "/" + unquote(uri, errors="surrogateescape")
        joined = next(
            (
                os.path.join(root, written[len(prefix) + 1 :])
                for prefix, root in prefixes
                if written.startswith(prefix + "/")
            ),
            None,
        )
        if joined is None:
            joined = os.path.join(ran_in, unquote(uri, errors="surrogateescape"))
        if not os.path.lexists(joined):
            return _recovered(written) or joined
        return joined

    def _uri(uri: str) -> str:
        # Relative to the source directory as given before its real path: the
        # scanned dirs were spelled as given, so with a symlink component in the
        # source directory the real path alone gave an absolute-looking path.
        absolute = _absolute(uri)
        base = given if _within(absolute, given) else cwd
        return quote(
            _source_relative_path(absolute, base).lstrip("/"),
            errors="surrogateescape",
        )

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
                    # The same choice _uri makes for the SARIF report: checkov
                    # wrote the path as the scanned directory was given, so a
                    # symlinked source directory is relative to the given
                    # spelling, and the two reports agree on the file.
                    written = os.path.abspath(record["file_abs_path"])
                    base = given if _within(written, given) else cwd
                    record["repo_file_path"] = _source_relative_path(written, base)


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
            description=(
                "Path to a Checkov configuration file. A relative path is taken "
                "from the directory of the config file that sets it, or from the "
                "working directory for --config-overrides, not from the source "
                "directory. Only a file the operator names and that lies outside "
                "the scanned tree is passed to Checkov; a `.checkov.yaml` or "
                "`.checkov.yml` found in the scanned tree is not read, and the "
                "scan tells Checkov to read none from its working directory "
                "either, because such a file can change what is reported."
            ),
        ),
    ] = None
    skip_path: Annotated[
        List[IgnorePathWithReason],
        Field(
            description=(
                "Path (file or directory) to skip, as a regular expression Checkov "
                "searches for in each path it walks, and also as a substring of "
                "that path. The paths Checkov walks start with the absolute path "
                'of the scanned directory. Word boundaries are not implicit: "dir1" '
                'skips any directory or subdirectory whose path holds "dir1". An '
                "entry whose path is empty is ignored (it would skip every file). "
                "Can be specified multiple times."
            ),
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

    # CKV_ too: checkov reads its own switches under that prefix as well
    # (CKV_SECRETS_SCAN_ENABLE_ALL, CKV_IGNORED_DIRECTORIES, ...), and under the
    # sandbox a variable the operator set that way never reached it.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        env_prefixes=("CHECKOV_", "CKV_")
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS
    check_conf: str = "NOT_PROVIDED"

    # The absolute target of the scan in progress, set by _execute_scan and read
    # when the results are rewritten (see rewrite_checkov_paths).
    _checkov_target: Optional[Path] = PrivateAttr(default=None)
    # The working directory the scan in progress runs checkov in, as
    # _subprocess_cwd chose it: the results are rewritten against it, not
    # against the root it is normally equal to (see _read_results_file).
    _checkov_cwd: Optional[Path] = PrivateAttr(default=None)

    def model_post_init(self, context):
        if self.config is None:
            self.config = CheckovScannerConfig()
        self.command = "checkov"
        self.use_uv_tool = True  # Enable UV tool execution
        self.tool_type = ScannerToolType.IAC

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # The version probe is recorded here and run once, by the dependency
        # check, the SARIF step or the inventory (resolve_deferred_tool_version):
        # construction must start nothing, whoever constructs the scanner.
        self._deferred_tool_version_probe = ("checkov", self._uv_from_spec())
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
            # UV missing: the resolver's direct binary, verified first. The
            # resolver probes under this scanner's own offline mode, as every uv
            # call of the mixin does: without it a scanner offline by its
            # options probed PyPI online while its run and install were offline.
            resolved = get_uv_tool_command(
                self.command,
                from_spec=self._uv_probe_from_spec(),
                offline=self._is_offline_mode(),
            )
            if resolved is None:
                return False
            return self._accept_binary_on_path(resolved)

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

        # Final fallback: consolidated UV-or-direct-binary resolver. A binary it
        # found on PATH has to run directly: with use_uv_tool left True every
        # scan went through uv, whose install had just failed. And a dependency
        # declared satisfied is recorded as such, as the branches above record it.
        resolved = get_uv_tool_command(
            self.command,
            from_spec=self._uv_probe_from_spec(),
            offline=self._is_offline_mode(),
        )
        if resolved is None:
            return False
        self.use_uv_tool = resolved[:1] == ["uv"]
        self.dependencies_satisfied = True
        return True

    def _accept_binary_on_path(self, resolved: List[str]) -> bool:
        """Whether the checkov the resolver found with no uv may run the scan.

        Without uv there is no install to fall back on, so the binary on PATH is
        the scan's checkov: it is verified against the scan's version constraint
        as ``_select_tool_execution`` verifies one. Before this it was declared
        satisfied unverified. One that falls short is MISSING with the reason;
        one that cannot be verified runs, with a warning.
        """
        from automated_security_helper.utils.pre_installed_tool import (
            verify_pre_installed_tool,
        )

        if resolved[:1] == ["uv"]:
            self.use_uv_tool = True
            self.dependencies_satisfied = True
            return True
        executable = resolved[0]
        checked = verify_pre_installed_tool(
            executable,
            self.command,
            None,
            self._get_tool_version_constraint(),
            uv_executable=None,
            values=self._values_to_redact(),
        )
        if checked.status == "unsatisfied":
            reason = (
                f"uv is not installed and the checkov on PATH ({executable}) "
                f"cannot be used: {checked.detail}"
            )
            self.dependency_unavailable_reason = reason
            self._plugin_log(reason, level=logging.ERROR)
            self.dependencies_satisfied = False
            return False
        if checked.status != "satisfied":
            self._plugin_log(
                f"uv is not installed and the checkov on PATH ({executable}) "
                f"could not be verified against the scan's requirement "
                f"({checked.detail}); running it anyway.",
                level=logging.WARNING,
            )
        self.use_uv_tool = False
        self.dependencies_satisfied = True
        return True

    @staticmethod
    def _config_file_values(config_file: str) -> dict[str, Any]:
        """The operator's checkov config file as a mapping, or {} when it cannot
        be read as one.

        checkov takes a value given on the command line over the file's
        (configargparse), and ASH always passes ``--framework`` and
        ``--skip-path`` values, so a ``framework`` or ``skip-path`` the operator
        put in the file was silently overridden. ``_process_config_options``
        reads the two keys here and folds them into the command line. A file
        that cannot be parsed changes nothing: checkov reads it itself and
        reports it.
        """
        try:
            with open(config_file, encoding="utf-8") as handle:
                parsed = yaml.safe_load(handle)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
            ASH_LOGGER.debug(
                f"Could not read the checkov config file {config_file} for its "
                f"framework and skip-path values: {error}",
                extra=NO_MARKUP,
            )
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _process_config_options(self):
        # Checkov config path
        configured_file = self.config.options.config_file
        if configured_file is not None and not str(configured_file).strip():
            # "" or whitespace resolved to the source directory itself, which
            # exists, so the discovery stopped there and a directory was handed
            # to checkov as its config file.
            ASH_LOGGER.warning(
                "Ignoring an empty scanners.checkov.options.config_file: it names "
                "no file. Checkov runs without a config file; no config file is "
                "discovered from the scanned tree in its place."
            )
            configured_file = None
        possible_config_paths = [
            item
            for item in [
                configured_file,
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
        file_values: dict = {}
        for index, conf_path in enumerate(possible_config_paths):
            configured = index == 0 and configured_file is not None
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
                file_values = self._config_file_values(candidate.as_posix())
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

        # --skip-download is decided per scan, in _execute_scan: the offline mode
        # is read at the moment it is asked (_scanner_offline), and this runs at
        # construction, so a scanner built before --offline took effect ran online.

        for item in self.config.options.additional_formats:
            self.args.extra_args.append(ToolExtraArg(key="--output", value=item))
        frameworks = list(self.config.options.frameworks)
        file_frameworks = file_values.get("framework")
        if isinstance(file_frameworks, str):
            file_frameworks = [file_frameworks]
        if (
            frameworks == ["all"]
            and isinstance(file_frameworks, list)
            and file_frameworks
            and all(isinstance(item, str) for item in file_frameworks)
        ):
            # The option is at its default and the operator's file names the
            # frameworks: the file's would have been overridden by the default
            # on the command line, so the file's are passed instead.
            frameworks = list(file_frameworks)
        for item in frameworks:
            self.args.extra_args.append(ToolExtraArg(key="--framework", value=item))
        for item in self.config.options.skip_frameworks:
            self.args.extra_args.append(
                ToolExtraArg(key="--skip-framework", value=item)
            )
        file_skips = file_values.get("skip-path")
        if isinstance(file_skips, str):
            file_skips = [file_skips]
        for item in file_skips if isinstance(file_skips, list) else []:
            # Passed on the command line too, since the command line's --skip-path
            # list replaces the file's whole.
            if isinstance(item, str) and item.strip():
                self.args.extra_args.append(
                    ToolExtraArg(key=f"--skip-path={item}", value=None)
                )

        for item in KNOWN_IGNORE_PATHS:
            self.args.extra_args.append(
                ToolExtraArg(
                    key=f"--skip-path={_known_ignore_skip_pattern(item)}", value=None
                )
            )

        for item in active_ignore_paths(
            self.config.options.skip_path, where="scanners.checkov.options.skip_path"
        ):
            if not str(item.path).strip():
                # "--skip-path=" matches every path, as a regex and as a substring,
                # so checkov would scan nothing and the scan would read as clean.
                ASH_LOGGER.warning(
                    f"Ignoring an empty scanners.checkov.options.skip_path entry "
                    f"(reason: {text_without_values(str(item.reason), self._environment_values())}): "
                    "an empty --skip-path would exclude every file.",
                    extra=NO_MARKUP,
                )
                continue
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
        if "," in str(target_results_dir):
            # checkov splits --output-file-path on commas into one path per
            # output format, so a results directory holding one is written
            # outside the results directory, possibly over an existing file.
            raise ScannerError(
                f"Not running checkov: its results directory "
                f"{target_results_dir.as_posix()} holds a comma, which checkov "
                "reads as a separator between per-format output paths. Use an "
                "--output-dir without a comma."
            )
        results_file = target_results_dir.joinpath("results_sarif.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A previous run into the same directory left its reports; a checkov
        # that fails before writing would leave them to be read as this run's.
        for stale in (results_file, results_file.parent / "results_json.json"):
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                ASH_LOGGER.debug(
                    f"Could not remove the previous {stale.name}: {error}",
                    extra=NO_MARKUP,
                )

        # Added for this resolution only and then removed, as bandit does with its
        # excluded paths: the pattern depends on the target, and extra_args
        # persists across scan() calls. A new list: the one extra_args holds is
        # put back as it was, unchanged.
        original_extra_args = self.args.extra_args
        given = _given_skip_paths(original_extra_args)
        # checkov's terraform module finder compiles one regex over every value
        # (_module_finder_compiles), and fails the whole terraform scan when it
        # cannot. The operator's own skip_path values are checked first and
        # named as the cause when they break it: before this the refusal always
        # blamed a link, and ran even when there was no link.
        if not _module_finder_compiles(given):
            raise ScannerError(
                f"Not running checkov on {Path(target).as_posix()}: the "
                "scanners.checkov.options.skip_path values, joined as checkov's "
                "terraform module finder joins them, do not compile as a regular "
                "expression, so checkov's terraform scan would fail. Balance the "
                "parentheses and brackets in them."
            )
        skips: List[str] = []
        for value in self._output_dir_skip_patterns(target):
            # An output directory ASH drops findings under anyway: left out of
            # --skip-path, with a note, rather than refusing the target.
            if _module_finder_compiles([*given, *skips, value]):
                skips.append(value)
                continue
            ASH_LOGGER.warning(
                f"Not excluding ASH's output directory from checkov with "
                f"{value!r}: with it, checkov's terraform module finder cannot "
                "compile its regex. ASH drops checkov's findings there.",
                extra=NO_MARKUP,
            )
        link_paths = self._links_leaving_tree(target)
        links = self._link_skip_patterns(target, link_paths)
        # A link has to be left out, so a target whose link values break the
        # module finder is not scanned; an ignored path is only left out of
        # --skip-path, as ASH drops checkov's findings there anyway.
        if links and not _module_finder_compiles([*given, *skips, *links]):
            raise ScannerError(
                f"Not running checkov on {Path(target).as_posix()}: "
                f"{_link_named_in_refusal(target, link_paths)!r}: "
                f"{REASON_LINK_LEAVES_TREE}, "
                "and the --skip-path values that would leave such links out fail "
                "checkov's terraform scan, so checkov would read the file it points at."
            )
        skips.extend(links)
        if self._scanner_offline():
            # Decided here, per scan, for the reason _process_config_options gives.
            skips_offline = [ToolExtraArg(key="--skip-download", value="")]
            ASH_LOGGER.info(
                "Running Checkov in offline mode - policy downloads disabled"
            )
        else:
            skips_offline = []
        # Directory entries (ending in "/") first: one of them keeps checkov out of
        # a whole tree for a few characters, where per-file entries use the budget
        # up one file at a time; a stable sort keeps each group's own order.
        ignored = sorted(
            self._ignore_skip_patterns(target, global_ignore_paths),
            key=lambda value: not value.endswith("/"),
        )
        budgeted: List[str] = []
        used = 0
        for value in ignored:
            used += len(value) + len("--skip-path") + 2
            if used > _IGNORE_SKIP_PATH_CHAR_BUDGET:
                # WARNING, not DEBUG: paths are often ignored because checkov
                # chokes on them, so a cut here can come back as a stall or a
                # finding in an ignored file with no visible cause.
                ASH_LOGGER.warning(
                    f"Not passing {len(ignored) - len(budgeted)} of {len(ignored)} "
                    "ignored paths to checkov --skip-path: together they take more "
                    f"than {_IGNORE_SKIP_PATH_CHAR_BUDGET} characters of command "
                    "line. checkov still reads those files; ASH drops its findings "
                    "there.",
                    extra=NO_MARKUP,
                )
                break
            budgeted.append(value)
        # One compile over the whole list first: compiling once per value over the
        # accumulated list was quadratic in the number of ignored files, before
        # the tool started and outside its timeout. Only when the whole list fails
        # is each value tried on its own, to find the ones that break it.
        if _module_finder_compiles([*given, *skips, *budgeted]):
            skips.extend(budgeted)
            budgeted = []
        for value in budgeted:
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
            *skips_offline,
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
        root = _skip_path_root(target)
        escaped_dot = "\\."
        patterns = []
        for entry in entries:
            literal = re.escape(f"{root}/{entry}").replace(escaped_dot, "[.]")
            patterns.append("^" + literal + ("" if entry.endswith("/") else "$"))
        return patterns

    @staticmethod
    def _links_leaving_tree(target: Path) -> List[str]:
        """The links to files whose target leaves ``target``, as checkov walks them,
        less the ones under a directory ``KNOWN_IGNORE_PATHS`` names: checkov is
        told to skip those directories whole (``_process_config_options``), so a
        value per link there only lengthened the command line (a ``node_modules``
        with thousands of links reached the argument-list limit)."""
        return [
            relative
            for relative in file_links_leaving_tree(target)
            if not _under_a_known_ignore_path(relative)
        ]

    def _link_skip_patterns(
        self, target: Path, links: Optional[List[str]] = None
    ) -> List[str]:
        """One ``--skip-path`` for each link to a file whose target leaves ``target``.

        ``links`` is the list ``_links_leaving_tree`` found, when the caller
        already walked the tree; without it the walk runs here.

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
        if links is None:
            links = self._links_leaving_tree(target)
        if not links:
            return []
        if os.sep != "/":
            raise ScannerError(
                f"Not running checkov on {Path(target).as_posix()}: {links[0]!r}: "
                f"{REASON_LINK_LEAVES_TREE}, and checkov's --skip-path cannot leave "
                "out a single file on this platform, so checkov would read the file "
                "it points at."
            )
        root = _skip_path_root(target)
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
        chosen = cwd_outside_scanned_tree(
            self._scanned_target(),
            results_dir=results_dir,
            source_dir=self.context.source_dir,
            config=getattr(self.context, "config", None),
        )
        # Kept for _read_results_file: the directory is usually the root, but
        # cwd_outside_scanned_tree makes another when the root is inside the
        # tree, and the paths checkov writes are relative to the one it ran in.
        self._checkov_cwd = Path(chosen) if chosen is not None else None
        return chosen

    def _scanned_target(self) -> Path:
        """The target of the scan in progress, or the source directory."""
        return self._checkov_target or Path(os.path.abspath(self.context.source_dir))

    def _read_results_file(self, results_file: Path) -> Optional[dict[str, Any]]:
        """Read checkov's SARIF with its paths made relative to the source directory.

        The JSON report, written when ``additional_formats`` asks for it, is
        rewritten the same way so it matches. CycloneDX carries no such path.
        """
        target = self._scanned_target()
        # The directory checkov ran in (_subprocess_cwd): the root, unless that
        # lies inside the tree and another directory was made. Read as the
        # root always, the paths of such a run were rebuilt against the wrong base.
        ran_in = (
            self._checkov_cwd.as_posix()
            if self._checkov_cwd is not None
            else Path(target).anchor
        )
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
                # Staged beside it under the write guard and renamed into place
                # when the block ends: a failure while writing (disk full) left a
                # truncated report under the name, where the reporters read it as
                # damaged output. The guard's atomic form does the staging, the
                # rename and the cleanup on a raise, so no rename of its own is
                # made here (every write below an output directory goes through
                # fs_guard, which the output-writers audit checks).
                with open_for_atomic_write(json_report) as handle:
                    json.dump(document, handle, indent=4)
            except (OSError, ValueError) as error:
                # A WARNING, not DEBUG: the report is left with checkov's
                # root-relative paths, which no suppression matches.
                ASH_LOGGER.warning(
                    f"Could not rewrite the paths in {json_report}: {error}. "
                    "Its paths stay as checkov wrote them.",
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

        Anchored at the start with ``^`` (unanchored, the value also skipped a
        deeper path holding the same text), not grouped, and a path holding ``(``
        or ``)`` is not emitted at all; the warning names ``skip_path`` instead.
        Checkov's terraform
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
            output_path = f"{_skip_path_root(target)}/{relative.as_posix()}/"
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
            # Anchored at the start: unanchored, the value also skipped a deeper
            # path that holds the same text (a copy of the tree under itself).
            patterns.append("^" + escape_for_pattern(output_path, PatternSyntax.REGEX))
        return patterns
