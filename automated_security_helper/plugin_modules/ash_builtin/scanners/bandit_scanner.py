"""Module containing the Bandit security scanner implementation."""

import bisect
import fnmatch
import logging
import os
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Optional

from pydantic import Field, PrivateAttr
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginConfigBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
)
from automated_security_helper.utils.link_exclusions import (
    ignored_entries,
    walked_files,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import mask_secrets_in_sarif
from automated_security_helper.utils.scanned_tree import REASON_LINK_LEAVES_TREE
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command


#: What an ``--exclude`` entry cannot hold: bandit splits the value on commas and
#: reads ``* ? [`` as fnmatch syntax, and a line break fails ASH's flag-key check.
_BANDIT_EXCLUDE_UNSAFE = frozenset(",*?[\n\r")

#: The longest ``--exclude=...`` argument passed. Linux refuses one argument longer
#: than 128 KiB (MAX_ARG_STRLEN) with E2BIG.
_EXCLUDE_ARGUMENT_LIMIT = 120 * 1024


class BanditScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Bandit configuration file. A relative path is taken from the directory of the config file that sets it, or from the working directory for --config-overrides, not from the source directory."
            f" {SET_BY_THE_OPERATOR}"
            " ASH does not look for one by name. A file named exactly `.bandit` is passed with `bandit --ini`, and any other file with `bandit --configfile`. Unless config_file names a `.bandit` file that exists, ASH passes bandit an empty config file with `bandit --ini`, so bandit does not read a `.bandit` file from the scanned tree. A path that is not a file is logged as a warning and ignored.",
        ),
    ] = None
    confidence_level: Annotated[
        Literal["all", "low", "medium", "high"],
        Field(description="Confidence level for Bandit findings"),
    ] = "all"
    ignore_nosec: Annotated[
        bool,
        Field(
            description="If True, do not skip lines with # nosec comments. Defaults to False."
        ),
    ] = False
    excluded_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            description="List of excluded paths and their corresponding reason to exclude from scanning"
        ),
    ] = []
    additional_formats: Annotated[
        List[
            Literal[
                "csv",
                "custom",
                "html",
                "json",
                "sarif",
                "txt",
                "xml",
                "yaml",
            ]
        ],
        Field(description="List of additional formats to output"),
    ] = []
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.bandit.options.tool_version"),
        Field(
            description=(
                "Version constraint for bandit installation, in pip requirement "
                "syntax. The default below is the constraint the scanner enforces."
            )
        ),
    ] = ">=1.7.0,<2.0.0"
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class BanditScannerConfig(ScannerPluginConfigBase):
    name: Literal["bandit"] = "bandit"
    enabled: bool = True
    options: Annotated[
        BanditScannerConfigOptions, Field(description="Configure Bandit scanner")
    ] = BanditScannerConfigOptions()


@ash_scanner_plugin
class BanditScanner(ScannerPluginBase[BanditScannerConfig]):
    """Implementation of a Python security scanner using Bandit.

    This scanner uses Bandit to perform static security analysis of Python code
    and returns results in a structured format using the StaticAnalysisReport model.
    """

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        env_prefixes=("BANDIT_",)
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    # The operator's .bandit file, when config_file names one; see
    # _process_config_options.
    _ini_file: Optional[Path] = PrivateAttr(default=None)

    def model_post_init(self, context):
        if self.config is None:
            self.config = BanditScannerConfig()
        self.command = "bandit"
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True  # Enable UV tool execution

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # Update tool version detection to work with explicit installation
        self.tool_version = self._get_uv_tool_version("bandit")
        self.description = "Bandit is a Python source code security analyzer."
        extra_args = [
            ToolExtraArg(
                key="--recursive",
                value=None,
            ),
        ]
        if ASH_LOGGER.level == logging.DEBUG:
            extra_args.append(
                ToolExtraArg(
                    key="--verbose",
                    value=None,
                )
            )
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg="--output",
            scan_path_arg=None,
            extra_args=extra_args,
        )
        super().model_post_init(context)

    def _get_tool_version_constraint(self) -> str | None:
        """Get version constraint for bandit installation.

        Returns:
            The configured ``tool_version`` constraint, whose default carries an
            upper bound excluding the next major version. No literal is repeated
            here: a copy of the constraint in this docstring went stale against
            the default beside it, which is what made the published docs drop the
            ceiling and tell readers to install an excluded major version.
        """
        # Use bandit-specific version constraint - bandit 1.7.0+ has better SARIF support
        return self.config.options.tool_version

    def _get_tool_package_extras(self) -> List[str] | None:
        """Get package extras for bandit installation.

        Returns:
            List of package extras needed for bandit (sarif and toml support)
        """
        # Bandit needs sarif extra for SARIF output format and toml extra for TOML config support
        return ["sarif", "toml"]

    def configure(self, config: ScannerPluginBase | None = None):
        """Configure the scanner with the provided configuration.

        Args:
            config: Scanner configuration

        Raises:
            ScannerError: If configuration fails
        """
        try:
            if config is not None:
                self.config = config

        except Exception as e:
            raise ScannerError(
                f"Failed to configure {self.__class__.__name__}: {str(e)}"
            )

    def validate_plugin_dependencies(self) -> bool:
        """Enhanced validation with explicit tool installation.

        Workflow:

        1. If UV tool execution is required but UV is not on PATH, defer to
           :func:`get_uv_tool_command` to see whether a direct binary fallback
           still satisfies the dependency.
        2. If UV is available and the tool is already reachable, succeed.
        3. Otherwise attempt explicit ``uv tool install`` with retry/timeout.
        4. As a last resort, ask :func:`get_uv_tool_command` to resolve the
           command — this consolidates the "uv missing → direct binary → None"
           fallback that used to be open-coded across scanners.

        Returns:
            True if validation passes, False otherwise
        """
        if not self._validate_uv_tool_availability():
            # UV is required but not present.  Defer to consolidated resolver:
            # if the tool is on PATH directly we can still run it.
            if get_uv_tool_command(self.command) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
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
                "Bandit not found via UV tool, attempting explicit installation...",
                level=logging.INFO,
            )

            # Attempt explicit tool installation with configured timeout
            timeout = self.config.options.install_timeout if self.config else 300
            retry_config = {
                "max_retries": 3,
                "base_delay": 1.0,
                "max_delay": 60.0,
            }

            if self._install_uv_tool(timeout=timeout, retry_config=retry_config):
                self._plugin_log(
                    "Successfully installed bandit via UV tool", level=logging.INFO
                )
                self.dependencies_satisfied = True
                return True

            self._plugin_log(
                "UV tool installation failed for bandit, falling back to consolidated resolver",
                level=logging.WARNING,
            )

        # Final fallback: consolidated UV-or-direct-binary resolver.
        return get_uv_tool_command(self.command) is not None

    def _process_config_options(self):
        # The operator's config file, if there is one. A config file inside the
        # scanned tree does not choose it (config/tool_config_trust.py), and ASH no
        # longer looks for .bandit, bandit.yaml or bandit.toml by name: their skips
        # and exclude_dirs would let the repository decide what its scan reports.
        ini_file: Path | None = None
        if self.config.options.config_file is not None:
            config_file_path = Path(self.config.options.config_file)
            if not config_file_path.is_absolute():
                config_file_path = Path(self.context.source_dir) / config_file_path
            if not config_file_path.is_file():
                ASH_LOGGER.warning(
                    "Configured bandit config file does not exist or is not a file: "
                    f"{config_file_path}. It is ignored, and bandit runs with an empty "
                    "config file."
                )
            elif config_file_path.name == ".bandit":
                ini_file = config_file_path
            else:
                self.args.extra_args.append(
                    ToolExtraArg(key="--configfile", value=config_file_path.as_posix())
                )
        # bandit reads a .bandit file it finds under the scan target on its own
        # unless --ini names one, so a scan always passes one: the operator's, or
        # an empty one written outside the scanned tree when the scan runs
        # (_execute_scan), not here, where constructing the scanner would write it.
        self._ini_file = ini_file

        self.args.extra_args.append(
            ToolExtraArg(
                key="--confidence-level", value=self.config.options.confidence_level
            )
        )
        self.args.extra_args.append(ToolExtraArg(key="--severity-level", value="all"))
        for fmt in self.config.options.additional_formats:
            self.args.extra_args.append(ToolExtraArg(key="--format", value=fmt))
        if self.config.options.ignore_nosec:
            self.args.extra_args.append(ToolExtraArg(key="--ignore-nosec", value=None))

        # Rebuilt, with the scan's own entries, when each command is assembled
        # (_execute_scan); this one is the value from the configuration alone.
        self.args.extra_args.append(
            ToolExtraArg(
                key=f"--exclude={','.join(self._configured_excludes())}", value=None
            )
        )

        return super()._process_config_options()

    def _configured_excludes(self) -> List[str]:
        """The ``--exclude`` entries the configuration gives, read when called.

        ASH's known ignore paths, each as ``<path>/**`` and ``**/<path>/**``, and each
        ``scanners.bandit.options.excluded_paths`` entry as ``**/<path>/**``.
        """
        entries = []
        for item in KNOWN_IGNORE_PATHS:
            entries.append(str(Path(item).joinpath("**")))
            entries.append(str(Path("**").joinpath(item, "**")))
        for item in self.config.options.excluded_paths:
            ASH_LOGGER.debug(
                f"Path '{item.path}' excluded from {self.config.name} scan for reason: {item.reason}"
            )
            entries.append(str(Path("**").joinpath(item.path, "**")))
        return entries

    # Bandit emits exit code 1 when findings are present; treat that as success
    # alongside 0. (Same as base default, but spelled out for clarity.)
    success_exit_codes: ClassVar[set] = {0, 1}

    # Python-only repos commonly have empty target dirs after conversion;
    # log at VERBOSE rather than INFO to keep the user-facing output clean.
    empty_target_log_level: ClassVar[int] = logging.VERBOSE

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args,
        **kwargs,
    ) -> Any:
        """The template scan, with this target's scanned-file count reset first.

        ``targets_attempted`` is set from bandit's SARIF (_record_scanned_files) and
        read by the executor after every target, so a target that returns before
        bandit runs (an empty directory) must not keep the last one's.
        """
        self.targets_attempted: Optional[int] = None
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ):
        """Resolve final argv and results path for Bandit.

        The ``--exclude`` value is assembled here, for this scan, from the current
        configuration (``_configured_excludes``), the links leaving ``target``
        (``_link_excludes``) and the scan's global ignore paths
        (``_ignore_excludes``). It was built once at construction, so the global
        ignore paths, which a scan passes in, never reached bandit, and an option
        changed after construction did not either. The value, and the ``--ini``,
        are in a new extra_args list for this resolution only; the list extra_args
        held is put back as it was, unchanged.
        """
        target_results_dir = self.results_dir.joinpath(target_type)
        results_file = target_results_dir.joinpath("bandit.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)

        files, links = walked_files(target)
        entries = self._configured_excludes() + self._link_excludes(
            target, files=files, links=links
        )
        length = len(f"--exclude={','.join(entries)}".encode())
        if length > _EXCLUDE_ARGUMENT_LIMIT:
            raise ScannerError(
                f"Not running bandit on {Path(target).as_posix()}: its --exclude "
                f"value, with the {len(links)} links that leave the scanned tree, is "
                f"longer than one command-line argument can be "
                f"({_EXCLUDE_ARGUMENT_LIMIT} bytes)."
            )
        left_out = 0
        for entry in self._ignore_excludes(target, files, global_ignore_paths):
            added = len(entry.encode()) + (1 if entries else 0)
            if length + added > _EXCLUDE_ARGUMENT_LIMIT:
                left_out += 1
                continue
            entries.append(entry)
            length += added
        if left_out:
            self._plugin_log(
                f"{left_out} paths the global ignore paths match are not in bandit's "
                "--exclude, which would be longer than one command-line argument "
                "can be; bandit reads them, and ASH drops their findings.",
                target_type=target_type,
                level=logging.WARNING,
            )

        original_extra_args = self.args.extra_args
        ini_file = self._ini_file or empty_tool_config(
            "bandit-empty.ini", "[bandit]\n", context=self.context
        )
        self.args.extra_args = [
            *(
                arg
                for arg in original_extra_args
                if not arg.key.startswith("--exclude=")
            ),
            ToolExtraArg(key=f"--exclude={','.join(entries)}", value=None),
            ToolExtraArg(key="--ini", value=ini_file.as_posix()),
        ]
        try:
            final_args = self._resolve_arguments(
                target=target, results_file=results_file
            )
        finally:
            self.args.extra_args = original_extra_args

        return final_args, results_file, None

    def _ignore_excludes(
        self,
        target: Path,
        files: List[str],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[str]:
        """``--exclude`` entries for the files the global ignore paths match.

        The files and fully ignored directories come from ``ignored_entries``, which
        matches each pattern as ASH does when it drops findings. Each is passed as
        bandit's walk spells it, ``<target>/<path>`` (a directory with its trailing
        ``/``). bandit 1.9.4 also leaves out every path an entry is a substring of,
        and reads ``,`` as a separator and ``* ? [`` as pattern syntax, so an entry
        is left out of the value when it holds one of those or a line break, or
        when it is the start of a path that is not ignored (``x.py`` of ``x.pyw``).
        bandit then reads that file, and ASH drops its findings after the scan. None
        on Windows, where bandit's walk does not join paths with ``/``.
        """
        if os.sep != "/":
            return []
        relative_entries = ignored_entries(
            target, self.context.source_dir, global_ignore_paths, files
        )
        if not relative_entries:
            return []
        root = Path(target).as_posix()
        walked = sorted(f"{root}/{relative}" for relative in files)
        # A path holding the root a second time could hold an entry other than at
        # its start; there are normally none.
        repeated = [path for path in walked if path.find(root, 1) != -1]
        entries = []
        for relative in relative_entries:
            entry = f"{root}/{relative}"
            if any(character in entry for character in _BANDIT_EXCLUDE_UNSAFE):
                continue
            if not entry.endswith("/"):
                index = bisect.bisect_left(walked, entry)
                after = walked[index + 1] if index + 1 < len(walked) else ""
                if after.startswith(entry):
                    continue
            if any(entry in path and not path.startswith(entry) for path in repeated):
                continue
            entries.append(entry)
        return entries

    def _link_excludes(
        self,
        target: Path,
        files: List[str] | None = None,
        links: List[str] | None = None,
    ) -> List[str]:
        """``--exclude`` entries for each link to a file whose target leaves ``target``.

        bandit reads a link to a file wherever it points: its walk lists the link
        among the files and opens it by name. The links come from
        ``file_links_leaving_tree``, which walks as bandit does (``os.walk``, which
        does not descend links to directories) and ignores ignore files, as bandit
        does.

        bandit 1.9.4 (``bandit/core/manager.py``) splits ``--exclude`` on commas and
        leaves out a walked file when an entry matches its path with ``fnmatch`` or
        is a substring of it. So each entry is the link's path as bandit's walk
        spells it, ``<target>/<path below it>``, and it is used only when it leaves
        out that file alone: it holds no comma, no ``*``, ``?`` or ``[``, and no line
        break (a flag key with one fails ASH's own check, which would drop the whole
        ``--exclude``), and no other file's path under ``target`` contains it.

        ``files`` and ``links`` are ``walked_files(target)``, when the caller has
        walked it already.

        Raises:
            ScannerError: Naming the first link that cannot be left out that way,
                or the first link at all when walked paths are not joined with
                ``/`` (Windows). bandit is then not run on ``target``, rather than
                read the file the link points at.
        """
        if files is None or links is None:
            files, links = walked_files(target)
        if not links:
            return []
        root = Path(target).as_posix()
        walked = [f"{root}/{relative}" for relative in files]
        entries = []
        for relative in links:
            entry = f"{root}/{relative}"
            if (
                os.sep != "/"
                or any(character in entry for character in _BANDIT_EXCLUDE_UNSAFE)
                or any(entry in other for other in walked if other != entry)
            ):
                raise ScannerError(
                    f"Not running bandit on {root}: {relative!r}: "
                    f"{REASON_LINK_LEAVES_TREE}, and bandit's --exclude cannot leave "
                    "out that file alone, so bandit would read the file it points at."
                )
            entries.append(entry)
        return entries

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Record how many files bandit scanned, and mask secret-shaped strings."""
        self._record_scanned_files(sarif_report, final_args, target)
        return mask_secrets_in_sarif(sarif_report)

    def _record_scanned_files(
        self, sarif_report: SarifReport, final_args: List[str], target: Path
    ) -> None:
        """Set ``targets_attempted`` from the files bandit's SARIF lists.

        bandit's SARIF carries ``run.properties.metrics``: ``_totals`` and one entry
        per file it scanned. None listed while the target holds ``.py`` or ``.pyw``
        files bandit was not told to exclude (matched as bandit 1.9.4 matches its
        ``--exclude`` entries, by ``fnmatch`` or as a substring) means bandit
        scanned none of them, and its result says nothing about them: an error, not
        a PASSED with no findings. None listed and none there is SKIPPED
        (``targets_attempted`` 0). No metrics leaves the count unset (no claim).

        Raises:
            ScannerError: When bandit scanned no file of the Python files there.
        """
        scanned = None
        for run in sarif_report.runs or []:
            properties = run.properties.model_dump() if run.properties else {}
            metrics = properties.get("metrics")
            if isinstance(metrics, dict):
                scanned = (scanned or 0) + sum(1 for key in metrics if key != "_totals")
        if scanned is None:
            return
        if scanned:
            self.targets_attempted = scanned
            return
        prefix = "--exclude="
        entries = [
            entry
            for arg in final_args
            if str(arg).startswith(prefix)
            for entry in str(arg)[len(prefix) :].split(",")
            if entry
        ]
        root = Path(target).as_posix()
        all_files, _ = walked_files(target)
        python = [
            f"{root}/{relative}"
            for relative in all_files
            if relative.endswith((".py", ".pyw"))
        ]
        unexcluded = [
            path
            for path in python
            if not any(fnmatch.fnmatch(path, e) or e in path for e in entries)
        ]
        if unexcluded:
            raise ScannerError(
                f"bandit scanned no file below {root}, though {len(unexcluded)} Python "
                "files there are not excluded, so its result says nothing about them."
            )
        self.targets_attempted = 0


if __name__ == "__main__":
    ASH_LOGGER.debug("Running Bandit via __main__")
    scanner = BanditScanner(
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                confidence_level="all",
                severity_threshold="ALL",
                ignore_nosec=False,
                excluded_paths=[],
                additional_formats=[],
            )
        )
    )
    report = scanner.scan(target=Path("."), target_type="source")

    if isinstance(report, SarifReport):
        print(
            report.model_dump_json(
                indent=2,
                by_alias=True,
                exclude_unset=True,
            )
        )
