# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Optional, Set
from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.tool_config_trust import empty_tool_directory
from automated_security_helper.models.core import ToolArgs

# trivy_default_misconfig_scanners and its reset live with the shared base, which
# the builtin trivy uses too; this module has always offered them, so it still does.
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    TrivyScannerBase,
    reset_trivy_default_misconfig_scanners as reset_trivy_default_misconfig_scanners,
    trivy_default_misconfig_scanners,
    trivy_timeout,
)
from automated_security_helper.base.scanner_plugin import (
    redacted_command_record,
)
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.base.uv_tool_mixin import guarded_values_read
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.subprocess_utils import (
    find_executable,
    in_tree_refusal,
)
from automated_security_helper.utils.process_env import snapshot_environ


class TrivyRepoScannerConfigOptions(ScannerOptionsBase):
    scanners: Annotated[
        List[Literal["vuln", "misconfig", "secret", "license"]],
        Field(
            description="List of what security issues to detect with Trivy Repo specifically",
        ),
    ] = [
        "vuln",
        "secret",
        "misconfig",
        "license",
    ]
    license_full: Annotated[
        bool,
        Field(
            description="Eagerly look for licenses in source code headers and license files",
        ),
    ] = True
    ignore_unfixed: Annotated[
        bool,
        Field(
            description="Display only fixed vulnerabilities",
        ),
    ] = True
    disable_telemetry: Annotated[
        bool,
        Field(
            description=(
                "Disable sending anonymous usage data to Aqua (--disable-telemetry). "
                "Only the operator sets it to false, with --config-overrides or in a "
                "config file outside every git checkout and the scanned directory: a "
                "config file inside one, or one an MCP client delivered, may set it "
                "to true but not to false. Offline, trivy sends none whatever this "
                "says."
            ),
        ),
    ] = True
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, skipping DB updates and check-update calls. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy config file (trivy.yaml), passed as --config. "
                f"{SET_BY_THE_OPERATOR} The file is used only when it is outside the "
                "scanned tree; otherwise it is ignored with a warning. A relative "
                "path is taken from the directory of the config "
                "file that sets it, or from the working directory for "
                "--config-overrides, not from the source directory. Unset or "
                "ignored, ASH passes TRIVY_CONFIG when that names a file outside the "
                "scanned tree (a relative path in it is taken from the working "
                "directory), and otherwise an empty config of its own, so trivy "
                "does not load a trivy.yaml from the directory it runs in. A path "
                "that does not exist fails the scan."
            ),
        ),
    ] = None
    module_dir: Annotated[
        Path | str | None,
        Field(
            description=(
                "A directory of trivy modules, passed as --module-dir. Unset, ASH "
                f"passes an empty directory of its own. {SET_BY_THE_OPERATOR} The "
                "directory is used, and a relative path taken, as for config_file. A "
                "path that is not a directory fails the scan."
            ),
        ),
    ] = None

    ignore_file: Annotated[
        str | None,
        Field(
            description=(
                f"A trivy ignore file, passed as --ignorefile. {SET_BY_THE_OPERATOR} "
                "The file is used only when it is outside the scanned tree; a "
                "relative path is taken from the directory of the config file that "
                "sets it, or from the working directory for --config-overrides and "
                "the environment variable. "
                "Unset, TRIVY_IGNOREFILE is used the same way, and "
                "otherwise trivy gets an empty one, so a .trivyignore in the scanned "
                "repository does not remove findings."
            ),
        ),
    ] = None
    secret_config_file: Annotated[
        str | None,
        Field(
            description=(
                "A trivy secret scanning config (trivy-secret.yaml), passed as "
                f"--secret-config. {SET_BY_THE_OPERATOR} The file is used only when "
                "it is outside the scanned tree; a relative path is taken from the "
                "directory of the config file that sets it, or from the working "
                "directory for --config-overrides and the environment variable. Unset, "
                "TRIVY_SECRET_CONFIG is used the same way, and otherwise trivy gets "
                "an empty one, so a trivy-secret.yaml in the scanned repository does "
                "not disable secret rules."
            ),
        ),
    ] = None


class TrivyRepoScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Trivy Repo scanner."""

    name: Literal["trivy-repo"] = "trivy-repo"
    enabled: bool = True
    options: Annotated[
        TrivyRepoScannerConfigOptions,
        Field(description="Configure trivy-repo scanner"),
    ] = TrivyRepoScannerConfigOptions()


@ash_scanner_plugin
class TrivyRepoScanner(TrivyScannerBase[TrivyRepoScannerConfig]):
    """Trivy repo scanner plugin.

    The option-to-flag mapping, install commands and package identity are shared
    with the ``trivy`` scanner of this module through ``TrivyScannerBase``; this class
    keeps its own config and its own ``scan()``, so what it reports is unchanged.
    """

    #: trivy is a native binary. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    # trivy exits 0 for a completed run, findings or not, unless --exit-code names
    # another code for findings (default 0, pkg/flag/report_flags.go), and 1 from
    # log.Fatal on any error (cmd/trivy/main.go). TrivyScannerBase._run_subprocess
    # passes --exit-code=0, which outranks TRIVY_EXIT_CODE and a trivy.yaml, so a
    # nonzero exit only ever means trivy failed.
    success_exit_codes: ClassVar[Set[int]] = {0}

    def model_post_init(self, context):
        if self.config is None:
            self.config = TrivyRepoScannerConfig()
        self.command = "trivy"
        self.subcommands = ["repository"]
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg="--output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """The binary, and offline, a vulnerability database for it to read.

        A copy found only inside the scanned tree is refused by ``find_executable``
        and answers None; the refusal is recorded (``dependency_unavailable_reason``,
        as ``ScannerPluginBase.validate_plugin_dependencies`` records it) so the
        MISSING row says so rather than "not installed". Offline, a scan that reads
        the vulnerability database needs one in trivy's cache
        (``TrivyScannerBase._offline_database_available``), as for the builtin
        trivy scanner.

        Returns:
            bool: True if validation passes
        """
        if self.dependency_unavailable_reason:
            return False
        trivy_binary = find_executable("trivy")
        if not trivy_binary or trivy_binary is None:
            refusal = in_tree_refusal("trivy")
            if refusal is not None:
                self.dependency_unavailable_reason = refusal
            return False
        return self._offline_database_available()

    def _process_config_options(self):
        self._append_trivy_options()
        if self.config.options.ignore_unfixed:
            # The default here, unlike the builtin trivy scanner's, so every default
            # run says once what it withholds, as grype's config warning does.
            self._plugin_log(
                "scanners.trivy-repo.options.ignore_unfixed is true (the default), "
                "which restricts which vulnerabilities reach the report: those with "
                "no fixed version are withheld, and the scan can pass with them "
                "present. Set it to false to report them.",
                level=logging.WARNING,
            )
        return super()._process_config_options()

    def _default_misconfig_scanners(self, binary: str) -> Optional[List[str]]:
        """``TrivyScannerBase._default_misconfig_scanners``, looked up in this module.

        Through this module's ``trivy_default_misconfig_scanners``, the name
        trivy-repo's callers have always used (and replaced, in its tests), rather
        than the base module's; both name the same function.
        """
        return trivy_default_misconfig_scanners(binary, list(self.subcommands))

    def _pinned_config_args(self) -> List[str]:
        """``--config`` and ``--module-dir``, so trivy loads neither from where it runs.

        trivy runs with the scan target as its working directory and loads a
        ``trivy.yaml`` from there unless ``--config`` names another, and loads the
        modules in ``--module-dir`` (or the config's ``module.dir``). Both are
        always passed. The config is ``TrivyScannerBase._trivy_config_file``'s, as
        for ``trivy``: the operator's ``config_file`` or ``TRIVY_CONFIG``, else the
        empty config ASH ships. The modules directory is the operator's, when
        ``_operator_path`` accepts it, and otherwise an empty one that ASH creates
        outside the scanned tree for this run (``empty_tool_directory``), new each
        time and removed when the run ends.
        """
        options = self.config.options
        config_file = self._trivy_config_file()
        module_dir: Optional[Path] = None
        if options.module_dir:
            module_dir = self._operator_path(
                "module_dir",
                options.module_dir,
                "trivy-repo runs with an empty modules directory instead.",
            )
            if module_dir is not None and not module_dir.is_dir():
                # Key only, as the other input refusals (_existing_file): an
                # option's value can come from the environment, and the path it
                # resolved to spells that value.
                raise ScannerError(
                    "scanners.trivy-repo.options.module_dir does not name a "
                    "directory: the path it is set to does not exist or is not a "
                    "directory. Fix the path or unset the option; trivy is not run "
                    "without it."
                )
        if module_dir is None:
            module_dir = empty_tool_directory("trivy-modules", context=self.context)
        return [
            f"--config={config_file}",
            f"--module-dir={module_dir.resolve().as_posix()}",
        ]

    def content_databases_in_use(self) -> list:
        """trivy-db, unless the scan's ``--scanners`` leave out ``vuln``.

        The secret, misconfiguration and license scanners never open it. An empty
        ``scanners`` list passes no ``--scanners``, so trivy runs its own default
        (``vuln,secret``, pkg/flag/scan_flags.go) or what a trivy.yaml says, and the
        database is held to its bounds then too.
        """
        scanners = self.config.options.scanners or []
        if scanners and "vuln" not in scanners:
            return []
        return super().content_databases_in_use()

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — TrivyRepoScanner overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[Any] | None = None,
        config: Any | None = None,
        *args,
        **kwargs,
    ) -> SarifReport | bool | None:
        """Run ``trivy repository`` on the target and return its SARIF report.

        The parameters are in the base ``scan()``'s order (target, target type,
        the global ignore paths, then the config), so a caller that passes them by
        position as the base declares them is read right; the executor passes
        them by keyword.

        Args:
            target: Target file or directory to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            The SarifReport trivy wrote; True for an empty target; False when trivy
            cannot run; None when trivy wrote no readable SARIF.
        """
        # Per target; see ScannerPluginBase.scan(). The tool lines too: a failed
        # converted-target run otherwise records the source target's stderr as its
        # own (exitCodeDescription).
        self.exit_code = 0
        self.output = []
        self._reset_errors()
        global_ignore_paths = list(global_ignore_paths or [])
        # Check if the target directory is empty or doesn't exist
        if _target_is_empty(target):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            # No tool runs for this target, so its record starts and ends now: a
            # start time left from the previous target would give it that
            # target's duration.
            self.start_time = None
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return True

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

        if not self.dependencies_satisfied:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        # No exit code until trivy returns one, as the template's scan() has it: a
        # scan refused before the tool starts reports none, not the 0 set above.
        self.exit_code = None

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)
            # A report left by an earlier run must not be read as this run's: trivy
            # writes none when it fails, and the read below takes whatever is here.
            results_file.unlink(missing_ok=True)

            final_args = self._resolve_arguments(
                target=target,
                results_file=results_file,
            )
            # Right after `trivy repository`, which needs no knowledge of how the
            # target is spelled further on; trivy takes flags in any position.
            head = [self.command, *self.subcommands]
            insert_at = (
                len(head) if final_args[: len(head)] == head else len(final_args)
            )
            # The --config token first: the secret config is read by the secret
            # scanner alone, and whether that scanner runs is read through the
            # config file the run passes (TrivyScannerBase._effective_scanners).
            pinned = self._pinned_config_args()
            inserted = [
                f"--ignorefile={self._ignore_file()}",
                f"--secret-config={self._secret_config_file(pinned)}",
                *pinned,
                # trivy's own deadline is five minutes and fails the scan when it
                # passes; matched to ASH's scan_timeout, as the builtin trivy scanner
                # does, so the bound the operator set is the one that applies.
                f"--timeout={trivy_timeout(self._effective_scan_timeout())}",
                # Each link leaving the target (trivy follows no link), and each
                # path the global ignore paths ignore.
                *self._link_skip_args(target, global_ignore_paths),
                # ASH's own output directories inside the target, as the builtin
                # trivy scanner skips them: the converted copies the converted
                # target scans already, and an earlier run's reports and results.
                *self._output_dir_skip_args(target, target_type),
            ]
            # The operator's own skip lists, which ASH's skip flags would
            # otherwise replace (TrivyScannerBase._operator_skip_args).
            inserted.extend(self._operator_skip_args(inserted))
            final_args[insert_at:insert_at] = inserted
            if self._offline():
                final_args = self._offline_misconfig_args(final_args)
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            # The database update, its skip flags and --cache-backend=memory are
            # added by TrivyScannerBase._run_subprocess, for trivy and trivy-repo
            # alike (utils/content_db_refresh.py), IN PLACE on final_args: the
            # SARIF invocation is recorded after the run, below, so it carries the
            # command that ran rather than the one assembled here.

            # The values hook is overridable and is read once, guarded, for the
            # log line and both SARIF records. When it raised or gave no usable
            # answer nothing can be redacted, so every record carries only the
            # command's name.
            read = guarded_values_read(self)
            redact_values = read.values
            if redact_values is None:
                self._plugin_log(
                    f"Running command: {self.command} (the arguments are not "
                    f"shown: the plugin's values hook {read.failure()})",
                    target_type=target_type,
                    level=logging.VERBOSE,
                )
            else:
                self._plugin_log(
                    "Running command: "
                    f"{text_without_values(' '.join(final_args), redact_values)}",
                    target_type=target_type,
                    level=logging.VERBOSE,
                )

            effective_timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                env=subprocess_env,
                timeout=effective_timeout,
            )
            # The run is over: its end time is recorded here, before the invocation
            # below reads it, so the first target's record carries this run's end
            # rather than None and the second's rather than the first's.
            self._post_scan(target=target, target_type=target_type)
            # The command as it ran, with the flags _run_subprocess added in place.
            if redact_values is None:
                shown_command = str(self.command)
                recorded_command_line = shown_command
                recorded_arguments: List[str] = []
            else:
                shown_command = text_without_values(" ".join(final_args), redact_values)
                recorded_command_line, recorded_arguments = redacted_command_record(
                    final_args, redact_values
                )
            # A run the subprocess layer flagged (timed out, could not start, its
            # output not recorded, ended by a foreign signal) is refused before its
            # file is read, whatever exit code it carries.
            self._refuse_flagged_response(response, effective_timeout)
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            # SARIF mode - parse SARIF results
            if Path(results_file).exists():
                with open(results_file, mode="r", encoding="utf-8") as f:
                    scanner_results = json.load(f)
                try:
                    sarif_report: SarifReport = SarifReport.model_validate(
                        scanner_results
                    )
                    sarif_report = self._attach_package_identity(sarif_report, target)
                    # trivy's own per-result severity, as the builtin trivy scanner
                    # reports it: without it ASH buckets the CVE rule's last CVSS
                    # score, which is another package's rating for the same CVE.
                    sarif_report = self._attach_trivy_severity(sarif_report)

                    # Attach scanner details for proper identification
                    sarif_report = attach_scanner_details(
                        sarif_report=sarif_report,
                        scanner_name=self.config.name,
                        scanner_version=getattr(self, "tool_version", None),
                        invocation_details={
                            "command_line": shown_command,
                            "arguments": recorded_arguments,
                            "working_directory": get_shortest_name(input=target),
                            "start_time": self.start_time.isoformat()
                            if self.start_time
                            else None,
                            "end_time": self.end_time.isoformat()
                            if self.end_time
                            else None,
                            "exit_code": self.exit_code,
                        },
                    )

                    if sarif_report.runs:
                        sarif_report.runs[0].invocations = [
                            Invocation(
                                commandLine=recorded_command_line,
                                arguments=recorded_arguments,
                                startTimeUtc=self.start_time,
                                endTimeUtc=self.end_time,
                                executionSuccessful=self._exit_code_accepted(),
                                exitCode=self.exit_code,
                                exitCodeDescription="\n".join(self.errors),
                                workingDirectory=ArtifactLocation(
                                    uri=get_shortest_name(input=target),
                                ),
                            )
                        ]
                    return sarif_report
                except Exception as e:
                    self._plugin_log(
                        f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}",
                        target_type=target_type,
                        level=logging.ERROR,
                        append_to_stream="stderr",
                    )
                    return
            else:
                self._plugin_log(
                    f"No results file found at {results_file}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )

        except Exception as e:
            # The run is over for this target, however it ended: the executor
            # records end_time, and one left from the previous target would give
            # this one an end before its start.
            self.end_time = datetime.now(timezone.utc)
            raise ScannerError(f"Trivy scan failed: {str(e)}")


def _target_is_empty(target: Path) -> bool:
    """Whether ``target`` is missing, or a directory with nothing in it.

    A target that is a file is not empty, and a directory that cannot be listed
    is left to the tool: the probe used to raise ``NotADirectoryError`` or
    ``PermissionError`` out of ``scan()`` before its error handling began.
    """
    try:
        if not target.exists():
            return True
        return target.is_dir() and not any(target.iterdir())
    except OSError:
        return False
