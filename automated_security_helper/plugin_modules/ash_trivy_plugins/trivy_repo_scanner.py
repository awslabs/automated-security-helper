# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import logging
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Optional, Set, Tuple
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
from automated_security_helper.utils.subprocess_utils import find_executable
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
        """Validate scanner configuration.

        Returns:
            bool: True if validation passes
        """
        trivy_binary = find_executable("trivy")
        if not trivy_binary or trivy_binary is None:
            return False
        return True

    def _process_config_options(self):
        self._append_trivy_options()
        return super()._process_config_options()

    def _environment_values(self) -> Tuple[str, ...]:
        """The configuration's environment values, plus the two variables this
        scanner reads straight from the environment (never through the
        configuration), so text that quotes one is redacted."""
        read = (
            os.environ.get("TRIVY_IGNOREFILE"),
            os.environ.get("TRIVY_SECRET_CONFIG"),
        )
        return (*super()._environment_values(), *(value for value in read if value))

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
                raise ScannerError(
                    f"scanners.trivy-repo.options.module_dir is "
                    f"{str(options.module_dir)!r}, which is not a directory "
                    f"(resolved to {module_dir.as_posix()}). Fix the path or unset "
                    "the option."
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
        config: Any | None = None,
        *args,
        **kwargs,
    ) -> SarifReport | bool | None:
        """Scan a target file/directory.

        This example scanner simply logs the target and returns a mock finding.

        Args:
            target: Target file or directory to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            dict: Scan results
        """
        # Per target; see ScannerPluginBase.scan().
        self.exit_code = 0
        # Passed by keyword, as the executor passes it to every scanner.
        global_ignore_paths = kwargs.get("global_ignore_paths") or []
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
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

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)

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
            final_args[insert_at:insert_at] = [
                # trivy's own deadline is five minutes and fails the scan when it
                # passes; matched to ASH's scan_timeout, as the builtin trivy scanner
                # does, so the bound the operator set is the one that applies.
                f"--timeout={trivy_timeout(self._effective_scan_timeout())}",
                f"--ignorefile={self._ignore_file()}",
                f"--secret-config={self._secret_config_file()}",
                *self._pinned_config_args(),
                # Each link leaving the target (trivy follows no link), and each
                # path the global ignore paths ignore.
                *self._link_skip_args(target, global_ignore_paths),
                # ASH's own output directories inside the target, as the builtin
                # trivy scanner skips them: the converted copies the converted
                # target scans already, and an earlier run's reports and results.
                *self._output_dir_skip_args(target, target_type),
            ]
            if self._offline():
                final_args = self._offline_misconfig_args(final_args)
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            # The database update, its skip flags and --cache-backend=memory are
            # added by TrivyScannerBase._run_subprocess, for trivy and trivy-repo
            # alike (utils/content_db_refresh.py).

            # The values hook is overridable and is read once, guarded, for the
            # log line and both SARIF records. When it raised or gave no usable
            # answer nothing can be redacted, so every record carries only the
            # command's name.
            read = guarded_values_read(self)
            redact_values = read.values
            if redact_values is None:
                shown_command = str(self.command)
                recorded_command_line = shown_command
                recorded_arguments: List[str] = []
                self._plugin_log(
                    f"Running command: {shown_command} (the arguments are not "
                    f"shown: the plugin's values hook {read.failure()})",
                    target_type=target_type,
                    level=logging.VERBOSE,
                )
            else:
                shown_command = text_without_values(" ".join(final_args), redact_values)
                recorded_command_line, recorded_arguments = redacted_command_record(
                    final_args, redact_values
                )
                self._plugin_log(
                    f"Running command: {shown_command}",
                    target_type=target_type,
                    level=logging.VERBOSE,
                )

            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                env=subprocess_env,
                timeout=self._effective_scan_timeout(),
            )
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
                    self._post_scan(
                        target=target,
                        target_type=target_type,
                    )
                    return sarif_report
                except Exception as e:
                    self._plugin_log(
                        f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}",
                        target_type=target_type,
                        level=logging.ERROR,
                        append_to_stream="stderr",
                    )
                    self._post_scan(
                        target=target,
                        target_type=target_type,
                    )
                    return
            else:
                self._plugin_log(
                    f"No results file found at {results_file}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Trivy scan failed: {str(e)}")
