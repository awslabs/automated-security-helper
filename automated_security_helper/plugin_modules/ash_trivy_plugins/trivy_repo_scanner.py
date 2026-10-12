# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import re
import shlex
import logging
import threading
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple
from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.tool_config_trust import (
    empty_tool_config,
    empty_tool_directory,
)
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    TrivyScannerBase,
)
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.utils.link_exclusions import (
    trivy_skip_dirs,
    trivy_skip_files,
)
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ


#: The trivy misconfiguration scanner that downloads the module sources a .tf file
#: names. See TrivyRepoScanner._offline_misconfig_args.
_TERRAFORM_MISCONFIG_SCANNER = "terraform"

_DEFAULT_MISCONFIG_SCANNERS: Dict[Tuple[str, ...], Optional[List[str]]] = {}
_DEFAULT_MISCONFIG_SCANNERS_LOCK = threading.Lock()


def reset_trivy_default_misconfig_scanners() -> None:
    """Forget the lists trivy_default_misconfig_scanners read (tests)."""
    with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
        _DEFAULT_MISCONFIG_SCANNERS.clear()


def trivy_default_misconfig_scanners(
    binary: str, subcommands: List[str]
) -> Optional[List[str]]:
    """trivy's default ``--misconfig-scanners`` list, as the installed trivy prints it.

    Read from ``<binary> <subcommands> --help`` (the "(default [...])" of that flag)
    rather than written down here, because the list differs between trivy releases
    and trivy given a value it does not know runs every misconfiguration scanner
    instead (measured with trivy 0.74.0). None when the list cannot be read. A list
    that was read is kept per binary and subcommand; a failed read is not, so the next
    scan tries again rather than every later scan in the process (a long-running MCP
    server, a workspace's projects) leaving out every misconfiguration check.
    """
    key = (binary, *subcommands)
    with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
        if key in _DEFAULT_MISCONFIG_SCANNERS:
            return _DEFAULT_MISCONFIG_SCANNERS[key]
    try:
        result = subprocess_utils.run_command(
            [binary, *subcommands, "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            log_level=logging.DEBUG,
        )
        text = f"{result.stdout or ''}\n{result.stderr or ''}"
    except Exception as error:  # the list is unknown; the caller fails closed
        ASH_LOGGER.debug(
            f"Could not run {binary} {' '.join(subcommands)} --help: {error}"
        )
        text = ""
    match = re.search(r"--misconfig-scanners\b[^\n]*?\(default \[([^\]]*)\]\)", text)
    listed = (
        [name.strip() for name in match.group(1).split(",") if name.strip()]
        if match
        else None
    )
    listed = listed or None
    if listed is not None:
        with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
            _DEFAULT_MISCONFIG_SCANNERS[key] = listed
    return listed


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
                "A trivy config file (trivy.yaml), passed as trivy --config. Unset, "
                "ASH passes an empty one, so trivy does not load a trivy.yaml from the "
                "directory it runs in. Honored only when set by --config-overrides "
                "or a config file outside the scanned tree, for a file outside that "
                "tree; otherwise ignored with a warning. A relative path is taken "
                "from the directory of the config file that sets it, or from the "
                "working directory for --config-overrides, not from the source "
                "directory. A path that does not exist fails the scan."
            ),
        ),
    ] = None
    module_dir: Annotated[
        Path | str | None,
        Field(
            description=(
                "A directory of trivy modules, passed as trivy --module-dir. Unset, "
                "ASH passes an empty directory of its own. Honored, and a relative "
                "path taken, as for config_file. A path that is not a directory "
                "fails the scan."
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

    def _offline_misconfig_args(self, final_args: List[str]) -> List[str]:
        """``final_args`` without trivy's Terraform checks, for an offline scan.

        trivy's Terraform scanner fetches the source of every ``module`` block it
        evaluates, with every offline flag ASH passes and with
        ``--tf-exclude-downloaded-modules`` (measured with trivy 0.75.0): a registry
        source contacted registry.terraform.io, a ``git::`` source ran the host's
        git, with the operator's git configuration and credentials, against the URL
        the repository chose, and an ``https://`` archive was downloaded. trivy has
        no setting that stops it. So offline, trivy gets ``--misconfig-scanners``
        naming its own default list without ``terraform``. When that list cannot be
        read from trivy, the misconfiguration scanner is not run offline at all,
        rather than guessed at. checkov still checks Terraform.
        """
        if "misconfig" not in (self.config.options.scanners or []):
            return final_args
        # model_post_init sets the command to "trivy"; the base class allows None.
        command = self.command or "trivy"
        binary = find_executable(command) or command
        defaults = trivy_default_misconfig_scanners(binary, list(self.subcommands))
        kept = [name for name in defaults or [] if name != _TERRAFORM_MISCONFIG_SCANNER]
        args = list(final_args)
        if kept:
            message = (
                "trivy's Terraform checks are skipped offline: trivy downloads the "
                "module sources a .tf file names, and has no setting that stops it. "
                "checkov still checks Terraform."
            )
            head = [self.command, *self.subcommands]
            insert_at = len(head) if args[: len(head)] == head else len(args)
            args[insert_at:insert_at] = [f"--misconfig-scanners={','.join(kept)}"]
        else:
            message = (
                "trivy's misconfiguration checks are skipped offline: ASH could not "
                f"read trivy's list of them from `{binary} "
                f"{' '.join(self.subcommands)} --help`, so it cannot leave out the "
                "Terraform checks, which download module sources."
            )
            index = args.index("--scanners") if "--scanners" in args else -1
            if index >= 0 and index + 1 < len(args):
                remaining = [
                    name for name in args[index + 1].split(",") if name != "misconfig"
                ]
                if not remaining:
                    raise ScannerError(message)
                args[index + 1] = ",".join(remaining)
        if message not in self._warned_inputs:
            self._warned_inputs.add(message)
            self._plugin_log(message, level=logging.WARNING)
        return args

    def _pinned_config_args(self) -> List[str]:
        """``--config`` and ``--module-dir``, so trivy loads neither from where it runs.

        trivy runs with the scan target as its working directory and loads a
        ``trivy.yaml`` from there unless ``--config`` names another, and loads the
        modules in ``--module-dir`` (or the config's ``module.dir``). Both are
        always passed: the operator's, when ``_operator_path`` accepts them, and
        otherwise an empty config file and an empty modules directory that ASH
        creates outside the scanned tree for this run (``empty_tool_config``,
        ``empty_tool_directory``), new each time and removed when the run ends.
        """
        options = self.config.options
        config_file: Optional[Path] = None
        if options.config_file:
            config_file = self._operator_path(
                "config_file",
                options.config_file,
                "trivy-repo runs with ASH's empty config instead.",
            )
            if config_file is not None and not config_file.is_file():
                raise ScannerError(
                    f"scanners.trivy-repo.options.config_file is "
                    f"{str(options.config_file)!r}, which is not a file (resolved to "
                    f"{config_file.as_posix()}). Fix the path or unset the option."
                )
        # Recorded for the staleness probe only when it is the operator's: ASH's
        # empty one is removed with the run, and trivy fails on a --config that
        # is missing (TrivyScannerBase._scan_config_file).
        self._scan_config_file = (
            config_file.resolve().as_posix() if config_file is not None else None
        )
        if config_file is None:
            config_file = empty_tool_config(
                "trivy-config.yaml", "", context=self.context
            )
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
            f"--config={config_file.resolve().as_posix()}",
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
                f"--ignorefile={self._ignore_file()}",
                f"--secret-config={self._secret_config_file()}",
                *self._pinned_config_args(),
                # Each link leaving the target (trivy follows no link), and each
                # path the global ignore paths ignore. In the joined form, since a
                # path can start with "-". See utils/link_exclusions.py.
                *(
                    f"--skip-files={path}"
                    for path in trivy_skip_files(
                        target, self.context.source_dir, global_ignore_paths
                    )
                ),
                *(
                    f"--skip-dirs={path}"
                    for path in trivy_skip_dirs(
                        target, self.context.source_dir, global_ignore_paths
                    )
                ),
            ]
            if self._offline():
                final_args = self._offline_misconfig_args(final_args)
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            # The database update, its skip flags and --cache-backend=memory are
            # added by TrivyScannerBase._run_subprocess, for trivy and trivy-repo
            # alike (utils/content_db_refresh.py).

            self._plugin_log(
                f"Running command: {' '.join(final_args)}",
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

                    # Attach scanner details for proper identification
                    sarif_report = attach_scanner_details(
                        sarif_report=sarif_report,
                        scanner_name=self.config.name,
                        scanner_version=getattr(self, "tool_version", None),
                        invocation_details={
                            "command_line": " ".join(final_args),
                            "arguments": final_args[1:],
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
                                commandLine=shlex.join(final_args),
                                arguments=final_args[1:],
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
