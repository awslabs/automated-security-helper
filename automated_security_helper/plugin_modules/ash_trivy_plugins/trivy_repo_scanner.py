# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import shlex
import shutil
import logging
from pathlib import Path
from typing import Annotated, Any, List, Literal, Optional, Set
from pydantic import Field, PrivateAttr

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
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
from automated_security_helper.config.path_trust import honored_path
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.content_db_refresh import (
    default_cache_dir,
    prepare_content_db,
    sandboxed_online,
    scan_id_for,
)
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write


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
            description="Disable sending anonymous usage data to Aqua",
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
                "A trivy config file (trivy.yaml), passed as --config. Unset, ASH "
                "passes an empty one, so trivy does not load a trivy.yaml from the "
                "directory it runs in. Honored only when set by --config-overrides "
                "or a config file outside the scanned tree, for a file outside that "
                "tree; otherwise ignored with a warning. A path that does not exist "
                "fails the scan."
            ),
        ),
    ] = None
    module_dir: Annotated[
        Path | str | None,
        Field(
            description=(
                "A directory of trivy modules, passed as --module-dir. Unset, ASH "
                "passes an empty directory of its own. Honored under the same rule "
                "as config_file. A path that is not a directory fails the scan."
            ),
        ),
    ] = None

    ignore_file: Annotated[
        str | None,
        Field(
            description=(
                "A trivy ignore file, passed as --ignorefile. Used only when it is "
                "outside the scanned tree; a relative path is taken from the source "
                "directory. Unset, TRIVY_IGNOREFILE is used the same way, and "
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
                "--secret-config. Used only when it is outside the scanned tree; a "
                "relative path is taken from the source directory. Unset, "
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

    # The in-tree trivy input files already reported as ignored.
    _warned_inputs: Set[str] = PrivateAttr(default_factory=set)

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

    def _ignore_file(self) -> str:
        """The file trivy reads finding IDs to ignore from (``--ignorefile``)."""
        return self._trivy_input_file(
            option="ignore_file",
            env="TRIVY_IGNOREFILE",
            default_name=".trivyignore",
            ash_name="trivyignore-empty",
            ash_content="",
        )

    def _secret_config_file(self) -> str:
        """The file trivy reads secret rules from (``--secret-config``)."""
        return self._trivy_input_file(
            option="secret_config_file",
            env="TRIVY_SECRET_CONFIG",
            default_name="trivy-secret.yaml",
            ash_name="trivy-secret-empty.yaml",
            # An empty file is a decode error in trivy; an empty mapping is not.
            ash_content="{}\n",
        )

    def _trivy_input_file(
        self,
        *,
        option: str,
        env: str,
        default_name: str,
        ash_name: str,
        ash_content: str,
    ) -> str:
        """A file to pass trivy for an input it would otherwise read from its cwd.

        Without the flag, trivy reads ``default_name`` (``.trivyignore``,
        ``trivy-secret.yaml``) from its working directory, the source directory,
        so the scanned repository could remove findings from its own report
        (measured with trivy 0.75.0). The operator's file, from the option or the
        environment variable, is used when it is outside the scanned tree
        (config/path_trust.py); a refused option falls through to the variable.
        Otherwise trivy gets a file ASH writes into the results directory, which
        sets nothing.
        """
        context_config = getattr(self.context, "config", None)
        source_dir = Path(self.context.source_dir)
        for key, value in (
            (
                f"scanners.trivy-repo.options.{option}",
                getattr(self.config.options, option),
            ),
            (env, os.environ.get(env)),
        ):
            if not value:
                continue
            path = honored_path(
                value, source_dir=source_dir, key=key, config=context_config
            )
            if path is None:
                continue
            if not path.is_file():
                raise ScannerError(
                    f"{key} is {value!r}, which is not a file (resolved to "
                    f"{path.as_posix()}). Fix the path or unset it; trivy is not run "
                    "without it."
                )
            return path.as_posix()
        in_tree = source_dir / default_name
        if in_tree.is_file() and in_tree.as_posix() not in self._warned_inputs:
            self._warned_inputs.add(in_tree.as_posix())
            self._plugin_log(
                f"Ignoring {in_tree.as_posix()}: it is inside the scanned tree. Set "
                f"scanners.trivy-repo.options.{option} to a file outside the tree "
                "to use one.",
                level=logging.WARNING,
            )
        if self.results_dir is None:
            raise ScannerError("TrivyRepoScanner has no results directory")
        written = Path(os.path.abspath(self.results_dir)) / ash_name
        written.parent.mkdir(parents=True, exist_ok=True)
        with open_for_write(written) as handle:
            handle.write(ash_content)
        return written.as_posix()

    def _pinned_config_args(self, results_dir: Path) -> List[str]:
        """``--config`` and ``--module-dir``, so trivy loads neither from where it runs.

        trivy runs with the scan target as its working directory and loads a
        ``trivy.yaml`` from there unless ``--config`` names another, and loads the
        modules in ``--module-dir`` (or the config's ``module.dir``). Both are
        always passed: the operator's, when ``_operator_path`` accepts them, and
        otherwise an empty config file and an empty modules directory that ASH
        creates in this run's results directory.
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
        if config_file is None:
            config_file = results_dir / "trivy-config.yaml"
            with open_for_write(config_file) as handle:
                handle.write("")
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
            module_dir = results_dir / "trivy-modules"
            # Fresh and empty every run: the output directory usually sits inside
            # the scanned tree, so whatever is already at this path is not ASH's.
            if module_dir.is_symlink() or module_dir.is_file():
                module_dir.unlink()
            elif module_dir.is_dir():
                shutil.rmtree(module_dir)
            module_dir.mkdir()
        return [
            f"--config={config_file.resolve().as_posix()}",
            f"--module-dir={module_dir.resolve().as_posix()}",
        ]

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
            # Before the target, which _resolve_arguments places after the options;
            # trivy also accepts flags after it, so they are appended when the
            # target is not found as given.
            pinned = self._pinned_config_args(target_results_dir)
            final_args = list(final_args)
            for spelling in (str(target), Path(target).as_posix()):
                if spelling in final_args:
                    target_index = final_args.index(spelling)
                    final_args[target_index:target_index] = pinned
                    break
            else:
                final_args.extend(pinned)

            # Right after `trivy repository`, which needs no knowledge of how the
            # target is spelled further on; trivy takes flags in any position.
            head = [self.command, *self.subcommands]
            insert_at = (
                len(head) if final_args[: len(head)] == head else len(final_args)
            )
            final_args[insert_at:insert_at] = [
                f"--ignorefile={self._ignore_file()}",
                f"--secret-config={self._secret_config_file()}",
            ]
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            if sandboxed_online(self._scanner_offline()):
                # The sandbox mounts trivy's cache read-only, so its database (and
                # the checks bundle, for misconfiguration scans) is updated first,
                # outside the sandbox, and trivy only reads it: no update of its
                # own, and its scan cache in memory rather than in that cache. See
                # utils/content_db_refresh.py. Not the Java database: `trivy
                # repository` does not analyze JAR, WAR or EAR files and never reads
                # it (measured with trivy 0.75), so its update is skipped rather
                # than downloading about 935 MiB the scan would not use.
                checks = "misconfig" in (self.config.options.scanners or [])
                prepare_content_db(
                    "trivy",
                    default_cache_dir("trivy", subprocess_env or snapshot_environ()),
                    offline=False,
                    checks=checks,
                    scan_id=scan_id_for(self.context),
                )
                final_args[insert_at:insert_at] = [
                    "--skip-db-update",
                    "--skip-java-db-update",
                    *(["--skip-check-update"] if checks else []),
                    "--cache-backend=memory",
                ]

            self._plugin_log(
                f"Running command: {' '.join(final_args)}",
                target_type=target_type,
                level=logging.VERBOSE,
            )

            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                env=subprocess_env,
                timeout=self._effective_scan_timeout(),
            )

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
                                executionSuccessful=(
                                    self.exit_code == 0 or self.exit_code == 1
                                ),
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
