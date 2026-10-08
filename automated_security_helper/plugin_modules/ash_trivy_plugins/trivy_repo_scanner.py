# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import shlex
import logging
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal, List
from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    identity_properties,
    install_path,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
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


class TrivyRepoScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Trivy Repo scanner."""

    name: Literal["trivy-repo"] = "trivy-repo"
    enabled: bool = True
    options: Annotated[
        TrivyRepoScannerConfigOptions,
        Field(description="Configure trivy-repo scanner"),
    ] = TrivyRepoScannerConfigOptions()


@ash_scanner_plugin
class TrivyRepoScanner(ScannerPluginBase[TrivyRepoScannerConfig]):
    """Trivy repo scanner plugin."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    # Env vars layered onto the subprocess. Populated by _process_config_options
    # when offline mode is active. Kept on the instance so concurrent scanners
    # do not race on os.environ.
    extra_env: Annotated[dict, Field(default_factory=dict)]

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

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "TrivyRepoScanner":
        """Set up custom installation commands for trivy.

        trivy had no install path inside ASH. It could only arrive from the
        container image, the nix toolchain or a package manager, so a
        ``python-local`` run on a machine without it scanned without it.
        """
        self.custom_install_commands.update(pinned_tool_install_commands("trivy"))
        return self

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
        if len(self.config.options.scanners) > 0:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--scanners",
                    value=",".join(self.config.options.scanners),
                )
            )

        if self.config.options.license_full:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--license-full",
                    value=None,
                )
            )

        if self.config.options.ignore_unfixed:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--ignore-unfixed",
                    value=None,
                )
            )

        if self.config.options.disable_telemetry:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--disable-telemetry",
                    value=None,
                )
            )

        severity_inclusion_map = {
            "LOW": "LOW,MEDIUM,HIGH,CRITICAL",
            "MEDIUM": "MEDIUM,HIGH,CRITICAL",
            "HIGH": "HIGH,CRITICAL",
            "CRITICAL": "CRITICAL",
        }
        threshold = self.config.options.severity_threshold
        if threshold is not None and threshold != "ALL":
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--severity",
                    value=severity_inclusion_map[threshold],
                )
            )

        if self._scanner_offline():
            for flag in (
                "--skip-db-update",
                "--skip-java-db-update",
                "--offline-scan",
                "--skip-check-update",
            ):
                self.args.extra_args.append(ToolExtraArg(key=flag, value=None))

            from automated_security_helper.utils.offline_mode_validator import (
                validate_trivy_offline_mode,
            )

            offline_valid, offline_messages = validate_trivy_offline_mode()
            if not offline_valid:
                for msg in offline_messages:
                    self._plugin_log(msg, level=logging.WARNING)

            ASH_LOGGER.info(
                "Running Trivy in offline mode - DB updates and check-update disabled"
            )

        return super()._process_config_options()

    @staticmethod
    def _package_from_message(message: str | None) -> tuple[str | None, str | None]:
        """Name and version from trivy's vulnerability or license message.

        A vulnerability message has ``Package: <name>`` and ``Installed
        Version: <version>`` on their own lines. A license message has
        ``PkgName: <name>`` and no version, for example::

            Artifact: scripts/e2e/inspector/package-lock.json
            License MPL-2.0
            PkgName: lightningcss
             Classification: reciprocal

        Reading it gives license findings a ``package_name``, so a license
        approval can name the package it covers rather than the whole file.
        A message with neither line (a misconfiguration or secret finding) is
        not about a package.
        """
        name = version = None
        for line in (message or "").splitlines():
            if line.startswith("Package: "):
                name = line[len("Package: ") :].strip() or None
            elif line.startswith("PkgName: "):
                name = line[len("PkgName: ") :].strip() or None
            elif line.startswith("Installed Version: "):
                version = line[len("Installed Version: ") :].strip() or None
        return name, version

    def _attach_package_identity(
        self, sarif_report: SarifReport, target: Path
    ) -> SarifReport:
        """Give each dependency result one package copy and say which it is.

        trivy groups packages by name and version before matching, so the same
        version installed at two places in one lockfile becomes ONE result with
        one location per copy. No suppression can then cover one copy and not
        the other. For npm lockfiles, each location's line is the line of that
        copy's ``packages`` key, so such a result is split into one result per
        location, each with ``package_path``. Results whose locations do not
        all resolve to a lockfile entry are left whole.
        """
        lock_index = NpmLockIndex(target)
        for run in sarif_report.runs or []:
            new_results = []
            for result in run.results or []:
                message = result.message.root.text if result.message else None
                name, version = self._package_from_message(message)
                if name is None:
                    new_results.append(result)
                    continue

                resolved = []
                for location in result.locations or []:
                    physical = location.physicalLocation
                    root = physical.root if physical else None
                    uri = (
                        root.artifactLocation.uri
                        if root and root.artifactLocation
                        else None
                    )
                    line = root.region.startLine if root and root.region else None
                    # Relativized the same way as grype's, so package_path is
                    # POSIX and scan-root-relative whatever form trivy used.
                    lock_rel = lock_index.relative(uri) if uri else None
                    entry = (
                        lock_index.by_line(lock_rel, line)
                        if lock_rel and line
                        else None
                    )
                    resolved.append(
                        install_path(lock_rel, entry.key)
                        if lock_rel and entry is not None
                        else None
                    )

                if resolved and all(resolved):
                    for location, path in zip(result.locations or [], resolved):
                        copy = result.model_copy(deep=True)
                        copy.locations = [location.model_copy(deep=True)]
                        self._set_identity(copy, name, version, path)
                        new_results.append(copy)
                else:
                    path = resolved[0] if len(resolved) == 1 else None
                    self._set_identity(result, name, version, path)
                    new_results.append(result)
            run.results = new_results
        return sarif_report

    @staticmethod
    def _set_identity(result, name, version, path) -> None:
        identity = identity_properties(name, version, path)
        if result.properties is None:
            result.properties = PropertyBag.model_validate(identity)
        else:
            for key, value in identity.items():
                setattr(result.properties, key, value)

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

            self._plugin_log(
                f"Running command: {' '.join(final_args)}",
                target_type=target_type,
                level=logging.VERBOSE,
            )

            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
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
