# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import shlex
import logging
import os
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Set

import yaml
from pydantic import Field

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
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
    SarifReport,
)
from automated_security_helper.utils.get_scan_set import file_links_leaving_tree
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.scanned_tree import (
    REASON_LINK_LEAVES_TREE,
    TreeInputRefused,
    open_in_scanned_tree,
    relative_display,
)
from automated_security_helper.utils.subprocess_utils import find_executable

# snyk code test reads exclusions from files in the tree it tests, at any depth,
# and leaves the files they name out of the analysis. Its native implementation
# collects files named .snyk, .dcignore and .gitignore (code-client-go
# internal/commands/code_workflow/native_workflow.go, getFilesForPath); its
# legacy one globs *.snyk, *.dcignore and *.gitignore by base name
# (@snyk/code-client src/files.ts, collectFilePolicies). Neither has an option
# that turns this off: code test takes no --policy-path. A file named exactly
# .gitignore is left to snyk, since ASH's own scan set honors it too
# (utils/get_scan_set.py).
_POLICY_SUFFIX = ".snyk"
_IGNORE_SUFFIXES = (".dcignore", ".gitignore")
_POLICY_SECTIONS = ("code", "global")
# A larger exclusion file is not parsed, and counts as excluding.
_MAX_EXCLUSION_FILE_BYTES = 1024 * 1024
_REFUSAL_FILES_SHOWN = 10


def tree_exclusion_files(target: Path) -> List[Path]:
    """The files under ``target`` that would make snyk code test leave files out.

    A ``.snyk`` policy counts when its ``exclude.code`` or ``exclude.global`` has
    an entry, and an ignore file when it has a rule. One that is not a regular
    file inside the tree (snyk reads a link's target), cannot be read, or cannot
    be parsed counts too. ``.git`` is walked as well, as snyk's native filter
    walks it.

    A link to a directory is not followed, and nothing behind it counts, because
    snyk does not follow one either. Its native filter lists files with Go's
    ``filepath.WalkDir`` (go-application-framework ``pkg/utils/file_filter.go``,
    ``GetAllFiles``), which reports a link to a directory as an entry and does not
    walk into it. Its legacy one globs with ``followSymbolicLinks`` set from
    ``symlinksEnabled`` (``@snyk/code-client`` ``collectFilePolicies``), which the
    CLI's ``snyk code test`` does not set (snyk/cli
    ``src/lib/plugins/sast/analysis.ts``). Measured on those sources as of
    2026-10-11.
    """
    found: List[Path] = []
    for directory, _subdirectories, names in os.walk(target):
        for name in names:
            if _is_exclusion_name(name):
                path = Path(directory) / name
                if _excludes(path, Path(target)):
                    found.append(path)
    return sorted(found)


def _is_exclusion_name(name: str) -> bool:
    if name.endswith(_POLICY_SUFFIX):
        return True
    return name != ".gitignore" and name.endswith(_IGNORE_SUFFIXES)


def _excludes(path: Path, root: Path) -> bool:
    try:
        with open_in_scanned_tree(path, root) as handle:
            content = handle.read(_MAX_EXCLUSION_FILE_BYTES + 1)
    except (TreeInputRefused, OSError):
        return True
    if len(content) > _MAX_EXCLUSION_FILE_BYTES:
        return True
    text = content.decode("utf-8", errors="replace")
    if not path.name.endswith(_POLICY_SUFFIX):
        return any(
            line.strip() and not line.strip().startswith("#")
            for line in text.splitlines()
        )
    try:
        policy = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        # RecursionError: nesting deeper than the parser's stack. Unreadable as
        # a policy, so it counts, like any file that cannot be parsed.
        return True
    exclude = policy.get("exclude") if isinstance(policy, dict) else None
    return isinstance(exclude, dict) and any(
        exclude.get(section) for section in _POLICY_SECTIONS
    )


#: ``snyk code test`` exits 3 when the target holds no file it supports.
_NO_SUPPORTED_FILES_EXIT_CODE = 3


class SnykCodeScannerConfigOptions(ScannerOptionsBase):
    honor_tree_exclusions: Annotated[
        bool,
        Field(
            description="Let snyk code test apply the exclusion files it finds in "
            "the scanned tree: the exclude.code and exclude.global entries of a "
            ".snyk file and the rules of a .dcignore file, which leave the files "
            "they name out of the analysis. snyk has no option that stops it "
            "reading them, so while this is false and the tree has one, snyk-code "
            f"does not run and its error names the files. {SET_BY_THE_OPERATOR}"
        ),
    ] = False


class SnykCodeScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Snyk code scanner."""

    name: Literal["snyk-code"] = "snyk-code"
    enabled: bool = True
    options: Annotated[
        SnykCodeScannerConfigOptions,
        Field(description="Configure snyk-code"),
    ] = SnykCodeScannerConfigOptions()


@ash_scanner_plugin
class SnykCodeScanner(ScannerPluginBase[SnykCodeScannerConfig]):
    """Example scanner plugin that demonstrates the decorator pattern."""

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        # The token file alone: configstore is shared with other npm tools' settings.
        read_paths=("~/.config/configstore/snyk.json",),
        env_prefixes=("SNYK_",),
        env_names=("SNYK_TOKEN",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    # src/cli/exit-codes.ts: 0 no issues, 1 issues found, 2 an error, 3 no supported
    # project detected.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}

    def model_post_init(self, context):
        if self.config is None:
            self.config = SnykCodeScannerConfig()
        self.command = "snyk"
        self.subcommands = ["code", "test"]
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-file-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate scanner configuration.

        Returns:
            bool: True if validation passes
        """
        # TODO: Validate this is rejecting snyk with offline mode.
        if self._is_offline_mode():
            self._plugin_log(
                f"Offline mode detected. Skipping validation for {self.__class__.__name__}"
            )
            return False

        # Check if SNYK_TOKEN is defined on the environment variable or if using local
        # mode, the file ${HOME}/.config/configstore/snyk.json or ${HOME}/.config/configstore/.snyk.json exists
        if os.environ.get("SNYK_TOKEN", "") != "":
            # Token found in environment variable
            pass
        else:
            # Check for credential files
            home = Path.home()
            snyk_config_paths = home.joinpath(".config", "configstore", "snyk.json")

            if not snyk_config_paths.exists():
                # No credentials found
                self._plugin_log(
                    "Warning: No Snyk credentials found. SNYK_TOKEN env var is not set and no credential files found at ~/.config/configstore/snyk.json. The scan might fail.",
                    level=logging.WARNING,
                )

        snyk_binary = find_executable("snyk")
        if not snyk_binary or snyk_binary is None:
            return False
        return True

    def _process_config_options(self):
        if not (
            self.config.options.severity_threshold == "ALL"
            or self.config.options.severity_threshold is None
        ):
            snyk_severity = (
                str(self.config.options.severity_threshold).lower()
                if self.config.options.severity_threshold != "CRITICAL"
                else "high"
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--severity-threshold",
                    value=snyk_severity,
                )
            )

        return super()._process_config_options()

    def _resolve_arguments(
        self, target: Path, results_file: Path | None = None
    ) -> List[str]:
        """Resolve arguments for Snyk code test command.

        Args:
            target: Target to scan
            results_file: Path to results file

        Returns:
            List[str]: Arguments to pass to Snyk
        """
        # Process configuration options to populate extra_args
        self._process_config_options()

        # Start with base command and subcommands
        args = [self.command, *self.subcommands]

        # Add extra args (like severity threshold)
        for tool_extra_arg in self.args.extra_args:
            if tool_extra_arg.value is not None:
                args.extend([tool_extra_arg.key, str(tool_extra_arg.value)])
            else:
                args.append(tool_extra_arg.key)

        # Add target path
        args.append(Path(target).as_posix())

        # Add SARIF output argument with equal sign format (required by Snyk)
        if results_file is not None:
            args.append(f"--sarif-file-output={Path(results_file).as_posix()}")

        return args

    def _refuse_links_leaving(self, target: Path) -> None:
        """Refuse a target holding any link whose target leaves it.

        ``snyk code test`` uploads the files it reads to Snyk, has no option that
        leaves out one path (``--exclude`` is for open-source projects, and takes
        names, not paths), and how it treats links has not been measured by running
        it. So a link the repository committed could send a file from outside the
        scanned tree, such as a credentials file, off the host. A link to a
        directory (``creds -> ~/.aws``) counts too: snyk's sources list files
        without walking into one (see ``tree_exclusion_files``), but that is read,
        not measured, and the files below one could be every credential the host
        has. The links come
        from ``file_links_leaving_tree``, which does not read ignore files and lists
        the directory links it does not enter.

        Raises:
            ScannerError: Naming the first such link. snyk is then not run on
                ``target``.
        """
        directory_links: List[str] = []
        links = sorted(
            file_links_leaving_tree(target, directory_links=directory_links)
            + directory_links
        )
        if links:
            raise ScannerError(
                f"Not running snyk code test on {Path(target).as_posix()}: "
                f"{links[0]!r}: {REASON_LINK_LEAVES_TREE}, and snyk has no option "
                "that leaves out one path, so it might upload the file it points at."
            )

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — SnykCodeScanner overrides scan() directly; this is unreachable."""
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
    ) -> dict:
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
        # No claim until this target's run makes one (exit 3 below), so the count
        # from an earlier target is never read as this one's. The exit code too:
        # _run_subprocess keeps the worst code of every run of this instance, and the
        # executor runs one instance over the source tree and then the converted one,
        # so after a source that exited 3 the converted target read 3 whatever its
        # own run returned, and was graded SKIPPED with its findings unread.
        self.targets_attempted = None
        self.exit_code = 0
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

        if not self.config.options.honor_tree_exclusions:
            excluding = tree_exclusion_files(Path(target))
            if excluding:
                raise ScannerError(self._exclusion_refusal(excluding, Path(target)))

        try:
            self._refuse_links_leaving(target)
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)

            final_args = self._resolve_arguments(
                target=target, results_file=results_file
            )

            self._plugin_log(
                f"Running command: {' '.join(final_args)}",
                target_type=target_type,
                level=logging.VERBOSE,
            )

            # No environment modifications are currently needed for Snyk Code.
            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                timeout=self._effective_scan_timeout(),
            )

            # snyk exits 1 when it found issues, which is a completed scan, 2 when it
            # failed, and 3 when it found no supported project; see success_exit_codes.
            self._record_target_exit_code(response)
            # Exit 3 is snyk's "no supported projects detected": the target holds no
            # file Snyk Code reads, so it evaluated nothing. SKIPPED, by the
            # maintainer's ruling, rather than the ERROR every other code outside
            # success_exit_codes gets: a Terraform-only tree is not a failed scan.
            # targets_attempted = 0 is what the executor grades SKIPPED. Exit 2 is
            # still a failure.
            if self.exit_code == _NO_SUPPORTED_FILES_EXIT_CODE:
                self._plugin_log(
                    f"Snyk Code found no supported files in {target}; nothing was "
                    "evaluated (snyk exit code 3).",
                    target_type=target_type,
                    level=logging.INFO,
                )
                self.targets_attempted = 0
                self._post_scan(target=target, target_type=target_type)
                return True

            if not self._exit_code_accepted():
                raise ScannerError(
                    f"Snyk scan failed with exit code {self.exit_code}: {self.errors}"
                )

            # SARIF mode - parse SARIF results
            if Path(results_file).exists():
                with open(results_file, mode="r", encoding="utf-8") as f:
                    scanner_results = json.load(f)
                try:
                    sarif_report: SarifReport = SarifReport.model_validate(
                        scanner_results
                    )

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
                                executionSuccessful=True,
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
            raise ScannerError(f"Snyk Code scan failed: {str(e)}")

    @staticmethod
    def _exclusion_refusal(files: List[Path], target: Path) -> str:
        shown = [
            relative_display(path, target) for path in files[:_REFUSAL_FILES_SHOWN]
        ]
        more = len(files) - len(shown)
        listed = ", ".join(shown) + (f" and {more} more" if more else "")
        return (
            f"snyk-code did not run: snyk code test would leave out the files that "
            f"{listed} in the scanned tree exclude, and it has no option that stops "
            "it reading them. Remove them, or accept them with --config-overrides "
            "scanners.snyk-code.options.honor_tree_exclusions=true."
        )
