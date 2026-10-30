"""Module containing the Syft security scanner implementation."""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Set

from pydantic import Field, PrivateAttr, ValidationError, model_validator
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.config.path_trust import (
    cwd_outside_scanned_tree,
    honored_path,
    resolved_path,
)
from automated_security_helper.utils.link_exclusions import syft_excludes
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    WAS_KILLED_ENDING,
)
from automated_security_helper.utils.suppression_matcher import active_ignore_paths


class SyftScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Syft configuration file. A relative path is taken from the directory of the config file that sets it, or from the working directory for --config-overrides, not from the source directory."
            f" {SET_BY_THE_OPERATOR}"
            " ASH does not look for one by name. Without one, syft gets an empty config, so it does not read `.syft.yaml` from the scanned tree.",
        ),
    ] = None
    exclude: Annotated[
        List[IgnorePathWithReason],
        Field(
            description='Paths (files or directories) to skip, each a glob relative to the scanned directory and passed to syft as one --exclude. A glob must start with "./", "*/" or "**/", and syft fails the scan on any other. "*" does not match across "/" and "**" does: "./dir1/**" skips the top-level "dir1", and "**/dir1/**" skips every directory named "dir1".',
        ),
    ] = []
    additional_outputs: Annotated[
        List[
            Literal[
                "cyclonedx-json",
                "cyclonedx-xml",
                "github-json",
                "spdx-json",
                "spdx-tag-value",
                "syft-json",
                "syft-table",
                "syft-text",
                # "template",
            ]
        ],
        Field(
            description="List of additional formats to output. Defaults to syft-table."
        ),
    ] = ["syft-table"]
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, disabling update checks. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]


class SyftScannerConfig(ScannerPluginConfigBase):
    name: Literal["syft"] = "syft"
    enabled: bool = True
    options: Annotated[
        SyftScannerConfigOptions, Field(description="Configure Syft scanner")
    ] = SyftScannerConfigOptions()  # type: ignore[call-arg]


@ash_scanner_plugin
class SyftScanner(ScannerPluginBase[SyftScannerConfig]):
    """SyftScanner implements IaC scanning using Syft."""

    #: syft is a native binary. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        cache_paths=("~/.cache/syft",),
        env_prefixes=("SYFT_",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    # syft exits 0 for a completed run; cmd/syft/main.go runs clio, whose Run exits 1
    # on any error, and syft installs no other exit-code mapping. An SBOM has no
    # "findings found" code.
    success_exit_codes: ClassVar[Set[int]] = {0}

    # Env vars to layer onto the subprocess. Populated in model_post_init when
    # offline mode is active. Kept local to the scanner instance so concurrent
    # scanners don't race on os.environ.
    extra_env: Annotated[dict, Field(default_factory=dict)]

    # The config-file warnings already given: _process_config_options runs at
    # construction and again on every scan() (the ToolArgs rebuild there drops
    # what it added), and the same missing or refused file need be said once.
    _config_warnings_given: Set[str] = PrivateAttr(default_factory=set)

    def model_post_init(self, context):
        if self.config is None:
            self.config = SyftScannerConfig()
        self.command = "syft"
        self.tool_type = ScannerToolType.SBOM

        if self._scanner_offline():
            self.extra_env.update(
                {
                    "SYFT_CHECK_FOR_APP_UPDATE": "false",
                    "SYFT_LOG_QUIET": "true",
                }
            )
            ASH_LOGGER.info("Running Syft in offline mode - update checks disabled")

        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "SyftScanner":
        """Set up custom installation commands for Syft.

        Every platform previously mapped to an empty list, so the table looked
        populated while ``get_installation_commands`` returned nothing. syft had no
        install path at all: on a machine without it the scan ran without syft,
        reported syft as not having run, and still exited 0.
        """
        self.custom_install_commands.update(pinned_tool_install_commands("syft"))
        return self

    def _use_empty_config(self) -> None:
        """Hand syft an empty config file ASH writes.

        Given no ``--config``, syft runs from the source directory and reads
        ``.syft.yaml`` from it, which would put the repository's file where the
        operator's refused or missing one was. An explicit ``--config`` ends
        the discovery.
        """
        self.args.extra_args.append(
            ToolExtraArg(
                key="--config",
                value=self._neutral_tool_file("syft-config-empty.yaml", "{}\n"),
            )
        )

    def _process_config_options(self):
        # Syft config path
        # Only the operator's config file. A config file inside the scanned tree
        # does not choose it (config/tool_config_trust.py), and ASH no longer looks
        # for .syft.yaml by name: its exclude would let the repository decide what
        # the SBOM lists. With none, scan() passes syft an empty one, so syft does
        # not read one from its working directory on its own.
        # A blank value names no file: Path("") joined to the source directory is
        # the source directory itself, which exists, so the probe below would read
        # it as a configured file (refused, with no refusal line to point at).
        # Blank reads as unset.
        possible_config_paths = [
            item
            for item in [self.config.options.config_file]
            if item is not None and str(item).strip()
        ]

        # Resolve config candidates against source_dir, not the process working
        # directory, and hand syft an absolute path. Same fix, same reason, as
        # checkov_scanner._process_config_options.
        #
        # The subprocess runs with cwd=context.source_dir (see
        # PluginBase._run_subprocess), so probing with a bare Path(...).exists()
        # asked a different question than the one syft would answer: it tested the
        # directory ASH happens to be invoked from, then passed the match through
        # get_shortest_name, which relativises against the process cwd.
        #
        # Latent here rather than observed, because this repository has no
        # .syft.yaml for the probe to find. It is the same defect grype hit -- and
        # fixing grype while leaving the identical probe here is how the bug comes
        # back the first time anyone adds a syft config.
        #
        # A config inside the scanned tree is never passed (see
        # config/path_trust.py), and syft runs from outside the tree so it does not
        # find one there itself (_working_directory): a .syft.yaml can turn on remote
        # license and package lookups, which contacted proxy.golang.org and
        # github.com in an offline scan, and change what is reported.
        source_dir = Path(self.context.source_dir)
        # A refused configured value drops the ``--config`` rather than falling
        # through to discovery: the option named one file, and discovery would
        # silently replace it. Whether a candidate may be used is honored_path's
        # call (config/path_trust.py), which weighs who named the path. Whether
        # the operator wrote the configured value is operator_wrote_value's
        # answer, as for checkov, bandit and grype: a work product the scan
        # derived from the repository reaches syft only when it is.
        from automated_security_helper.config.operator_only_options import (
            operator_wrote_value,
        )

        context_config = getattr(self.context, "config", None)
        for index, conf_path in enumerate(possible_config_paths):
            configured = index == 0 and self.config.options.config_file is not None
            # As syft will read it: "~" expanded, a relative path taken from the
            # source directory (path_trust.resolved_path, the resolution
            # honored_path checks). Joining the value as written under the
            # source directory read a "~/..." path as a file below the scanned
            # tree, so the operator's home config was judged missing and an
            # empty one passed in its place.
            candidate = resolved_path(conf_path, source_dir)
            # os.path.exists, not Path.exists: under a directory this process
            # cannot search, Path.exists raises PermissionError on Python
            # 3.10-3.13, out of the scanner's construction; os.path.exists
            # answers False on any OSError, which takes the missing-file path.
            if os.path.exists(candidate):
                honored = honored_path(
                    conf_path,
                    source_dir=source_dir,
                    config=context_config,
                    key="scanners.syft.options.config_file"
                    if configured
                    else f"syft config file {conf_path}",
                    operator_written=configured
                    and operator_wrote_value(
                        context_config,
                        "scanner",
                        "syft",
                        ("options", "config_file"),
                        conf_path,
                        config_from_context=self._config_from_context,
                    ),
                )
                if honored is None:
                    if configured:
                        # honored_path has logged why (inside the scanned tree,
                        # delivered by an MCP client, or a work product derived
                        # from the repository); this line says what runs instead.
                        self._use_empty_config()
                        self._warn_once(
                            "Configured syft config file was not used; the "
                            "warning above names the file and the reason. Syft "
                            "will run with an empty config file that ASH writes; "
                            "no config file is discovered from the scanned tree "
                            "in its place."
                        )
                        break
                    continue
                self.args.extra_args.append(
                    ToolExtraArg(key="--config", value=honored.as_posix())
                )
                break
            elif configured:
                # A configured file that does not exist takes no discovered
                # replacement (config/path_trust.py, "Configured tool inputs
                # that are refused or missing").
                self._use_empty_config()
                self._warn_once(
                    text_without_values(
                        f"Configured syft config file does not exist: "
                        f"{self.config.options.config_file}. Syft will run "
                        "with an empty config file that ASH writes; no config "
                        "file is discovered from the scanned tree in its place.",
                        self._environment_values(),
                    )
                )
                break

        for item in active_ignore_paths(
            self.config.options.exclude, where="scanners.syft.options.exclude"
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
                    key="--exclude",
                    value=item.path,
                )
            )

        return super()._process_config_options()

    def _warn_once(self, message: str) -> None:
        """Log ``message`` as a warning the first time it is given, and not on the
        later ``_process_config_options`` runs that every ``scan()`` makes."""
        if message in self._config_warnings_given:
            return
        self._config_warnings_given.add(message)
        ASH_LOGGER.warning(message)

    def _base_path(self, target: Path) -> Path:
        """What syft gets as ``--base-path``: the source directory for a target
        inside it, else the target itself.

        syft reports paths relative to the base path and follows no link above
        it. The source target is the source directory. The converted target lives
        under the output directory, which is inside the source tree by default
        (``.ash/ash_output``) but is wherever ``--output-dir`` put it, and a base
        path that does not contain the scanned directory would make syft spell
        every path from a directory the scan is not under.
        """
        source_dir = Path(os.path.abspath(self.context.source_dir))
        scanned = Path(os.path.abspath(target))
        if scanned == source_dir or source_dir in scanned.parents:
            return source_dir
        return scanned

    def _working_directory(self, target: Path, results_dir: Path) -> Path:
        """A working directory outside the scanned tree, online and offline.

        syft reads ``.syft.yaml`` (and ``.syft/config.yaml``) from its working
        directory. See _process_config_options for why that matters.
        """
        return cwd_outside_scanned_tree(
            target,
            results_dir=results_dir,
            source_dir=self.context.source_dir,
            config=getattr(self.context, "config", None),
        )

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — SyftScanner overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def _refuse_flagged_response(self, response: object, timeout: float | None) -> None:
        """Raise for a run the subprocess layer flagged, before its file is read.

        The same four readings ``ScannerPluginBase.scan`` makes for every
        template scanner, which this override of ``scan()`` left out: a killed
        tool writes no results file, so the error would otherwise be "No such
        file or directory" instead of the timeout; a tool that could not start
        the same; a tool that ran while ASH could not record its output (exit 0,
        results file possibly complete) is not graded on that file; a tool a
        signal ASH did not send ended did not finish.
        """
        if not isinstance(response, dict):
            return
        name = self.__class__.__name__
        if response.get("timed_out"):
            limit = self._timeout_limit_token(timeout)
            if self.scan_could_not_stop is not None:
                ending = f"{COULD_NOT_STOP_ENDING}. It produced no"
            else:
                ending = f"{WAS_KILLED_ENDING}, so it produced no"
            raise ScannerError(
                text_without_values(
                    f"{name} timed out after {limit}{ending} results file. Raise "
                    f"scanners.{getattr(self.config, 'name', '<scanner>')}.options"
                    ".scan_timeout if this target legitimately needs longer, or set "
                    "it to null to leave this scanner unbounded.",
                    self._values_to_redact(),
                )
            )
        if response.get("spawn_failed"):
            raise ScannerError(
                f"{name} could not start its tool, so it produced no results file."
            )
        if response.get("post_run_error"):
            raise ScannerError(
                text_without_values(
                    f"{name} ran, but ASH could not record the scanner's output: "
                    f"{response.get('error')}",
                    self._values_to_redact(),
                )
            )
        if response.get("signaled"):
            raise ScannerError(
                text_without_values(
                    f"{name} did not finish: {response.get('error')}",
                    self._values_to_redact(),
                )
            )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: SyftScannerConfig | None = None,
    ) -> CycloneDXReport | bool:
        """Execute Syft scan and return results.

        Args:
            target: Path to scan

        Returns:
            CycloneDXReport: containing the SBOM findings and metadata.

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        # Per target; see ScannerPluginBase.scan(). The tool lines too, so a
        # failed converted-target run does not quote the source target's stderr.
        self.exit_code = 0
        self.output = []
        self._reset_errors()
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

        try:
            # Absolute, because syft runs from outside the source directory
            # (_working_directory), where a relative path names something else.
            target = Path(os.path.abspath(target))
            target_results_dir = Path(os.path.abspath(self.results_dir)).joinpath(
                target_type
            )
            target_results_dir.mkdir(parents=True, exist_ok=True)
            results_file = target_results_dir.joinpath("syft.cdx.json")
            self.args = ToolArgs(
                format_arg="--output",
                format_arg_value=f"cyclonedx-json={results_file.as_posix()}",
                scan_path_arg=None,
                extra_args=[
                    ToolExtraArg(
                        key="--base-path",
                        value=self._base_path(target).as_posix(),
                    ),
                ],
            )
            # Re-apply config options (exclude paths, config file) that were
            # set during model_post_init but lost by the ToolArgs rebuild above.
            self._process_config_options()
            if not any(arg.key == "--config" for arg in self.args.extra_args):
                empty = empty_tool_config(
                    "syft-empty.yaml", "{}\n", context=self.context
                )
                self.args.extra_args.append(
                    ToolExtraArg(key="--config", value=empty.as_posix())
                )
            # Each link leaving this target (syft follows none of them), and each
            # path the global ignore paths ignore. Rebuilt with the arguments above
            # for every target. See utils/link_exclusions.py.
            self.args.extra_args.extend(
                ToolExtraArg(key="--exclude", value=pattern)
                for pattern in syft_excludes(
                    target, self.context.source_dir, global_ignore_paths
                )
            )
            conf: SyftScannerConfig = self.config
            opts: SyftScannerConfigOptions = conf.options
            for out in opts.additional_outputs:
                out_ext = "txt"
                if "json" in out:
                    out_ext = "json"
                elif "xml" in out:
                    out_ext = "xml"
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--output",
                        value=f"{out}={results_file.as_posix()}.{out}.{out_ext}",
                    )
                )

            # ASH's own output directories inside the target. Rebuilt with the
            # ToolArgs above on every call, so nothing accumulates.
            from automated_security_helper.utils.scan_output_dirs import (
                output_dir_exclude_globs,
            )

            self.args.extra_args.extend(
                ToolExtraArg(key="--exclude", value=pattern)
                for pattern in output_dir_exclude_globs(
                    self._ash_output_dirs_inside(target)
                )
            )
            final_args = self._resolve_arguments(
                target=target,
            )
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            effective_timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                cwd=self._working_directory(target, target_results_dir),
                env=subprocess_env,
                timeout=effective_timeout,
            )

            self._post_scan(
                target=target,
                target_type=target_type,
            )
            self._refuse_flagged_response(response, effective_timeout)
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            syft_results = {}
            with open(results_file, mode="r", encoding="utf-8") as f:
                syft_results = json.load(f)
            try:
                sbom_report = CycloneDXReport.model_validate(syft_results)
            except ValidationError as e:
                # Not returned as it is: the declared result is a CycloneDXReport
                # or a bool, and a raw dict reaches the executor as a result it
                # cannot grade, reported as "not SARIF and carries no status",
                # which names neither syft nor the cause. The error's count, not
                # its text: the text quotes the document's values.
                raise ScannerError(
                    f"{self.__class__.__name__} wrote a results file that is not "
                    f"CycloneDX ASH can read ({e.error_count()} validation "
                    "error(s)), so its SBOM could not be recorded"
                )

            return sbom_report

        except Exception as e:
            # The run is over for this target, however it ended: the executor
            # records end_time, and one left from the previous target would give
            # this one an end before its start.
            self.end_time = datetime.now(timezone.utc)
            # Redacted, as the module's other error paths are: the text can quote
            # a path the configuration read from the environment.
            failure = text_without_values(
                f"{self.__class__.__name__} scan failed: {str(e)}",
                self._values_to_redact(),
            )
        # Raised outside the except block, so the original exception, whose text
        # is not redacted, is attached to the new one neither as __context__ nor
        # as __cause__: `raise ... from None` would only hide it from the default
        # traceback while leaving it readable on the object.
        raise ScannerError(failure)


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


def _demo_main(source_dir: Path, output_dir: Path) -> Path:
    """Scan ``source_dir`` with syft and write the SBOM under ``output_dir``.

    What ``python -m`` on this module does: a scanner with the plugin context the
    executor would give it, one source scan, and the CycloneDX document written as
    ``syft.cdx.json`` (the name the scanner writes). A result that is not a report
    (True for an empty target, False when syft cannot run) is written as JSON too.
    Returns the file written.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config

    context = PluginContext(
        source_dir=source_dir, output_dir=output_dir, config=get_default_config()
    )
    scanner = SyftScanner(context=context)
    report: Any = scanner.scan(target=source_dir, target_type="source")
    if hasattr(report, "model_dump_json"):
        report_json = report.model_dump_json(
            indent=2, by_alias=True, exclude_unset=True
        )
    else:
        report_json = json.dumps(report, indent=2)
    destination = output_dir.joinpath("syft.cdx.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open_for_write(destination, encoding=None, errors=None) as f:
        f.write(report_json)
    return destination


if __name__ == "__main__":
    _demo_main(Path.cwd(), Path.cwd().joinpath(".ash", "ash_output"))
