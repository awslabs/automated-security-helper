"""Module containing the Semgrep security scanner implementation.

The bulk of the logic (arg-building, offline cache, SARIF post-processing)
lives in :mod:`_grep_scanner_base`. This module only customises:

- the binary command (`semgrep`) and uv-tool resolution
- semgrep-specific dependency validation (Windows skip + UV-tool fallback)
- the cache env var and `SEMGREP_RULES` env propagation for subprocess
"""

import logging
import platform
from pathlib import Path
from typing import Annotated, List, Literal, ClassVar, Optional, Tuple

from pydantic import Field

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    DEFAULT_EXCLUDES,
    GrepScannerBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.process_env import hold_environ, release_environ
from automated_security_helper.utils.uv_tool_runner import (
    find_executable,
    get_uv_tool_command,
)

#: semgrep's own switch for its version check: the variable its
#: ``semgrep --enable-version-check`` / ``semgrep --disable-version-check`` option
#: reads. "0" is off.
_VERSION_CHECK_ENV = "SEMGREP_ENABLE_VERSION_CHECK"
_VERSION_CHECK_OFF = "0"


def _command_words(command) -> List[str]:
    """A resolver answer as its words: the list ``get_uv_tool_command`` returns, or
    one word for a bare path given as a string."""
    if isinstance(command, str):
        return [command]
    return list(command)


def _is_uv_form(command: List[str]) -> bool:
    """Whether a resolver answer runs the tool through uv.

    Told by the first word's file name, so ``["uv", ...]`` and
    ``["/usr/local/bin/uv", ...]`` both count; a comparison of the first three
    words with ``["uv", "tool", "run"]`` read a uv named by its path as a
    semgrep binary, which is the mistake this reading replaces.
    """
    words = _command_words(command)
    return bool(words) and Path(words[0]).name in ("uv", "uv.exe")


class SemgrepScannerConfigOptions(ScannerOptionsBase):
    config: Annotated[
        str,
        Field(
            description="YAML configuration file, directory of YAML files ending in .yml|.yaml, URL of a configuration file, or Semgrep registry entry name. Defaults to 'p/ci' for consistent results across online and offline modes.",
        ),
    ] = "p/ci"

    exclude: Annotated[
        List[str],
        Field(
            description="Skip any file or directory whose path matches the pattern.",
        ),
    ] = list(DEFAULT_EXCLUDES)

    exclude_rule: Annotated[
        List[str],
        Field(description="Skip any rule with the given id."),
    ] = []

    severity: Annotated[
        List[Literal["INFO", "WARNING", "ERROR"]],
        Field(
            description="Report findings only from rules matching the supplied severity level.",
        ),
    ] = []

    metrics: Annotated[
        Literal["auto", "on", "off"],
        Field(
            description="Configures how usage metrics are sent to the Semgrep server.",
        ),
    ] = "auto"

    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached rules. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]

    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.semgrep.options.tool_version"),
        Field(
            description=(
                "Version constraint for semgrep installation, in pip requirement "
                "syntax. Leave unset to use the scanner's own default constraint."
            )
        ),
    ] = None

    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class SemgrepScannerConfig(ScannerPluginConfigBase):
    name: Literal["semgrep"] = "semgrep"
    # Semgrep does not support Windows at all
    enabled: bool = platform.system().lower() != "windows"
    options: Annotated[
        SemgrepScannerConfigOptions, Field(description="Configure Semgrep scanner")
    ] = SemgrepScannerConfigOptions()


@ash_scanner_plugin
class SemgrepScanner(GrepScannerBase[SemgrepScannerConfig]):
    """SemgrepScanner implements code scanning using Semgrep."""

    #: semgrep is a Python package ASH runs through uv. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=("~/.semgrep",),
        # semgrep writes its settings, log and rule files to $XDG_CONFIG_HOME/.semgrep
        # when that is set; where ~/.semgrep is read-only, that is a private one.
        cache_env=("XDG_CONFIG_HOME",),
        env_prefixes=("SEMGREP_",),
        # semgrep-core loads root certificates through OCaml's ca-certs, which on
        # macOS runs /usr/bin/security against the system keychains.
        system_trust_roots=True,
        # The offline rule cache ASH checked before the scan and passes as --config.
        read_path_env=("SEMGREP_RULES_CACHE_DIR",),
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = SemgrepScannerConfig()
        self.command = "semgrep"
        self.use_uv_tool = True  # Enable UV tool execution
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.SAST

        self._setup_uv_tool_install_commands()
        # The version probe is recorded here and run once, by the dependency
        # check, the SARIF step or the inventory (resolve_deferred_tool_version):
        # construction must start nothing, whoever constructs the scanner.
        self._deferred_tool_version_probe = ("semgrep", self._uv_from_spec())
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    # ---------------------------------------------------------------
    # GrepScannerBase hooks
    # ---------------------------------------------------------------

    def cache_dir_env_var(self) -> str:
        return "SEMGREP_RULES_CACHE_DIR"

    def cache_dir_name(self) -> str:
        return "Semgrep"

    def default_rulesets(self) -> List[str]:
        return ["p/ci"]

    def extra_subprocess_env(self) -> dict | None:
        """The version check off, and `SEMGREP_RULES` from the cache dir offline.

        semgrep ends `scan` with a version check that opens
        ``~/.cache/semgrep_version``. Where that file is not readable (a sandbox
        that grants no path in the home) the open raises, semgrep exits 2 after it
        has printed its findings, and the scan counts as failed. The check only
        shows upgrade banners, so it is off for every run, online as well.
        """
        env = {_VERSION_CHECK_ENV: _VERSION_CHECK_OFF}
        # The cache the command's --config names (the base records it, absolute,
        # when the offline resolution read it; None when local rules or path trust
        # left the cache unread, and online). The variable used to be re-read from
        # the environment here, so a scan whose --config carried no cache still
        # exported one, and a relative value was made absolute against the scan-time
        # working directory while the --config had been resolved at construction.
        if self._scanner_offline() and self._cache_dir_in_use:
            env["SEMGREP_RULES"] = f"{self._cache_dir_in_use}/*"
        return env

    def _direct_or_uv_command_found(self, *, direct_only: bool = False) -> bool:
        """Whether ``get_uv_tool_command`` found a way to run semgrep, and set
        ``use_uv_tool`` to how it found it.

        The resolver answers with ``["uv", "tool", "run", "semgrep"]`` when uv runs
        the tool, and with the path of a semgrep binary on PATH otherwise. Both
        used to be read as "the binary is on PATH", which turned uv off and made
        the scan exec a semgrep that is not there when uv was the only route. The
        uv form is told by the first word's file name (``_is_uv_form``), so a uv
        named by its full path counts as uv too.

        With ``direct_only`` the resolver is not consulted at all: after uv's own
        install of the tool failed, ``uv tool run`` would repeat that install at
        scan time (offline, it fails again), so only a semgrep binary on PATH
        satisfies the dependency. The binary is looked up directly
        (``find_executable``) rather than read off the resolver's answer, because
        the resolver probes ``uv tool run semgrep --version`` first and answers the
        uv form whenever that probe succeeds (``utils/uv_tool_runner.py``,
        ``get_uv_tool_command``: uv run, then the binary, then None), and it
        remembers its answer per process, so a uv form from an earlier probe would
        hide a binary that is on PATH now. The check reports MISSING when no binary
        is found.

        A binary on PATH, however it was found, is verified against the scan's
        requirement before it is taken (``_direct_binary_satisfies``), as
        ``_select_tool_execution`` verifies a pre-installed tool before running it
        directly.
        """
        if direct_only:
            found = find_executable(self.command)
            if found is None:
                self._plugin_log(
                    "uv's install of semgrep failed and no semgrep binary is on PATH; "
                    "the scan would repeat that install through uv tool run, so "
                    "semgrep is missing.",
                    level=logging.WARNING,
                )
                return False
            if not self._direct_binary_satisfies(found):
                return False
            self.use_uv_tool = False
            self.dependencies_satisfied = True
            return True
        # The scanner's own offline mode reaches the probe too: with options.offline
        # set and ASH online, the resolver used to probe (and could install) from
        # PyPI while the scan, the version probe and the install ran offline.
        command = get_uv_tool_command(
            self.command,
            from_spec=self._uv_probe_from_spec(),
            offline=self._is_offline_mode(),
        )
        if command is None:
            return False
        uses_uv = _is_uv_form(command)
        if not uses_uv and not self._direct_binary_satisfies(
            _command_words(command)[0]
        ):
            return False
        self.use_uv_tool = uses_uv
        self.dependencies_satisfied = True
        return True

    def _direct_binary_satisfies(self, executable: str) -> bool:
        """Whether the semgrep binary the resolver found on PATH may run the scan.

        Verified against the scan's requirement (the package, its extras and the
        version constraint, ``utils/pre_installed_tool.verify_pre_installed_tool``),
        as ``_select_tool_execution`` verifies a pre-installed tool before running
        it directly. It used to run unverified: with uv missing, or after uv's
        install of the tool failed, whatever ``semgrep`` PATH held ran the scan
        and reported under this scanner's version constraint. A copy verified not
        to satisfy the requirement is refused, with the reason recorded for the
        MISSING row. One that cannot be verified (no uv to resolve the requirement
        with, a probe the sandbox refused) runs, with a warning: it is the only
        route left, and refusing it would make every host without uv MISSING. One
        whose records could not be redacted (the plugin's own values hook raised
        or gave no usable answer) is refused, with the reason recorded: that is
        the plugin's failure, not the host's, and a run shown against nothing is
        worse than a MISSING row.
        """
        from automated_security_helper.utils.pre_installed_tool import (
            build_requirement,
            verify_pre_installed_tool,
        )
        from automated_security_helper.utils.uv_tool_runner import (
            find_uv_or_none,
            shown_uv_output,
        )

        from automated_security_helper.base.uv_tool_mixin import guarded_values_read

        extras = self._get_tool_package_extras()
        constraint = self._get_tool_version_constraint()
        package = self.uv_tool_package_name or self.command
        requirement = build_requirement(package, extras, constraint)
        # The values hook is read ONCE, guarded, for the verify and every line
        # below, as _select_tool_execution reads it: a bare read let a raising
        # hook crash the dependency check, a generator answer was drained by the
        # verify so the lines after it logged the requirement and the answer's
        # detail unredacted, and a None went into the verify as is. With no usable
        # values the copy is REFUSED: its probe's excerpt could not be redacted,
        # and the scan's own records (every subprocess line, every error) would
        # be shown against nothing; the mixin's run path refuses the uv route on
        # the same failure, and a security tool whose redaction is broken does
        # not run. The reason names the hook's failure and no path, no detail.
        read = guarded_values_read(self)
        if read.values is None:
            failure = read.failure()
            self._plugin_log(
                f"The {self.command} on PATH was not verified: the plugin's values "
                f"hook {failure}, so its check could not be redacted. It is the "
                "only copy ASH can run here, and it does not run unverified.",
                level=logging.WARNING,
            )
            self.dependency_unavailable_reason = (
                f"{self.command} cannot be used: the plugin's values hook {failure}, "
                "so the copy on PATH could not be verified and its records could "
                "not be redacted. Fix the plugin's values hook, or install uv so ASH "
                "can run a verified copy."
            )
            return False
        values: Tuple[str, ...] = read.values
        answer = verify_pre_installed_tool(
            executable,
            package,
            extras,
            constraint,
            uv_executable=find_uv_or_none(),
            values=values,
        )

        def _shown(text: str) -> str:
            return shown_uv_output(
                text,
                values,
                plugin_inputs=self._uv_run_inputs_for_records(),
                tool_name=self.command,
                limit=None,
            )

        if answer.status == "satisfied":
            self._plugin_log(
                _shown(
                    f"Using {self.command} at {executable} directly; it satisfies "
                    f"{requirement!r}"
                ),
                level=logging.INFO,
            )
            # With a default, as the mixin reads it: a verifier stand-in that
            # carries only a status and a detail is an answer without a version.
            verified_version = getattr(answer, "version", None)
            if verified_version:
                self.tool_version = verified_version
            return True
        if answer.status == "unsatisfied":
            # The log gets the full story, the copy's path and the answer's
            # detail, which quotes the tool's own words. The REASON that reaches
            # the results (dependency_unavailable_reason) gets the answer's
            # summary, the path-free, excerpt-free line the verifier provides for
            # exactly that use; the detail stands in only for an answer without
            # one. This is the mixin's rule for the same two lines.
            remedy = (
                "It is the only copy ASH can run here, so semgrep is missing. "
                f"Install a copy that satisfies {requirement!r}, or install uv so "
                "ASH can run one."
            )
            self._plugin_log(
                _shown(
                    f"{self.command} at {executable} cannot be used: {answer.detail}. "
                    f"{remedy}"
                ),
                level=logging.ERROR,
            )
            summary = getattr(answer, "summary", "") or answer.detail
            self.dependency_unavailable_reason = _shown(
                f"{self.command} cannot be used: {summary}. {remedy}"
            )
            return False
        self._plugin_log(
            _shown(
                f"Using {self.command} at {executable} directly, unverified against "
                f"{requirement!r}: {answer.detail}"
            ),
            level=logging.WARNING,
        )
        return True

    def _get_uv_tool_version(
        self, tool_name: str, package_name: Optional[str] = None
    ) -> Optional[str]:
        """The version probe, run with semgrep's version check off.

        ``semgrep --version`` prints the version and then runs the same version
        check as a scan, so under a sandbox that cannot read the check's cache file
        it exits 2 and the version stays unknown. The probe is started through uv,
        which takes no argument for this, so the variable is held in ASH's
        environment for the length of the probe; the hold is counted, so scanners
        probing at once keep it until the last one is done.
        """
        hold_environ(_VERSION_CHECK_ENV, _VERSION_CHECK_OFF)
        try:
            return super()._get_uv_tool_version(tool_name, package_name)
        finally:
            release_environ(_VERSION_CHECK_ENV)

    # ---------------------------------------------------------------
    # Semgrep-specific UV-tool dependency resolution
    # ---------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        """semgrep 1.125.0+ has improved stability."""
        if self.config and self.config.options.tool_version:
            return self.config.options.tool_version
        return ">=1.125.0,<2.0.0"

    def unsupported_platform_reason(self) -> str | None:
        """Windows, permanently: semgrep publishes no Windows build.

        Stated here rather than only inside ``validate_plugin_dependencies`` so ScanPhase
        can tell this apart from a dependency that is merely absent. It used to be only
        the ``return False`` below, which ScanPhase read as MISSING -- so every Windows
        leg recorded a scanner that cannot exist there as one that should have run.
        SKIPPED is the honest classification and the completeness gate tolerates it.

        The same fact also sets ``SemgrepScannerConfig.enabled`` to False on Windows by
        default, and that is not this method's substitute: a config default is
        overridable, and this repository's own ``.ash/.ash.yaml`` does override it with
        ``semgrep: enabled: true``, which is how the MISSING classification was reached
        at all. An operator asking for semgrep on Windows should get a clear SKIPPED with
        a reason, not a silent config default and not a failed gate.
        """
        if platform.system().lower() == "windows":
            return "semgrep publishes no Windows build"
        return None

    def _validate_tool_dependencies(self) -> bool:
        """Semgrep's tool-reachability check.

        Named for the ``GrepScannerBase`` hook rather than overriding
        ``validate_plugin_dependencies`` directly: the base method now consults the
        offline-cache verdict first, and an override here would skip it.
        """
        unsupported = self.unsupported_platform_reason()
        if unsupported is not None:
            # Still False, because the answer to "can this run here" is still no. What
            # changed is that ScanPhase now asks the question above first, so this return
            # no longer has to carry two different meanings.
            self._plugin_log(
                f"Semgrep will be skipped: {unsupported}",
                level=logging.INFO,
            )
            return False

        if not self._validate_uv_tool_availability():
            # UV missing — defer to consolidated resolver: if the tool is on
            # PATH directly (or uv answers its probe after all) we can still run it.
            # Two oracles, and the resolver's wins: the runner's availability
            # check answers False for a probe that failed as well as for a uv that
            # is absent, while the resolver's uv form means its own
            # `uv tool run semgrep --version` just succeeded. The runner asks its
            # question again when the scan runs (UVToolRunner.run_tool), so a
            # failed availability probe that is still inside its retry window
            # refuses the scan there, with the window's reason, rather than here.
            if self._direct_or_uv_command_found():
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False

        if self.use_uv_tool:
            installation_info = self._get_tool_installation_info()
            if installation_info.get("available"):
                # Runs a verified binary on PATH directly instead of re-resolving
                # through uv, and fails offline with the missing extras named (#520).
                return self._select_tool_execution(installation_info)

            self._plugin_log(
                "Semgrep not found via UV tool, attempting explicit installation..."
            )
            timeout = (
                getattr(self.config.options, "install_timeout", 300)
                if self.config
                else 300
            )
            if self._install_uv_tool(timeout=timeout):
                self._plugin_log("Successfully installed semgrep via UV tool")
                self.dependencies_satisfied = True
                return True
            # Last resort: a semgrep binary on PATH. The resolver's uv form is not
            # an answer here, because uv's install of the tool has just failed and
            # `uv tool run` would repeat it at scan time.
            if self._direct_or_uv_command_found(direct_only=True):
                return True
            self._plugin_log(
                "Direct executable detection also failed for semgrep",
                level=logging.ERROR,
            )
            return False

        self.dependencies_satisfied = True
        return True
