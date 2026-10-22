# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the JupyterConverter implementation."""

import glob
import json
import re
import shutil
import subprocess  # nosec B404 — DEVNULL and the errors of nbconvert's runs; spawns go through the runners below
import tempfile
from contextlib import nullcontext
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    ContextManager,
    Dict,
    List,
    Literal,
    NamedTuple,
    Optional,
    Tuple,
)

from pydantic import Field, PrivateAttr

from automated_security_helper.models.core import ignore_paths_that_skip_scanning
from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)

from automated_security_helper.base.options import (
    ConverterOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import (
    honors_ignore_files,
    scan_set,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    ignore_path_matches,
)
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import (
    SandboxUnavailable,
    active_scope,
    plugin_probe_scope,
    sandbox_requested,
    sandbox_scope,
    scanner_sandbox_scope,
)
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    refusal_reason,
    relative_display,
)
from automated_security_helper.utils.subprocess_utils import (
    child_environ,
    lookup_for_scan,
    run_ended_with_the_server,
    run_succeeded,
    signal_death,
    signal_ending,
    spawn_run,
)
from automated_security_helper.utils.pre_installed_tool import ANSI_ESCAPE
from automated_security_helper.utils.terminal_text import shown_on_one_line

#: The name nbconvert is given the staged copy under, and the name it writes its
#: output under. Not the notebook's own name: nbconvert expands each notebook
#: argument with ``glob.glob``, so ``[x].ipynb`` matches only ``x.ipynb``, and it
#: passes the output name through ``str.format``, which a ``{`` in it breaks. ASH
#: names the converted file after the original notebook itself.
_STAGED_NAME = "notebook"

#: A ``language_info.file_extension`` the copy keeps. nbconvert's generic script
#: exporter appends the notebook's value to the output name, so one holding a path
#: separator or ``..`` would place the output outside the directory it was given.
_PLAIN_EXTENSION = re.compile(r"\.[A-Za-z0-9_+-]{1,16}")


class _NbconvertNotRun(Exception):
    """nbconvert was not run on a notebook, for the reason given.

    Its message is ASH's own and quotes nothing from the notebook, so the failed
    input records it in full, where any other error is recorded by its type only.
    """


class _FoundNbconvert(NamedTuple):
    """The dependency check's answer about a jupyter-nbconvert to run directly.

    ``path`` and ``version`` for a copy whose nbconvert satisfies the
    converter's requirement, with ``reason`` and ``detail`` None. For a copy
    that does not, ``path`` is None, ``reason`` says why without naming the
    copy (it reaches the results), and ``detail`` says the same with the
    copy's host path, for the caller's log: whether the refusal is detail or
    a failure is the caller's call, so the caller picks the level too.
    """

    path: Optional[str]
    reason: Optional[str]
    detail: Optional[str]
    version: Optional[str]


def _first_line(text: object) -> str:
    """``text``'s first line that is not blank, stripped; "" for none."""
    if not isinstance(text, str):
        return ""
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def _parse_notebook(
    content: bytes,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """``content``'s parsed notebook and None, or None and why it is not one.

    Decided from the copy before nbconvert runs, so a file that was never a
    notebook (malformed JSON, a Git LFS pointer, a fixture stub) is recorded as
    an input error, which a reviewed suppression can accept, rather than a tool
    failure, which nothing can. The reason is ASH's own words and quotes nothing
    from the file: a failed input's reason reaches the results and the reports.

    The structure check follows the declared nbformat version, because nbconvert
    reads every version with ``as_version=4``: a version 4 or later file keeps
    its cells at the top level, and version 3 and earlier files keep them under
    ``worksheets[].cells``, which the read upgrades and converts. A dict with
    neither list is a notebook under no version. Anything else structural is
    left to nbconvert: a false pass here costs only the tool-failure
    classification the file had before this check, while a false reject fails a
    convertible notebook with no tool at fault.

    The parsed object is returned so the file is read once: staging reads the
    notebook's language from it rather than parsing the content again.
    """
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None, "its text is not UTF-8"
    try:
        notebook = json.loads(text)
    except ValueError:
        return None, "its text is not JSON"
    if not isinstance(notebook, dict):
        return None, "its JSON is not an object"
    version = notebook.get("nbformat")
    if isinstance(version, int) and version >= 4:
        if not isinstance(notebook.get("cells"), list):
            return None, "it has no cells list"
    elif not isinstance(notebook.get("cells"), list) and not isinstance(
        notebook.get("worksheets"), list
    ):
        return None, "it has no cells or worksheets list"
    return notebook, None


def _is_uv_error(stderr: object) -> bool:
    """Whether ``uv tool run`` failed itself, before nbconvert ran.

    uv reports its own errors on stderr either as ``error: ...`` or, for a tool it
    cannot resolve (offline with nbconvert not in its cache, for one), as a
    diagnostic that starts with a multiplication sign, and it can print
    ``warning:`` lines ahead of either. nbconvert's own failures start with a
    traceback or ``[NbConvertApp]``, and an ``error:`` line later in them is
    nbconvert's. Judged by the first line that is not blank and is not one of
    uv's leading warnings, with color codes stripped first: under FORCE_COLOR
    uv colors its prefixes even into a pipe.
    """
    if not isinstance(stderr, str):
        return False
    for line in stderr.splitlines():
        text = ANSI_ESCAPE.sub("", line).strip()
        if not text or text.startswith("warning:"):
            continue
        return text.startswith(("error:", "\N{MULTIPLICATION SIGN}"))
    return False


class JupyterConverterConfigOptions(ConverterOptionsBase):
    tool_version: Annotated[
        str | None,
        tool_version_constraint("converters.jupyter.options.tool_version"),
        Field(
            description="Version constraint for nbconvert tool installation (e.g., '>=7.16.0'). If not specified, the latest version will be installed."
        ),
    ] = ">=7.16.0,<8.0.0"
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation (default: 300)"),
    ] = 300


class JupyterConverterConfig(ConverterPluginConfigBase):
    """Jupyter Notebook (.ipynb) to Python converter configuration."""

    name: Literal["jupyter"] = "jupyter"
    enabled: bool = True
    options: Annotated[
        JupyterConverterConfigOptions,
        Field(description="Configure Jupyter Notebook converter"),
    ] = JupyterConverterConfigOptions()


@ash_converter_plugin
class JupyterConverter(ConverterPluginBase[JupyterConverterConfig]):
    """Converter implementation for Jupyter notebooks security scanning."""

    # How the dependency check chose to run nbconvert: "uv" (`uv tool run` with
    # this converter's requirement) or "direct" (the jupyter-nbconvert it verified,
    # by that path, kept in _nbconvert_path). None before a check. A conversion
    # launches only that one.
    _nbconvert_route: Optional[str] = PrivateAttr(default=None)
    _nbconvert_path: Optional[str] = PrivateAttr(default=None)

    # nbconvert converts a staged copy of one notebook, so under a sandbox it may not
    # read the scanned tree or the output directory, only that copy and its tools.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        staged_input_only=True
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = JupyterConverterConfig()

        self.command = "jupyter-nbconvert"
        self.uv_tool_package_name = "nbconvert"
        self.use_uv_tool = True  # Enable UV tool execution

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # First, so the version probe below has the results directory a sandbox
        # scope is built from.
        super().model_post_init(context)

        # Deferred until the dependency check asks
        # (resolve_deferred_tool_version), so construction runs nothing and the
        # environment is resolved only when a notebook needs nbconvert. The
        # spec the probe resolves under is _uv_from_spec, the requirement the
        # check reads, so it reports the version that runs.
        self.defer_tool_version_probe(self.command)

    def _probe_scope(self) -> ContextManager[Optional[SandboxUnavailable]]:
        """Sandbox this converter's probes, unless a caller already confined them.

        nbconvert is a third-party tool, and its version probe and dependency check
        start it. ``plugin_probe_scope`` runs those sandboxed under a sandbox, writing
        only to a throwaway directory, and refuses them when the sandbox cannot be
        provided. The convert phase enters the same scope around this converter; one
        entered here as well would only add a second throwaway directory.
        """
        if active_scope() is not None:
            return nullcontext()
        return plugin_probe_scope(self, self.context)

    def _get_tool_version_constraint(self) -> Optional[str]:
        """Get version constraint for nbconvert installation.

        Returns:
            Version constraint string for nbconvert (e.g., ">=7.16.0") or None for latest
        """
        return self.config.options.tool_version

    def _get_tool_package_extras(self) -> Optional[List[str]]:
        """Get package extras for nbconvert installation.

        Returns:
            List of package extras needed for nbconvert. Should be nothing needed by
            default for script export.
        """
        return []

    def _uv_from_spec(self) -> Optional[str]:
        """The one ``--from`` spec every nbconvert environment resolves under.

        The version probe, the install refreshes and the run share it, so they
        resolve one environment and the reported ``tool_version`` is the version
        that runs. Built from the package (``nbconvert``), not the command: the
        mixin's default builds from ``self.command``, and ``jupyter-nbconvert``
        names no package.
        """
        from automated_security_helper.utils.pre_installed_tool import (
            build_requirement,
        )

        return build_requirement(
            self.uv_tool_package_name or "nbconvert",
            self._get_tool_package_extras(),
            self._get_tool_version_constraint(),
        )

    def _shown_uv_from_spec(self) -> Optional[str]:
        """The requirement as a message shows it: with a constraint the config
        read from the environment as the placeholder (text_without_values),
        since reasons reach the results and ash.log is a sink. The resolved
        form (_uv_from_spec) is for uv alone. Redacted with
        ``_values_to_redact()``, as the base classes' lines are: the union
        keeps the config's values when a plugin's own ``_environment_values()``
        returns fewer than the config read."""
        requirement = self._uv_from_spec()
        if requirement is None:
            return None
        from automated_security_helper.utils.error_text import text_without_values

        return text_without_values(requirement, self._values_to_redact())

    def _get_tool_with_dependencies(self) -> Optional[List[str]]:
        """Get additional dependencies to install with nbconvert.

        Returns:
            List of additional dependencies needed for nbconvert (jupyter for CLI access)
        """
        return ["jupyter"]

    def validate_plugin_dependencies(self) -> bool:
        """Whether nbconvert can run, and the way a conversion runs it.

        Ready only with a way to run nbconvert that can be vouched for: uv, with
        nbconvert installed through it or by this check (a copy on PATH that
        does not verify is replaced by that install); or a jupyter-nbconvert
        verified against this converter's requirement, run by that path. The choice is
        recorded in ``_nbconvert_route``, and a conversion launches only that one.
        A jupyter-nbconvert found on PATH and not verified makes nothing ready, and
        ``dependency_unavailable_reason`` says why the converter is missing.

        Under a sandbox (``sandbox.mode`` other than ``off``) nothing is installed,
        as for the scanners, every check runs sandboxed (``_probe_scope``), and the
        route is the verified direct copy: ``uv tool run`` writes uv's tools
        directory, which the sandbox mounts read-only.

        Returns:
            True if converter is ready to use, False otherwise
        """
        with self._probe_scope():
            return self._validate_dependencies()

    def _validate_dependencies(self) -> bool:
        """``validate_plugin_dependencies`` without the scope it runs in."""
        self.dependency_unavailable_reason = None
        self._nbconvert_route = None
        self._nbconvert_path = None
        # Nothing to convert, so nbconvert is neither looked for nor installed. A
        # count of None (the scan set could not be read) is not "no notebooks".
        if self.candidate_input_count() == 0:
            return True
        # nbconvert is needed, so its version is worth asking for: `uv tool run
        # --from nbconvert`, which resolves and downloads nbconvert to answer.
        # The probe runs nbconvert, so under a sandbox it runs sandboxed, as a
        # scanner's version probe does.
        with self._probe_scope():
            self.resolve_deferred_tool_version()

        if self.use_uv_tool and not sandbox_requested(self.context):
            # Check if tool is already available (UV-installed or pre-installed)
            installation_info = self._get_tool_installation_info()

            if installation_info.get("available"):
                source = installation_info.get("preferred_source", "unknown")
                if source == "uv":
                    ASH_LOGGER.debug(f"{self.command} already installed via UV tool")
                    self._nbconvert_route = "uv"
                    return True
                # A copy on PATH runs only once resolved by the scan's own
                # lookup and verified, and then by that path: the installation
                # info's find is not a way around the lookup's refusals.
                found = self._verified_direct_nbconvert()
                if found.path is not None:
                    ASH_LOGGER.debug(
                        f"Using pre-installed {self.command} at {found.path} "
                        "directly; it satisfies the converter's requirement",
                        extra=NO_MARKUP,
                    )
                    self._use_direct_nbconvert(found)
                    return True
                # uv being present is not by itself a way to run nbconvert:
                # nbconvert is installed through uv, with the converter's
                # requirement, and the uv route is chosen only when that
                # succeeds. With the install failing (offline, say), the
                # converter is missing, with the verification's reason, rather
                # than ready with every notebook failing at conversion.
                if self._install_uv_tool(timeout=self.config.options.install_timeout):
                    # The refused copy is detail here, logged once with its
                    # host path (found.detail): the scan still converts,
                    # through uv.
                    ASH_LOGGER.debug(
                        shown_on_one_line(
                            f"{self.command} on PATH is not used ({found.detail}); "
                            "nbconvert was installed through uv and runs through it"
                        ),
                        extra=NO_MARKUP,
                    )
                    self.tool_version = self._get_uv_tool_version(self.command)
                    self._nbconvert_route = "uv"
                    return True
                return self._nbconvert_unavailable(found.reason, found.detail)

            # Tool not available, attempt installation
            installation_success = self._install_uv_tool(
                timeout=self.config.options.install_timeout
            )

            if installation_success:
                ASH_LOGGER.debug(f"UV tool installation successful for {self.command}")
                # Update tool version after successful installation
                self.tool_version = self._get_uv_tool_version(self.command)
                self._nbconvert_route = "uv"
                return True
            else:
                ASH_LOGGER.warning(
                    f"UV tool installation failed for {self.command}, looking for "
                    f"a {self.command} that satisfies the converter's requirement"
                )
        elif self.use_uv_tool:
            # A sandboxed scan runs nbconvert directly: `uv tool run` writes uv's
            # tools directory, which the sandbox mounts read-only (measured with
            # uv 0.12: "Could not create temporary file"), and installing runs
            # the package's build code outside any sandbox, so a sandboxed scan
            # installs no tool. Run `ash dependencies install` first for a copy
            # the lookup below can verify.
            ASH_LOGGER.debug(
                "A sandboxed scan does not run nbconvert through uv; looking for "
                f"a {self.command} that satisfies the converter's requirement"
            )

        # An installed jupyter-nbconvert, run directly by its absolute path, and
        # only once its nbconvert is verified to satisfy tool_version. Nothing is
        # run to find it: a copy that answers a probe by name says nothing about
        # which nbconvert it belongs to.
        found = self._verified_direct_nbconvert()
        if found.path is not None:
            ASH_LOGGER.debug(f"Found {self.command} at {found.path}", extra=NO_MARKUP)
            self._use_direct_nbconvert(found)
            return True
        return self._nbconvert_unavailable(found.reason, found.detail)

    def _use_direct_nbconvert(self, found: _FoundNbconvert) -> None:
        """Record the verified copy as the one a conversion runs, and its own
        version as the reported ``tool_version``: on this route the version
        that runs is the copy's, not the one uv resolves under the
        requirement."""
        self._nbconvert_route = "direct"
        self._nbconvert_path = found.path
        # The copy's own version, or none at all: a copy whose --version
        # answered nothing leaves the version unknown, where keeping the
        # deferred probe's answer would report the version uv resolved,
        # which is not what runs on this route.
        self.tool_version = found.version or None

    def _nbconvert_unavailable(
        self, reason: Optional[str], detail: Optional[str] = None
    ) -> bool:
        """The dependency check's answer when nothing can run nbconvert: False,
        with ``reason`` recorded as ``dependency_unavailable_reason``. The one
        warning carries ``detail`` where there is one: the refused copy's host
        path belongs in the log, never in the recorded reason."""
        self.dependency_unavailable_reason = reason
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"Converter {self.command} is not available: {detail or reason}. "
                f"Jupyter notebook conversion will be skipped."
            ),
            extra=NO_MARKUP,
        )
        return False

    def _verified_direct_nbconvert(
        self, executable: Optional[str] = None
    ) -> _FoundNbconvert:
        """The ``jupyter-nbconvert`` to run directly, as a :class:`_FoundNbconvert`.

        With no ``executable``, the one :func:`lookup_for_scan` finds, so its
        refusals hold for every caller. With one, that copy: the conversion
        passes the path the dependency check recorded, so a PATH that changed
        since the check cannot swap in a copy the check never saw. Either way it
        counts only once :func:`verify_pre_installed_tool` says its nbconvert
        satisfies the converter's requirement (``tool_version`` and extras), as
        a scanner's tool from PATH is checked. The verdict is remembered per
        file, so asking again at conversion costs nothing. A verified copy's
        ``version`` is the verdict's, read from the copy itself, so the caller
        reports the version that runs. The reason is what the dependency check
        records as ``dependency_unavailable_reason``, so it names no host path;
        the results' row for the converter carries it as its own
        ``dependency_unavailable_reason``, beside the dependencies recorded as
        unavailable and the candidate count, and a conversion
        that refuses the copy records its own fixed reason for the input. The
        detail names the copy by its path, and the caller logs it at the level
        of what the refusal means there (the dependency check may still install
        through uv).
        """
        from automated_security_helper.utils.pre_installed_tool import (
            verify_pre_installed_tool,
        )
        from automated_security_helper.utils.uv_tool_runner import find_uv_or_none

        extras = self._get_tool_package_extras()
        constraint = self._get_tool_version_constraint()
        # Only messages below name the requirement, so it is the shown form;
        # the verification gets the constraint itself.
        requirement = self._shown_uv_from_spec()
        if executable is None:
            executable, refused = lookup_for_scan(self.command, self.context.source_dir)
            if executable is None:
                reason = refused or (
                    f"no {self.command} was found to run {requirement!r} with"
                )
                return _FoundNbconvert(None, reason, reason, None)
        verdict = verify_pre_installed_tool(
            executable,
            self.uv_tool_package_name,
            extras,
            constraint,
            uv_executable=find_uv_or_none(),
            values=self._values_to_redact(),
        )
        if verdict.status == "satisfied":
            return _FoundNbconvert(
                executable, None, None, getattr(verdict, "version", None)
            )
        # The recorded reason takes the verdict's summary, never its detail:
        # the detail names the copy by path and can quote the probe's own
        # output or the real constraint, and the reason reaches the results.
        summary = verdict.summary
        return _FoundNbconvert(
            None,
            (
                f"the {self.command} found cannot be used, as its nbconvert "
                f"does not satisfy {requirement!r}"
                + (f": {summary}" if summary else "")
            ),
            (
                f"the {self.command} at {executable} cannot be used, as its "
                f"nbconvert does not satisfy {requirement!r}: {verdict.detail}"
            ),
            getattr(verdict, "version", None),
        )

    def _execute_nbconvert_via_uv(
        self, cmd: List[str], timeout: int = 60, cwd: Optional[Path] = None
    ) -> bool:
        """Execute jupyter nbconvert command via UV tool runner.

        Args:
            cmd: Command list to execute (should start with 'jupyter')
            timeout: Timeout in seconds
            cwd: Working directory for nbconvert. It must not be the scanned tree:
                nbconvert puts its working directory first on ``sys.path`` and reads
                ``jupyter_nbconvert_config`` files from it, and
                ``TemplateExporter.extra_template_basedirs`` defaults to it, so a
                ``python/`` or ``script/`` directory there replaces the template
                nbconvert renders the output with. With no value, an empty
                temporary directory is used.

        Returns:
            True if nbconvert succeeded, False if uv could not run it at all: uv is
            unavailable, the run did not start, uv failed itself (its own
            ``error:`` line), or the runner raised. No other nbconvert runs in
            uv's place.

        Raises:
            subprocess.CalledProcessError: nbconvert ran under uv and exited
                non-zero, as the direct route raises it.
            subprocess.TimeoutExpired: nbconvert ran under uv and did not finish.
        """
        if cwd is None:
            with tempfile.TemporaryDirectory(prefix="ash-nbconvert-cwd-") as empty:
                return self._execute_nbconvert_via_uv(
                    cmd, timeout=timeout, cwd=Path(empty)
                )
        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            uv_runner = get_uv_tool_runner()

            # Check UV availability
            if not uv_runner.is_uv_available():
                ASH_LOGGER.debug(
                    f"{uv_runner.unavailable_reason()} for nbconvert execution"
                )
                return False

            # Extract jupyter arguments (skip 'jupyter')
            if len(cmd) < 1 or cmd[0] != "jupyter":
                ASH_LOGGER.error(f"Invalid jupyter command format: {cmd}")
                return False

            jupyter_args = cmd[2:]  # Skip 'jupyter' and 'nbconvert'

            ASH_LOGGER.debug(f"Executing jupyter via UV with args: {jupyter_args}")

            # The requirement goes in the one --from spec, nbconvert plus tool_version,
            # as the scanners pass theirs, so uv runs a version that satisfies it or
            # none. run_tool's version_constraint would build a second --from from
            # the command name, which uv refuses.
            requirement = self._uv_from_spec()
            result = uv_runner.run_tool(
                tool_name=self.command,
                package_name=requirement,
                args=jupyter_args,
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
                package_extras=None,
                version_constraint=None,
                timeout=timeout,
                # uv's own resolver and installer lines land on stderr ahead of
                # any diagnostic, and _is_uv_error judges the first line, so
                # without --quiet a uv failure behind an "Installed 1 package"
                # line reads as nbconvert's.
                quiet=True,
            )

            from automated_security_helper.utils.subprocess_utils import (
                PostRunErrorProcess,
                SpawnFailedProcess,
                TimedOutProcess,
            )

            # On this route (run_tool without results_dir) a cancelled scan
            # raises ScanCancelled out of the runner. A cancel that comes back
            # as a response instead is re-raised as the same stop: read as a
            # run result it would be recorded per notebook, and the loop would
            # go on converting under a scan that is stopping.
            if getattr(result, "cancelled", False):
                raise ScanCancelled(
                    getattr(result, "error", "") or "the scan was cancelled"
                )

            # Flags first: a run whose output ASH could not record can exit 0,
            # and it converted nothing ASH can rely on.
            if run_succeeded(result):
                ASH_LOGGER.debug("jupyter execution via UV succeeded")
                return True
            if isinstance(result, PostRunErrorProcess):
                # ASH's failure after the start, whatever the code: no verdict
                # of nbconvert's on the notebook. A tool ASH stopped while it
                # ran has no code at all, and "exit code None" would read as
                # one. A negative code is a signal's, not an exit code. The
                # attribution ("a signal ASH did not send") is the runner's
                # call, carried as ``signaled``: the builders withhold it when
                # ASH's own stop may have been the sender (a kill while the
                # server stops, after a failed wait), and re-deriving it here
                # from the bare code claimed an outside sender for those.
                # Without the flag the death is named, not attributed.
                if getattr(result, "signaled", False):
                    death = signal_death(result.returncode, "jupyter execution via UV")
                else:
                    death = signal_ending(result.returncode, "jupyter execution via UV")
                if death is not None:
                    _, reason = death
                    ASH_LOGGER.warning(
                        reason + (f": {result.error}" if result.error else ""),
                        extra=NO_MARKUP,
                    )
                    return False
                code_text = (
                    "with no exit code observed"
                    if result.returncode is None
                    else f"with exit code {result.returncode}"
                )
                ASH_LOGGER.warning(
                    f"jupyter execution via UV failed {code_text}"
                    + (f": {result.error}" if result.error else ""),
                    extra=NO_MARKUP,
                )
                return False
            if isinstance(result, SpawnFailedProcess):
                ASH_LOGGER.warning(
                    f"uv could not be started: {result.stderr}", extra=NO_MARKUP
                )
                return False
            if _is_uv_error(result.stderr):
                # uv's own failure, such as an environment it could not provide
                # offline, or no nbconvert that satisfies the requirement:
                # nbconvert never ran.
                ASH_LOGGER.warning(
                    "uv could not run nbconvert: "
                    f"{ANSI_ESCAPE.sub('', str(result.stderr)).strip()}",
                    extra=NO_MARKUP,
                )
                return False
            if isinstance(result, TimedOutProcess):
                raise subprocess.TimeoutExpired(
                    result.args, timeout, result.stdout, result.stderr
                )
            raise subprocess.CalledProcessError(
                result.returncode, result.args, result.stdout, result.stderr
            )

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # nbconvert's own verdict on the notebook: not uv failing to run it.
            raise
        except UVToolRunnerError as e:
            ASH_LOGGER.warning(f"UV tool runner error for jupyter: {e}")
            return False
        except ImportError as e:
            ASH_LOGGER.warning(f"UV tool runner module not available: {e}")
            return False
        except Exception as e:
            ASH_LOGGER.warning(f"Unexpected error during UV jupyter execution: {e}")
            return False

    def _notebooks_in_scan_set(self) -> List[str]:
        """Every ``.ipynb`` in the scan set, found without invoking nbconvert.

        Extracted from ``convert`` so ``candidate_input_count`` can answer from the same
        predicate rather than a second copy of it. A second copy is the specific thing to
        avoid here: the count decides whether a missing nbconvert costs coverage, so a
        copy that drifted from the real selection would make the completeness gate fire
        on files this converter would not have touched, or stay silent on ones it would.
        """
        ipynb_files = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
            honor_ignore_files=honors_ignore_files(self.context.config),
            run_id=getattr(self.context, "run_id", None),
        )
        return [f.strip() for f in ipynb_files if f.strip().endswith(".ipynb")]

    def candidate_input_count(self) -> int | None:
        """How many notebooks this converter would convert, tool or no tool.

        ``scan_set`` reads the filesystem and the ignore rules; nbconvert is not involved,
        which is what lets this be answered for a converter that has already been dropped
        for an unavailable tool. That is the case it exists for: in ``--mode nix`` the dev
        shell supplies scanner binaries and exports ``ASH_OFFLINE=YES``, so
        ``uv tool install nbconvert`` is correctly refused and this converter is
        unavailable on every such run. Before this method the completeness gate reported
        that as lost conversion coverage even on a tree with no notebooks in it, which is
        what failed both nix CI legs on a fixture holding one YAML template, one Python
        file and one package.json.

        Returning a real count rather than None on the error path is deliberate: if the
        scan set cannot be read, that is not evidence of zero notebooks, so it answers
        None and the gate stays strict.
        """
        try:
            # Less the notebooks convert() would refuse, judged by the same check it
            # opens them with, so a symlinked notebook is not counted as lost coverage.
            return len(
                [
                    notebook
                    for notebook in self._notebooks_in_scan_set()
                    if refusal_reason(notebook, self.context.source_dir) is None
                ]
            )
        except Exception as exc:  # pragma: no cover - defensive
            ASH_LOGGER.debug(
                f"Could not count .ipynb candidates for the jupyter converter ({exc!r}); "
                "reporting no count so the completeness gate stays strict"
            )
            return None

    @staticmethod
    def _stage_notebook(
        content: bytes, staged: Path, notebook: Optional[Dict[str, Any]] = None
    ) -> str:
        """Write the notebook nbconvert will read, and choose its exporter.

        The exporter is ASH's choice, by the notebook's language: ``python`` for a
        Python notebook or one that names no language, and nbconvert's generic
        ``script`` otherwise. Two ``language_info`` keys are removed from the copy,
        because the notebook is tree content: ``nbconvert_exporter``, since nbconvert
        imports whatever class it names, and ``file_extension`` unless it is a plain
        extension, since the script exporter appends it to the output name. Content
        that is not a JSON object is copied unchanged and left for nbconvert to
        reject.

        ``notebook`` is ``content``'s parsed object, from the caller's pre-check, so
        the file is read once; with None the content is parsed here. The copy
        written is the content, re-encoded only when a key is removed.

        Returns:
            The ``--to`` value to run nbconvert with.
        """
        exporter = "python"
        if notebook is None:
            try:
                notebook = json.loads(content)
            except ValueError:
                notebook = None
        if isinstance(notebook, dict):
            metadata = notebook.get("metadata")
            language_info = (
                metadata.get("language_info") if isinstance(metadata, dict) else None
            )
            if isinstance(language_info, dict):
                language = language_info.get("name")
                if isinstance(language, str) and language.lower() not in ("", "python"):
                    exporter = "script"
                removed = "nbconvert_exporter" in language_info
                language_info.pop("nbconvert_exporter", None)
                extension = language_info.get("file_extension")
                if extension is not None and not (
                    isinstance(extension, str) and _PLAIN_EXTENSION.fullmatch(extension)
                ):
                    del language_info["file_extension"]
                    removed = True
                if removed:
                    content = json.dumps(notebook).encode("utf-8")
        staged.write_bytes(content)
        return exporter

    def _run_nbconvert(
        self,
        notebook: Path,
        output_dir: Path,
        display: str,
        exporter: str = "python",
    ) -> None:
        """Run nbconvert on ``notebook``, writing its output into ``output_dir``.

        nbconvert runs in the staged notebook's directory, which holds nothing but the
        copy. It must not run in the scanned tree: ``NbConvertApp.init_syspath`` puts
        the working directory first on ``sys.path``, it reads
        ``jupyter_nbconvert_config`` files from it, and
        ``TemplateExporter.extra_template_basedirs`` defaults to it, so a module or a
        template directory there would be used.

        nbconvert is launched once, the way the dependency check chose
        (``_nbconvert_route``): through uv, or the jupyter-nbconvert it verified, by
        that path. A sandboxed scan launches the verified copy through the
        scanner-sandbox choke point (``spawn_run``) instead of uv: ``uv tool run``
        writes uv's tools directory, which the sandbox mounts read-only.

        Args:
            notebook: The staged copy to convert.
            output_dir: An empty directory for nbconvert to write into. The output is
                named after the copy, ``notebook`` plus the exporter's extension.
            display: The original notebook's path, for messages.
            exporter: The ``--to`` exporter, as :meth:`_stage_notebook` chose it.

        Raises:
            subprocess.CalledProcessError: nbconvert exited non-zero, on either
                route.
            subprocess.TimeoutExpired: nbconvert did not finish in time, on either
                route.
            SandboxUnavailable: the sandbox backend refused this one spawn.
            _NbconvertNotRun: uv could not run nbconvert on the notebook, the
                jupyter-nbconvert the check chose cannot be used now, or the OS
                refused the direct launch. Its message names no path: the failed
                input's record names the notebook, and the copy's path is the
                host's, so it is logged and not recorded.
        """
        run_dir = notebook.parent
        cmd = [
            "jupyter",
            "nbconvert",
            "--log-level",
            "WARN",
            "--to",
            exporter,
            # nbconvert expands each notebook argument with glob.glob. The name is
            # fixed, but the staging directory's path comes from TMPDIR.
            glob.escape(str(notebook)),
            "--output",
            notebook.stem,
            "--output-dir",
            str(output_dir),
        ]

        sandboxed = sandbox_requested(self.context)
        if not sandboxed and self.use_uv_tool and self._nbconvert_route in (None, "uv"):
            if self._execute_nbconvert_via_uv(cmd, timeout=60, cwd=run_dir):
                return
            # uv was the check's choice, so no jupyter-nbconvert from PATH runs in
            # its place: a second run after nbconvert failed on the notebook would
            # double the time and report the second failure's reason.
            # No path in the reason: the failed input's record names the notebook.
            raise _NbconvertNotRun(
                f"uv could not run nbconvert, and no other {self.command} is run "
                "in its place"
            )
        # The copy the dependency check verified, by the path it recorded,
        # verified again; one that does not satisfy tool_version now is not
        # run, and the notebook is not converted.
        found = self._verified_direct_nbconvert(
            executable=getattr(self, "_nbconvert_path", None)
        )
        if found.path is None:
            # The detail names the copy by its host path and quotes its
            # verdict: logged once, on one line, and the record keeps a reason
            # with neither.
            ASH_LOGGER.warning(
                shown_on_one_line(
                    f"nbconvert is not run for {display}: {found.detail}"
                ),
                extra=NO_MARKUP,
            )
            raise _NbconvertNotRun(
                f"the {self.command} the dependency check chose cannot be used now, "
                f"and no other {self.command} is run in its place"
            )
        direct = [found.path, *cmd[2:]]
        try:
            if sandboxed:
                # Under a sandbox the launch goes through the scanner-sandbox
                # choke point, which confines it to the conversion scope
                # (_conversion_scope), records it, and stops it with a
                # cancelled scan, as run_ended_with_the_server does for an
                # unsandboxed helper.
                result = spawn_run(  # nosec B603 — list args, the verified nbconvert's absolute path
                    direct,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    timeout=60,
                    cwd=run_dir,
                    env=child_environ(),
                )
            else:
                # In a process group the MCP server kills when it stops: through
                # plain subprocess.run nbconvert outlived it, for up to its 60 s.
                result = run_ended_with_the_server(  # nosec B603 — list args, the verified nbconvert's absolute path
                    direct,
                    capture_output=True,
                    # Not ASH's stdin: a terminal, a CI pipe or the MCP client's
                    # channel.
                    stdin=subprocess.DEVNULL,
                    text=True,
                    timeout=60,
                    cwd=run_dir,
                    env=snapshot_environ(),
                )
        except SandboxUnavailable:
            # The backend refused this one spawn: recorded as a refused input by
            # the caller, not as a run of nbconvert.
            raise
        except OSError as e:
            # The launch itself failed (the verified copy gone, or not
            # executable): nbconvert never ran, and the OS's own reason says
            # why, with no path and no file content. Raised here, around the
            # one launch, so an OSError in ASH's own work before or after it
            # keeps its own record.
            raise _NbconvertNotRun(
                "nbconvert could not be started: " + (e.strerror or type(e).__name__)
            )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, direct, result.stdout, result.stderr
            )

    @staticmethod
    def _move_output(output_dir: Path, target_base: Path) -> Optional[Path]:
        """Move nbconvert's output to ``target_base`` plus its extension.

        nbconvert names its output after the staged copy: ``notebook.py`` from the
        python exporter, and from the script exporter ``notebook`` plus the
        notebook's ``file_extension`` (``.r`` for R). The extension is kept, so the
        converted file of an R notebook is ``<name>-converted.r``, as it was when
        nbconvert wrote it there itself.

        Returns:
            The converted file, or None when nbconvert did not write exactly one.
        """
        written = [
            entry
            for entry in output_dir.iterdir()
            if (entry.name == _STAGED_NAME or entry.name.startswith(f"{_STAGED_NAME}."))
            and entry.is_file()
            and not entry.is_symlink()
        ]
        if len(written) != 1:
            return None
        (produced,) = written
        target = target_base.with_name(
            target_base.name + produced.name[len(_STAGED_NAME) :]
        )
        from automated_security_helper.utils.sandbox.fs_guard import open_for_write

        target.parent.mkdir(parents=True, exist_ok=True)
        # Created fresh and never through a link: anything already at the name is
        # removed, O_EXCL refuses whatever appears in its place, and fs_guard
        # follows no link at a directory below the output directory either.
        target.unlink(missing_ok=True)
        with (
            open_for_write(target, binary=True, mode=0o644, exclusive=True) as out,
            produced.open("rb") as source,
        ):
            shutil.copyfileobj(source, out)
        return target

    def _conversion_scope(self, staging_dir: Path) -> ContextManager[None]:
        """Where one notebook's nbconvert runs: sandboxed like a scanner, or as is.

        Under a sandbox, nbconvert gets a scanner's policy: no network unless
        ``sandbox.network_scanners`` names this converter, the environment allowlist,
        the staged copy and the tool readable, and only this converter's results
        directory writable. ``staging_dir`` is the scan target, so the copy is
        readable; ``sandbox_requirements`` leaves the source and output directories
        out of the read paths.

        Raises:
            SandboxUnavailable: A sandbox was requested and cannot be provided.
        """
        if not sandbox_requested(self.context):
            return nullcontext()
        return sandbox_scope(scanner_sandbox_scope(self, self.context, staging_dir))

    def _refuse_unconfinable(self, ipynb_file: str, reason: str) -> None:
        """Record a notebook nbconvert was not run on because it could not be confined.

        The sandbox refused it: no backend could be used, or the backend could not
        plan this one spawn. Kept with the other refused inputs on the converter's
        row, and as a failed input, which the completeness gate counts as lost
        coverage, as it counts a scanner that cannot be sandboxed.
        """
        display = relative_display(ipynb_file, self.context.source_dir)
        why = f"nbconvert was not run on it, the scanner sandbox refused it: {reason}"
        self.record_refused_input(TreeInputRefused(display, why))
        self.record_failed_input(ipynb_file, why)

    def _record_failure(self, ipynb_file: str, reason: str) -> None:
        """Record a notebook nbconvert ran on and did not convert.

        Recorded with or without a sandbox, and the completeness gate counts it as
        lost coverage either way: its contents reached no scanner. Under a sandbox
        the reason says so, since the confinement can be the cause.
        """
        where = " under the scanner sandbox" if sandbox_requested(self.context) else ""
        self.record_failed_input(ipynb_file, f"{reason}{where}")

    def convert(self) -> List[Path]:
        """Converts Jupyter notebooks (.ipynb files) in the source_dir to Python files using CLI.

        Returns:
            List[Path]: List of converted Python files
        """
        ASH_LOGGER.debug(
            f"Searching for .ipynb files in search_path within the ASH scan set: {self.context.source_dir}"
        )
        # Find all notebook files to scan from the scan set
        ipynb_files = self._notebooks_in_scan_set()

        ASH_LOGGER.debug(f"Found {len(ipynb_files)} .ipynb files in scan set.")
        results: List[Path] = []

        # Add warning if no Jupyter notebook files found
        if not ipynb_files:
            ASH_LOGGER.info(
                f"No Jupyter notebook (.ipynb) files found in {self.context.source_dir}"
            )
            return results

        self.results_dir.mkdir(parents=True, exist_ok=True)
        # An expired entry no longer applies (active_ignore_paths); of the rest,
        # only the entries the operator supplied skip conversion, and
        # --ignore-suppressions lifts them all (ignore_paths_that_skip_scanning).
        ignore_paths = ignore_paths_that_skip_scanning(
            active_ignore_paths(self.context.config.global_settings.ignore_paths),
            ignore_suppressions=self.context.ignore_suppressions,
        )

        for ipynb_file in ipynb_files:
            try:
                skip_item = False
                # Skip directories
                if Path(ipynb_file).is_dir():
                    ASH_LOGGER.debug(f"Skipping directory: {ipynb_file}")
                    skip_item = True
                else:
                    for ignore_path in ignore_paths:
                        rel_path = (
                            Path(ipynb_file)
                            .relative_to(self.context.source_dir)
                            .as_posix()
                        )
                        if ignore_path_matches(rel_path, ignore_path.path):
                            ASH_LOGGER.debug(
                                f"Skipping conversion of ignored path: {ipynb_file} due to global ignore_path '{ignore_path.path}' with reason '{ignore_path.reason}'"
                            )
                            skip_item = True
                            break
                if skip_item:
                    continue

                ASH_LOGGER.debug(f"Converting {ipynb_file} to .py")
                short_ipynb_file = get_shortest_name(ipynb_file)
                normalized_ipynb_file = get_normalized_filename(short_ipynb_file)
                # The converted file is <name>-converted plus the exporter's extension,
                # .py for a Python notebook; see _move_output.
                filename_base = normalized_ipynb_file.replace(".ipynb", "")
                target_base = self.results_dir.joinpath(f"{filename_base}-converted")

                ASH_LOGGER.verbose(
                    f"Converting {ipynb_file} to target_path: {target_base.as_posix()}"
                )

                # Opened under the scanned-tree rule. nbconvert is given a copy made
                # through this handle, never the original path, so it cannot follow a
                # link that replaced the notebook after the check.
                try:
                    notebook_handle = self.open_source_file(ipynb_file)
                except TreeInputRefused as refused:
                    self.record_refused_input(refused)
                    continue

                # The copy is staged as run/notebook.ipynb in a private directory
                # outside the tree, and nbconvert, run in run/, which holds nothing
                # but the copy, writes into a fresh directory under the converter's
                # results directory: the one place a scanner sandbox lets it write.
                self.results_dir.mkdir(parents=True, exist_ok=True)
                with (
                    notebook_handle,
                    tempfile.TemporaryDirectory(prefix="ash-nbconvert-") as staging_dir,
                    tempfile.TemporaryDirectory(
                        prefix=".ash-nbconvert-out-", dir=self.results_dir
                    ) as nbconvert_out,
                ):
                    content = notebook_handle.read()
                    # An input error, not a tool failure: nothing nbconvert
                    # could say about the file would change what the file is,
                    # so it is never launched on one.
                    parsed, problem = _parse_notebook(content)
                    if problem is not None:
                        self.record_failed_input(
                            ipynb_file,
                            f"not a Jupyter notebook: {problem}",
                            kind="input",
                        )
                        continue
                    confinement = self._conversion_scope(Path(staging_dir))
                    run_dir = Path(staging_dir).joinpath("run")
                    run_dir.mkdir()
                    output_dir = Path(nbconvert_out)
                    staged_notebook = run_dir.joinpath(f"{_STAGED_NAME}.ipynb")
                    exporter = self._stage_notebook(content, staged_notebook, parsed)
                    with confinement:
                        self._run_nbconvert(
                            staged_notebook, output_dir, ipynb_file, exporter
                        )
                    converted = self._move_output(output_dir, target_base)

                if converted is None:
                    self._record_failure(
                        ipynb_file, "nbconvert exited 0 but wrote no output"
                    )
                    continue
                results.append(converted)
                ASH_LOGGER.debug(f"Successfully converted {ipynb_file} to {converted}")

            # The scope could not be built, or the backend refused the spawn.
            except SandboxUnavailable as refusal:
                self._refuse_unconfinable(ipynb_file, str(refusal))
            # Every failure is recorded, not only logged: the completeness gate reads
            # failed_inputs, and a notebook that was not converted is coverage lost.
            # nbconvert is launched once, so nothing converts it in another way.
            except subprocess.TimeoutExpired as e:
                self._record_failure(
                    ipynb_file, f"nbconvert did not finish within {e.timeout}s"
                )
            except subprocess.CalledProcessError as e:
                # A run cancelled with the process (an MCP server stop, say)
                # reports no exit code, and "code None" would read as one.
                self._record_failure(
                    ipynb_file,
                    (
                        "nbconvert did not report an exit code"
                        if e.returncode is None
                        else f"nbconvert exited with code {e.returncode}"
                    ),
                )
                if e.stderr:
                    ASH_LOGGER.debug(f"nbconvert stderr: {e.stderr}", extra=NO_MARKUP)
            except _NbconvertNotRun as e:
                self._record_failure(ipynb_file, str(e))
            except Exception as e:
                # The type only: the message of an error raised reading the
                # notebook can quote its content, and a failed input's reason is
                # recorded without the input's content.
                self._record_failure(
                    ipynb_file, f"conversion raised {type(e).__name__}"
                )
                import traceback

                ASH_LOGGER.debug(
                    f"Jupyter conversion error traceback: {traceback.format_exc()}"
                )

        return results
