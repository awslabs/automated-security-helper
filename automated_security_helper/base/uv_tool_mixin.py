"""Mixin providing UV tool management for PluginBase.

All UV-related methods (installation, validation, version detection,
execution) live here.  PluginBase inherits from this mixin so that
every plugin/scanner can call ``self._install_uv_tool()`` etc. without
any change to call sites.

The mixin accesses ``self.command``, ``self.use_uv_tool``,
``self.uv_tool_package_name``, ``self.uv_tool_install_commands``,
``self.context``, ``self.config``, ``self._plugin_log()``,
``self.exit_code``, ``self.output``, and ``self.errors`` -- all of
which are defined on PluginBase.
"""

from __future__ import annotations

import contextvars
import logging
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Tuple,
)

# The scan's own uv run keeps the caller's FORCE_COLOR or CLICOLOR_FORCE, under
# which uv colors its messages even into a pipe -- and a terminal-aware uv can
# also write non-color CSI codes (erase-line, cursor moves) and OSC hyperlinks.
# One escape regex for the package: error_text owns it (shown_tool_stderr and
# shown_uv_output strip the same codes).
from automated_security_helper.utils.error_text import ESCAPE_CODES as _ANSI_ESCAPE
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.subprocess_utils import (
    RESPONSE_FLAGS,
    TIMEOUT_RETURNCODE,
    StartWatch,
    could_not_stop_default,
)

# checking_only is re-exported here, where the scanners' dependency checks live;
# it is defined beside the uv probes it governs.
from automated_security_helper.utils.uv_tool_runner import (
    checking_only,
    is_checking_only,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "GuardedValues",
    "UVToolMixin",
    "checking_only",
    "guarded_values",
    "guarded_values_read",
    "is_checking_only",
]


class GuardedValues(NamedTuple):
    """One guarded read of a plugin's values hook (``guarded_values_read``).

    ``values`` is ``None`` when the hook raised or gave no usable answer.
    ``raised`` names the exception class when it raised, and is ``None``
    otherwise, so a note can tell a raise from an unusable answer.
    """

    values: Optional[Tuple[str, ...]]
    raised: Optional[str]

    def failure(self) -> str:
        """The words a note uses for a failed read: ``raised RuntimeError`` or
        ``returned an unusable answer``. Empty when the read succeeded."""
        if self.values is not None:
            return ""
        if self.raised is not None:
            return f"raised {self.raised}"
        return "returned an unusable answer"


def guarded_values_read(plugin: Any) -> GuardedValues:
    """The ONE guarded read of ``plugin._values_to_redact()``, with why it failed.

    ``values`` is ``None`` when the hook raised or answered something that is
    not a value set (``None``, a number): then no redaction can be done, and
    the caller takes its conservative arm (a value-free note, a skipped
    best-effort line, a refused run). It is ``()`` when there are genuinely
    none, and a bare string or path is ONE value, never its characters
    (``utils.redacted_model.environment_strings``, the normalizer every sink
    reads values through). An iterable is drained here, outside the
    normalizer's own TypeError arm, so one that raises mid-iteration takes the
    guarded path too.

    A function over the plugin rather than a method, so a caller holding only
    the hook (the unbound ``PluginBase`` and mixin methods are also called on
    stand-ins) reads it the same way. ``PluginBase._guarded_values`` is the
    method form.
    """
    from automated_security_helper.utils.redacted_model import environment_strings

    try:
        answered = plugin._values_to_redact()
        if isinstance(answered, (str, os.PathLike)):
            return GuardedValues(environment_strings(answered), None)
        if isinstance(answered, Iterable):
            return GuardedValues(environment_strings(tuple(answered)), None)
    except Exception as hook_error:  # noqa: BLE001 -- an overridable hook
        return GuardedValues(None, type(hook_error).__name__)
    return GuardedValues(None, None)


def guarded_values(plugin: Any) -> Optional[Tuple[str, ...]]:
    """:func:`guarded_values_read`'s values: ``None`` when the hook raised or
    gave no usable answer, ``()`` when there are none."""
    return guarded_values_read(plugin).values


#: Set while the scan phase constructs every registered scanner (see
#: deferred_tool_version_probes).
_DEFER_VERSION_PROBES: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "ash_defer_uv_tool_version_probes", default=False
)


@contextmanager
def deferred_tool_version_probes() -> Iterator[None]:
    """Within the block, ``_get_uv_tool_version`` records its probe and spawns nothing.

    The scan phase constructs every registered scanner, because a scanner's
    selectable name is only known on an instance, and bandit, checkov and semgrep
    probe their version while constructed, with ``uv tool run --from <spec> <tool>
    --version``. uv resolves that spec against the package index when the
    environment is not cached, so a scan of one scanner reached the index for
    scanners it would never run. Constructed inside this block, a scanner keeps
    its probe for ``resolve_deferred_tool_version``, which the scan phase calls
    only for a scanner that was selected. A scanner constructed anywhere else
    (``ash dependencies``, the MCP server, a test) probes at once, as before.
    """
    token = _DEFER_VERSION_PROBES.set(True)
    try:
        yield
    finally:
        _DEFER_VERSION_PROBES.reset(token)


def _uv_unavailable(runner: Any) -> str:
    """Why ``runner``'s last availability check failed: absent uv, or a refusal.

    A sandbox scope that refuses the check says nothing about uv; logging that as
    "UV is not available" sends the operator to install a uv they already have.
    """
    reason = getattr(runner, "unavailable_reason", None)
    text = reason() if callable(reason) else None
    return text if isinstance(text, str) else "UV is not available"


class UVToolMixin:
    """UV tool management methods extracted from PluginBase."""

    # A private attribute of PluginBase: why the last _try_uv_tool_execution
    # could not run the tool through uv, or None.
    _uv_run_failure: Optional[str]

    if TYPE_CHECKING:
        # PluginBase declares it, as a PrivateAttr defaulting to None, which
        # resolve_deferred_tool_version sets again once the probe has run.
        _deferred_tool_version_probe: Optional[tuple[str, Optional[str]]]

        # ScannerPluginBase and ConverterPluginBase declare it, defaulting to
        # None. Typed here only: a real class-level annotation would be read by
        # pydantic as a required field of every plugin model that mixes this in.
        dependency_unavailable_reason: Optional[str]

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def _uv_from_spec(self) -> Optional[str]:
        """The ``--from`` spec this plugin's scan will run under.

        Mirrors the construction in ``UVToolRunner.run_tool``, which builds the
        spec from ``self.command`` plus this plugin's extras and version
        constraint. Returns ``None`` when the scan passes no ``--from`` at all,
        so the probe matches that too.

        Why the probe needs this: ``uv tool run bandit`` and
        ``uv tool run --from 'bandit[sarif,toml]>=1.7.0,<2.0.0' bandit`` resolve
        to different environments. stevedore's entry-point cache is keyed on
        ``sys.executable`` and ``sys.prefix``, so those two invocations warm two
        different cache files -- and a probe that warms the wrong one leaves the
        scan's file cold for N concurrent scanners to race, which is the whole
        problem serializing the probe was meant to remove. Measured directly:
        one workspace scan produced five distinct bandit environments.
        """
        extras = self._get_tool_package_extras()
        constraint = self._get_tool_version_constraint()
        if not extras and not constraint:
            return None
        base = f"{self.command}[{','.join(extras)}]" if extras else self.command
        return f"{base}{constraint}" if constraint else base

    def _uv_run_inputs(self) -> Tuple[str, ...]:
        """The plugin-built requirement strings of this plugin's uv runs: the
        ``--from`` spec (or the bare command) and every ``--with`` dependency.

        ONE builder for every site that hides a RUN's inputs -- the
        pre-dispatch record, the report lines, the offline explainer, the
        verdict lines, the scan-failure excerpt and the sandbox records -- so
        "the same hiding arms" holds by construction: an input hidden on one
        line cannot print on the next because that site assembled a smaller
        set. Records about an INSTALL are the one deliberate exception: the
        installed package (``uv_tool_package_name``) can differ from the
        run's ``--from`` base, so they share their own builder,
        ``uv_tool_runner.uv_install_inputs``, instead of this one.
        """
        return (
            self._uv_from_spec() or self.command,
            *(self._get_tool_with_dependencies() or []),
        )

    def _uv_run_inputs_for_records(self) -> Tuple[str, ...]:
        """``_uv_run_inputs``, best-effort, for a record ABOUT the run.

        The hooks it reads are overridable, and a record must never replace
        the run's own outcome with a hook's error: a raise here used to drop
        a dispatch entirely, or turn a successful run into a post-run error.
        On a raise the record keeps the plain value layer, the same fallback
        ``scanner_sandbox_scope`` uses when it reads these hooks.
        """
        try:
            return tuple(self._uv_run_inputs())
        except Exception:  # noqa: BLE001 -- a raising hook adds nothing
            return ()

    def _get_uv_tool_version(
        self, tool_name: str, package_name: Optional[str] = None
    ) -> Optional[str]:
        """Get version of a tool managed by UV.

        Args:
            tool_name: Name of the tool to get version for
            package_name: ``--from`` spec to probe under. When omitted, defaults
                to :meth:`_uv_from_spec` so the probe shares an environment --
                and therefore an entry-point cache file -- with the scan.

        Returns:
            Version string if detected, None if version cannot be determined or UV is not available
        """
        if package_name is None:
            package_name = self._uv_from_spec()
        if not self.use_uv_tool:
            self._plugin_log(
                f"UV tool execution is disabled for {tool_name}",
                level=logging.DEBUG,
            )
            return None
        if _DEFER_VERSION_PROBES.get():
            # Kept for resolve_deferred_tool_version; see deferred_tool_version_probes.
            self._deferred_tool_version_probe = (tool_name, package_name)
            return None

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            runner = get_uv_tool_runner()

            if not runner.is_uv_available():
                self._plugin_log(
                    f"{_uv_unavailable(runner)} for {tool_name} version detection",
                    level=logging.WARNING,
                )
                return None

            # The carried version is redacted before its first-line cut, so
            # the probe gets the plugin's values; guarded as every read of
            # the overridable hook is (_values_to_redact's guarding rule). The
            # runner memoizes the answer it carries, so a probe run without
            # the values could keep the unredacted text for the process: with
            # no usable values the probe is not run and the version stays
            # unknown.
            read = guarded_values_read(self)
            probe_values = read.values
            if probe_values is None:
                self._plugin_log(
                    f"Could not determine UV tool {tool_name} version: the "
                    f"plugin's values hook {read.failure()}, so the probe was "
                    "not run",
                    level=logging.WARNING,
                )
                return None
            version = runner.get_tool_version(
                tool_name, package_name, values=probe_values
            )
            if version:
                self._plugin_log(
                    f"Detected UV tool {tool_name} version: {version}",
                    level=logging.DEBUG,
                )
            else:
                self._plugin_log(
                    f"Could not determine UV tool {tool_name} version",
                    level=logging.WARNING,
                )
            return version

        except UVToolRunnerError as e:
            # The runner's text can embed the full argv, and an argument can
            # carry a value the plugin's config read from the environment:
            # redacted with the plugin's own values, as the mixin's lines are
            # (the same class as the dispatch and run arms below).
            self._plugin_log(
                text_without_values(
                    f"UV tool runner error getting {tool_name} version: {e}",
                    self._values_to_redact(),
                ),
                level=logging.WARNING,
            )
            return None
        except ImportError as e:
            self._plugin_log(
                text_without_values(
                    f"UV tool runner module not available for {tool_name}: {e}",
                    self._values_to_redact(),
                ),
                level=logging.ERROR,
            )
            return None
        except Exception as e:
            self._plugin_log(
                text_without_values(
                    f"Unexpected error getting UV tool {tool_name} version: {e}",
                    self._values_to_redact(),
                ),
                level=logging.WARNING,
            )
            return None

    def resolve_deferred_tool_version(self) -> None:
        """Run the version probe construction deferred, and record its answer.

        For a scanner the scan phase selected; see deferred_tool_version_probes.
        The scanners that probe at construction assign the probe's answer to
        ``tool_version``, so this does the same. Nothing to do when nothing was
        deferred.
        """
        deferred = self._deferred_tool_version_probe
        if deferred is None:
            return
        self._deferred_tool_version_probe = None
        tool_name, package_name = deferred
        self.tool_version = self._get_uv_tool_version(tool_name, package_name)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _try_uv_tool_execution(
        self,
        command: List[str],
        working_dir: Path,
        results_dir: Optional[Path] = None,
        stdout_preference: str = "write",
        stderr_preference: str = "write",
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        values: Iterable[str] = (),
    ) -> Optional[Dict[str, str]]:
        """Attempt to execute command using UV tool run.

        Args:
            command: Command to execute
            working_dir: Working directory for the command
            results_dir: Directory to write output files to
            stdout_preference: How to handle stdout
            stderr_preference: How to handle stderr
            env: Environment variables for the child process. Passed through
                to the underlying tool runner; when ``None`` the child
                inherits the parent env unchanged.
            values: The scan config's environment values, for the runner's
                timeout text (``UVToolRunner.run_tool``).

        Returns:
            Dictionary with command results when uv ran the tool, or None when it
            could not: uv is not available, or its launch raised before any child
            started. Then ``_uv_run_failure`` says why, for ``_run_subprocess`` to
            report; no other copy of the tool runs in its place.
        """
        self._uv_run_failure = None
        # Whether the uv launch started a child. One that did ran the tool, so a
        # failure after it is ASH's own, answered here as post_run_error.
        launch = StartWatch()
        # The ONE guarded read of the overridable values hook for this call
        # (_values_to_redact's guarding rule): the pre-dispatch record, the
        # run's record-only context and the error arms below all reuse it.
        # Without the values none of those records can be shown safely, and
        # entering the record context with an empty set would print what the
        # values would have hidden, so a raising hook -- the plugin's own
        # failure -- refuses the uv route the way an unavailable uv does:
        # _uv_run_failure says why, and no other copy of the tool runs.
        read = guarded_values_read(self)
        if read.values is None:
            self._uv_run_failure = (
                f"the plugin's values hook {read.failure()}, so the run's "
                "records could not be redacted"
            )
            self._plugin_log(
                f"Not running {self.command} through uv: {self._uv_run_failure}",
                level=logging.WARNING,
            )
            return None
        record_values: Tuple[str, ...] = read.values
        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            uv_runner = get_uv_tool_runner()

            uv_available, probe_failure = uv_runner.uv_availability()
            if not uv_available:
                # The failure of the probe that answered this call, when
                # there was one: "uv is not available" alone reads as "uv is
                # not installed", while the probe may have timed out or been
                # refused by the sandbox. With no failure (uv absent), the
                # plain sentence is the whole truth.
                self._uv_run_failure = (
                    f"uv is not available ({probe_failure})"
                    if probe_failure
                    else "uv is not available"
                )
                self._plugin_log(
                    f"UV is not available, so {self.command} cannot run through uv"
                    + (f": {probe_failure}" if probe_failure else ""),
                    level=logging.WARNING,
                )
                return None

            tool_args = command[1:] if len(command) > 1 else []

            # An argument can carry a value the plugin's config read from the
            # environment, and ash.log is a sink: a uv run's COMMAND-LINE
            # record gets the run's plugin inputs with the full uv layer,
            # like the report lines and the failure excerpt, so a glued or
            # pinned spec hidden there cannot print here. This line is kept
            # (rather than dropped) because it is the only pre-dispatch
            # record when the runner's launch raises before logging.
            from automated_security_helper.utils.uv_tool_runner import (
                shown_uv_output,
            )

            record_inputs = self._uv_run_inputs_for_records()
            self._plugin_log(
                shown_uv_output(
                    f"Executing {self.command} via UV tool run with args: {tool_args}",
                    record_values,
                    plugin_inputs=record_inputs,
                    tool_name=self.command,
                    limit=None,
                ),
                level=logging.DEBUG,
            )

            package_extras = self._get_tool_package_extras()
            version_constraint = self._get_tool_version_constraint()

            # The run's records get the same input set whatever the sandbox
            # mode: under the default "off" there is no sandbox scope, and
            # without this record-only context the process runner's own
            # "Running command:" and "Command stderr:" lines fell back to
            # the plain value layer, printing a glued or pinned spec that
            # every report line hides.
            from automated_security_helper.utils.sandbox.scope import (
                uv_record_inputs,
            )

            # The try covers the launch alone. What raises here before a child
            # started is a uv run that could not start; nothing after the launch
            # is.
            with (
                launch.watching(),
                uv_record_inputs(record_values, record_inputs, self.command),
            ):
                result = uv_runner.run_tool(
                    tool_name=self.command,
                    args=tool_args,
                    cwd=working_dir,
                    capture_output=True,
                    text=True,
                    check=False,
                    package_extras=package_extras,
                    version_constraint=version_constraint,
                    results_dir=results_dir,
                    stdout_preference=stdout_preference,
                    stderr_preference=stderr_preference,
                    class_name=self.__class__.__name__,
                    env=env,
                    timeout=timeout,
                    values=values,
                )

        except UVToolRunnerError as e:
            # The runner's own verdict, taken as it is: a failure after its
            # launch's start is RETURNED as a result (an after-the-start
            # response, a timeout), never raised, so this raise is a uv run
            # that could not start. The watch is not consulted here, because
            # the runner has already adjudicated; the arms below consult it
            # for raises that bypass that adjudication, and it answers only
            # for the launch's own spawn (the runner's watched_launch scope),
            # never for a helper probe or an install.
            self._uv_run_failure = str(e)
            # The runner's spawn and timeout texts quote the full argv, and an
            # argument can carry a value the plugin's config read from the
            # environment: the log line is redacted with the method's one
            # guarded read of the plugin's values. _uv_run_failure keeps the
            # raw text for the refused record, whose printers redact with the
            # run's values.
            self._plugin_log(
                text_without_values(
                    f"UV tool runner error for {self.command}: {e}",
                    record_values,
                ),
                level=logging.WARNING,
            )
            return None
        except ImportError as e:
            after = self._uv_failure_after_the_start(
                launch, e, stdout_preference, record_values=record_values
            )
            if after is not None:
                return after
            self._uv_run_failure = f"the uv tool runner could not be imported: {e}"
            # Redacted like the runner-error arm above: the raise can quote the
            # full argv, and an argument can carry an env-read value.
            self._plugin_log(
                text_without_values(
                    f"UV tool runner module not available: {e}",
                    record_values,
                ),
                level=logging.WARNING,
            )
            return None
        except Exception as e:
            after = self._uv_failure_after_the_start(
                launch, e, stdout_preference, record_values=record_values
            )
            if after is not None:
                return after
            self._uv_run_failure = f"{type(e).__name__}: {e}"
            self._plugin_log(
                text_without_values(
                    f"Unexpected error during UV tool execution for {self.command}: {e}",
                    record_values,
                ),
                level=logging.WARNING,
            )
            # The traceback is formatted and redacted, as the plugin loader
            # logs its import failures: exc_info would append the exception's
            # own text raw under the redacted message.
            if ASH_LOGGER.isEnabledFor(logging.DEBUG):
                import traceback

                ASH_LOGGER.debug(
                    text_without_values(
                        "UV tool execution error details (redacted):\n"
                        + "".join(traceback.format_exception(e)),
                        record_values,
                    ),
                    extra=NO_MARKUP,
                )
            return None

        return self._uv_response(result, results_dir)

    def _uv_failure_after_the_start(
        self,
        launch: StartWatch,
        error: BaseException,
        stdout_preference: str = "write",
        *,
        record_values: Tuple[str, ...],
    ) -> Optional[Dict[str, Any]]:
        """The response for ``error`` from a uv launch that started its child, or
        None when it started none: a uv run that could not start.

        The uv runner raised after its child started: the tool ran, so this is
        post_run_error with the child's own exit code, never a second run.
        ``stdout_preference`` is the call's own, passed through so the response
        carries the stdout body only when the preference returns it, the bound
        the runner's completed responses honor. ``record_values`` is the
        caller's one guarded read of the plugin's values, taken as a parameter
        rather than read from the hook again (_values_to_redact's guarding
        rule), so two reads cannot disagree.
        """
        after = launch.failure_after_the_start(
            error, stdout_preference=stdout_preference
        )
        if after is not None and ASH_LOGGER.isEnabledFor(logging.DEBUG):
            # Redacted like the arms above: the wait's failure can quote the
            # argv, and an argument can carry an env-read value. The traceback
            # is formatted and redacted too; exc_info would append the
            # exception's own text raw under the redacted message.
            import traceback

            ASH_LOGGER.debug(
                text_without_values(
                    f"UV tool run failed after its child started: {error}\n"
                    + "".join(traceback.format_exception(error)),
                    record_values,
                ),
                extra=NO_MARKUP,
            )
        return after

    def _uv_response(self, result: Any, results_dir: Optional[Path]) -> Dict[str, Any]:
        """The response for a uv run that returned, handled once.

        Every flag the result carries is copied, with its error: scan() and
        _run_subprocess grade the scan by it, whatever exit codes the scanner
        accepts. When handling the response raises, the response already
        assembled is kept, with its flag, code and reason, and the error is added
        to the reason; post_run_error is added only to a response with no flag.
        Nothing here falls back to direct execution.
        """
        response: Optional[Dict[str, Any]] = None
        try:
            response = {
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "returncode": result.returncode,
            }
            for flag in RESPONSE_FLAGS:
                if getattr(result, flag, False) is True:
                    response[flag] = True
            # The recorded could-not-stop state, carried as its own key: the
            # response's error is prose and is never read back for the fact. The
            # pid the reason names rides beside it as data.
            if getattr(result, "could_not_stop", False) is True:
                response["could_not_stop"] = True
                pid = getattr(result, "could_not_stop_pid", None)
                if isinstance(pid, int) and not isinstance(pid, bool):
                    response["could_not_stop_pid"] = pid
            if response.get("signaled"):
                response["signal"] = getattr(result, "signal", None)
            if response.get("post_run_error"):
                # A run whose output ASH could not record: its error is ASH's.
                response["spawn_failed"] = False
                response["error"] = str(getattr(result, "error", "") or "")
            elif any(response.get(flag) for flag in RESPONSE_FLAGS):
                # Its error, as the run_command path's response gives it, or
                # failing that the reason stderr holds.
                response["error"] = str(
                    getattr(result, "error", "") or response["stderr"] or ""
                )

            # The report lines compute the uv run's plugin-built inputs from
            # the plugin's own hooks (PluginBase._process_command_response
            # reads them when use_uv_tool is set), so they get the SAME
            # hiding arms as the offline explainer and the pre-dispatch
            # record. Computed, not carried: an attribute set around this
            # call was per-instance mutable state, and two concurrent
            # responses on one instance had one finally-clear erase the
            # other's inputs mid-call, weakening its redaction. The seam
            # stays the documented one-argument signature.
            self._process_command_response(response)
            self._explain_offline_resolve_failure(response, results_dir)

            self._plugin_log(
                f"UV tool execution completed for {self.command} with exit code {response['returncode']}",
                level=logging.DEBUG,
            )

            return response

        except Exception as e:
            # As at the mixin's other sites: the message and the traceback it
            # carries can quote a path with an env-read value, so both pass
            # through the plugin's redaction instead of exc_info's raw print.
            if ASH_LOGGER.isEnabledFor(logging.DEBUG):
                import traceback

                ASH_LOGGER.debug(
                    text_without_values(
                        "UV tool response error details (redacted):\n"
                        + "".join(traceback.format_exception(e)),
                        self._values_to_redact(),
                    ),
                    extra=NO_MARKUP,
                )
            if response is not None:
                failed: Dict[str, Any] = dict(response)
            else:
                # Building the response raised: every field is read on its own,
                # so one unreadable field does not drop the others, and the
                # flags the result carries still grade the scan. A timed-out,
                # cancelled, rejected or signaled run keeps that flag, its code
                # and its reason; it is never turned into post_run_error below.
                failed = {"stdout": "", "stderr": "", "returncode": None}
                for field in ("stdout", "stderr"):
                    try:
                        failed[field] = getattr(result, field, "") or ""
                    except Exception:
                        pass
                try:
                    failed["returncode"] = getattr(result, "returncode", None)
                except Exception:
                    pass
                for flag in RESPONSE_FLAGS:
                    try:
                        if getattr(result, flag, False) is True:
                            failed[flag] = True
                    except Exception:
                        pass
                # Whether the result's could-not-stop state could be read at
                # all. A read that raises leaves it UNKNOWN, which is not the
                # same as False: the fallback below answers 124 only for a
                # stop that is known to have worked, because 124 says ASH
                # stopped the tool, and that is never claimed blind.
                could_not_stop_readable = True
                try:
                    if getattr(result, "could_not_stop", False) is True:
                        failed["could_not_stop"] = True
                except Exception:
                    could_not_stop_readable = False
                try:
                    pid = getattr(result, "could_not_stop_pid", None)
                    if isinstance(pid, int) and not isinstance(pid, bool):
                        failed["could_not_stop_pid"] = pid
                except Exception:
                    pass
                if failed.get("signaled"):
                    try:
                        failed["signal"] = getattr(result, "signal", None)
                    except Exception:
                        failed["signal"] = None
                if any(failed.get(flag) is True for flag in RESPONSE_FLAGS):
                    try:
                        failed["error"] = str(
                            getattr(result, "error", "") or failed["stderr"] or ""
                        )
                    except Exception:
                        pass
                if (
                    failed.get("timed_out") is True
                    and failed["returncode"] is None
                    and could_not_stop_readable
                    and failed.get("could_not_stop") is not True
                ):
                    # ASH stopped this tool at the limit, so its code is the
                    # timeout's own: no code is only for a run that failed after
                    # the start or a child ASH could not stop. The latter is the
                    # result's recorded could_not_stop state, copied above; the
                    # reason's text is never read for it, so a tool quoting the
                    # words keeps its 124, and a reason that could not be read
                    # drops no real could-not-stop.
                    failed["returncode"] = TIMEOUT_RETURNCODE
            earlier = failed.get("error")
            if failed.get("could_not_stop") is True:
                try:
                    readable = bool(earlier) and bool(str(earlier))
                except Exception:
                    readable = False
                if not readable:
                    # The response's own reason is empty or could not be read,
                    # and the recorded state says the stop failed. The reason
                    # leads with that fact, and the pid carried as data, before
                    # the handling error below: what the operator acts on is
                    # never lost to text that happened to be unreadable. The
                    # shared marker is written here, never parsed.
                    earlier = could_not_stop_default(failed.get("could_not_stop_pid"))
            failed["error"] = (
                f"{earlier}; {error_text(e)}" if earlier else error_text(e)
            )
            if not any(failed.get(flag) is True for flag in RESPONSE_FLAGS):
                failed["post_run_error"] = True
                failed["spawn_failed"] = False
            return failed

    def _explain_offline_resolve_failure(
        self, response: Dict[str, Any], results_dir: Optional[Path]
    ) -> None:
        """Put the cause first when ``uv tool run --offline`` could not resolve.

        uv exits 1 for a resolve failure, which bandit also uses for "found
        issues", so the scan carries on, finds no results file, and used to
        report ``[Errno 2] No such file or directory`` followed by uv's resolver
        text (#520). This prepends a message naming the requirement and what to
        do. It changes no control flow; ``_select_tool_execution`` is where a
        usable binary on PATH is chosen instead.
        """
        if not self._is_offline_mode() or response.get("returncode", 0) == 0:
            return
        stderr = response.get("stderr") or ""
        log_path: Optional[Path] = None
        read_cut = False
        # The ONE guarded read of the overridable values hook for this
        # explainer (_values_to_redact's guarding rule): the bounded read's
        # trim and the shown lines below reuse it. The explainer is
        # cause-first, best-effort text: a raising hook skips it and leaves
        # the scan's real error alone, because without the values nothing
        # below can be shown.
        values = guarded_values(self)
        if values is None:
            return
        if not stderr and results_dir is not None:
            log_path = Path(results_dir) / f"{self.__class__.__name__}.stderr.log"
            try:
                from automated_security_helper.base.plugin_base import (
                    read_log_bounded,
                )

                # The one bounded read (plugin_base.read_log_bounded): the
                # message keeps 800 characters, so reading megabytes buys
                # nothing; one byte past the bound is read so an overflow is
                # KNOWN; and a cut tail is TRIMMED, because a value split at
                # the read's edge survives whole-spelling redaction -- a log
                # that is mostly escape codes strips to under the kept head,
                # which put the edge's live piece INSIDE the kept text. This
                # explainer is best-effort cause-first text: an unreadable
                # log skips it and leaves the scan's real error alone.
                # The run's inputs join the trim: the shower hides them
                # whole, so a cut just after a glued extra's value is the
                # same edge piece a value split leaves.
                stderr, read_cut = read_log_bounded(
                    log_path, 800 * 32, values, self._uv_run_inputs_for_records()
                )
            except Exception:  # noqa: BLE001 -- reading the log is best-effort
                return
        # Quoted below as text, so without the escape codes: they would be
        # shown as escapes on a terminal and written into the reports. The
        # full CSI set, the SAME codes the shown layers strip -- a non-color
        # code (an erase-line \x1b[K) inside the phrase otherwise defeats the
        # cause match below while the quoted text beside it strips clean.
        stderr = _ANSI_ESCAPE.sub("", stderr)
        # uv wraps the message at the scan's COLUMNS, so it is matched with every
        # run of whitespace as one space.
        if "No solution found when resolving" not in " ".join(stderr.split()):
            # The excerpt's read keeps only what the message can show, and
            # the resolver's error can come after more earlier output than
            # that bound: the cause match then consults the log itself, with
            # a reader that returns a verdict and never text (log_says). The
            # message still quotes the bounded excerpt and names the log.
            if not read_cut or log_path is None:
                return
            from automated_security_helper.base.plugin_base import log_says

            try:
                if not log_says(log_path, "No solution found when resolving"):
                    return
            except Exception:  # noqa: BLE001 -- reading the log is best-effort
                return
        requirement = self._uv_from_spec() or self.command
        # The --from spec is plugin-built and uv's stderr quotes the
        # requirement back, so both can hold a value this plugin's config read
        # from the environment, and this message goes to ``errors`` (reports)
        # and an ERROR log: the same redaction as the install's debug line,
        # with the spec as the plugin-built input. With nothing env-read in
        # the plugin's values, the text is unchanged. REDACTED BEFORE the
        # excerpt is cut: slicing first could cut inside the quoted
        # requirement and leave a live value fragment at a cut edge, the
        # piece shape the redaction's rules show. The cut keeps BOTH ends --
        # uv's error line leads its stderr and its closing "hint:" lines are
        # often the most specific thing it says -- around a counting marker,
        # and the composed message bounds itself here (limit=None), so the
        # shared helper's tail-keep can never cost this message its
        # actionable head. The 800 kept characters are a readability budget
        # for the message's CONTENT: the log sink's display escaping can
        # expand control and markup characters severalfold, so the rendered
        # record can run longer; bounding after escaping would couple this
        # composer to the sink's escaping rules, and the record stays bounded
        # by a small multiple either way.
        from automated_security_helper.utils.uv_tool_runner import shown_uv_output

        # The run's WHOLE input set, not just the --from spec: a --with
        # dependency holding a glued or pinned value is quoted back by uv's
        # resolver text too, and a smaller set here would print on this line
        # what the report lines beside it hide. One set also keeps the
        # placeholder numbering consistent across the two lines.
        inputs = self._uv_run_inputs_for_records()
        shown_requirement = shown_uv_output(
            repr(requirement),
            values,
            plugin_inputs=inputs,
            tool_name=self.command,
            limit=None,
        )
        # Stripped only AFTER the redaction: a whole-text strip first eats
        # the last character of a value ending the resolver's text (a form
        # feed, say), and the fragment then misses the whole-spelling match.
        said = shown_uv_output(
            stderr,
            values,
            plugin_inputs=inputs,
            tool_name=self.command,
            limit=None,
        ).strip()
        head_keep, tail_keep = 500, 300
        if read_cut and log_path is not None:
            # The read stopped before the log's end, so the text's last bytes
            # are the READ's cut, not uv's closing hint lines: a tail-keep
            # would present a mid-file fragment as the conclusion, the cut
            # can split a value or a multibyte character right there, and a
            # dropped-characters count could not include the unread bytes.
            # Head only, with the log named for the rest.
            said = (
                f"{said[:head_keep]}... (the log continues beyond this "
                f"excerpt; see {log_path.as_posix()})"
            )
        elif len(said) > head_keep + tail_keep:
            dropped = len(said) - head_keep - tail_keep
            said = (
                f"{said[:head_keep]}... ({dropped} more characters not shown) "
                f"...{said[-tail_keep:]}"
            )
        message = (
            f"Offline mode: uv could not resolve {shown_requirement} from its local "
            f"cache, so {self.command} never ran. uv only finds tools installed "
            f"under its current tool directory (`uv tool dir`); a different $HOME "
            f"or UV_TOOL_DIR than at install time hides them. Install "
            f"{shown_requirement} where uv can see it, or put a {self.command} that "
            f"satisfies it on PATH. uv said: {said}"
        )
        # The COMPOSED message is redacted whole: the clause naming the log on
        # an overflowing read and the command interpolations are added after
        # the piecewise redaction above, and the results directory in the
        # named log path can sit under an env-read output path. The pieces
        # already redacted are unchanged by a second pass.
        message = text_without_values(message, values)
        self.errors.insert(0, message)
        self._plugin_log(message, level=logging.ERROR)

    # ------------------------------------------------------------------
    # Availability / validation
    # ------------------------------------------------------------------

    def _validate_uv_tool_availability(self) -> bool:
        """Validate that UV tool execution is available when required.

        Returns:
            True if UV tool is available or not required, False if required but unavailable
        """
        if not self.use_uv_tool:
            return True

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            runner = get_uv_tool_runner()
            is_available = runner.is_uv_available()

            if not is_available:
                self._plugin_log(
                    f"UV tool execution is required for {self.command}, but: "
                    f"{_uv_unavailable(runner)}",
                    level=logging.WARNING,
                )
                return False

            self._plugin_log(
                f"UV tool execution validated for {self.command}",
                level=logging.DEBUG,
            )
            return True

        except UVToolRunnerError as e:
            # Same class as the run arm: the runner's text can quote argv.
            self._plugin_log(
                text_without_values(
                    f"UV tool runner error during validation: {e}",
                    self._values_to_redact(),
                ),
                level=logging.WARNING,
            )
            return False
        except ImportError as e:
            self._plugin_log(
                text_without_values(
                    f"UV tool runner module not available during validation: {e}",
                    self._values_to_redact(),
                ),
                level=logging.ERROR,
            )
            return False
        except Exception as e:
            self._plugin_log(
                text_without_values(
                    f"Unexpected error during UV tool validation: {e}",
                    self._values_to_redact(),
                ),
                level=logging.WARNING,
            )
            return False

    def _validate_tool_availability_with_pre_installed(self) -> Dict[str, Any]:
        """Validate tool availability including pre-installed tools.

        Returns:
            Dictionary containing validation results and tool information
        """
        validation_result = {
            "available": False,
            "validation_method": "none",
            "installation_info": {},
            "errors": [],
            "warnings": [],
        }

        if not self.command:
            validation_result["errors"].append("No command specified for scanner")
            return validation_result

        installation_info = self._get_tool_installation_info()
        validation_result["installation_info"] = installation_info

        if installation_info["available"]:
            validation_result["available"] = True
            validation_result["validation_method"] = installation_info[
                "preferred_source"
            ]

            if installation_info["preferred_source"] == "uv":
                self._plugin_log(
                    f"Tool {self.command} validated via UV tool (version: {installation_info.get('uv_version', 'unknown')})",
                    level=15,
                )
            elif installation_info["preferred_source"] == "pre_installed":
                self._plugin_log(
                    f"Tool {self.command} validated via pre-installed executable "
                    f"(version: {installation_info.get('pre_installed_version', 'unknown')}, "
                    f"path: {installation_info.get('pre_installed_path', 'unknown')})",
                    level=15,
                )
                validation_result["warnings"].append(
                    f"Using pre-installed {self.command} instead of UV-managed version. "
                    f"Consider installing via UV for better dependency isolation."
                )

            return validation_result

        if self.use_uv_tool and self._should_install_tool(prefer_cached=True):
            self._plugin_log(
                f"Tool {self.command} not available, attempting UV installation",
                level=15,
            )

            if self._install_uv_tool():
                updated_info = self._get_tool_installation_info()
                validation_result["installation_info"] = updated_info

                if updated_info["available"]:
                    validation_result["available"] = True
                    validation_result["validation_method"] = "uv_installed"
                    self._plugin_log(
                        f"Tool {self.command} successfully installed and validated via UV",
                        level=15,
                    )
                else:
                    validation_result["errors"].append(
                        f"Tool {self.command} installation appeared to succeed but tool is still not available"
                    )
            else:
                validation_result["errors"].append(
                    f"Failed to install tool {self.command} via UV"
                )
        else:
            validation_result["errors"].append(
                f"Tool {self.command} is not available and cannot be installed"
            )

        return validation_result

    def _select_tool_execution(self, installation_info: Dict[str, Any]) -> bool:
        """Decide how an available tool runs, and whether it can run at all.

        Called by the uv-backed scanners once ``_get_tool_installation_info``
        reports the tool available. Returns the dependency verdict and sets
        ``use_uv_tool`` and ``dependencies_satisfied`` to match.

        Before this existed, the "pre_installed" branch logged "Using
        pre-installed <tool> at <path>" and left ``use_uv_tool`` True, so the
        scan still went through ``uv tool run --from <requirement>``. Offline,
        that resolve has only uv's cache to work from, and a cache that does not
        hold the tool fails the scan with uv's resolver output as the error
        (#520), while the binary on PATH goes unused.

        Rules, in order:

        * Online with the tool visible to ``uv tool list``: unchanged, run via uv.
        * Otherwise, if an executable on PATH is verified to satisfy the scan's
          requirement (extras and version constraint included, see
          ``utils/pre_installed_tool.py``), run it directly. Offline this
          applies to a uv-installed tool too: ``uv tool run --offline`` can only
          reuse an environment that is already there, and a configured
          ``tool_version`` the installed tool does not match fails the same way.
        * A tool uv cannot see, verified NOT to satisfy it: offline, the
          dependency is unsatisfied and ``dependency_unavailable_reason`` says
          what is missing. Online, keep uv, which can resolve the missing pieces.
          Offline, a tool from the Nix store that cannot be verified at all is
          treated the same way: ``--mode nix`` promises the pinned tool, and the
          uv fallback would run an unpinned one or fail on an uncached wheel.
        * Anything else (not verifiable, or a uv-visible tool whose PATH
          executable does not verify): keep uv, the previous behavior, rather
          than guess. If that resolve then fails offline,
          ``_explain_offline_resolve_failure`` names the cause.
        """
        from automated_security_helper.utils.pre_installed_tool import (
            build_requirement,
            verify_pre_installed_tool,
        )
        from automated_security_helper.utils.uv_tool_runner import (
            find_executable,
            find_uv_or_none,
        )

        source = installation_info.get("preferred_source")
        offline = self._is_offline_mode()

        if source == "uv" and not offline:
            self._plugin_log(
                f"{self.command} already installed via UV tool", level=logging.INFO
            )
            self.dependencies_satisfied = True
            return True

        executable = installation_info.get("pre_installed_path") or find_executable(
            self.command
        )
        if executable is None:
            # Only reachable for source == "uv" offline with nothing on PATH.
            self._plugin_log(
                f"{self.command} already installed via UV tool", level=logging.INFO
            )
            self.dependencies_satisfied = True
            return True

        extras = self._get_tool_package_extras()
        constraint = self._get_tool_version_constraint()
        requirement = build_requirement(self.command, extras, constraint)
        # The values hook is read ONCE for the verify and every record below:
        # it is overridable, and two reads can disagree with each other.
        values = self._values_to_redact()
        verdict = verify_pre_installed_tool(
            executable,
            self.command,
            extras,
            constraint,
            uv_executable=find_uv_or_none(),
            values=values,
        )

        # The requirement is plugin-built and the verdict's detail quotes it
        # back, so both can hold a value this plugin's config read from the
        # environment; these lines reach the log and (below) the reports via
        # dependency_unavailable_reason. Same redaction as the offline
        # resolver message; with nothing env-read, the text is unchanged.
        from automated_security_helper.utils.uv_tool_runner import shown_uv_output

        def _shown(text: str) -> str:
            return shown_uv_output(
                text,
                values,
                plugin_inputs=self._uv_run_inputs_for_records(),
                tool_name=self.command,
                limit=None,
            )

        if verdict.status == "satisfied":
            self._plugin_log(
                _shown(
                    f"Using pre-installed {self.command} at {executable} directly; "
                    f"it satisfies {requirement!r}"
                ),
                level=logging.INFO,
            )
            self.use_uv_tool = False
            self.dependencies_satisfied = True
            return True

        # A tool from the Nix store is the pinned one `--mode nix` exists to run.
        # Falling back to `uv tool run --offline` would run whatever PyPI build
        # uv's cache happens to hold, or fail on the first wheel it lacks, so a
        # Nix tool that cannot be verified is as unusable offline as one that
        # verifiably falls short.
        from_nix = verdict.from_nix or os.path.realpath(executable).startswith(
            "/nix/store/"
        )

        # Only for a tool uv cannot see. When uv can, the executable on PATH may
        # be a different install than uv's, so failing it says nothing about
        # whether `uv tool run --offline` will work.
        if (
            offline
            and source == "pre_installed"
            and (
                verdict.status == "unsatisfied"
                or (verdict.status == "unverifiable" and from_nix)
            )
        ):
            if from_nix:
                remedy = (
                    "It comes from the Nix flake, so ASH will not substitute a uv "
                    "install for it. Pin a build in flake.nix that satisfies "
                    f"{requirement!r}, or set this scanner's tool_version to the "
                    "version the flake provides."
                )
            else:
                remedy = (
                    "uv cannot fetch what is missing while offline. Install it "
                    f"before going offline, e.g. `uv tool install '{requirement}'`, "
                    "or rebuild the image with `ash build-image --offline`."
                )
            cannot = (
                "cannot be used"
                if verdict.status == "unsatisfied"
                else "could not be verified"
            )
            reason = _shown(
                f"Offline mode: {self.command} at {executable} {cannot}: "
                f"{verdict.detail}. {remedy}"
            )
            self.dependency_unavailable_reason = reason
            self._plugin_log(reason, level=logging.ERROR)
            self.dependencies_satisfied = False
            return False

        if source == "uv":
            self._plugin_log(
                f"{self.command} already installed via UV tool", level=logging.INFO
            )
        else:
            self._plugin_log(
                _shown(
                    f"Using pre-installed {self.command} at {executable} through uv, "
                    f"not directly: {verdict.detail}"
                ),
                level=logging.WARNING
                if verdict.status == "unsatisfied"
                else logging.INFO,
            )
        self.dependencies_satisfied = True
        return True

    # ------------------------------------------------------------------
    # Installation setup
    # ------------------------------------------------------------------

    def _environment_values(self) -> Tuple[str, ...]:
        """The values the scan's config read from the environment, to redact.

        A plugin's own log line that names a configured option can carry one,
        and ash.log is a sink; ``utils.error_text.text_without_values`` takes
        these. Empty for a plugin with no context or a config that read none.
        The hook a plugin overrides to add the values it knows; the base
        classes' lines redact with :meth:`_values_to_redact`, which adds the
        config's to whatever this gives. Here rather than on PluginBase, which
        inherits this mixin, so the mixin's own lines can use it.
        """
        from automated_security_helper.utils.error_text import (
            config_environment_values,
        )

        return config_environment_values(
            getattr(getattr(self, "context", None), "config", None)
        )

    def _values_to_redact(self) -> Tuple[str, ...]:
        """The values every line of this plugin's own is redacted with: the
        scan config's, then this plugin's ``_environment_values()``
        (``utils.error_text.plugin_environment_values``).

        ``_environment_values()`` is the hook a plugin overrides to add the
        values it knows. One that gives fewer than the config read drops none
        of the config's from these, and one that raises adds nothing. The base
        classes redact with these, never with the hook alone.

        Guarding rule, ONE for every caller: this method itself is
        overridable, so a caller treats it as a hook that can raise. A call
        on a RECORD or best-effort path -- a log line, a carried excerpt, the
        offline explainer -- reads it once, guarded, and on a raise degrades
        to a value-free note or skips the best-effort text (never to an empty
        value set, which would print what the values would have hidden). A
        call on the run's OWN path -- building the spec, preparing a tool's
        environment -- stays bare, because a raise there is the plugin's own
        failure and must surface as one. A helper below a guarded read takes
        the values as a parameter rather than reading the hook again
        (_carry_stderr_log), so two reads cannot disagree. The guarded read is
        :meth:`_guarded_values`: ``None`` when the hook raised or gave no
        usable answer, and a bare string is one value.
        """
        from automated_security_helper.utils.error_text import (
            config_environment_values,
            plugin_environment_values,
        )

        return plugin_environment_values(
            self,
            config_environment_values(
                getattr(getattr(self, "context", None), "config", None)
            ),
        )

    def _guarded_values(self) -> Optional[Tuple[str, ...]]:
        """The values of :func:`guarded_values_read`: ``None`` when the hook
        raised or gave no usable answer, ``()`` when there are none."""
        return guarded_values_read(self).values

    def _setup_uv_tool_install_commands(self) -> None:
        """Set up UV tool install commands with version constraints and offline mode support.

        This method should be called during scanner initialization to prepare
        the installation commands based on the scanner's configuration.
        """
        if not self.use_uv_tool or not self.command:
            return

        version_constraint = self._get_tool_version_constraint()
        package_extras = self._get_tool_package_extras()

        tool_name = self.uv_tool_package_name or self.command

        from automated_security_helper.utils.uv_tool_runner import (
            UVToolRunnerError,
            checked_requirement,
            shown_uv_output,
            uv_install_inputs,
        )

        # The values hook is overridable and is read ONCE for both of this
        # method's log lines, as _run_uv_tool's one guarded read serves its
        # whole run: two reads can disagree with each other, and this method
        # runs at plugin construction, so a raising hook must not crash the
        # scanner for the sake of a log line. When it raises, the lines that
        # would carry the spec are replaced by a note naming the failure; the
        # stored command is unaffected, and the run path's own guarded read
        # refuses the uv route with the same reason before anything runs.
        read = guarded_values_read(self)
        values: Tuple[str, ...] = read.values or ()
        values_note: Optional[str] = (
            None
            if read.values is not None
            else f"the plugin's values hook {read.failure()}, so this line is not shown"
        )

        # The same builder the install and its records use, so the stored
        # command, the installation-attempt record and this method's own
        # debug line cannot drift apart (a hand-built spec here printed a
        # short pin and a glued extra in clear through the plain layer), and
        # with the tool's extra dependencies included, so every record of one
        # install numbers its hidden arguments from the same input set.
        install_inputs = uv_install_inputs(
            tool_name,
            version_constraint=version_constraint,
            package_extras=package_extras,
            with_dependencies=self._get_tool_with_dependencies(),
        )
        tool_spec = install_inputs.spec

        try:
            checked_requirement(tool_spec, "the tool spec")
        except UVToolRunnerError as error:
            self.uv_tool_install_commands = []
            # The refusal's text carries no part of the spec, and the tool is
            # named from this plugin's own fields. The redaction of the
            # plugin's values stays as a second guard on the same line, since
            # ash.log is a sink and the command line below holds the real
            # spec; the stored command keeps it, only what is logged is bare.
            if values_note is not None:
                self._plugin_log(
                    f"{tool_name}: the tool spec was refused; {values_note}",
                    level=logging.WARNING,
                )
            else:
                self._plugin_log(
                    text_without_values(f"{tool_name}: {error}", values),
                    level=logging.WARNING,
                )
            return

        install_cmd_str = f"uv tool install {tool_spec}"
        self.uv_tool_install_commands = [install_cmd_str]

        if values_note is not None:
            self._plugin_log(
                f"{tool_name}: set up the UV tool install command; {values_note}",
                f"Offline mode: {self._is_offline_mode()}",
                level=logging.DEBUG,
            )
        else:
            self._plugin_log(
                shown_uv_output(
                    f"Set up UV tool install command: {install_cmd_str}",
                    values,
                    plugin_inputs=install_inputs.inputs,
                    tool_name=tool_name,
                    limit=None,
                ),
                f"Offline mode: {self._is_offline_mode()}",
                level=logging.DEBUG,
            )

    # ------------------------------------------------------------------
    # Offline mode
    # ------------------------------------------------------------------

    def _is_offline_mode(self) -> bool:
        """Check if ASH is running in offline mode.

        Returns:
            True if offline mode is enabled, False otherwise
        """
        from automated_security_helper.core.constants import is_offline_mode

        return is_offline_mode()

    # ------------------------------------------------------------------
    # Installation
    # ------------------------------------------------------------------

    def _install_uv_tool(
        self, timeout: int = 300, retry_config: Optional[Dict] = None
    ) -> bool:
        """Execute UV tool installation commands with comprehensive logging and retry logic.

        Args:
            timeout: Timeout in seconds for installation (default: 300)
            retry_config: Optional retry configuration dict with keys:
                - max_retries: Maximum number of retry attempts (default: 3)
                - base_delay: Base delay for exponential backoff (default: 1.0)
                - max_delay: Maximum delay between retries (default: 60.0)

        Returns:
            True if installation succeeded, False otherwise
        """
        installation_start_time = time.time()
        installation_start_datetime = datetime.now(timezone.utc)

        # retry_config comes from the caller and a plugin can build it from
        # its config, so the dict's values are redacted like every other
        # record (ash.log is a sink) -- here and on the [INSTALLATION_CONFIG]
        # line below. The hook is overridable and this is the method's ONE
        # read of it (_values_to_redact's guarding rule): every record line
        # and error arm below reuses record_values, so a raising hook loses
        # the record texts, never the install.
        record_values: Optional[Tuple[str, ...]] = guarded_values(self)
        retry_shown = (
            text_without_values(str(retry_config), record_values)
            if record_values is not None
            else "(not shown)"
        )
        self._plugin_log(
            f"[INSTALLATION_START] Initiating UV tool installation for '{self.command}'",
            f"Installation parameters: timeout={timeout}s, retry_config={retry_shown}",
            f"Start time: {installation_start_datetime.isoformat()}",
            level=15,
        )

        if not self.use_uv_tool or not self.command:
            self._plugin_log(
                f"[INSTALLATION_SKIP] UV tool installation not applicable for scanner '{self.__class__.__name__}'",
                f"Reason: use_uv_tool={self.use_uv_tool}, command={self.command}",
                level=logging.DEBUG,
            )
            return False

        if self._is_offline_mode():
            self._plugin_log(
                "[INSTALLATION_SKIP] Offline mode detected (ASH_OFFLINE=true)",
                f"Skipping UV tool installation for '{self.command}' and relying on pre-installed tools",
                "Fallback strategy: Will attempt to use pre-installed version if available",
                level=15,
            )
            return False

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRetryConfig,
                UVToolRunnerError,
            )

            runner = get_uv_tool_runner()

            uv_check_start = time.time()
            uv_available = runner.is_uv_available()
            uv_check_time = time.time() - uv_check_start

            if not uv_available:
                self._plugin_log(
                    f"[INSTALLATION_FAILED] {_uv_unavailable(runner)} for tool "
                    "installation",
                    f"UV availability check took {uv_check_time:.3f}s",
                    "Fallback strategy: Scanner will attempt direct tool execution",
                    level=logging.WARNING,
                )
                return False

            self._plugin_log(
                f"[INSTALLATION_PROGRESS] UV availability confirmed in {uv_check_time:.3f}s",
                level=logging.DEBUG,
            )

            cache_info = runner.get_cache_info()
            if cache_info.get("cache_available"):
                self._plugin_log(
                    "[INSTALLATION_CACHE] UV cache is available and functional",
                    f"Cache details: {cache_info.get('details', 'No details available')}",
                    level=logging.DEBUG,
                )
            else:
                self._plugin_log(
                    "[INSTALLATION_CACHE] UV cache not available or has issues",
                    f"Cache error: {cache_info.get('error', 'Unknown')}",
                    level=logging.DEBUG,
                )

            if retry_config:
                config = UVToolRetryConfig(
                    max_retries=retry_config.get("max_retries", 3),
                    base_delay=retry_config.get("base_delay", 1.0),
                    max_delay=retry_config.get("max_delay", 60.0),
                    exponential_base=retry_config.get("exponential_base", 2.0),
                    jitter=retry_config.get("jitter", True),
                    network_check_timeout=retry_config.get(
                        "network_check_timeout", 5.0
                    ),
                )
                # The same dict's values as the [INSTALLATION_START] line, so
                # the same redaction and the same raising-hook fallback.
                config_detail = (
                    text_without_values(
                        f"max_retries={config.max_retries}, "
                        f"base_delay={config.base_delay}s, "
                        f"max_delay={config.max_delay}s",
                        record_values,
                    )
                    if record_values is not None
                    else "(values not shown)"
                )
                self._plugin_log(
                    "[INSTALLATION_CONFIG] Using custom retry configuration",
                    config_detail,
                    level=logging.DEBUG,
                )
            else:
                config = None
                self._plugin_log(
                    "[INSTALLATION_CONFIG] Using default retry configuration",
                    level=logging.DEBUG,
                )

            version_constraint = self._get_tool_version_constraint()
            package_extras = self._get_tool_package_extras()
            with_dependencies = self._get_tool_with_dependencies()

            tool_name = self.uv_tool_package_name or self.command

            # The constraint can be a value the config read from the
            # environment, and ash.log is a sink: the lines show it as the
            # placeholder, while the install below gets the real one. The
            # inputs come from the one install-input builder -- the same set
            # the runner's stderr debug line hides -- so a spec that PINS a
            # short value (below the value layer's whole-word band) is hidden
            # by origin, like the uv run's own command-line records, and the
            # two install records cannot drift about the --with entries.
            from automated_security_helper.utils.uv_tool_runner import (
                shown_uv_output,
                uv_install_inputs,
            )

            install_inputs = uv_install_inputs(
                tool_name, version_constraint, package_extras, with_dependencies
            )
            tool_spec = install_inputs.spec
            if record_values is not None:
                attempt_lines = (
                    shown_uv_output(
                        f"Tool specification: {tool_spec}",
                        record_values,
                        plugin_inputs=install_inputs.inputs,
                        # The PUBLIC anchor, the same name the runner's stderr
                        # debug line passes (uv_tool_package_name or command):
                        # with the command here instead, the package name token
                        # of a hidden spec was replaced in this record and kept
                        # in the runner's, numbering the placeholders apart.
                        tool_name=tool_name,
                        limit=None,
                    ),
                    shown_uv_output(
                        f"Version constraint: {version_constraint or 'latest'}",
                        record_values,
                        plugin_inputs=install_inputs.inputs,
                        tool_name=tool_name,
                        limit=None,
                    ),
                    # The extras are plugin-built like the spec they ride in
                    # (builtins: constants; a third-party override can build one
                    # from its config), so each extra is an input of its own
                    # here: a glued env-read value hides the extra whole, while
                    # a plain extra stays readable.
                    shown_uv_output(
                        f"Package extras: {package_extras or 'none'}",
                        record_values,
                        plugin_inputs=(*install_inputs.inputs, *(package_extras or ())),
                        tool_name=tool_name,
                        limit=None,
                    ),
                )
            else:
                # The raising-hook degrade: a value-free note, never an empty
                # value set, which would print what the values would have
                # hidden.
                attempt_lines = (
                    "Tool specification: (not shown)",
                    "Version constraint: (not shown)",
                    "Package extras: (not shown)",
                )
            self._plugin_log(
                "[INSTALLATION_ATTEMPT] Starting installation of UV tool",
                *attempt_lines,
                f"Timeout: {timeout}s",
                level=15,
            )

            pre_install_check_start = time.time()
            already_installed = runner.is_tool_installed(self.command)
            pre_install_check_time = time.time() - pre_install_check_start

            if already_installed:
                validation_result = runner.validate_cached_tool(
                    self.command, self.uv_tool_package_name
                )

                if validation_result["is_functional"]:
                    self._plugin_log(
                        f"[INSTALLATION_SKIP] Tool '{self.command}' is already installed and functional",
                        f"Installed version: {validation_result['version'] or 'unknown'}",
                        f"Pre-installation check took {pre_install_check_time:.3f}s",
                        "Skipping installation and using cached version",
                        level=15,
                    )
                    return True
                else:
                    self._plugin_log(
                        f"[INSTALLATION_WARNING] Tool '{self.command}' is installed but not functional",
                        f"Validation error: {validation_result.get('error', 'unknown')}",
                        "Proceeding with reinstallation",
                        level=logging.WARNING,
                    )

            if is_checking_only():
                # A dependency question (core/scanner_inventory.py), not a scan.
                # Everything a scan checks before installing has passed -- not
                # offline, uv present, the tool not already installed -- so a scan
                # would install it now. Recorded instead, and nothing is installed.
                self._installs_on_first_scan = True
                self._plugin_log(
                    "[INSTALLATION_SKIP] Dependency check only; nothing is installed",
                    f"'{self.command}' is not installed; a scan installs it",
                    level=logging.DEBUG,
                )
                return False

            self._plugin_log(
                "[INSTALLATION_PROGRESS] Tool not currently installed, proceeding with installation",
                f"Pre-installation check took {pre_install_check_time:.3f}s",
                level=logging.DEBUG,
            )

            install_start_time = time.time()

            if timeout > 60:
                self._plugin_log(
                    f"[INSTALLATION_PROGRESS] Starting installation (timeout: {timeout}s)",
                    "This may take several minutes depending on network speed and tool size",
                    level=15,
                )

            success = runner.install_tool_with_version(
                tool_name=tool_name,
                version_constraint=version_constraint,
                timeout=timeout,
                retry_config=config,
                package_extras=package_extras,
                with_dependencies=with_dependencies,
                # The runner redacts uv's stderr with these before its debug
                # log: the constraint and dependencies can carry values this
                # plugin's config read from the environment, and uv can
                # respell them past any token replacement. The method's one
                # guarded read: None here means the values hook raised, which
                # is the runner's documented "no caller checked where its
                # inputs came from" mode -- every plugin-built argument is
                # hidden from its debug line, so nothing degrades to an empty
                # value set.
                values=record_values,
            )

            install_duration = time.time() - install_start_time

            if install_duration > 30:
                self._plugin_log(
                    f"[INSTALLATION_PROGRESS] Installation attempt completed in {install_duration:.1f}s",
                    level=15,
                )

            installation_time = time.time() - installation_start_time

            if success:
                from automated_security_helper.utils.subprocess_utils import (
                    clear_find_executable_cache,
                )

                clear_find_executable_cache()

                # Second argument is the ``--from`` spec, a string. This passed
                # ``package_extras`` (a list) until now, which raised TypeError
                # inside the probe and was swallowed by the broad except below,
                # so the version silently read as unknown. After memoization it
                # was worse: the failure was cached under the key
                # "bandit::['sarif', 'toml']" and served to later callers.
                post_install_version = runner.get_installed_tool_version(
                    self.command, self._uv_from_spec(), values=record_values
                )

                self._plugin_log(
                    f"[INSTALLATION_SUCCESS] Successfully installed UV tool '{self.command}'",
                    f"Installed version: {post_install_version or 'unknown'}",
                    f"Total installation time: {installation_time:.3f}s",
                    f"Installation completed at: {datetime.now(timezone.utc).isoformat()}",
                    level=15,
                )
                return True
            else:
                self._plugin_log(
                    f"[INSTALLATION_FAILED] Failed to install UV tool '{self.command}' after all retry attempts",
                    f"Total installation time: {installation_time:.3f}s",
                    "Fallback strategy: Scanner will attempt direct tool execution or validation",
                    level=logging.WARNING,
                )
                return False

        except UVToolRunnerError as e:
            installation_time = time.time() - installation_start_time
            self._plugin_log(
                "[INSTALLATION_ERROR] UV tool runner error during installation",
                f"Tool: {self.command}",
                # Same class as the run arm: the runner's text can quote argv.
                # The method's one guarded read; its raising-hook degrade is a
                # value-free note, never an empty value set.
                text_without_values(f"Error: {e}", record_values)
                if record_values is not None
                else "Error: (not shown)",
                "Error type: UVToolRunnerError",
                f"Installation time before error: {installation_time:.3f}s",
                "Fallback strategy: Scanner will attempt alternative validation methods",
                level=logging.WARNING,
            )
            return False
        except ImportError as e:
            installation_time = time.time() - installation_start_time
            self._plugin_log(
                "[INSTALLATION_ERROR] UV tool runner module not available",
                f"Tool: {self.command}",
                # Same class as the run arm: the error's text can quote argv.
                # The method's one guarded read, degraded as the arm above.
                text_without_values(f"Error: {e}", record_values)
                if record_values is not None
                else "Error: (not shown)",
                "Error type: ImportError",
                f"Installation time before error: {installation_time:.3f}s",
                "Resolution: Ensure UV tool runner dependencies are properly installed",
                level=logging.ERROR,
            )
            return False
        except Exception as e:
            installation_time = time.time() - installation_start_time
            self._plugin_log(
                "[INSTALLATION_ERROR] Unexpected error during UV tool installation",
                f"Tool: {self.command}",
                # Same class as the run arm: the error's text can quote argv.
                # The method's one guarded read, degraded as the arms above.
                text_without_values(f"Error: {e}", record_values)
                if record_values is not None
                else "Error: (not shown)",
                f"Error type: {type(e).__name__}",
                f"Installation time before error: {installation_time:.3f}s",
                "Fallback strategy: Scanner will attempt alternative validation methods",
                level=logging.WARNING,
            )
            # The traceback carries the error's own text, so it is redacted
            # too instead of exc_info's raw print -- with the method's one
            # guarded read, and skipped entirely when the hook raised: this
            # best-effort text cannot be redacted then, and an empty value
            # set would print what the values would have hidden.
            if record_values is not None and ASH_LOGGER.isEnabledFor(logging.DEBUG):
                import traceback

                ASH_LOGGER.debug(
                    text_without_values(
                        f"UV tool installation error details for {self.command} "
                        "(redacted):\n" + "".join(traceback.format_exception(e)),
                        record_values,
                    ),
                    extra=NO_MARKUP,
                )
            return False

    # ------------------------------------------------------------------
    # Installation status
    # ------------------------------------------------------------------

    def _is_uv_tool_installed(self) -> bool:
        """Check if the UV tool is already installed.

        Returns:
            True if tool is installed, False otherwise
        """
        if not self.use_uv_tool or not self.command:
            return False

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            runner = get_uv_tool_runner()

            if not runner.is_uv_available():
                return False

            try:
                installed_tools = runner.list_available_tools()
                is_installed = self.command in installed_tools

                self._plugin_log(
                    f"UV tool {self.command} installation status: {'installed' if is_installed else 'not installed'}",
                    level=logging.DEBUG,
                )

                return is_installed

            except UVToolRunnerError:
                version = runner.get_tool_version(
                    self.command, self.uv_tool_package_name
                )
                is_installed = version is not None

                self._plugin_log(
                    f"UV tool {self.command} installation status (via version check): {'installed' if is_installed else 'not installed'}",
                    level=logging.DEBUG,
                )

                return is_installed

        except (UVToolRunnerError, ImportError) as e:
            self._plugin_log(
                f"Error checking UV tool installation status: {e}",
                level=logging.WARNING,
            )
            return False
        except Exception as e:
            self._plugin_log(
                f"Unexpected error checking UV tool installation: {e}",
                level=logging.WARNING,
            )
            return False

    def _get_tool_installation_info(self) -> Dict[str, Any]:
        """Get comprehensive installation information for the scanner's tool.

        Returns:
            Dictionary containing installation information including UV and pre-installed status
        """
        if not self.command:
            return {
                "tool_name": None,
                "is_uv_installed": False,
                "is_pre_installed": False,
                "uv_version": None,
                "pre_installed_version": None,
                "pre_installed_path": None,
                "preferred_source": "none",
                "available": False,
            }

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            runner = get_uv_tool_runner()
            info = runner.get_tool_installation_info(
                self.command, self.uv_tool_package_name
            )
            info["tool_name"] = self.command

            self._plugin_log(
                f"Tool installation info for {self.command}: "
                f"UV installed: {info['is_uv_installed']}, "
                f"Pre-installed: {info['is_pre_installed']}, "
                f"Preferred: {info['preferred_source']}, "
                f"Available: {info['available']}",
                level=logging.DEBUG,
            )

            return info

        except Exception as e:
            self._plugin_log(
                f"Error getting tool installation info: {e}",
                level=logging.WARNING,
            )
            return {
                "tool_name": self.command,
                "is_uv_installed": False,
                "is_pre_installed": False,
                "uv_version": None,
                "pre_installed_version": None,
                "pre_installed_path": None,
                "preferred_source": "none",
                "available": False,
                "error": str(e),
            }

    def _should_install_tool(self, prefer_cached: bool = True) -> bool:
        """Determine if the tool should be installed via UV.

        Args:
            prefer_cached: Whether to prefer cached/pre-installed tools over installation

        Returns:
            True if tool should be installed via UV, False if existing installation should be used
        """
        if not self.use_uv_tool or not self.command:
            return False

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            runner = get_uv_tool_runner()
            should_install = runner.should_install_tool(self.command, prefer_cached)

            self._plugin_log(
                f"Should install {self.command} via UV: {should_install} (prefer_cached: {prefer_cached})",
                level=logging.DEBUG,
            )

            return should_install

        except Exception as e:
            self._plugin_log(
                f"Error determining if tool should be installed: {e}",
                level=logging.WARNING,
            )
            return False

    # ------------------------------------------------------------------
    # Extension points (meant to be overridden by subclasses)
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> Optional[str]:
        """Get version constraint for tool installation.

        This method should be implemented by each scanner to provide
        version constraints specific to that tool.

        Returns:
            Version constraint string (e.g., ">=1.7.0", "==3.2.0") or None for latest
        """

    def _get_tool_package_extras(self) -> Optional[List[str]]:
        """Get package extras for tool installation.

        This method should be implemented by each scanner to provide
        package extras specific to that tool (e.g., ["sarif", "toml"]).

        Returns:
            List of package extras or None if no extras are needed
        """
        return None

    def _get_tool_with_dependencies(self) -> Optional[List[str]]:
        """Get additional dependencies to install with the tool using --with flag.

        This method should be implemented by each plugin to provide
        additional dependencies that should be installed alongside the main tool.

        Returns:
            List of additional dependencies or None if no additional dependencies are needed
        """
        return None
