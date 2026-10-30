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
from collections.abc import Mapping
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
    UVToolRunnerError,
    checking_only,
    is_checking_only,
)

#: The runner's module, for the import-failure arm of the uv run: an
#: ImportError whose ``name`` is this module (or one under it) is the runner
#: failing to import; any other names the component that failed.
_UV_TOOL_RUNNER_MODULE = "automated_security_helper.utils.uv_tool_runner"

if TYPE_CHECKING:
    pass

#: "The stderr log's identity before the run was not read": the default of
#: ``_uv_response`` and ``_explain_offline_resolve_failure`` for a caller that
#: did not read it, under which the explainer reads the log as it always has.
#: Distinct from None, which is a read that found no log.
_LOG_NOT_READ: Any = object()

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
    not a value set (``None``, a number, bytes, a mapping, an iterable holding
    anything but strings and paths): then no redaction can be done, and the
    caller takes its conservative arm (a value-free note, a skipped
    best-effort line, a refused run). It is ``()`` when there are genuinely
    none, and a bare string or path is ONE value, never its characters
    (``utils.redacted_model.environment_strings``, the normalizer every sink
    reads values through). An iterable is drained here, outside the
    normalizer's own TypeError arm, so one that raises mid-iteration takes the
    guarded path too. A ``None`` ENTRY inside an iterable is an unset value
    (an override adding a token it has not got), not a broken hook: it is
    skipped, since dropping it hides nothing, and the other entries stand.

    Why bytes, mappings and non-string entries are unusable rather than
    normalized: the normalizer drops every entry that is not a string or a
    path, so bytes (an iterable of integers) and a list of integers normalized
    to ``()``, the "genuinely none" answer that licenses every sink to record
    its lines in clear, and a mapping yielded its KEYS as the value set while
    the values it held printed. A broken answer is a broken hook, and the
    conservative arm is the one for a broken hook.

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
        if isinstance(answered, (bytes, bytearray, memoryview, Mapping)):
            return GuardedValues(None, None)
        if isinstance(answered, Iterable):
            # A None entry is an unset value, not a broken hook (docstring):
            # refusing the whole answer for it refused every run of a plugin
            # whose override adds a token it has not got.
            entries = tuple(entry for entry in answered if entry is not None)
            if any(not isinstance(entry, (str, os.PathLike)) for entry in entries):
                return GuardedValues(None, None)
            return GuardedValues(environment_strings(entries), None)
    except Exception as hook_error:  # noqa: BLE001 -- an overridable hook
        return GuardedValues(None, type(hook_error).__name__)
    return GuardedValues(None, None)


def _redacted_line(text: str, values: Optional[Tuple[str, ...]], withheld: str) -> str:
    """``text`` redacted with ``values``, or ``withheld`` when there are none.

    For a log line that quotes an error's text after the plugin's values hook
    was read guarded: with no usable values nothing can redact the text, and an
    empty value set would print what the values would have hidden, so the line
    is replaced by the caller's value-free words.
    """
    if values is None:
        return withheld
    return text_without_values(text, values)


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
    used to probe their version while constructed, with ``uv tool run --from
    <spec> <tool> --version``. uv resolves that spec against the package index
    when the environment is not cached, so a scan of one scanner reached the
    index for scanners it would never run. Construction starts nothing, whoever
    constructs the scanner: the built-in scanners record the probe themselves
    (``_deferred_tool_version_probe``), and ``resolve_deferred_tool_version`` runs
    it once, from the dependency check, the SARIF step or the inventory. A
    scanner constructed outside a scan (``ash dependencies``, the MCP server, a
    test) therefore probes only when that is called. This block covers a plugin
    that still calls ``_get_uv_tool_version`` while constructed: inside it the
    call is recorded the same way; outside it the call probes at once.
    """
    token = _DEFER_VERSION_PROBES.set(True)
    try:
        yield
    finally:
        _DEFER_VERSION_PROBES.reset(token)


#: The runner's own words for a uv that is simply not there
#: (``UVToolRunner.unavailable_reason``), the answer that carries no reason.
_UV_ABSENT = "UV is not available"


def _uv_unavailable(runner: Any, failure: Optional[str] = None) -> str:
    """Why ``runner``'s last availability check failed: absent uv, a probe that
    failed, or a refusal.

    ``failure`` is the probe's own failure as :func:`_uv_available` carries it
    ("the probe timed out after 10 seconds"); with one, the words name it. A
    sandbox scope that refuses the check, or a probe that timed out or was
    killed, says nothing about uv; logging either as "UV is not available"
    sends the operator to install a uv they already have.

    A refusal the runner recorded for this thread's last check comes first,
    in the runner's own sentence (``unavailable_reason``: "The scanner
    sandbox refused to run uv (...)"), which names the sandbox as the actor;
    the probe's failure text for the same event ("the probe's spawn failed
    with SandboxUnavailable: ...") names the exception, and the operator
    reads the sentence. ``unavailable_reason`` answers the plain
    ``_UV_ABSENT`` sentence when no refusal was recorded, so that answer is
    the one that defers to ``failure``.
    """
    reason = getattr(runner, "unavailable_reason", None)
    text = reason() if callable(reason) else None
    if isinstance(text, str) and text != _UV_ABSENT:
        return text
    if failure:
        return f"uv is not available ({failure})"
    return _UV_ABSENT


def _uv_available(runner: Any) -> Tuple[bool, Optional[str]]:
    """``runner.uv_availability()``: ``(available, the probe's failure or None)``.

    The one read of uv's availability for the mixin's gates, so each of them can
    say why uv did not answer (``_uv_unavailable``) instead of reading the bare
    ``is_uv_available()`` and dropping the failure the probe carried. A runner
    without the two-valued form (an older stand-in) is read through
    ``is_uv_available()`` with no failure.
    """
    availability = getattr(runner, "uv_availability", None)
    if callable(availability):
        answer = availability()
        if isinstance(answer, tuple) and len(answer) == 2:
            available, failure = answer
            return bool(available), failure if isinstance(failure, str) else None
    return bool(runner.is_uv_available()), None


def _without_whitespace(requirement: str) -> str:
    """``requirement`` as given when it holds no whitespace; otherwise in the
    canonical spelling ``packaging`` prints, which holds none; the string as
    given when it is not a requirement at all (the caller's check decides what
    to do with that).

    Only a part that holds whitespace is respelled: ``packaging`` sorts a
    requirement's specifiers and extras when it prints one, so canonicalizing
    every part would store ``bandit[sarif,toml]>=1.7.0,<2.0.0`` (the spelling
    the plugin wrote and its documentation shows) as
    ``bandit[sarif,toml]<2.0.0,>=1.7.0``.
    """
    if not any(character.isspace() for character in requirement):
        return requirement
    from packaging.requirements import InvalidRequirement, Requirement

    try:
        return str(Requirement(requirement))
    except InvalidRequirement:
        return requirement


class UVToolMixin:
    """UV tool management methods extracted from PluginBase."""

    # Private attributes of PluginBase, typed here for the methods below. An
    # underscore-named annotation is never a pydantic field, so these two are
    # plain annotations: why the last _try_uv_tool_execution could not run the
    # tool through uv, or None; and the version probe deferred at construction
    # (a PrivateAttr defaulting to None on PluginBase), which
    # resolve_deferred_tool_version clears once the probe has answered.
    _uv_run_failure: Optional[str]
    _deferred_tool_version_probe: Optional[tuple[str, Optional[str]]]

    if TYPE_CHECKING:
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
        spec from the package that provides the tool (``uv_tool_package_name``,
        else ``self.command``) plus this plugin's extras and version constraint.
        Returns ``None`` when the scan passes no ``--from`` at all (no extras,
        no constraint, and a package named like the command), so the probe
        matches that too; a package named apart from the command is always a
        ``--from`` (``uv tool run jupyter-nbconvert`` would resolve a package
        named after the executable), so it is returned bare. ``run_tool``
        applies the same rule, comparing the two names as PEP 503 does.

        Why the probe needs this: ``uv tool run bandit`` and
        ``uv tool run --from 'bandit[sarif,toml]>=1.7.8,<2.0.0' bandit`` resolve
        to different environments. stevedore's entry-point cache is keyed on
        ``sys.executable`` and ``sys.prefix``, so those two invocations warm two
        different cache files -- and a probe that warms the wrong one leaves the
        scan's file cold for N concurrent scanners to race, which is the whole
        problem serializing the probe was meant to remove. Measured directly:
        one workspace scan produced five distinct bandit environments.
        """
        extras = self._get_tool_package_extras()
        constraint = self._get_tool_version_constraint()
        package = self._uv_package()
        if not extras and not constraint:
            return package if package != self.command else None
        base = f"{package}[{','.join(extras)}]" if extras else package
        return f"{base}{constraint}" if constraint else base

    def _uv_package(self) -> str:
        """The package that provides this plugin's tool: ``uv_tool_package_name``,
        else the command's own name. The name every uv spec of this plugin is
        built around, and the ``package`` the runner's requirement check holds
        each spec to, so a constraint glued onto the name cannot name another
        package (``checked_requirement``)."""
        return self.uv_tool_package_name or self.command

    def _uv_probe_from_spec(self) -> Optional[str]:
        """:meth:`_uv_from_spec` as the dependency check hands it to the probe.

        ``get_uv_tool_command`` runs ``uv tool run --from <spec> <tool> --version``
        with the spec as given, while ``run_tool`` passes the scan's own ``--from``
        only through ``checked_requirement`` (a package name, optional extras and
        a PEP 440 specifier; never a path, a URL or a marker). The same check
        here, with the package named so a constraint glued onto the name cannot
        rename it: a spec the run would refuse is refused before the probe,
        logged in this plugin's fixed words with nothing of the spec in the
        line, and the probe runs bare, as ``get_tool_version`` answers None for
        the same refusal.
        """
        spec = self._uv_from_spec()
        if spec is None:
            return None
        from automated_security_helper.utils.uv_tool_runner import (
            UVToolRunnerError,
            checked_requirement,
        )

        try:
            return checked_requirement(
                spec,
                f"the --from spec for {self.command}",
                package=self.uv_tool_package_name or self.command,
            )
        except UVToolRunnerError as error:
            # The refusal's text carries no part of the spec, and the tool is
            # named from this plugin's own field, so the line is value-free as
            # built; the redaction of the plugin's values is the second guard
            # the install-command setup keeps on the same kind of line, read
            # guarded as every record line reads it (_values_to_redact).
            message = f"{self.command}: {error}"
            values = self._guarded_values()
            if values:
                message = text_without_values(message, values)
            self._plugin_log(message, level=logging.WARNING)
            return None

    def _checked_uv_from_spec(self) -> Optional[str]:
        """:meth:`_uv_from_spec`, refused when it does not name this plugin's package.

        For the PROBE sites of this mixin (the version probe, the installation
        info, the cached-tool check, the post-install version read), which hand
        the spec to ``uv tool run --from`` and so resolve whatever package it
        names. The spec is glued from the package name and the plugin's
        constraint, and a constraint without an operator ("2" from an
        overridden hook) glues into a valid requirement for ANOTHER package
        ("bandit2"); the run path checks its own spec against the package
        (``UVToolRunner.run_tool``), while the probes ran the glued one.
        ``UVToolRunnerError`` is the runner's own refusal, which every probe
        site here already handles (a refused spec is a refused probe, logged by
        the site's own arm). :meth:`_uv_probe_from_spec` above is the sibling
        for the scanners' dependency-check probe, which logs the refusal and
        probes bare instead. The record sites keep the unchecked spec: they
        hide the string as built.
        """
        from automated_security_helper.utils.uv_tool_runner import checked_requirement

        spec = self._uv_from_spec()
        if spec is None:
            return None
        return checked_requirement(
            spec,
            f"the --from spec for {self.command}",
            package=self.uv_tool_package_name or self.command,
        )

    def _uv_stderr_log_identity(
        self, results_dir: Optional[Path]
    ) -> Optional[Tuple[int, int, int, int]]:
        """The identity of this plugin's stderr log under ``results_dir`` now, or
        None when there is none: read BEFORE a uv run, so the offline explainer
        can tell a log that run wrote from one left by an earlier run
        (``plugin_base._log_identity``)."""
        if results_dir is None:
            return None
        from automated_security_helper.base.plugin_base import _log_identity

        return _log_identity(
            Path(results_dir) / f"{self.__class__.__name__}.stderr.log"
        )

    def _uv_run_inputs(self) -> Tuple[str, ...]:
        """The plugin-built requirement strings of this plugin's uv runs: the
        ``--from`` spec (or the bare command) and every ``--with`` dependency.

        ONE builder for every site that hides a RUN's inputs -- the
        pre-dispatch record, the report lines, the offline explainer, the
        verdict lines, the scan-failure excerpt and the sandbox records -- so
        "the same hiding arms" holds by construction: an input hidden on one
        line cannot print on the next because that site assembled a smaller
        set. Records about an INSTALL are the one deliberate exception: an
        install's inputs are the install spec and its ``--with`` entries as
        ``uv tool install`` takes them (the same package the run's ``--from``
        is built on, ``uv_tool_package_name`` else the command, but spelled
        for the install), so they share their own builder,
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
        if not self.use_uv_tool:
            self._plugin_log(
                f"UV tool execution is disabled for {tool_name}",
                level=logging.DEBUG,
            )
            return None
        if _DEFER_VERSION_PROBES.get():
            # Kept for resolve_deferred_tool_version with the spec as given: a
            # None is resolved when the probe runs, so the probe reads the
            # requirement the dependency check reads then, not the one the
            # plugin was built with. See deferred_tool_version_probes.
            self._deferred_tool_version_probe = (tool_name, package_name)
            return None
        # The ONE guarded read of the overridable values hook for this call
        # (_values_to_redact's guarding rule), taken BEFORE the try: the
        # error arms below quote the runner's text and need the values too,
        # and reading the hook bare inside a handler let a raising hook turn
        # a logged-and-returned failure into an exception escaping scanner
        # construction. The carried version is redacted before its first-line
        # cut, so the probe gets the same values. The runner memoizes the
        # answer it carries, so a probe run without the values could keep the
        # unredacted text for the process: with no usable values the probe is
        # not run and the version stays unknown.
        read = guarded_values_read(self)
        probe_values = read.values
        withheld = f"(error text not shown: the plugin's values hook {read.failure()})"

        try:
            # UVToolRunnerError is the module's own import: a local import of
            # it here would leave the except arms below reading an unbound
            # name when this import is what raised (the ImportError arm was
            # unreachable: evaluating ``except UVToolRunnerError`` raised
            # UnboundLocalError first).
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            runner = get_uv_tool_runner()

            uv_available, probe_failure = _uv_available(runner)
            if not uv_available:
                self._plugin_log(
                    f"{_uv_unavailable(runner, probe_failure)} for {tool_name} "
                    "version detection",
                    level=logging.WARNING,
                )
                return None

            if package_name is None:
                # Refused, not probed, when the built spec names another
                # package than this plugin's: see _checked_uv_from_spec.
                package_name = self._checked_uv_from_spec()

            if probe_values is None:
                self._plugin_log(
                    f"Could not determine UV tool {tool_name} version: the "
                    f"plugin's values hook {read.failure()}, so the probe was "
                    "not run",
                    level=logging.WARNING,
                )
                return None
            version = runner.get_tool_version(
                tool_name,
                package_name,
                values=probe_values,
                # This plugin's own offline mode and the package its spec is
                # built around, as the run and the install pass them: the
                # probe used to go online for a scanner offline by its options.
                offline=self._is_offline_mode(),
                package=self._uv_package(),
                **self._uv_python_kwargs(),
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
            # redacted with the method's one guarded read of the plugin's
            # values, as the mixin's lines are (the same class as the dispatch
            # and run arms below); with no usable values the text is withheld.
            self._plugin_log(
                _redacted_line(
                    f"UV tool runner error getting {tool_name} version: {e}",
                    probe_values,
                    f"UV tool runner error getting {tool_name} version {withheld}",
                ),
                level=logging.WARNING,
            )
            return None
        except ImportError as e:
            self._plugin_log(
                _redacted_line(
                    f"UV tool runner module not available for {tool_name}: {e}",
                    probe_values,
                    f"UV tool runner module not available for {tool_name} {withheld}",
                ),
                level=logging.ERROR,
            )
            return None
        except Exception as e:
            self._plugin_log(
                _redacted_line(
                    f"Unexpected error getting UV tool {tool_name} version: {e}",
                    probe_values,
                    f"Unexpected error getting UV tool {tool_name} version {withheld}",
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

        The probe stays owed until a version was read: ``_get_uv_tool_version``
        answers a runner error, a spawn error or a timeout with None, and
        clearing the deferral before the probe ran left ``tool_version`` None
        for the instance's life after one transient failure, with the probe
        never sent again. A later call resolves it; the runner memoizes a
        completed probe's answer, so a tool that answered nothing costs a memo
        read, not another process.

        A None answer never overwrites ``tool_version``. The scan can select
        another route before this is called again (a verified copy on PATH, a
        direct binary) and set ``tool_version`` from it with ``use_uv_tool``
        cleared; the uv probe then answers None, and assigning that answer
        erased the version the route had read, in the SARIF step that reads
        it. A route that left uv also drops the owed probe without asking it.
        """
        deferred = self._deferred_tool_version_probe
        if deferred is None:
            return
        if not self.use_uv_tool:
            # Another route was selected and owns tool_version now; the uv
            # probe is no longer owed, and asking it would answer None.
            self._deferred_tool_version_probe = None
            return
        tool_name, package_name = deferred
        version = self._get_uv_tool_version(tool_name, package_name)
        if version is None:
            # Still owed; whatever tool_version holds is kept as it is.
            return
        self.tool_version = version
        self._deferred_tool_version_probe = None

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
        # The plugin's inputs for the records are read inside the try, after
        # the runner is in hand; the error arms below redact with them too, so
        # a failure before that read (the runner's import, its lookup, the
        # availability probe) must find a bound name: nothing has been built
        # from those inputs by then, so there is nothing of them to hide.
        record_inputs: Tuple[str, ...] = ()
        try:
            # Whether a stderr log already sits where this run would write its
            # own, for the offline explainer: a leftover from an earlier run in
            # the same results directory is not this run's output. Read inside
            # the try, so a plugin whose hook raises takes the documented
            # _uv_run_failure arm below instead of raising out of the dispatch.
            stderr_log_before = self._uv_stderr_log_identity(results_dir)
            # UVToolRunnerError is the module's own import: named by the except
            # arm below, a local import of it would leave that arm reading an
            # unbound name when this import is what raised.
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            uv_runner = get_uv_tool_runner()

            # The one availability read every gate shares (_uv_available), so
            # an older stand-in with only ``is_uv_available`` is read through
            # that, as the other four gates read it, instead of raising on
            # the unpack of an answer that is not the two-valued one.
            uv_available, probe_failure = _uv_available(uv_runner)
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
                    # The package that provides the command, when it is named
                    # apart from it: the --from spec is built on it, so the
                    # run resolves the package the install named, not one
                    # named after the executable.
                    package_name=self.uv_tool_package_name,
                    args=tool_args,
                    cwd=working_dir,
                    capture_output=True,
                    text=True,
                    check=False,
                    package_extras=package_extras,
                    version_constraint=version_constraint,
                    # The plugin's extra dependencies, as the install passes
                    # them and as the run's records count them: a run that
                    # resolves an ephemeral environment lacked them.
                    with_dependencies=self._get_tool_with_dependencies(),
                    results_dir=results_dir,
                    stdout_preference=stdout_preference,
                    stderr_preference=stderr_preference,
                    class_name=self.__class__.__name__,
                    env=env,
                    timeout=timeout,
                    values=values,
                    # This plugin's own offline mode (options.offline), which
                    # the runner would otherwise not see.
                    offline=self._is_offline_mode(),
                    **self._uv_python_kwargs(),
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
            # The runner's spawn and timeout texts can quote the full argv, and
            # an argument can carry a value the plugin's config read from the
            # environment: the log line is redacted with the method's one
            # guarded read of the plugin's values THROUGH THE UV LAYER, the
            # same arms every other record of this run gets (the pre-dispatch
            # line, the report lines), so a glued or respelled spec hidden
            # there cannot print here through the plain value layer.
            # _uv_run_failure keeps the raw text for the refused record, whose
            # printers redact with the run's values.
            self._plugin_log(
                self._shown_run_text(
                    f"UV tool runner error for {self.command}: {e}",
                    record_values,
                    record_inputs,
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
            # The try covers more than the runner's import: the sandbox scope's
            # record context and the plugin's own input hooks import too, and
            # an ImportError from one of those worded as the runner failing to
            # import pointed the operator at the wrong component. The failed
            # module's name decides the wording.
            failed_module = getattr(e, "name", None) or ""
            if failed_module == _UV_TOOL_RUNNER_MODULE or failed_module.startswith(
                f"{_UV_TOOL_RUNNER_MODULE}."
            ):
                self._uv_run_failure = f"the uv tool runner could not be imported: {e}"
                logged = f"UV tool runner module not available: {e}"
            else:
                self._uv_run_failure = (
                    f"an import failed while preparing the uv run: {e}"
                )
                logged = (
                    f"Import failed while preparing the uv run of {self.command}: {e}"
                )
            # Redacted like the runner-error arm above: the raise can quote the
            # full argv, and an argument can carry an env-read value.
            self._plugin_log(
                self._shown_run_text(logged, record_values, record_inputs),
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
                self._shown_run_text(
                    f"Unexpected error during UV tool execution for {self.command}: {e}",
                    record_values,
                    record_inputs,
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

        return self._uv_response(
            result, results_dir, stderr_log_before=stderr_log_before
        )

    def _shown_run_text(
        self,
        text: str,
        record_values: Tuple[str, ...],
        record_inputs: Tuple[str, ...],
    ) -> str:
        """``text`` about this plugin's uv run, redacted with the uv layer.

        The run's records all hide the same set: the plugin's env-read values
        in every spelling uv prints them in, and the plugin-built inputs (the
        ``--from`` spec, the ``--with`` entries) that hold one. A line about a
        run that went through the plain value layer alone printed a respelled
        or glued value the report lines beside it hid.
        """
        from automated_security_helper.utils.uv_tool_runner import shown_uv_output

        return shown_uv_output(
            text,
            record_values,
            plugin_inputs=record_inputs,
            tool_name=self.command,
            limit=None,
        )

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

    def _uv_response(
        self,
        result: Any,
        results_dir: Optional[Path],
        *,
        stderr_log_before: Any = _LOG_NOT_READ,
    ) -> Dict[str, Any]:
        """The response for a uv run that returned, handled once.

        Every flag the result carries is copied, with its error: scan() and
        _run_subprocess grade the scan by it, whatever exit codes the scanner
        accepts. When handling the response raises, the response already
        assembled is kept, with its flag, code and reason, and the error is added
        to the reason; post_run_error is added only to a response with no flag.
        Nothing here falls back to direct execution.

        ``stderr_log_before`` is the identity of this plugin's stderr log under
        ``results_dir`` as read before the run (``_uv_stderr_log_identity``), so
        the offline explainer reads the log only when this run wrote it. A
        caller that did not read it leaves the default, and the explainer reads
        the log as it always has.
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
            # The mark is this caller's, set after its own call returned, not by
            # the method it called: that method is an extension seam, and an
            # override that never calls super() left the response unmarked, so
            # _run_subprocess processed it a second time. A call that raised sets
            # no mark, and the handler below hands back a response that is not
            # marked, so it is processed once there.
            mark = getattr(self, "_mark_processed", None)
            if callable(mark):
                mark(response)
            # The explainer is best-effort, cause-first text about a run that
            # has already been processed: a raise inside it (a hook it reads
            # raising, say) used to fall into the handler below and grade the
            # run as post_run_error, so it is guarded on its own and its
            # failure logged at DEBUG, leaving the scan's real error alone.
            try:
                self._explain_offline_resolve_failure(
                    response, results_dir, stderr_log_before=stderr_log_before
                )
            except Exception as explainer_error:  # noqa: BLE001 -- best effort
                explainer_values = guarded_values(self)
                if explainer_values is not None:
                    self._plugin_log(
                        text_without_values(
                            "The offline-resolve explainer could not run: "
                            f"{type(explainer_error).__name__}: {explainer_error}",
                            explainer_values,
                        ),
                        level=logging.DEBUG,
                    )

            self._plugin_log(
                f"UV tool execution completed for {self.command} with exit code {response['returncode']}",
                level=logging.DEBUG,
            )

            return response

        except Exception as e:
            # As at the mixin's other sites: the message and the traceback it
            # carries can quote a path with an env-read value, so both pass
            # through the plugin's redaction instead of exc_info's raw print.
            # The values hook is overridable and read GUARDED here, once for
            # the handler: a raise from it inside this handler would escape,
            # and the tool that ran (and maybe timed out) would be recorded as
            # a spawn failure. With no values the DEBUG line is not shown,
            # since nothing could redact it, and the error text kept in the
            # response is reduced to the exception's type.
            handler_values = guarded_values(self)
            if ASH_LOGGER.isEnabledFor(logging.DEBUG) and handler_values is not None:
                import traceback

                ASH_LOGGER.debug(
                    text_without_values(
                        "UV tool response error details (redacted):\n"
                        + "".join(traceback.format_exception(e)),
                        handler_values,
                    ),
                    extra=NO_MARKUP,
                )
            # Whatever the response holds so far is kept, and every field it
            # does not hold yet is read on its own, so one unreadable field
            # does not drop the others, and the flags the result carries still
            # grade the scan. A timed-out, cancelled, rejected or signaled run
            # keeps that flag, its code and its reason; it is never turned
            # into post_run_error below. The per-field reads used to run only
            # when the response dict was never created, so a raise after it
            # was (reading one flag) kept a half-built response that had lost
            # the later flags, the could-not-stop state and the runner's
            # reason, and graded the run as a plain post-run error.
            rebuilt = response is None
            failed: Dict[str, Any] = dict(response) if response is not None else {}
            for field in ("stdout", "stderr"):
                if field not in failed:
                    failed[field] = ""
                    try:
                        failed[field] = getattr(result, field, "") or ""
                    except Exception:
                        pass
            if "returncode" not in failed:
                failed["returncode"] = None
                try:
                    failed["returncode"] = getattr(result, "returncode", None)
                except Exception:
                    pass
            for flag in RESPONSE_FLAGS:
                if flag in failed:
                    continue
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
            if "could_not_stop" not in failed:
                try:
                    if getattr(result, "could_not_stop", False) is True:
                        failed["could_not_stop"] = True
                except Exception:
                    could_not_stop_readable = False
            if "could_not_stop_pid" not in failed:
                try:
                    pid = getattr(result, "could_not_stop_pid", None)
                    if isinstance(pid, int) and not isinstance(pid, bool):
                        failed["could_not_stop_pid"] = pid
                except Exception:
                    pass
            if failed.get("signaled") and "signal" not in failed:
                try:
                    failed["signal"] = getattr(result, "signal", None)
                except Exception:
                    failed["signal"] = None
            if "error" not in failed and any(
                failed.get(flag) is True for flag in RESPONSE_FLAGS
            ):
                try:
                    failed["error"] = str(
                        getattr(result, "error", "") or failed["stderr"] or ""
                    )
                except Exception:
                    pass
            if (
                rebuilt
                and failed.get("timed_out") is True
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
                # drops no real could-not-stop. Only for a response built
                # here: one the normal path built carries the code it read.
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
            # The handling error's text reaches the results through the
            # response's error field, so it is redacted with the handler's one
            # guarded read, as the direct path redacts the same field; with no
            # usable values only the exception's type is kept, since nothing
            # could redact its text.
            handling = (
                error_text(e, handler_values)
                if handler_values is not None
                else f"{type(e).__name__} (text not shown: the values hook failed)"
            )
            failed["error"] = f"{earlier}; {handling}" if earlier else handling
            if not any(failed.get(flag) is True for flag in RESPONSE_FLAGS):
                failed["post_run_error"] = True
                failed["spawn_failed"] = False
            # A response that was processed before this handler ran is marked;
            # the copy returned here stands for it, so it is marked in its
            # place, and the dispatcher does not process the same run's lines a
            # second time. The original's mark is retired: nothing else would.
            was_processed = getattr(self, "_was_processed", None)
            mark = getattr(self, "_mark_processed", None)
            forget = getattr(self, "_forget_processed", None)
            if (
                response is not None
                and callable(was_processed)
                and callable(mark)
                and callable(forget)
            ):
                try:
                    if was_processed(response):
                        mark(failed)
                        forget(response)
                except Exception:  # noqa: BLE001 -- a stand-in without the marks
                    pass
            # The tool ran and this is its code: folded into the plugin's exit
            # code here, because _process_command_response, which does that
            # fold on the normal path, raised or never ran, and a run that
            # exited non-zero would otherwise leave the default looking
            # accepted. A bool is no code (it passes isinstance(int)). The fold
            # goes through the plugin's own ranking, as the normal path's does,
            # so a scanner that ranks its codes itself ranks this one too.
            code = failed.get("returncode")
            if isinstance(code, int) and not isinstance(code, bool):
                from automated_security_helper.base.plugin_base import (
                    _folded_exit_code,
                )

                try:
                    self.exit_code = _folded_exit_code(
                        self, getattr(self, "exit_code", None), code
                    )
                except Exception:  # noqa: BLE001 -- the response is the record
                    pass
            return failed

    def _explain_offline_resolve_failure(
        self,
        response: Dict[str, Any],
        results_dir: Optional[Path],
        *,
        stderr_log_before: Any = _LOG_NOT_READ,
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
            if stderr_log_before is not _LOG_NOT_READ:
                # Only a log THIS run wrote: one that is absent, or whose
                # identity is the one read before the run, is a leftover of an
                # earlier run in the same results directory, and its text would
                # explain a resolve failure this run never had.
                from automated_security_helper.base.plugin_base import _log_identity

                if _log_identity(log_path) in (None, stderr_log_before):
                    return
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
        # The cause match reads the text without its escape codes: a non-color
        # code (an erase-line \x1b[K) inside the phrase otherwise defeats it.
        # Only the MATCH reads the stripped copy. The text quoted below goes to
        # the shower as written, which matches the values against it first and
        # strips the codes itself: a whole-text strip here first left only the
        # stripped spelling for a value that holds a code, and a short value of
        # that kind glued to word characters then printed (the shower's
        # documented order).
        matchable = _ANSI_ESCAPE.sub("", stderr)
        # uv wraps the message at the scan's COLUMNS, so it is matched with every
        # run of whitespace as one space.
        if "No solution found when resolving" not in " ".join(matchable.split()):
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
        # Cause first, once: an ERROR-level _plugin_log appends the message to
        # errors itself (with the plugin's prefix), so inserting it at the
        # front as well recorded it twice. The appended entry is moved to the
        # front; a stand-in whose _plugin_log appends nothing gets the insert.
        before = len(self.errors)
        self._plugin_log(message, level=logging.ERROR)
        if len(self.errors) > before and self.errors[-1].endswith(message):
            line = self.errors.pop()
            self.errors.insert(0, line)
            # The message quotes the stderr log ("uv said: ..."), so it stands
            # in for the log's text and is not one of ASH's plain notes. Kept
            # among the notes, the failure message read the log again beside
            # it, printed uv's text twice, and cut the pair together, which
            # could drop the log's last lines.
            notes = getattr(self, "_plugin_log_lines", None)
            if isinstance(notes, list) and line in notes:
                notes.remove(line)
        else:
            self.errors.insert(0, message)

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

        # The method's one guarded read of the values hook, for the error arms
        # (which quote the runner's text); a raising hook used to escape them.
        read = guarded_values_read(self)
        withheld = f"(error text not shown: the plugin's values hook {read.failure()})"

        try:
            # UVToolRunnerError is the module's own import (see
            # _get_uv_tool_version): a local import left the except arm unbound
            # when the import raised.
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            runner = get_uv_tool_runner()
            is_available, probe_failure = _uv_available(runner)

            if not is_available:
                self._plugin_log(
                    f"UV tool execution is required for {self.command}, but: "
                    f"{_uv_unavailable(runner, probe_failure)}",
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
                _redacted_line(
                    f"UV tool runner error during validation: {e}",
                    read.values,
                    f"UV tool runner error during validation {withheld}",
                ),
                level=logging.WARNING,
            )
            return False
        except ImportError as e:
            self._plugin_log(
                _redacted_line(
                    f"UV tool runner module not available during validation: {e}",
                    read.values,
                    f"UV tool runner module not available during validation {withheld}",
                ),
                level=logging.ERROR,
            )
            return False
        except Exception as e:
            self._plugin_log(
                _redacted_line(
                    f"Unexpected error during UV tool validation: {e}",
                    read.values,
                    f"Unexpected error during UV tool validation {withheld}",
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
            validation_result["validation_method"] = installation_info[
                "preferred_source"
            ]

            if installation_info["preferred_source"] == "uv":
                self._plugin_log(
                    f"Tool {self.command} validated via UV tool (version: {installation_info.get('uv_version') or 'unknown'})",
                    level=15,
                )
            elif installation_info["preferred_source"] == "pre_installed":
                # The info dict carries the key with None (the PATH copy's
                # version is not probed), so a .get default never applied and
                # the line read "version: None".
                self._plugin_log(
                    f"Tool {self.command} validated via pre-installed executable "
                    f"(version: {installation_info.get('pre_installed_version') or 'unknown'}, "
                    f"path: {installation_info.get('pre_installed_path') or 'unknown'})",
                    level=15,
                )

            # How the tool runs is decided here, not merely reported: the
            # "pre_installed" branch used to log the PATH copy as the validated
            # route, warn that it was being used, and leave use_uv_tool True,
            # so the scan still went through `uv tool run --from <spec>` while
            # the copy was never verified against the requirement (the shape
            # that failed offline with uv's resolver text). _select_tool_execution
            # verifies the copy and switches to it, keeps uv, or refuses offline.
            validation_result["available"] = bool(
                self._select_tool_execution(installation_info)
            )
            if not validation_result["available"]:
                reason = getattr(self, "dependency_unavailable_reason", None)
                validation_result["errors"].append(
                    reason
                    or f"Tool {self.command} is not usable for this scan's requirement"
                )
            elif installation_info["preferred_source"] == "pre_installed" and getattr(
                self, "use_uv_tool", False
            ):
                validation_result["warnings"].append(
                    f"The pre-installed {self.command} was not verified to satisfy "
                    "this scanner's requirement, so it runs through uv, not directly."
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
        # The package that provides the command, when named apart from it: the
        # requirement verified against the copy's environment is the one the
        # scan runs under, not one named after the executable.
        package = self.uv_tool_package_name or self.command
        requirement = build_requirement(package, extras, constraint)
        # The values hook is read ONCE, guarded, for the verify and every
        # record below: it is overridable, two reads can disagree with each
        # other, and a bare read let a raising hook (or one answering None, or
        # a generator the verify drained before the record lines read it)
        # crash the dependency check instead of degrading it. With no usable
        # values the copy cannot be verified (the probe's excerpt could not be
        # redacted and would be memoized in clear), so the previous behavior
        # is kept: the run goes through uv, and the line says why.
        read = guarded_values_read(self)
        if read.values is None:
            self._plugin_log(
                f"The pre-installed {self.command} was not verified: the plugin's "
                f"values hook {read.failure()}, so its check could not be "
                "redacted. It runs through uv, as before.",
                level=logging.WARNING,
            )
            self.dependencies_satisfied = True
            return True
        values: Tuple[str, ...] = read.values
        verdict = verify_pre_installed_tool(
            executable,
            package,
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
            # The copy that runs is this one, so the version the reports name
            # (SARIF scanner_version) is its own, not the one the uv probe read
            # from uv's environment. Read with a default: a verifier stand-in
            # that carries only status and detail is a verdict without one.
            verified_version = getattr(verdict, "version", None)
            if verified_version:
                self.tool_version = verified_version
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
            # The log gets the full story: the copy's path and the verdict's
            # detail, which quotes uv's own words. The REASON that reaches the
            # results (dependency_unavailable_reason) gets the verdict's
            # summary, the path-free, excerpt-free line the verdict provides
            # for exactly that use; the detail stands in only for a verdict
            # that carries no summary.
            self._plugin_log(
                _shown(
                    f"Offline mode: {self.command} at {executable} {cannot}: "
                    f"{verdict.detail}. {remedy}"
                ),
                level=logging.ERROR,
            )
            summary = getattr(verdict, "summary", "") or verdict.detail
            reason = _shown(
                f"Offline mode: {self.command} {cannot}: {summary}. {remedy}"
            )
            self.dependency_unavailable_reason = reason
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
        with_dependencies = list(self._get_tool_with_dependencies() or [])
        install_inputs = uv_install_inputs(
            tool_name,
            version_constraint=version_constraint,
            package_extras=package_extras,
            with_dependencies=with_dependencies,
        )
        tool_spec = install_inputs.spec

        try:
            # Against the package, as the scan-time install checks its own
            # spec: a constraint without an operator glued onto the name is a
            # valid requirement for ANOTHER package, and `ash dependencies
            # install` would have installed it.
            checked_requirement(tool_spec, "the tool spec", package=tool_name)
            # Each --with dependency, as the scan-time install checks them
            # (UVToolRunner.install_tool_with_version): unchecked here, a URL,
            # a path or a marker reached `ash dependencies install`. Whitespace
            # inside one (PEP 508 allows "jupyter >= 1.0") is not refused here:
            # the command builder below stores every requirement in the
            # canonical spelling, which carries none, exactly as it does for
            # the tool spec's own constraint, and the torn check after it
            # refuses whatever still holds whitespace. A refusal at this point
            # cleared the command for a dependency the builder would have
            # spelled safely.
            for position, dependency in enumerate(with_dependencies, start=1):
                checked_requirement(dependency, f"--with dependency {position}")
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

        install_cmd_parts = ["uv", "tool", "install"]
        python_request = self._get_tool_python_request()
        if python_request:
            # One argv element each, and the request must carry no whitespace:
            # get_installation_commands splits this string on whitespace.
            install_cmd_parts.extend(["--python", python_request])
        # The plugin's extra dependencies, as the scan-time install passes
        # them (UVToolRunner.install_tool_with_version): without them the
        # command `ash dependencies` runs built a different environment than
        # the scan's. The ONE read above serves the checks, the spec builder
        # and this loop: the hook is overridable, and a second read could
        # answer differently from the one that was checked. Each is stored
        # in its canonical spelling, as the tool spec below is.
        for dependency in with_dependencies:
            install_cmd_parts.extend(["--with", _without_whitespace(dependency)])
        # The stored command is ONE string that get_installation_commands
        # splits on whitespace, so every requirement in it is spelled without
        # any: a plugin-built constraint such as ">= 1.0" parses (the check
        # above accepts it) but was torn into two uv arguments. The canonical
        # spelling packaging prints carries none; a part that still holds
        # whitespace after that cannot be stored safely and refuses the
        # command, as the refused spec above does.
        install_cmd_parts.append(_without_whitespace(tool_spec))
        torn = [part for part in install_cmd_parts if any(c.isspace() for c in part)]
        if torn:
            self.uv_tool_install_commands = []
            self._plugin_log(
                f"{tool_name}: the UV tool install command was not stored: "
                f"{len(torn)} of its argument(s) hold whitespace, which the "
                "stored command cannot carry",
                level=logging.WARNING,
            )
            return

        install_cmd_str = " ".join(install_cmd_parts)
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
        """Whether this plugin's uv calls run offline.

        ASH's own mode first (``ASH_OFFLINE``), then the plugin's own: a scanner
        resolves ``options.offline`` through ``_scanner_offline``
        (``ScannerPluginBase``), which puts that scanner offline while the rest
        of the run stays online. The mixin used to read only the global mode,
        so a scanner's ``options.offline: true`` never reached uv: its
        ``uv tool run``, version probes and install all went online. Every uv
        call of this mixin passes this value as the runner's ``offline``; the
        scanners' own ``get_uv_tool_command`` calls take it as a parameter too.

        Returns:
            True if offline mode is enabled, False otherwise
        """
        from automated_security_helper.core.constants import is_offline_mode

        if is_offline_mode():
            return True
        scanner_offline = getattr(self, "_scanner_offline", None)
        if callable(scanner_offline):
            try:
                return bool(scanner_offline())
            except Exception:  # noqa: BLE001 -- a config read that raises follows ASH
                return False
        return False

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
                "[INSTALLATION_SKIP] Offline mode detected (ASH_OFFLINE, or this "
                "plugin's own options.offline)",
                f"Skipping UV tool installation for '{self.command}' and relying on pre-installed tools",
                "Fallback strategy: Will attempt to use pre-installed version if available",
                level=15,
            )
            return False

        try:
            # UVToolRunnerError is the module's own import (see
            # _get_uv_tool_version): a local import left the except arm unbound
            # when the import raised.
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRetryConfig,
            )

            runner = get_uv_tool_runner()

            uv_check_start = time.time()
            uv_available, probe_failure = _uv_available(runner)
            uv_check_time = time.time() - uv_check_start

            if not uv_available:
                self._plugin_log(
                    f"[INSTALLATION_FAILED] {_uv_unavailable(runner, probe_failure)} "
                    "for tool installation",
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

            # `is not None`, not truthiness: a caller's EMPTY dict asks for the
            # defaults through the retry path (and gets them, every key
            # defaulted), where a falsy test logged it as the default
            # configuration and passed None, which the runner reads the same
            # way today but which hid the caller's choice from the log.
            if retry_config is not None:
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

            # Whether the install below has to rebuild a tool uv already lists:
            # the runner answers True without installing for a listed tool
            # unless told to reinstall.
            reinstall = False
            if already_installed:
                # Probed under the scan's own --from spec (the extras and the
                # constraint), the environment the scan runs in, not a bare
                # package name's; the spec checked against the package (see
                # _checked_uv_from_spec); the version it carries redacted with
                # the method's one guarded read, as every other line here is.
                validation_result = runner.validate_cached_tool(
                    self.command,
                    self._checked_uv_from_spec(),
                    offline=self._is_offline_mode(),
                    package=self._uv_package(),
                    values=record_values,
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
                elif not validation_result.get("probed", True):
                    # The probe never exited (a timeout, a sandbox refusal, a
                    # spawn failure, a refused spec), so it said nothing about
                    # the installed tool: reinstalling on that answer rebuilt a
                    # working tool over the network on every scan. Kept as
                    # installed; the scan's own run is the next word on it.
                    self._plugin_log(
                        f"[INSTALLATION_SKIP] Tool '{self.command}' is installed; its "
                        "version probe did not run, so it is kept as installed",
                        f"Probe: {validation_result.get('error', 'unknown')}",
                        level=logging.WARNING,
                    )
                    return True
                else:
                    self._plugin_log(
                        f"[INSTALLATION_WARNING] Tool '{self.command}' is installed but not functional",
                        f"Validation error: {validation_result.get('error', 'unknown')}",
                        "Proceeding with reinstallation",
                        level=logging.WARNING,
                    )
                    reinstall = True

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
                reinstall=reinstall,
                offline=self._is_offline_mode(),
                **self._uv_python_kwargs(),
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
                # Best effort: the install succeeded whatever this read does.
                # A raise here (the listing timing out, a probe the sandbox
                # refused) used to fall into the handlers below and report
                # the successful install as [INSTALLATION_ERROR], False.
                try:
                    post_install_version = runner.get_installed_tool_version(
                        self.command,
                        self._checked_uv_from_spec(),
                        values=record_values,
                        **self._uv_python_kwargs(),
                    )
                except Exception as version_error:  # noqa: BLE001
                    post_install_version = None
                    self._plugin_log(
                        text_without_values(
                            f"Could not read the installed version of "
                            f"{self.command} after the install: {version_error}",
                            record_values,
                        )
                        if record_values is not None
                        else f"Could not read the installed version of "
                        f"{self.command} after the install (not shown)",
                        level=logging.DEBUG,
                    )

                # The version the install produced is the plugin's tool
                # version from here on: it was only logged before, so the
                # scanner's reports kept the version a pre-install probe read
                # (or none) for a tool that had just been installed.
                if post_install_version:
                    self.tool_version = post_install_version

                self._plugin_log(
                    f"[INSTALLATION_SUCCESS] Successfully installed UV tool '{self.command}'",
                    f"Installed version: {post_install_version or 'unknown'}",
                    f"Total installation time: {installation_time:.3f}s",
                    f"Installation completed at: {datetime.now(timezone.utc).isoformat()}",
                    level=15,
                )
                return True
            else:
                # The runner's False is documented as "nothing was installed":
                # uv absent, offline, a dependency question, a sandboxed scan,
                # or a refused spec; an install that ran and failed RAISES and
                # is answered by the arms below, never here. The arms above
                # have returned for uv absent and for offline, so a False here
                # is a sandboxed scan or a spec the runner refused, and the
                # runner has logged which; the line says that, not a retry
                # count that never ran.
                self._plugin_log(
                    f"[INSTALLATION_FAILED] UV tool '{self.command}' was not installed; "
                    "the runner installed nothing (a sandboxed scan, or a spec it "
                    "refused; its own log line names which)",
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

        # The method's one guarded read of the values hook, for the error
        # arms: the runner's text can quote argv, and these lines printed it
        # through no redaction at all.
        read = guarded_values_read(self)
        withheld = f"(error text not shown: the plugin's values hook {read.failure()})"

        try:
            # UVToolRunnerError is the module's own import (see
            # _get_uv_tool_version): a local import left the except arms
            # unbound when the import raised.
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            runner = get_uv_tool_runner()

            uv_available, probe_failure = _uv_available(runner)
            if not uv_available:
                self._plugin_log(
                    f"{_uv_unavailable(runner, probe_failure)}; {self.command} is "
                    "not installed as a UV tool",
                    level=logging.DEBUG,
                )
                return False

            try:
                installed_tools = runner.list_available_tools()
            except UVToolRunnerError as e:
                # The listing is the question "is it installed"; its failure
                # is answered "not known to be", never by running the tool.
                # The fallback used to probe `uv tool run --from <spec>
                # <tool> --version`, which SUCCEEDS for a tool uv can resolve
                # into an ephemeral environment on the spot, so a tool that
                # was not installed read as installed whenever the listing
                # was unavailable, and the install was skipped.
                self._plugin_log(
                    _redacted_line(
                        f"UV tool {self.command}: the installed-tool listing failed, "
                        f"so it is treated as not installed: {e}",
                        read.values,
                        f"UV tool {self.command}: the installed-tool listing failed, "
                        f"so it is treated as not installed {withheld}",
                    ),
                    level=logging.WARNING,
                )
                return False

            is_installed = self.command in installed_tools
            self._plugin_log(
                f"UV tool {self.command} installation status: {'installed' if is_installed else 'not installed'}",
                level=logging.DEBUG,
            )
            return is_installed

        except (UVToolRunnerError, ImportError) as e:
            self._plugin_log(
                _redacted_line(
                    f"Error checking UV tool installation status: {e}",
                    read.values,
                    f"Error checking UV tool installation status {withheld}",
                ),
                level=logging.WARNING,
            )
            return False
        except Exception as e:
            self._plugin_log(
                _redacted_line(
                    f"Unexpected error checking UV tool installation: {e}",
                    read.values,
                    f"Unexpected error checking UV tool installation {withheld}",
                ),
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

        # The method's one guarded read of the values hook, for the error arm.
        read = guarded_values_read(self)

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            runner = get_uv_tool_runner()
            # The version probe runs under the scan's own --from spec (the
            # package, its extras and the constraint) and offline mode, the
            # environment the scan runs in; a bare package name probed a
            # different one, and a scanner offline by its options probed online.
            # The spec is checked against the package first (see
            # _checked_uv_from_spec).
            info = runner.get_tool_installation_info(
                self.command,
                self._checked_uv_from_spec(),
                offline=self._is_offline_mode(),
                package=self._uv_package(),
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
            # The uv side raised (the runner could not be imported, a probe
            # was refused, a spec was refused), which says nothing about a
            # copy of the tool on PATH: that side is read on its own here, so
            # the tool is not reported as absent because uv could not answer.
            # The error's text can quote argv and is redacted or withheld with
            # the method's one guarded read; the dict keeps only the type.
            self._plugin_log(
                _redacted_line(
                    f"Error getting tool installation info: {e}",
                    read.values,
                    "Error getting tool installation info (error text not shown: "
                    f"the plugin's values hook {read.failure()})",
                ),
                level=logging.WARNING,
            )
            pre_installed_path: Optional[str] = None
            try:
                from automated_security_helper.utils.uv_tool_runner import (
                    find_executable,
                )

                pre_installed_path = find_executable(self.command)
            except Exception:  # noqa: BLE001 -- best effort beside the error
                pre_installed_path = None
            return {
                "tool_name": self.command,
                "is_uv_installed": False,
                "is_pre_installed": pre_installed_path is not None,
                "uv_version": None,
                "pre_installed_version": None,
                "pre_installed_path": pre_installed_path,
                "preferred_source": "pre_installed" if pre_installed_path else "none",
                "available": pre_installed_path is not None,
                "error": type(e).__name__,
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
            # The caller reaches this once the tool was found unavailable, so a
            # False here read as "already installed" and no install was tried:
            # the scan then started a tool that was not there. An answer that
            # cannot be read is not the runner's no; the install is attempted,
            # and a failure of its own is recorded by the install.
            # The runner's text can quote argv, as on the availability check's
            # error arm: redacted or withheld with one guarded read, as the
            # sibling arms are.
            read = guarded_values_read(self)
            self._plugin_log(
                _redacted_line(
                    f"Could not determine whether {self.command} should be "
                    f"installed via UV ({e}); attempting the installation",
                    read.values,
                    f"Could not determine whether {self.command} should be "
                    "installed via UV (error text not shown: the plugin's values "
                    f"hook {read.failure()}); attempting the installation",
                ),
                level=logging.WARNING,
            )
            return True

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

    def _get_tool_python_request(self) -> Optional[str]:
        """Interpreter request for ``uv tool install/run --python``, or None.

        None, the default, leaves the interpreter to uv, which is how every
        uv-backed plugin behaved before this hook existed. Override it for a tool
        whose dependencies publish no wheels for the newest interpreter uv may
        pick: uv then builds those dependencies from source, which needs a C
        toolchain and system headers, and the install fails. GuardDog is the
        case that added this (pygit2 and yara-python have no CPython 3.14 wheels
        at the pinned version). A version specifier such as ``">=3.10,<3.14"``
        lets uv choose, or download, any interpreter that satisfies it.

        The value must carry no whitespace; see ``_setup_uv_tool_install_commands``.
        """
        return None

    def _uv_python_kwargs(self) -> Dict[str, Any]:
        """``{"python_request": ...}`` for the runner calls, or ``{}`` when unset.

        Empty rather than ``{"python_request": None}`` when unset, so every
        existing plugin calls the runner with exactly the arguments it did before.
        """
        python_request = self._get_tool_python_request()
        return {"python_request": python_request} if python_request else {}

    def _get_tool_with_dependencies(self) -> Optional[List[str]]:
        """Get additional dependencies to install with the tool using --with flag.

        This method should be implemented by each plugin to provide
        additional dependencies that should be installed alongside the main tool.

        Returns:
            List of additional dependencies or None if no additional dependencies are needed
        """
        return None
