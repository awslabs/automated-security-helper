"""Which sandbox, if any, applies to the spawn happening now.

The scanner executor enters :func:`sandbox_scope` around each ``scanner.scan()`` call.
The scope lives in a context variable, so it is per thread: scanners run in parallel
threads, each with its own policy, and spawns ASH makes for itself (``git``, the
container runtime) see no scope and are left alone. A converter's tool reads the
scanned tree as a scanner's does, so the convert phase and the jupyter converter
enter the same kind of scope around what a converter runs (:func:`converter_run_scope`,
:func:`plugin_probe_scope`). :func:`prepare_spawn` is called by every spawn helper in
``utils/subprocess_utils.py``; it is the single place a command line is rewritten for a
sandbox.

A scanner that starts a process from a thread it created itself would not inherit the
scope. No builtin scanner does; ``tests/unit/utils/test_sandbox_choke_point.py`` keeps
scanner modules off raw ``subprocess`` so their spawns go through the helpers.
"""

from __future__ import annotations

import contextvars
import logging
import os
import platform
import shlex
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from automated_security_helper.core.enums import SandboxMode
from automated_security_helper.utils.log import ASH_LOGGER, delivers
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.backends import (
    AUTO_ORDER,
    BACKENDS,
    SandboxBackend,
    SpawnPlan,
)
from automated_security_helper.utils.sandbox.fs_guard import (
    register_writable_root,
    release_with_holder,
    release_writable_root,
    sweep_writable,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    SandboxUnavailable as SandboxUnavailable,
    _broader_than_a_tool,
    _refuse_symlinked_results_dir,
    refuse_symlinked_output_dir,
    build_scanner_policy,
)
from automated_security_helper.utils.tool_config_dir import active_tool_config_dir


def _active_scanned_trees() -> Tuple[Path, ...]:
    """The roots of the active scan when a scope is built (``scanned_trees()``).

    Read once, where the scope is made: the scanner threads run with a copy of
    the scan's context, so a scope built in one of them sees the roots the scan
    opened (``subprocess_utils.scanning_tree``), and a scope built outside any
    scan carries none.
    """
    from automated_security_helper.utils.subprocess_utils import scanned_trees

    return tuple(Path(root) for root in scanned_trees())


@dataclass
class SandboxScope:
    """Everything needed to build a policy for any spawn one scanner makes."""

    backend: SandboxBackend
    scanner_name: str
    requirements: SandboxRequirements
    source_dir: Path
    output_dir: Path
    results_dir: Path
    scan_target: Optional[Path]
    offline: bool
    network_scanners: Optional[List[str]] = None
    extra_read_paths: List[str] = field(default_factory=list)
    network_limit: Optional[List[str]] = None
    read_path_scanners: List[str] = field(default_factory=list)
    env_scanners: List[str] = field(default_factory=list)
    #: Spawns this scope refused (``SandboxUnavailable``: the policy or the backend
    #: would not have them), and why the last one was. A converter's row reads
    #: them: a refused spawn converted nothing.
    refused_spawns: int = 0
    last_refusal: Optional[str] = None
    #: Spawns whose planning failed some other way (a program the backend could not
    #: find, a private directory it could not make), and the last failure's type and
    #: text. Kept apart from the refusals: the sandbox did not refuse these, and a
    #: converter's row names them for what they are. A backend that only meets the
    #: failure once the child starts (bwrap's missing program is Popen's
    #: ``FileNotFoundError``) never counts here, so the count is a floor.
    failed_spawns: int = 0
    last_failure: Optional[str] = None
    #: The owning plugin's env-read values, for the one line this module logs
    #: itself: a planned argv can carry a value the plugin's config read from
    #: the environment.
    environment_values: Tuple[str, ...] = ()
    #: True when the plugin's values hook raised or gave no value set when
    #: the scope was built. ``environment_values`` is then empty, which must
    #: not read as "no values": the post-spawn sweep, whose only redaction is
    #: this scope's values, names no entry or path in its notes.
    environment_values_unread: bool = False
    #: True for a scope built for a plugin CLASS, before construction (the
    #: construction probes): a class has no values hook to call, so
    #: ``environment_values_unread`` is set for it too, but nothing failed, and
    #: the records say so instead of reporting a read that never happened.
    class_scope: bool = False
    #: The owning plugin's uv-run inputs (its --from spec and --with
    #: dependencies), empty for a plugin that does not run through uv: a uv
    #: run's command-line records hide them with the full uv layer, like the
    #: report lines, so a glued or pinned spec hidden there cannot print in a
    #: record.
    plugin_inputs: Tuple[str, ...] = ()
    #: The owning plugin's public command (``self.command``), the name every
    #: report line passes as the layers' tool name. The public anchor is
    #: never replaced by the input layer, and one name keeps the records'
    #: placeholder numbering consistent with the report lines; a scanner
    #: whose config name differs from its command otherwise had the command
    #: replaced here and kept there. Empty for a pre-construction scope; the
    #: records fall back to ``scanner_name``.
    command: str = ""
    #: The roots of the active scan, the repository's own directories: the policy
    #: takes them as data, like ``source_dir``, so under sandbox-exec (the one
    #: backend that restricts exec) a root is not made executable by a path that
    #: happens to reach it, and a tool given a staged copy does not read one.
    #: Not a read grant.
    scanned_trees: Tuple[Path, ...] = field(default_factory=_active_scanned_trees)


@dataclass
class RefusingScope:
    """A scope for a scanner that asked for a sandbox it cannot have.

    Active while such a scanner is constructed and validated, so that its probes
    (``tool --version``, ``uv tool run``) fail instead of running unsandboxed.
    """

    scanner_name: str
    reason: str
    #: Spawns refused under this scope; see ``SandboxScope.refused_spawns``.
    refused_spawns: int = 0
    last_refusal: Optional[str] = None
    #: Never counted here (every spawn under this scope is refused before any
    #: planning), kept so a converter's row reads one shape from either scope.
    failed_spawns: int = 0
    last_failure: Optional[str] = None


_ACTIVE: contextvars.ContextVar["SandboxScope | RefusingScope | None"] = (
    contextvars.ContextVar("ash_sandbox_scope", default=None)
)

_probe_lock = threading.Lock()
# Keyed by mode and by the scanned-tree scope: which bwrap or firejail a probe finds
# depends on the trees being scanned and the in-tree opt-in, so a scan of one tree
# must not reuse a backend another scan's lookup chose.
_resolved: Dict[Any, "SandboxBackend | SandboxUnavailable"] = {}


class TransientProbeFailure(SandboxUnavailable):
    """A backend's probe failed through a passing condition, not a missing feature.

    Raised when ``SandboxBackend.probe`` met a condition that can be gone by the
    next request: the probe process ran past the backend's probe timeout, or the
    system refused a resource for now (``EAGAIN``, ``EBUSY``). The backend sets
    the fact where the exception was caught (``probe_was_transient``); nothing
    here reads the reason's wording. An answer reached through such a failure
    (the refusal itself, or under auto a fallback chosen because the preferred
    backend met one) is remembered for the scan only (``_TransientHold``); a
    missing program or kernel feature, and a backend found with no transient
    skip, are remembered for the process.
    """


#: How long an answer reached through a transient condition is kept when no scan
#: is running (a probe made outside any scan: ``ash dependencies``, a plugin
#: probe before the scan opens). Inside a scan the answer is kept for the scan,
#: not for a time (``_TransientHold``): a scan asks once per scanner, serialized
#: by ``_probe_lock``, and scanners start as the pool frees up, so a clock window
#: that ended mid-scan gave its later scanners another answer than its first.
_TRANSIENT_RETRY_SECONDS = 60.0


class _TransientHold(NamedTuple):
    """How long one transient answer is kept.

    ``scan`` is the notes set of the scan that was running when the answer was
    reached (``_scan_notes``), held by reference so that "the same scan" is an
    identity test; the answer is served to that scan only and is probed again by
    the next scan, or by a request outside any scan. With ``scan`` None the
    answer was reached outside a scan and ``until`` is the monotonic time from
    which it is probed again.
    """

    scan: Optional[Set[Any]]
    until: float

    def lapsed(self, now: float, scan: Optional[Set[Any]]) -> bool:
        if self.scan is not None:
            return scan is not self.scan
        return now >= self.until


#: Cache keys whose answer was reached through a transient condition, and how
#: long each is kept.
_transient_holds: Dict[Any, _TransientHold] = {}


def _scan_notes() -> Optional[Set[Any]]:
    """The set the active scan keeps its once-only notes in, or None outside one.

    ``scanning_tree`` gives a nested scope the enclosing scope's set, so every
    scope of one scan, and the scanner threads that run with a copy of the scan's
    context, share one set; the next scan opens its own. Its identity names the
    scan, and the notes written into it end with the scan.
    """
    from automated_security_helper.utils.subprocess_utils import _TREE_SCOPE

    tree = _TREE_SCOPE.get()
    return tree.warned if tree is not None else None


def _probe_failure_is_transient(refusal: SandboxUnavailable) -> bool:
    """Whether the probe that produced ``refusal`` could answer differently later.

    By type: ``_probe_backend`` raises a ``TransientProbeFailure`` for a probe the
    backend marked transient, and ``_resolve_auto`` raises one when any backend it
    tried was, so under auto one transient member makes the whole answer
    transient, which re-probes the others too. The cost is bounded: one probe per
    tree scope per scan (or per window outside a scan), each bounded by the
    backend's probe timeout, for as long as the condition lasts, where
    remembering a timeout for the process refused or downgraded every later scan.
    """
    return isinstance(refusal, TransientProbeFailure)


#: The (tree scope key, scanner name, setting) triples whose grant-withheld
#: warning was written outside any scan, in this process. A scope is built for
#: every spawn of a scanner (its probes, its scan, each converter run), so the
#: warning repeated several times per scan. Inside a scan the triples live in the
#: scan's own notes set (``_scan_notes``) instead and end with it: one process can
#: scan trees in turn, or the same tree again (an MCP server), each scan under its
#: own configuration, and a process-wide set made the second scan's log empty of a
#: note its settings still earn, and was never pruned. The scanned tree stays in
#: the key because a scan's nested scopes share one notes set.
#: Read and written under ``_withheld_lock`` (``_warn_withheld_once``), a lock
#: of its own: ``_probe_lock`` is held across a backend probe, which can run to
#: the probe timeout, and a note must not queue behind one. ``clear_backend_cache``
#: empties it for the tests.
_WARNED_WITHHELD: Set[Tuple[Any, str, str]] = set()
_withheld_lock = threading.Lock()


def clear_backend_cache() -> None:
    """Forget probe results and the grant warnings already written. For tests."""
    with _probe_lock:
        _resolved.clear()
        _transient_holds.clear()
    # The set has a lock of its own (see above); nothing takes it while holding
    # the probe lock, so taking it after the probe state is cleared cannot invert.
    with _withheld_lock:
        _WARNED_WITHHELD.clear()


class SandboxBackendUnavailable(SandboxUnavailable):
    """No working backend for the requested sandbox mode.

    Carries the requested mode, so a reader can tell a backend the operator
    named that is unavailable (the tool could not start as requested) from
    ASH's own default finding no backend (a missing dependency). Any other
    SandboxUnavailable is a refusal, not an availability failure.
    """

    def __init__(self, reason: str, mode: str):
        super().__init__(reason)
        self.reason = reason
        self.mode = mode

    def __reduce__(self) -> Tuple[type, Tuple[Any, ...]]:
        # Rebuilt from its own arguments: OSError's default rebuilds from ``args``,
        # which holds the reason alone, and this __init__ needs the mode too, so
        # a pickle or a copy raised TypeError.
        return (type(self), (self.reason, self.mode))


def _probe_backend(name: str) -> SandboxBackend:
    backend = BACKENDS[name]()
    reason = backend.probe()
    if reason:
        # ``is True``: a test double that answers any attribute must not make
        # every refusal transient.
        if getattr(backend, "probe_was_transient", False) is True:
            raise TransientProbeFailure(reason)
        raise SandboxUnavailable(reason)
    return backend


def resolve_backend(mode: "SandboxMode | str") -> SandboxBackend:
    """The working backend for ``mode``; raises SandboxUnavailable with the reason.

    Probed once per process and mode, under a lock, because parallel scanner threads
    ask at the same moment and each probe starts a process. An answer reached
    through a transient condition (``_probe_failure_is_transient``: the refusal
    itself, or under auto a fallback taken because the preferred backend met one)
    is kept for the scan that reached it (``_TransientHold``), so every scanner of
    one scan gets one answer, and probed again by the next scan; reached outside
    any scan, it is kept for ``_TRANSIENT_RETRY_SECONDS``.
    """
    from automated_security_helper.utils.subprocess_utils import tree_scope_key

    mode_value = SandboxMode(mode).value
    if mode_value == SandboxMode.off.value:
        raise ValueError("resolve_backend called for sandbox mode 'off'")
    cache_key = (mode_value, tree_scope_key())
    with _probe_lock:
        now = time.monotonic()
        scan = _scan_notes()
        cached = _resolved.get(cache_key)
        hold = _transient_holds.get(cache_key)
        if cached is not None and hold is not None and hold.lapsed(now, scan):
            # Reached through a transient condition, and the scan it was kept
            # for is over (or the window outside a scan has passed).
            cached = None
        if cached is None:
            transient = False
            try:
                if mode_value == SandboxMode.auto.value:
                    cached, transient = _resolve_auto()
                else:
                    cached = _probe_backend(mode_value)
                ASH_LOGGER.info(
                    f"Scanner sandbox: using {cached.name} (--sandbox {mode_value})"
                )
            except SandboxUnavailable as e:
                # Kept without its traceback: the frames (the plugin, its
                # context, the config) would otherwise stay referenced for the
                # process's life, one stack per tree scope.
                cached = e.with_traceback(None)
                cached.__context__ = None
                transient = _probe_failure_is_transient(cached)
            _resolved[cache_key] = cached
            if transient:
                # Kept for the scan that asked. Outside a scan the window is
                # counted from the end of the probe: a probe that ran to its own
                # timeout used up part of the window if it started from ``now``,
                # and two such probes under auto left it already past.
                probed_at = time.monotonic()
                _transient_holds[cache_key] = _TransientHold(
                    scan, probed_at + _TRANSIENT_RETRY_SECONDS
                )
            else:
                _transient_holds.pop(cache_key, None)
    if isinstance(cached, SandboxUnavailable):
        # Classified at the raise, not in the cache, so a cached refusal is
        # always graded with the mode of the current request.
        raise SandboxBackendUnavailable(str(cached), mode_value) from cached
    return cached


def _resolve_auto() -> Tuple[SandboxBackend, bool]:
    """The first working backend of this platform's order, and whether a backend
    skipped on the way failed transiently.

    A fallback reached past a transient skip is an answer for now, not for the
    process: ``resolve_backend`` keeps it for the transient window only, so the
    preferred backend is tried again instead of the fallback staying pinned for
    the tree scope.
    """
    system = platform.system().lower()
    order = AUTO_ORDER.get(system, ())
    if not order:
        raise SandboxUnavailable(
            f"no scanner sandbox is available on {platform.system()}; run ASH under "
            "WSL2 and use --sandbox bwrap there, or use --mode container"
        )
    reasons = []
    transient = False
    for name in order:
        try:
            return _probe_backend(name), transient
        except SandboxUnavailable as e:
            reasons.append(f"{name}: {e}")
            transient = transient or _probe_failure_is_transient(e)
    failure_type = TransientProbeFailure if transient else SandboxUnavailable
    raise failure_type(
        "--sandbox auto found no working sandbox (" + "; ".join(reasons) + ")"
    )


def _sandbox_settings(context: Any) -> Any:
    """The run's SandboxConfig, or None when the context carries no real config.

    Typed strictly: anything that is not a SandboxConfig (a test double, a config
    from before the key existed) has no sandbox settings, which means mode off.
    """
    from automated_security_helper.config.ash_config import SandboxConfig

    config = getattr(context, "config", None)
    settings = getattr(config, "sandbox", None)
    return settings if isinstance(settings, SandboxConfig) else None


def scanner_sandbox_scope(
    scanner_plugin: Any,
    context: Any,
    scan_target: Optional[Path],
) -> Optional[SandboxScope]:
    """The scope for one scanner run, None when no sandbox applies.

    Raises SandboxUnavailable when a sandbox was requested and this scanner cannot
    have one. The executor grades the raise by what was asked: a backend missing
    under ``--sandbox auto`` is MISSING, like any missing dependency; a backend
    the operator named that is unavailable is ERROR with the start-failure code;
    a refusal that is not availability is ERROR with the reason and no exit
    code. In every case the scanner never runs unsandboxed.
    """
    from automated_security_helper.core.constants import is_offline_mode

    settings = _sandbox_settings(context)
    mode = SandboxMode(settings.mode if settings is not None else SandboxMode.off)
    if mode == SandboxMode.off:
        return None

    name = _plugin_name(scanner_plugin)
    declared, declared_config = _declared_identity(scanner_plugin)
    config = getattr(scanner_plugin, "config", None)
    # A class (the phases pass one while constructing a plugin) has no config yet,
    # so nothing has renamed it; only an instance's config can.
    if declared is not None and declared != name:
        raise SandboxUnavailable(
            f"{name}: the config names this scanner {name!r}, but its own name is "
            f"{declared!r}. Sandbox grants follow a scanner's own name, so a "
            "scanner renamed by a config file is not run sandboxed."
        )
    if (
        declared is not None
        and declared_config is not None
        and config is not None
        and not isinstance(config, declared_config)
    ):
        # The names agree; the config is of another class than the one the
        # scanner declares (its section fell back to the generic config class),
        # which is what the refusal says: naming the same name twice as a rename
        # sent the operator to look for a rename that was never made.
        raise SandboxUnavailable(
            f"{name}: the config for this scanner is a "
            f"{type(config).__name__}, not the {declared_config.__name__} its own "
            "code declares, so its options were not read as that class reads "
            "them. Sandbox grants follow a scanner's own declaration, so a "
            "scanner configured through another class is not run sandboxed."
        )
    requirements = getattr(scanner_plugin, "sandbox_requirements", None)
    if not isinstance(requirements, SandboxRequirements):
        requirements = SandboxRequirements()
    environment_values: Tuple[str, ...] = ()
    # A class carries no values to read, and the sweep's only redaction is the
    # scope's values: said outright, so the sweep writes value-free notes for a
    # pre-construction scope instead of quoting a path against an empty set.
    environment_values_unread = isinstance(scanner_plugin, type)
    plugin_inputs: Tuple[str, ...] = ()
    command = ""
    if not isinstance(scanner_plugin, type):
        # plugin_probe_scope can pass the CLASS, before construction: an
        # unbound hook cannot be called, so the pre-construction scope
        # carries no values, said outright rather than through a swallowed
        # TypeError from the unbound call. For an instance, read the hook
        # through the one guarded read the plugin's record paths use (a bare
        # string answer is ONE value, not its characters). A double without
        # the method contributes nothing. A hook that raised or gave no value
        # set also contributes nothing to the records that union the scope's
        # values with their own, and is marked unread so the sweep, which has
        # no other source of values, writes a value-free note instead of
        # quoting a path with an empty value set. Imported here: the base
        # package imports this one.
        from automated_security_helper.base.uv_tool_mixin import (
            guarded_values_read,
        )

        if callable(getattr(scanner_plugin, "_values_to_redact", None)):
            values_read = guarded_values_read(scanner_plugin)
            if values_read.values is None:
                environment_values_unread = True
            else:
                environment_values = values_read.values
        inputs_getter = getattr(scanner_plugin, "_uv_run_inputs", None)
        try:
            plugin_inputs = (
                tuple(inputs_getter())
                if callable(inputs_getter)
                and getattr(scanner_plugin, "use_uv_tool", False)
                else ()
            )
        except Exception:  # noqa: BLE001 -- a raising getter adds nothing
            plugin_inputs = ()
        try:
            # The plugin's public command, so the scope's records pass the
            # SAME tool name the report lines pass -- read defensively like
            # the getters above.
            command = str(getattr(scanner_plugin, "command", "") or "")
        except Exception:  # noqa: BLE001 -- a raising attribute adds nothing
            command = ""

    backend = resolve_backend(mode)
    results_dir = getattr(scanner_plugin, "results_dir", None)
    if not isinstance(results_dir, (str, Path)):
        results_dir = Path(context.output_dir).joinpath("scanners", name)
    # Checked here as well as when each spawn's policy is built, so a planted
    # symlink refuses the scanner before anything runs -- ERROR with this
    # reason and no exit code -- rather than failing its tool partway through.
    refuse_symlinked_output_dir(Path(context.source_dir), Path(context.output_dir))
    _refuse_symlinked_results_dir(
        Path(context.output_dir), Path(results_dir), Path(context.source_dir)
    )
    # Registered before the scanner runs anything, so even ASH's first write
    # there (a worker's request file) is guarded, and released with the scope.
    results_root = register_writable_root(results_dir)
    network_scanners = getattr(settings, "network_scanners", None)
    if (
        requirements.network
        and requirements.network_requires_grant
        and network_scanners is None
        and not is_offline_mode()
    ):
        _warn_withheld_once(
            name,
            "network",
            f"{name}'s settings ask for a network, and those settings can come from "
            "the scanned repository, so the sandbox does not grant it. To allow it, "
            f"add {name} to sandbox.network_scanners with --config-overrides or a "
            "config file outside every git checkout and the scanned directory.",
        )
    elif (
        requirements.network
        and network_scanners is not None
        and name not in network_scanners
        and not is_offline_mode()
    ):
        # The operator's list replaces every declared need, so this is their
        # choice; said once at INFO rather than withheld in silence.
        _warn_withheld_once(
            name,
            "network_list",
            f"{name} declares a network need, and sandbox.network_scanners does "
            "not name it, so the sandbox withholds the network from it.",
            level=logging.INFO,
        )
    read_path_scanners = list(getattr(settings, "read_path_scanners", []) or [])
    env_scanners = list(getattr(settings, "env_scanners", []) or [])
    # read_paths alone: cache_paths that follow a scanner's options are never
    # mounted, granted or not (the policy gives such a tool a private cache), so
    # the read_path_scanners advice would not change what a cache-only scanner
    # gets.
    for withheld, key in (
        (
            requirements.read_paths
            and requirements.read_paths_require_grant
            and name not in read_path_scanners,
            "read_path_scanners",
        ),
        (
            (requirements.env_prefixes or requirements.env_names)
            and requirements.env_requires_grant
            and name not in env_scanners,
            "env_scanners",
        ),
    ):
        if withheld:
            _warn_withheld_once(
                name,
                key,
                f"{name}'s settings ask for "
                f"{'host paths' if key == 'read_path_scanners' else 'environment variables'}"
                " the default policy does not allow, and those settings can come "
                "from the scanned repository, so the sandbox does not grant them. "
                f"To allow them, add {name} to sandbox.{key} with "
                "--config-overrides or a config file outside every git checkout "
                "and the scanned directory.",
            )
    scope = SandboxScope(
        backend=backend,
        scanner_name=name,
        requirements=requirements,
        source_dir=Path(context.source_dir),
        output_dir=Path(context.output_dir),
        results_dir=Path(results_dir),
        scan_target=Path(scan_target) if scan_target else None,
        offline=is_offline_mode(),
        network_scanners=list(network_scanners)
        if network_scanners is not None
        else None,
        extra_read_paths=list(getattr(settings, "extra_read_paths", []) or []),
        network_limit=list(settings.network_limit)
        if settings.network_limit is not None
        else None,
        read_path_scanners=read_path_scanners,
        env_scanners=env_scanners,
        environment_values=environment_values,
        environment_values_unread=environment_values_unread,
        class_scope=isinstance(scanner_plugin, type),
        plugin_inputs=plugin_inputs,
        command=command,
    )
    # Released when the scope is collected, or when the scan ends (run_roots).
    release_with_holder(scope, results_root)
    return scope


def _warn_withheld_once(
    name: str, key: str, message: str, level: int = logging.WARNING
) -> None:
    """Write a grant-withheld note once per scan, tree, scanner and setting.

    A scope is built for each spawn of a scanner (its probes, its scan, each
    converter run), so the same sentence otherwise repeated several times per
    scan; the setting it names does not change between them. It does change
    between scans: one process can scan several trees in turn, or the same tree
    again (an MCP server), each under its own configuration, so the note is kept
    in the active scan's own notes set (``_scan_notes``) and a later scan writes
    it again; the key carries the tree scope (``tree_scope_key``; a scope built
    outside any scan carries the empty one, and its notes are kept for the
    process in ``_WARNED_WITHHELD``). Checked and added under
    ``_withheld_lock``, the set's own lock: the scanner threads build their
    scopes at the same moment, and ``_probe_lock`` is held across a backend
    probe, which can run to the probe timeout. ``level`` is INFO for the
    operator's own choice (the network list that omits
    the scanner) and WARNING, the default, for a withheld grant; the note goes
    through the logger's own ``info`` or ``warning`` method, the methods the
    tests of these notes read.
    """
    from automated_security_helper.utils.subprocess_utils import tree_scope_key

    if level not in (logging.INFO, logging.WARNING):
        # Only the two levels the notes use have a method here; any other was
        # written as a warning without a word.
        raise ValueError(f"a withheld-grant note is INFO or WARNING, not {level}")
    entry = (tree_scope_key(), name, key)
    notes = _scan_notes()
    written = notes if notes is not None else _WARNED_WITHHELD
    with _withheld_lock:
        if entry in written:
            return
        written.add(entry)
    write = ASH_LOGGER.info if level == logging.INFO else ASH_LOGGER.warning
    write(message)


def sandbox_refusal_grades_missing(refusal: SandboxUnavailable) -> bool:
    """Whether a scanner whose sandbox was refused this way is MISSING, not ERROR.

    Only an unavailable backend under auto: any working backend was asked for
    and none works, which is a missing dependency like any other. Every other
    refusal is an ERROR -- a backend the operator named that is unavailable (the
    tool could not start as requested), and a refusal that is not about
    availability at all, such as a results directory the scanned repository
    committed as a symlink. The one test, read by the executor that grades the
    scan and by ScanPhase deciding whether a dependency check can say anything,
    so the two cannot drift.
    """
    return (
        isinstance(refusal, SandboxBackendUnavailable)
        and refusal.mode == SandboxMode.auto.value
    )


def _record_probe_refusal(plugin: Any, refusal: SandboxUnavailable) -> None:
    """Make the sandbox the scanner's recorded dependency reason.

    Only for an unavailable backend (``SandboxBackendUnavailable``, named or
    auto), and only on a constructed plugin whose
    ``dependency_unavailable_reason`` exists and is empty: a reason the scanner
    recorded itself stands, and a class has no instance to record on. The
    record is what reaches a check that starts no process (detect-secrets runs
    in-process): the refusing scope cannot stop such a check the way it stops a
    probe-starting one, so without it ``ash dependencies``' probe-free check
    answers True for a scanner every scan under this sandbox refuses -- under
    auto the scan grades it MISSING, under a named backend the executor
    refuses it before scan() with an ERROR naming the backend. The sweep and
    the scan must agree either way, and the recorded reason names the SANDBOX
    ("scanner sandbox unavailable: ..."), so the verdict never blames a tool
    that is there.

    Not for a refusal that is not about availability, such as a results
    directory the scanned repository committed as a symlink: nothing is
    missing there, something was refused, and a dependency reason would send
    the operator to reinstall a tool when the repository planted the cause.
    The scan itself does not read the record: ScanPhase reads the refusal
    plugin_probe_scope yields and does not run the check under one the
    executor grades ERROR. A check that probes through the refusing scope
    still answers for its own failed probes either way.
    """
    if isinstance(plugin, type) or not isinstance(refusal, SandboxBackendUnavailable):
        return
    if not hasattr(plugin, "dependency_unavailable_reason"):
        return
    if getattr(plugin, "dependency_unavailable_reason", None):
        return
    try:
        plugin.dependency_unavailable_reason = f"scanner sandbox unavailable: {refusal}"
    except (AttributeError, TypeError, ValueError):
        return


@contextmanager
def plugin_probe_scope(
    plugin: Any, context: Any
) -> Iterator[Optional[SandboxUnavailable]]:
    """Sandbox what a scanner runs while it is constructed and validated.

    Scanners probe their tools before their scan starts:
    ``validate_plugin_dependencies`` runs the binary, and for a scanner that uses
    uv it also runs the deferred ``uv tool run <tool> --version`` probe (which
    construction only names). Those are third-party code too, so under a sandbox
    they run sandboxed, writing only to a throwaway directory. ``plugin`` may be
    the class, before it is constructed.

    A scanner that cannot be sandboxed gets a refusing scope, so its probes fail
    rather than run unsandboxed, and the block is given the refusal: None when
    there was none. ScanPhase reads it, and for every refusal the executor grades
    ERROR (``sandbox_refusal_grades_missing`` is False) it does not run the
    dependency check, whose probes could only fail for the sandbox: the scanner
    is queued and the executor refuses it before scan(), naming the refusal --
    the unavailable backend the operator named, or the planted symlink. An
    unavailable backend is also recorded as the scanner's dependency reason
    (_record_probe_refusal), so the MISSING a failed check records under auto
    names the sandbox.

    A scanner that runs offline while ASH does not (its own ``options.offline:
    true``) gets the offline tool variables on these probes as well, sandbox or not,
    as its scan command does: ``semgrep --version`` checks semgrep.dev and
    ``checkov --version`` pypi.org without them.
    """
    from automated_security_helper.utils.offline_tool_env import offline_tool_scope

    with offline_tool_scope(_probe_offline(plugin, context)):
        with _sandboxed_probe_scope(plugin, context) as refusal:
            yield refusal


def _probe_offline(plugin: Any, context: Any) -> bool:
    """Whether the scanner a probe scope covers runs offline by its own option.

    An instance answers for itself (``_scanner_offline``). A class, probed before it
    is constructed, has its option read from the run's config, the way ScanPhase
    builds it. False when neither says so; ASH's own offline mode is read where the
    variables are added (``offline_tool_environment``).
    """
    if not isinstance(plugin, type):
        check = getattr(plugin, "_scanner_offline", None)
        return bool(check()) if callable(check) else False
    config = getattr(context, "config", None)
    get_plugin_config = getattr(config, "get_plugin_config", None)
    if not callable(get_plugin_config):
        return False
    from automated_security_helper.base.plugin_config import plugin_config_key

    # A converter class's section is under converters, not scanners: read from
    # the scanners section, a converter named like a scanner read that
    # scanner's option.
    plugin_config = get_plugin_config(
        plugin_type=_plugin_section(plugin), plugin_name=plugin_config_key(plugin)
    )
    options = (
        plugin_config.get("options")
        if isinstance(plugin_config, dict)
        else getattr(plugin_config, "options", None)
    )
    offline = (
        options.get("offline")
        if isinstance(options, dict)
        else getattr(options, "offline", False)
    )
    return offline is True


def _plugin_section(plugin_class: type) -> str:
    """The config section a plugin class is configured under: converters or scanners."""
    from automated_security_helper.base.converter_plugin import ConverterPluginBase

    try:
        is_converter = issubclass(plugin_class, ConverterPluginBase)
    except TypeError:
        is_converter = False
    return "converter" if is_converter else "scanner"


@contextmanager
def _sandboxed_probe_scope(
    plugin: Any, context: Any
) -> Iterator[Optional[SandboxUnavailable]]:
    """The sandbox half of :func:`plugin_probe_scope`.

    The probe directory is removed however the block ends: made before the scope
    is built, it is removed in the one ``finally`` that covers the build too, so a
    build that raises anything but SandboxUnavailable leaves no directory behind.
    """
    import shutil
    import tempfile

    settings = _sandbox_settings(context)
    if settings is None or SandboxMode(settings.mode) == SandboxMode.off:
        yield None
        return
    probe_dir = Path(tempfile.mkdtemp(prefix="ash-sandbox-probe-"))
    try:
        probe: "SandboxScope | RefusingScope"
        hit: Optional[SandboxUnavailable] = None
        try:
            probe = scanner_sandbox_scope(plugin, context, None) or RefusingScope(
                str(getattr(plugin, "__name__", plugin.__class__.__name__)),
                "no sandbox scope",
            )
            if isinstance(probe, SandboxScope):
                probe.results_dir = probe_dir
        except SandboxUnavailable as refusal:
            probe = RefusingScope(_plugin_name(plugin), str(refusal))
            hit = refusal
            _record_probe_refusal(plugin, refusal)
        scope_reset = _ACTIVE.set(probe)
        try:
            yield hit
        finally:
            _ACTIVE.reset(scope_reset)
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)


def sandbox_requested(context: Any) -> bool:
    """Whether the run's ``sandbox.mode`` is anything but ``off``."""
    settings = _sandbox_settings(context)
    return settings is not None and SandboxMode(settings.mode) != SandboxMode.off


@contextmanager
def converter_run_scope(
    converter: Any, context: Any
) -> "Iterator[SandboxScope | RefusingScope | None]":
    """Sandbox what a converter's ``convert()`` runs, as a scanner's ``scan()`` is.

    A converter's tool reads the scanned tree like a scanner's, so under a sandbox its
    spawns get a scanner's policy, with the converter's results directory as the one
    writable place. When the sandbox cannot be provided the scope refuses every spawn,
    so a tool never runs unsandboxed. Yields the scope, None with the sandbox off: its
    ``refused_spawns`` says whether the converter lost inputs to a refusal, and its
    ``failed_spawns`` whether it lost them to a plan that failed some other way.
    """
    if not sandbox_requested(context):
        yield None
        return
    scope: "SandboxScope | RefusingScope"
    try:
        scope = scanner_sandbox_scope(converter, context, None) or RefusingScope(
            _plugin_name(converter), "no sandbox scope"
        )
    except SandboxUnavailable as refusal:
        scope = RefusingScope(_plugin_name(converter), str(refusal))
    scope_reset = _ACTIVE.set(scope)
    try:
        yield scope
    finally:
        _ACTIVE.reset(scope_reset)


def _plugin_name(plugin: Any) -> str:
    """The name a plugin is configured under: its config's, else its declared one.

    An instance whose config carries no name (a config built with an empty name,
    or a double without one) is named by what its class declares, as a class is;
    named by its class name instead, it read as a scanner renamed by a config
    file and was refused for a rename nothing made. The class name is the last
    resort, for a plugin that declares no name at all.
    """
    name = str(getattr(getattr(plugin, "config", None), "name", "") or "")
    if name:
        return name
    # The name its config class declares, which is what an instance of it is
    # called and what grants are looked up by.
    from automated_security_helper.base.plugin_config import declared_plugin_name

    plugin_class = plugin if isinstance(plugin, type) else type(plugin)
    return declared_plugin_name(plugin_class) or plugin_class.__name__


def _declared_identity(plugin: Any) -> "tuple[Optional[str], Optional[type]]":
    """The name and config class a scanner's own code declares, or (None, None).

    A config file can set ``name`` on a plugin's section, and a plugin whose section
    AshConfig does not type falls back to the generic config class when its own
    class rejects that name. Grants are looked up by name, so both are read from
    the plugin class, never from the config instance.
    """
    import typing

    from automated_security_helper.base.plugin_config import declared_plugin_name

    plugin_class = plugin if isinstance(plugin, type) else type(plugin)
    name = declared_plugin_name(plugin_class)
    if name is not None:
        field = getattr(plugin_class, "model_fields")["config"]
        for candidate in typing.get_args(field.annotation) or (field.annotation,):
            name_field = (getattr(candidate, "model_fields", None) or {}).get("name")
            if getattr(name_field, "default", None) == name:
                return name, candidate
        return name, None
    # Not a pydantic plugin class: read the config class's own default.
    config = getattr(plugin, "config", None)
    fields = getattr(type(config), "model_fields", None)
    if isinstance(fields, dict) and "name" in fields:
        default = fields["name"].default
        if isinstance(default, str) and default:
            return default, type(config)
    return None, None


@contextmanager
def sandbox_scope(scope: Optional[SandboxScope]) -> Iterator[None]:
    """Make ``scope`` the active one for spawns in this thread."""
    scope_reset = _ACTIVE.set(scope)
    try:
        yield
    finally:
        _ACTIVE.reset(scope_reset)


def active_scope() -> "SandboxScope | RefusingScope | None":
    return _ACTIVE.get()


#: Record-ONLY context for a uv run outside any sandbox scope: (values,
#: plugin inputs, the plugin's public command). Under the default sandbox
#: mode "off" there is no scope, but the process runner's own records (the
#: "Running command:" line, "Command stderr:") still quote the run's argv,
#: and a glued or pinned spec hidden on the report lines must not print
#: there. This context carries the SAME input set to those records; it
#: grants nothing and sandboxes nothing.
_RECORD_INPUTS: contextvars.ContextVar[
    Optional[Tuple[Tuple[str, ...], Tuple[str, ...], str]]
] = contextvars.ContextVar("ash_uv_record_inputs", default=None)


@contextmanager
def uv_record_inputs(
    values: Sequence[str], plugin_inputs: Sequence[str], command: str
) -> Iterator[None]:
    """Give a uv run's records their inputs while the block runs.

    Set by the uv dispatch around ``run_tool`` whatever the sandbox mode, so
    ``scope_shown_text`` can hide the run's plugin-built inputs even when no
    sandbox scope exists to carry them. An active sandbox scope's values and
    inputs are UNIONED with this context's: hiding another run's set hides
    more, never less, and choosing one source dropped whichever half the
    record was made from (a scope with inputs lost the dispatch-time values;
    a non-uv scope lost the inputs entirely).
    """
    token = _RECORD_INPUTS.set(
        (tuple(values), tuple(plugin_inputs), str(command or ""))
    )
    try:
        yield
    finally:
        _RECORD_INPUTS.reset(token)


def scope_shown_text(text: str, values: Sequence[str] = ()) -> str:
    """*text* for a record made while a scanner's sandbox scope may be active.

    The caller's ``values``, the scope's env-read values and a uv run's
    record-only context (``uv_record_inputs``, set by the dispatch whatever
    the sandbox mode) are all hidden together -- the UNION of both sources'
    values and inputs, because these records can quote a path or a tool's
    words, either can hold a value the plugin's config read from the
    environment, and preferring one source dropped whichever half the record
    was made from. With neither source, only the caller's values apply, and
    with none the text is unchanged.

    Never raises: its callers sit inside ``except`` blocks on the sweep and
    cleanup paths (fs_guard's symlink sweep, a sandbox plan's cleanup steps),
    where a raise from the redaction would stop the sweep partway or skip the
    remaining cleanup. A failure here returns a value-free note instead.
    """
    try:
        return _scope_shown_text(text, values)
    except Exception:
        return "(this text could not be shown)"


def _scope_shown_text(text: str, values: Sequence[str] = ()) -> str:
    scope = active_scope()
    merged = [value for value in values if value]
    for value in tuple(getattr(scope, "environment_values", ()) or ()):
        if value and value not in merged:
            merged.append(value)
    plugin_inputs = [
        entry for entry in tuple(getattr(scope, "plugin_inputs", ()) or ()) if entry
    ]
    # The plugin's public command, the SAME tool name every report line
    # passes: a scanner whose config name differs from its command otherwise
    # had the command replaced in these records and kept on the report
    # lines, numbering the placeholders differently. A non-empty command from
    # either source wins; the config name is the last resort, for a scope
    # built before construction with no record context.
    scope_command = str(getattr(scope, "command", "") or "")
    record = _RECORD_INPUTS.get()
    record_command = ""
    if record is not None:
        record_values, record_inputs, record_command = record
        for value in record_values:
            if value and value not in merged:
                merged.append(value)
        for entry in record_inputs:
            if entry and entry not in plugin_inputs:
                plugin_inputs.append(entry)
    tool_name = (
        scope_command or record_command or str(getattr(scope, "scanner_name", "") or "")
    )
    if plugin_inputs:
        from automated_security_helper.utils.uv_tool_runner import shown_uv_output

        return shown_uv_output(
            text,
            merged,
            plugin_inputs=tuple(plugin_inputs),
            tool_name=tool_name,
            limit=None,
        )
    if not merged:
        return text
    from automated_security_helper.utils.error_text import text_without_values

    return text_without_values(text, merged)


@contextmanager
def outside_scanner_sandbox() -> Iterator[None]:
    """Run the block's spawns unsandboxed, for ASH's own work on a scanner's behalf.

    For preparing content a sandboxed scanner then reads, such as trivy's database:
    a sandbox may mount the cache read-only or through a throwaway overlay, so an
    update made inside it would not reach the host, or would let one scanner change
    what the next one reads. The block runs no scanner code and reads nothing from
    the scanned tree.
    """
    previous = _ACTIVE.set(None)
    try:
        yield
    finally:
        _ACTIVE.reset(previous)


#: Programs that spawns in an ``also_runs`` block start besides their own argv0.
_ALSO_RUNS: contextvars.ContextVar[Tuple[str, ...]] = contextvars.ContextVar(
    "ash_sandbox_also_runs", default=()
)


@contextmanager
def also_runs(*executables: str) -> Iterator[None]:
    """Spawns in the block also start ``executables``: grant each as argv0 is granted.

    For ASH's own checks that hand a tool another program to run. The pre-installed
    tool check runs ``uv pip install --dry-run --python <interpreter>``, and uv runs
    that interpreter. A policy grants paths for argv0 only, so the interpreter's
    environment was readable only while a broad directory around uv (all of
    ~/.local, for a uv in ~/.local/bin) was mounted. Each executable named here gets
    the grants argv0 gets, through the same breadth filter
    (``policy._executable_prefix``): its directory and install prefix, never a home,
    a directory holding one, or a directory directly in one. Only ASH's own code names them; nothing a
    scanner's options say reaches this.
    """
    token = _ALSO_RUNS.set(_ALSO_RUNS.get() + tuple(executables))
    try:
        yield
    finally:
        _ALSO_RUNS.reset(token)


#: Directories spawns in a ``reads_directory`` block may read besides the policy's.
_READ_GRANTS: contextvars.ContextVar[Tuple[Path, ...]] = contextvars.ContextVar(
    "ash_sandbox_read_grants", default=()
)


@contextmanager
def reads_directory(directory: "str | Path") -> Iterator[None]:
    """Spawns in the block may read ``directory``: one existing directory, as data.

    For ASH's own checks that hand a tool a directory ASH made for the check. The
    pre-installed tool check stages a Nix program's distribution metadata under
    TMPDIR and asks ``uv pip install --dry-run --target <directory>`` about it;
    a policy grants argv0's paths and the interpreter's (``also_runs``), none of
    which reach a directory under TMPDIR, so under every backend the dry run
    could not read what it was asked about. The grant is the one directory,
    resolved, read-only and, under sandbox-exec, not executable (it joins the
    policy's ``scan_data``; the other backends do not restrict exec), for the
    spawns of this block alone. One directory per call: no pattern, no
    expansion, no parent; a path that is not an existing directory is refused
    (``NotADirectoryError``).

    The directory is RESOLVED here, once, and the resolved path is what is granted:
    the backends grant real paths (bwrap binds, Landlock lists and sandbox-exec
    allows ``os.path.realpath`` of every policy path), so a grant judged by its
    spelling and granted by its target would let a symlink named here stand in
    for wherever it points. The resolved directory is refused (``ValueError``) when
    it is one the breadth rules keep out of every policy (``_broader_than_a_tool``):
    a filesystem root, a home directory, a directory holding one, a directory
    directly in one, or one that holds the user's keyrings. Only ASH's own code
    names it; nothing a scanner's options say reaches this.
    """
    real = Path(os.path.realpath(directory))
    if real == Path(real.anchor) or _broader_than_a_tool(real):
        raise ValueError(
            "refusing to grant a directory as broad as a filesystem root or a home "
            f"for reading: {directory} resolves to {real}"
        )
    if not real.is_dir():
        raise NotADirectoryError(
            f"a read grant names a directory that does not exist: {real}"
        )
    token = _READ_GRANTS.set(_READ_GRANTS.get() + (real,))
    try:
        yield
    finally:
        _READ_GRANTS.reset(token)


def prepare_spawn(
    argv: Sequence[str],
    env: Optional[Mapping[str, str]],
    cwd: "str | Path | None",
) -> Optional[SpawnPlan]:
    """The sandboxed command for this spawn, or None when no scope is active.

    A spawn the plan refuses (SandboxUnavailable) is counted on the scope as a
    refusal; one whose planning failed any other way (a program the backend could
    not find, a private directory it could not make) is counted apart, as a
    failure. Either way the spawn did not run and a converter's row reads both
    counts for what it lost, but only the first was the sandbox's refusal: the
    second is the same error the spawn would have raised unsandboxed, met at
    planning time by a backend that resolves the program itself (Landlock) and
    at Popen time by one that does not (bwrap), so a converter's row must not
    call it a refusal.
    """
    scope = _ACTIVE.get()
    if scope is None:
        return None
    try:
        if isinstance(scope, RefusingScope):
            raise SandboxUnavailable(
                f"{scope.scanner_name} cannot be sandboxed as requested: {scope.reason}"
            )
        return _plan_spawn(scope, argv, env, cwd)
    except SandboxUnavailable as refusal:
        scope.refused_spawns += 1
        scope.last_refusal = str(refusal)
        raise
    except Exception as failure:
        scope.failed_spawns += 1
        scope.last_failure = f"{type(failure).__name__}: {failure}"
        raise


def _plan_spawn(
    scope: SandboxScope,
    argv: Sequence[str],
    env: Optional[Mapping[str, str]],
    cwd: "str | Path | None",
) -> SpawnPlan:
    """``prepare_spawn`` for an active scope: the policy, then the backend's plan."""
    # A snapshot rather than os.environ: scanner threads mutate the environment while
    # others spawn (see utils/process_env.py).
    base_env = dict(env) if env is not None else snapshot_environ()
    policy = build_scanner_policy(
        scope.scanner_name,
        scope.requirements,
        argv0=str(argv[0]),
        source_dir=scope.source_dir,
        output_dir=scope.output_dir,
        results_dir=scope.results_dir,
        scan_target=scope.scan_target,
        cwd=Path(cwd) if cwd else None,
        offline=scope.offline,
        network_scanners=scope.network_scanners,
        extra_read_paths=scope.extra_read_paths,
        network_limit=scope.network_limit,
        read_path_scanners=scope.read_path_scanners,
        env_scanners=scope.env_scanners,
        # This thread's scanner run's own config files, and no other run's.
        tool_config_dir=active_tool_config_dir(),
        also_runs=_ALSO_RUNS.get(),
        scanned_trees=scope.scanned_trees,
        read_grants=_READ_GRANTS.get(),
    )
    plan = scope.backend.plan(list(argv), base_env, policy)
    # Everything after the plan runs under its cleanup: a registration that
    # raises, or the record below, would otherwise leave the backend's private
    # directories behind and the roots registered so far held.
    writable: List[Path] = []
    try:
        writable.extend(register_writable_root(path) for path in policy.writable)
    except BaseException:
        # The roots registered before the one that raised, released here because
        # the release step below is not in the plan yet.
        for root in writable:
            release_writable_root(root)
        plan.run_cleanup()
        raise

    def sweep() -> None:
        sweep_writable(
            writable,
            scope.environment_values,
            values_unread=scope.environment_values_unread,
            skip=plan.private_dirs,
        )

    def release() -> None:
        # This spawn's registrations; its scope's and the output directory's
        # stay.
        for root in writable:
            release_writable_root(root)

    # The sweep is the cleanup's FIRST step: before the backend's own steps and
    # before every write ASH makes into the results directory afterwards (the
    # stream logs; subprocess_utils._write_stream_logs runs the cleanup for
    # exactly this), so a link a scanner left at a log's name is gone before the
    # write. It passes over the plan's private directories: the backend's own
    # step removes each whole (shutil.rmtree follows no link), and what they
    # hold, the cache entries uv links, is ASH's own and not something the
    # scanner left to be counted and removed as a scanner's.
    plan.cleanup.insert(0, sweep)
    plan.cleanup.insert(1, release)
    try:
        _record_plan(scope, policy, plan)
    except BaseException:
        # The release step is in the plan now, so run_cleanup releases each
        # root once; releasing here as well would take a registration the
        # scope or the output directory still holds on the same root.
        plan.run_cleanup()
        raise
    return plan


def _record_plan(scope: SandboxScope, policy: Any, plan: SpawnPlan) -> None:
    """The DEBUG record of a planned spawn.

    The planned argv is plugin-built text, so it can carry an env-read value,
    and for a uv run it carries the run's own inputs: the record goes through
    the one scope-record helper (scope_shown_text), which applies the full uv
    layer when the scope carries inputs and the plain value layer otherwise;
    the active scope here is this spawn's own. When the plugin's values could
    not be read (``environment_values_unread``) nothing in the argv can be
    redacted, so the record names the spawn and not its argv.

    A failure while the record is made (an argument whose ``str`` raises) is
    logged by its type and does not reach the caller: the record is a log line, and
    raising from it failed a spawn that was planned, counted it as a failed plan,
    and ran the plan's cleanup. Only ``Exception`` is absorbed here; an interrupt
    still reaches ``_plan_spawn``'s cleanup.

    Guarded by BOTH halves of emission: .debug() is gated by the logger's level
    (isEnabledFor), and the record then has to reach a handler whose level admits
    it (utils/log.py delivers). The CLI's logger sits at TRACE with its file
    handlers at INFO, so the logger-level check alone was always true there and
    the regex work ran for records no handler took; delivers alone would build
    the record a raised logger level never emits.
    """
    if not (
        ASH_LOGGER.isEnabledFor(logging.DEBUG) and delivers(ASH_LOGGER, logging.DEBUG)
    ):
        return
    try:
        head = (
            f"Scanner sandbox ({scope.backend.name}, "
            f"network={'yes' if policy.network else 'no'}) for {scope.scanner_name}"
        )
        if scope.environment_values_unread:
            # A class scope has no values hook to read, so nothing failed there;
            # the instance case is a hook that raised or gave no value set.
            why = (
                "a class scope carries no redaction values"
                if scope.class_scope
                else "the plugin's redaction values could not be read"
            )
            ASH_LOGGER.debug(
                f"{head}: the planned command line is not shown because {why}"
            )
            return
        ASH_LOGGER.debug(
            scope_shown_text(
                f"{head}: {_argv_text(plan.argv)}", _quoted_spellings(scope)
            )
        )
    except Exception as failure:  # noqa: BLE001 -- a log line must not fail a spawn
        # An argument whose text cannot be made, or a policy that lacks a field:
        # the spawn is still planned and still runs. Only the type is said, never
        # the message, which may quote the argument.
        ASH_LOGGER.debug(
            f"Scanner sandbox for {scope.scanner_name}: the planned command line "
            f"could not be recorded ({type(failure).__name__})"
        )


def _argv_text(argv: Sequence[Any]) -> str:
    """``argv`` as one shell-quoted line, for the record of a planned spawn.

    Each argument as the text the process will see: subprocess accepts a path
    object or a bytes argument, and a plain join raised TypeError for a path here,
    after the plan had made its temporary directories and the writable-root
    registrations above, which nothing then released. A bytes argument is decoded
    like a path (``os.fsdecode``), not shown by its ``str``: that prints the
    escaped bytes (``b'--token=s\\xc3\\xa9cret'``), which a redaction of the value
    by its text never matches and anyone can decode. Quoted (``shlex.join``) so
    an argument holding a blank stays one argument in the record.
    """
    return shlex.join(
        os.fsdecode(arg) if isinstance(arg, (bytes, os.PathLike)) else str(arg)
        for arg in argv
    )


def _quoted_spellings(scope: SandboxScope) -> List[str]:
    """The spellings ``shlex.quote`` gives the hidden texts that differ from them.

    ``scope_shown_text`` hides a value, and a uv run's plugin-built input, by
    its text. Quoting rewrites only a quote character inside an argument, so a
    text holding one is spelled differently in the quoted line and would print:
    its quoted spelling is passed as a value to hide as well. Covers the
    scope's env-read values and plugin inputs and the uv record context's
    (``uv_record_inputs``), the same set ``scope_shown_text`` merges. Runs
    before that function's never-raises wrapper and inside the window after the
    writable-root registrations, so it raises for nothing: an entry that is
    not text is passed over (``scope_shown_text`` ignores it the same way).
    """
    merged: List[Any] = list(scope.environment_values or ())
    merged.extend(scope.plugin_inputs or ())
    record = _RECORD_INPUTS.get()
    if record is not None:
        merged.extend(record[0])
        merged.extend(record[1])
    spellings: List[str] = []
    for value in merged:
        if isinstance(value, str) and value and "'" in value:
            quoted = shlex.quote(value)[1:-1]
            if quoted not in spellings:
                spellings.append(quoted)
    return spellings
