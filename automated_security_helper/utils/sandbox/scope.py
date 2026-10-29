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
import platform
import shlex
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

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
    _refuse_symlinked_results_dir,
    refuse_symlinked_output_dir,
    build_scanner_policy,
)
from automated_security_helper.utils.tool_config_dir import active_tool_config_dir


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
    #: Spawns this scope refused (the backend could not plan them), and why the last
    #: one was. A converter's row reads them: a refused spawn converted nothing.
    refused_spawns: int = 0
    last_refusal: Optional[str] = None
    #: The owning plugin's env-read values, for the one line this module logs
    #: itself: a planned argv can carry a value the plugin's config read from
    #: the environment.
    environment_values: Tuple[str, ...] = ()
    #: True when the plugin's values hook raised or gave no value set when
    #: the scope was built. ``environment_values`` is then empty, which must
    #: not read as "no values": the post-spawn sweep, whose only redaction is
    #: this scope's values, names no entry or path in its notes.
    environment_values_unread: bool = False
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


_ACTIVE: contextvars.ContextVar["SandboxScope | RefusingScope | None"] = (
    contextvars.ContextVar("ash_sandbox_scope", default=None)
)

_probe_lock = threading.Lock()
# Keyed by mode and by the scanned-tree scope: which bwrap or firejail a probe finds
# depends on the trees being scanned and the in-tree opt-in, so a scan of one tree
# must not reuse a backend another scan's lookup chose.
_resolved: Dict[Any, "SandboxBackend | SandboxUnavailable"] = {}

#: Fragments of a probe's reason that name a passing condition, not a missing
#: feature: the probe process ran past the backend's probe timeout (the text
#: subprocess gives a TimeoutExpired, which ``SandboxBackend.probe`` keeps as
#: the reason), or the kernel refused a resource for now (EAGAIN's strerror).
#: Such a refusal is reported for this request and not remembered, so the next
#: scan of the tree probes again; a missing program or kernel feature is
#: remembered for the process like a working backend is.
_TRANSIENT_REASON_MARKERS: Tuple[str, ...] = ("timed out", "temporarily unavailable")


def _probe_reason_is_transient(refusal: SandboxUnavailable) -> bool:
    """Whether the probe that produced ``refusal`` could answer differently later.

    Read from the reason's text: the backends report a probe that raised as text,
    so the exception class is not available here. Under auto the reason joins
    every backend's, and one transient member makes the whole answer transient,
    which re-probes the others too. The cost is one more probe per request of
    ``resolve_backend`` (one per scanner, serialized by the lock, each bounded
    by the backend's probe timeout) for as long as the condition lasts, where
    remembering a timeout refused or downgraded every later scan in the process.
    """
    reason = str(refusal)
    return any(marker in reason for marker in _TRANSIENT_REASON_MARKERS)


def clear_backend_cache() -> None:
    """Forget probe results. For tests."""
    with _probe_lock:
        _resolved.clear()


class SandboxBackendUnavailable(SandboxUnavailable):
    """No working backend for the requested sandbox mode.

    Carries the requested mode, so a reader can tell a backend the operator
    named that is unavailable (the tool could not start as requested) from
    ASH's own default finding no backend (a missing dependency). Any other
    SandboxUnavailable is a refusal, not an availability failure.
    """

    def __init__(self, reason: str, mode: str):
        super().__init__(reason)
        self.mode = mode


def _probe_backend(name: str) -> SandboxBackend:
    backend = BACKENDS[name]()
    reason = backend.probe()
    if reason:
        raise SandboxUnavailable(reason)
    return backend


def resolve_backend(mode: "SandboxMode | str") -> SandboxBackend:
    """The working backend for ``mode``; raises SandboxUnavailable with the reason.

    Probed once per process and mode, under a lock, because parallel scanner threads
    ask at the same moment and each probe starts a process. A refusal whose reason
    is transient (``_probe_reason_is_transient``) is raised but not kept, so the
    next request probes again.
    """
    from automated_security_helper.utils.subprocess_utils import tree_scope_key

    mode_value = SandboxMode(mode).value
    if mode_value == SandboxMode.off.value:
        raise ValueError("resolve_backend called for sandbox mode 'off'")
    cache_key = (mode_value, tree_scope_key())
    with _probe_lock:
        cached = _resolved.get(cache_key)
        if cached is None:
            try:
                if mode_value == SandboxMode.auto.value:
                    cached = _resolve_auto()
                else:
                    cached = _probe_backend(mode_value)
                ASH_LOGGER.info(
                    f"Scanner sandbox: using {cached.name} (--sandbox {mode_value})"
                )
            except SandboxUnavailable as e:
                cached = e
            if not (
                isinstance(cached, SandboxUnavailable)
                and _probe_reason_is_transient(cached)
            ):
                _resolved[cache_key] = cached
    if isinstance(cached, SandboxUnavailable):
        # Classified at the raise, not in the cache, so a cached refusal is
        # always graded with the mode of the current request.
        raise SandboxBackendUnavailable(str(cached), mode_value) from cached
    return cached


def _resolve_auto() -> SandboxBackend:
    system = platform.system().lower()
    order = AUTO_ORDER.get(system, ())
    if not order:
        raise SandboxUnavailable(
            f"no scanner sandbox is available on {platform.system()}; run ASH under "
            "WSL2 and use --sandbox bwrap there, or use --mode container"
        )
    reasons = []
    for name in order:
        try:
            return _probe_backend(name)
        except SandboxUnavailable as e:
            reasons.append(f"{name}: {e}")
    raise SandboxUnavailable(
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
    if declared is not None and (
        declared != name
        or (
            declared_config is not None
            and config is not None
            and not isinstance(config, declared_config)
        )
    ):
        raise SandboxUnavailable(
            f"{name}: the config names this scanner {name!r}, but its own name is "
            f"{declared!r}. Sandbox grants follow a scanner's own name, so a "
            "scanner renamed by a config file is not run sandboxed."
        )
    requirements = getattr(scanner_plugin, "sandbox_requirements", None)
    if not isinstance(requirements, SandboxRequirements):
        requirements = SandboxRequirements()
    environment_values: Tuple[str, ...] = ()
    environment_values_unread = False
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
    _refuse_symlinked_results_dir(Path(context.output_dir), Path(results_dir))
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
        ASH_LOGGER.warning(
            f"{name}'s settings ask for a network, and those settings can come from "
            "the scanned repository, so the sandbox does not grant it. To allow it, "
            f"add {name} to sandbox.network_scanners with --config-overrides or a "
            "config file outside every git checkout and the scanned directory."
        )
    read_path_scanners = list(getattr(settings, "read_path_scanners", []) or [])
    env_scanners = list(getattr(settings, "env_scanners", []) or [])
    for withheld, key in (
        (
            (requirements.read_paths or requirements.cache_paths)
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
            ASH_LOGGER.warning(
                f"{name}'s settings ask for "
                f"{'host paths' if key == 'read_path_scanners' else 'environment variables'}"
                " the default policy does not allow, and those settings can come "
                "from the scanned repository, so the sandbox does not grant them. "
                f"To allow them, add {name} to sandbox.{key} with "
                "--config-overrides or a config file outside every git checkout "
                "and the scanned directory."
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
        plugin_inputs=plugin_inputs,
        command=command,
    )
    # Released when the scope is collected, or when the scan ends (run_roots).
    release_with_holder(scope, results_root)
    return scope


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

    plugin_config = get_plugin_config(
        plugin_type="scanner", plugin_name=plugin_config_key(plugin)
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


@contextmanager
def _sandboxed_probe_scope(
    plugin: Any, context: Any
) -> Iterator[Optional[SandboxUnavailable]]:
    """The sandbox half of :func:`plugin_probe_scope`."""
    import shutil
    import tempfile

    settings = _sandbox_settings(context)
    if settings is None or SandboxMode(settings.mode) == SandboxMode.off:
        yield None
        return
    probe_dir = Path(tempfile.mkdtemp(prefix="ash-sandbox-probe-"))
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
    ``refused_spawns`` says whether the converter lost inputs to a refusal.
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
    name = str(getattr(getattr(plugin, "config", None), "name", "") or "")
    if name:
        return name
    if isinstance(plugin, type):
        # The name its config class declares, which is what an instance of it is
        # called and what grants are looked up by.
        from automated_security_helper.base.plugin_config import declared_plugin_name

        return declared_plugin_name(plugin) or plugin.__name__
    return plugin.__class__.__name__


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


def prepare_spawn(
    argv: Sequence[str],
    env: Optional[Mapping[str, str]],
    cwd: "str | Path | None",
) -> Optional[SpawnPlan]:
    """The sandboxed command for this spawn, or None when no scope is active."""
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
    )
    plan = scope.backend.plan(list(argv), base_env, policy)
    # First in line once the process has exited: nothing ASH writes into the
    # results directory afterwards may follow a link the scanner left there.
    writable = [register_writable_root(path) for path in policy.writable]

    def sweep() -> None:
        sweep_writable(
            writable,
            scope.environment_values,
            values_unread=scope.environment_values_unread,
        )

    def release() -> None:
        # This spawn's registrations; its scope's and the output directory's stay.
        for root in writable:
            release_writable_root(root)

    plan.cleanup.insert(0, sweep)
    plan.cleanup.insert(1, release)
    # The planned argv is plugin-built text, so it can carry an env-read
    # value, and for a uv run it carries the run's own inputs: the record
    # goes through the one scope-record helper (scope_shown_text), which
    # applies the full uv layer when the scope carries inputs and the plain
    # value layer otherwise -- the active scope here is this spawn's own.
    # Guarded by BOTH halves of emission: .debug() is gated by the logger's
    # level (isEnabledFor), and the record then has to reach a handler whose
    # level admits it (utils/log.py delivers). The CLI's logger sits at TRACE
    # with its file handlers at INFO, so the logger-level check alone was
    # always true there and the regex work ran for records no handler took;
    # delivers alone would build the record a raised logger level never emits.
    if ASH_LOGGER.isEnabledFor(logging.DEBUG) and delivers(ASH_LOGGER, logging.DEBUG):
        ASH_LOGGER.debug(
            scope_shown_text(
                f"Scanner sandbox ({scope.backend.name}, "
                f"network={'yes' if policy.network else 'no'}) "
                f"for {scope.scanner_name}: {_argv_text(plan.argv)}",
                _quoted_spellings(scope),
            )
        )
    return plan


def _argv_text(argv: Sequence[Any]) -> str:
    """``argv`` as one shell-quoted line, for the record of a planned spawn.

    Each argument by its ``str``: subprocess accepts a path object as an
    argument, and a plain join raised TypeError for one here, after the plan
    had made its temporary directories and the writable-root registrations
    above, which nothing then released. Quoted (``shlex.join``) so an argument
    holding a blank stays one argument in the record.
    """
    return shlex.join(str(arg) for arg in argv)


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
