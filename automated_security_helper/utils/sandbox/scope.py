"""Which sandbox, if any, applies to the spawn happening now.

The scanner executor enters :func:`sandbox_scope` around each ``scanner.scan()`` call.
The scope lives in a context variable, so it is per thread: scanners run in parallel
threads, each with its own policy, and spawns ASH makes outside a scanner (``git``,
converters, the container runtime) see no scope and are left alone.
:func:`prepare_spawn` is called by every spawn helper in ``utils/subprocess_utils.py``;
it is the single place a command line is rewritten for a sandbox.

A scanner that starts a process from a thread it created itself would not inherit the
scope. No builtin scanner does; ``tests/unit/utils/test_sandbox_choke_point.py`` keeps
scanner modules off raw ``subprocess`` so their spawns go through the helpers.
"""

from __future__ import annotations

import contextvars
import platform
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence

from automated_security_helper.core.enums import SandboxMode
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.backends import (
    AUTO_ORDER,
    BACKENDS,
    SandboxBackend,
    SpawnPlan,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    SandboxUnavailable as SandboxUnavailable,
    _refuse_symlinked_results_dir,
    build_scanner_policy,
)


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


@dataclass
class RefusingScope:
    """A scope for a scanner that asked for a sandbox it cannot have.

    Active while such a scanner is constructed and validated, so that its probes
    (``tool --version``, ``uv tool run``) fail instead of running unsandboxed.
    """

    scanner_name: str
    reason: str


_ACTIVE: contextvars.ContextVar["SandboxScope | RefusingScope | None"] = (
    contextvars.ContextVar("ash_sandbox_scope", default=None)
)

_probe_lock = threading.Lock()
_resolved: Dict[str, "SandboxBackend | SandboxUnavailable"] = {}


def clear_backend_cache() -> None:
    """Forget probe results. For tests."""
    with _probe_lock:
        _resolved.clear()


def _probe_backend(name: str) -> SandboxBackend:
    backend = BACKENDS[name]()
    reason = backend.probe()
    if reason:
        raise SandboxUnavailable(reason)
    return backend


def resolve_backend(mode: "SandboxMode | str") -> SandboxBackend:
    """The working backend for ``mode``; raises SandboxUnavailable with the reason.

    Probed once per process and mode, under a lock, because parallel scanner threads
    ask at the same moment and each probe starts a process.
    """
    mode_value = SandboxMode(mode).value
    if mode_value == SandboxMode.off.value:
        raise ValueError("resolve_backend called for sandbox mode 'off'")
    with _probe_lock:
        cached = _resolved.get(mode_value)
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
            _resolved[mode_value] = cached
    if isinstance(cached, SandboxUnavailable):
        raise cached
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
    have one; the executor records the scanner MISSING with that message.
    """
    from automated_security_helper.core.constants import is_offline_mode

    settings = _sandbox_settings(context)
    mode = SandboxMode(settings.mode if settings is not None else SandboxMode.off)
    if mode == SandboxMode.off:
        return None

    name = _plugin_name(scanner_plugin)
    requirements = getattr(scanner_plugin, "sandbox_requirements", None)
    if not isinstance(requirements, SandboxRequirements):
        requirements = SandboxRequirements()

    backend = resolve_backend(mode)
    results_dir = getattr(scanner_plugin, "results_dir", None)
    if not isinstance(results_dir, (str, Path)):
        results_dir = Path(context.output_dir).joinpath("scanners", name)
    # Checked here as well as when each spawn's policy is built, so a planted
    # symlink makes the scanner MISSING with the reason rather than ERROR.
    _refuse_symlinked_results_dir(Path(context.output_dir), Path(results_dir))
    network_scanners = getattr(settings, "network_scanners", None)
    return SandboxScope(
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
    )


@contextmanager
def plugin_probe_scope(plugin: Any, context: Any) -> Iterator[None]:
    """Sandbox what a scanner runs while it is constructed and validated.

    Scanners probe their tools before any scan starts: ``model_post_init`` runs
    ``uv tool run <tool> --version`` for a scanner that may not even be selected,
    and ``validate_plugin_dependencies`` runs the binary. Those are third-party code
    too, so under a sandbox they run sandboxed, writing only to a throwaway
    directory. ``plugin`` may be the class, before it is constructed.

    A scanner that cannot be sandboxed gets a refusing scope, so its probes fail
    rather than run unsandboxed, and it is recorded MISSING later with the reason.
    """
    import shutil
    import tempfile

    settings = _sandbox_settings(context)
    if settings is None or SandboxMode(settings.mode) == SandboxMode.off:
        yield
        return
    probe_dir = Path(tempfile.mkdtemp(prefix="ash-sandbox-probe-"))
    probe: "SandboxScope | RefusingScope"
    try:
        probe = scanner_sandbox_scope(plugin, context, None) or RefusingScope(
            str(getattr(plugin, "__name__", plugin.__class__.__name__)),
            "no sandbox scope",
        )
        if isinstance(probe, SandboxScope):
            probe.results_dir = probe_dir
    except SandboxUnavailable as refusal:
        probe = RefusingScope(_plugin_name(plugin), str(refusal))
    token = _ACTIVE.set(probe)
    try:
        yield
    finally:
        _ACTIVE.reset(token)
        shutil.rmtree(probe_dir, ignore_errors=True)


def _plugin_name(plugin: Any) -> str:
    name = str(getattr(getattr(plugin, "config", None), "name", "") or "")
    if name:
        return name
    if isinstance(plugin, type):
        return plugin.__name__
    return plugin.__class__.__name__


@contextmanager
def sandbox_scope(scope: Optional[SandboxScope]) -> Iterator[None]:
    """Make ``scope`` the active one for spawns in this thread."""
    token = _ACTIVE.set(scope)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def active_scope() -> "SandboxScope | RefusingScope | None":
    return _ACTIVE.get()


def prepare_spawn(
    argv: Sequence[str],
    env: Optional[Mapping[str, str]],
    cwd: "str | Path | None",
) -> Optional[SpawnPlan]:
    """The sandboxed command for this spawn, or None when no scope is active."""
    scope = _ACTIVE.get()
    if scope is None:
        return None
    if isinstance(scope, RefusingScope):
        raise SandboxUnavailable(
            f"{scope.scanner_name} cannot be sandboxed as requested: {scope.reason}"
        )
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
    )
    plan = scope.backend.plan(list(argv), base_env, policy)
    ASH_LOGGER.debug(
        f"Scanner sandbox ({scope.backend.name}, network={'yes' if policy.network else 'no'}) "
        f"for {scope.scanner_name}: {' '.join(plan.argv)}"
    )
    return plan
