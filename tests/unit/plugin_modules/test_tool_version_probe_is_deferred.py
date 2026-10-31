# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin asks uv for its tool's version only when its dependencies are checked.

The defect
----------
bandit, checkov and semgrep ran ``uv tool run --from <spec> <tool> --version`` from
``model_post_init``, which resolves the tool and downloads it when uv's cache lacks
it. The scan phase constructs every registered scanner before it applies
``--scanners`` (scan_phase.py), and ``ash plugin list`` constructs them all as well,
so a scan of one scanner probed all three, online unless ASH_OFFLINE was set, and so
did every test that built a real scanner. The jupyter converter had the same probe
and had been given its own way out (probe only once a notebook needs nbconvert).

The probe is named at construction and run once, from the dependency check,
which runs only for a plugin that is going to run or whose dependencies are asked
about (the scanner inventory asks). Both readers of the version, the SARIF a scan
writes and the inventory, also run a pending probe before they read it.

What the tests do
-----------------
Every scanner and converter the shipped plugin packages register is constructed
with every process start refused and recorded (an audit hook sees
``subprocess.Popen``, ``os.posix_spawn``, ``os.system``, ``os.exec*``,
``os.spawn*`` and ``os.fork``, however the code reached them) and uv's version
probe recorded, and must start nothing and leave no new thread behind. The plugins
that had the probe must then run it once, on their first dependency check, and the
SARIF reader must run it for a plugin whose check never ran. A real
``ash scan --scanners bandit`` in a child interpreter, with a stand-in ``uv`` that
records its calls (first on PATH, and the uv ASH's lookup finds; see
tests/utils/stand_in_uv.py), must ask about bandit and about nothing else.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils import uv_tool_runner
from tests.utils.helpers import importing_this_checkout
from tests.utils.stand_in_uv import (
    UV_PROBED_TOOLS,
    assert_reached_the_stand_in,
    calls_naming,
    install_stand_in_uv,
    reaching_the_stand_in,
    recorded_calls,
    stand_in_env,
)


def _shipped_plugin_classes():
    """Every scanner and converter class the shipped plugin packages register.

    Resolved through ash_plugin_manager.plugin_modules() after importing every
    package under automated_security_helper.plugin_modules, so a plugin added to
    any of them is covered without editing this file. Classes from modules outside
    that package (other tests' plugin packages, in this process) are left out.
    """
    import importlib
    import pkgutil

    from automated_security_helper import plugin_modules
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.loader import load_internal_plugins

    load_internal_plugins()
    for package in pkgutil.iter_modules(plugin_modules.__path__):
        if package.ispkg:
            importlib.import_module(f"{plugin_modules.__name__}.{package.name}")
    shipped = plugin_modules.__name__ + "."
    classes = {
        cls
        for kind in ("scanner", "converter")
        for cls in ash_plugin_manager.plugin_modules(kind)
        if cls.__module__.startswith(shipped)
    }
    return sorted(classes, key=lambda cls: cls.__name__)


SHIPPED = _shipped_plugin_classes()

#: The audit events that start a process. A recording audit hook refuses each one
#: while _PROCESS_STARTS is a list; the hook cannot be removed, so it is inert
#: otherwise.
_PROCESS_START_EVENTS = {
    "subprocess.Popen",
    "os.posix_spawn",
    "os.system",
    "os.exec",
    "os.spawn",
    "os.fork",
    "os.forkpty",
}
_PROCESS_STARTS: list | None = None


def _argv_of(event, args):
    """The command an event names, never the environment it carries."""
    if event in ("subprocess.Popen", "os.posix_spawn", "os.exec"):
        return args[1]
    if event == "os.spawn":
        return args[2]
    if event == "os.system":
        return args[0]
    return None


def _refuse_process_starts(event, args):
    starts = _PROCESS_STARTS
    if starts is not None and event in _PROCESS_START_EVENTS:
        starts.append((event, _argv_of(event, args)))
        raise RuntimeError(f"this test allows no process to start ({event})")


sys.addaudithook(_refuse_process_starts)

#: The plugins that defer a version probe, and the tool each one probes.
PROBED = {
    "BanditScanner": "bandit",
    "CheckovScanner": "checkov",
    "SemgrepScanner": "semgrep",
}


@pytest.fixture
def plugin_context(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="deferred-probe"),
    )


@pytest.fixture
def recorders(monkeypatch):
    """Record every process start and every uv version probe, and allow none."""
    global _PROCESS_STARTS
    spawned: list = []
    probed = []

    def _probe(self, tool_name, package_name=None, *a, **k):
        probed.append(tool_name)
        return f"{tool_name} 0.0.0"

    monkeypatch.setattr(uv_tool_runner.UVToolRunner, "get_tool_version", _probe)
    # The mixin asks uv_availability() first; the tool guard answers it as a host
    # without uv, which would end the probe before the recorder sees it.
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "uv_availability", lambda self: (True, None)
    )
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: True
    )
    _PROCESS_STARTS = spawned
    try:
        yield spawned, probed
    finally:
        _PROCESS_STARTS = None


def _defined_below_plugin_modules() -> set:
    """Every scanner and converter class a module below plugin_modules defines.

    Counted independently of SHIPPED: every module there imported by walking the
    package, not through the registry, so a sweep that silently shrank (a hard-coded
    list, say, that a new package is missing from) disagrees with it.
    """
    import importlib
    import pkgutil

    from automated_security_helper import plugin_modules

    found = set()
    for info in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        module = importlib.import_module(info.name)
        found.update(
            value
            for value in vars(module).values()
            if isinstance(value, type)
            and getattr(value, "ash_plugin_type", None) in ("scanner", "converter")
            and value.__module__ == module.__name__
        )
    return found


@pytest.mark.unit
def test_the_sweep_covers_every_shipped_scanner_and_converter():
    names = {cls.__name__ for cls in SHIPPED}
    assert set(PROBED) <= names
    assert {"JupyterConverter", "ArchiveConverter", "SnykCodeScanner"} <= names
    assert set(SHIPPED) == _defined_below_plugin_modules(), sorted(names)


@pytest.mark.unit
def test_the_recorders_see_a_process_start_by_any_route(recorders, tmp_path):
    """Control: each route a constructor could take to start a tool is caught."""
    import threading

    spawned, _ = recorders
    attempts = {
        "subprocess.Popen": lambda: subprocess.run(["true"], check=False),
        "os.system": lambda: os.system("true"),
    }
    if hasattr(os, "posix_spawn"):
        attempts["os.posix_spawn"] = lambda: os.posix_spawn("/bin/true", ["true"], {})
    for attempt in attempts.values():
        with pytest.raises(RuntimeError, match="allows no process"):
            attempt()
    assert [event for event, _ in spawned] == list(attempts)
    # On Windows, Popen joins the argument list into one command line before it
    # raises the audit event, so the recorded arguments are the string "true";
    # elsewhere they are the list. Each platform expects exactly its own form.
    expected_args = "true" if os.name == "nt" else ["true"]
    assert spawned[0][1] == expected_args
    started = threading.Timer(30, lambda: None)
    started.start()
    try:
        assert started in _new_threads(set())
    finally:
        started.cancel()


@pytest.mark.skipif(
    not os.path.isdir("/proc/self/task"), reason="lists threads through /proc"
)
@pytest.mark.unit
def test_the_os_thread_listing_sees_a_thread_threading_does_not():
    """Control: _thread.start_new_thread is not in threading.enumerate().

    The started thread records its own native id and the assertion looks for
    exactly that id among the new tids: a raw thread some other test or
    library left running in this window would otherwise satisfy a bare
    "any new tid" read, and the control would pass with the counted start
    removed.
    """
    import _thread
    import threading
    import time

    before_threads = set(threading.enumerate())
    before_tids = _os_thread_ids()
    release = threading.Event()
    recorded: list[str] = []

    def _record_then_wait():
        recorded.append(str(threading.get_native_id()))
        release.wait(30)

    _thread.start_new_thread(_record_then_wait, ())
    try:
        # The OS thread exists once start_new_thread returns, but the body's
        # record is the thread's own first statement, so give it a moment.
        deadline = time.monotonic() + 30
        while not recorded and time.monotonic() < deadline:
            time.sleep(0.01)
        assert recorded, "the started thread never ran its body"
        assert recorded[0] in _os_thread_ids() - before_tids
        assert _new_threads(before_threads) == []
    finally:
        release.set()


@pytest.mark.skipif(
    not os.path.isdir("/proc/self/task"), reason="lists threads through /proc"
)
@pytest.mark.unit
def test_a_thread_count_misses_a_left_raw_thread_the_tid_set_catches():
    """Pin of the miss the id-set comparison closes.

    The shape: in the measured window a raw thread is left running while an
    unrelated thread exits. The count nets to zero, so "after <= before"
    passes over the leak; the id set names the left thread exactly. Both
    reads go through _os_thread_ids, the helper the guarded cell and the
    control use, so what this pins is the comparison the suite runs.
    """
    import _thread
    import threading
    import time

    unrelated_may_exit = threading.Event()
    unrelated = threading.Thread(target=unrelated_may_exit.wait, args=(30,))
    unrelated.start()
    left_may_exit = threading.Event()
    left_tid: list[str] = []

    def _left_thread():
        left_tid.append(str(threading.get_native_id()))
        left_may_exit.wait(30)

    try:
        before = _os_thread_ids()
        count_before = len(before)
        # The window: a raw thread is left behind, the unrelated one exits.
        _thread.start_new_thread(_left_thread, ())
        unrelated_may_exit.set()
        unrelated.join(timeout=30)
        # The left thread appends its tid as its first statement, possibly
        # after a sample was taken, so the loop settles only on a sample that
        # holds that tid and no longer holds the unrelated thread's.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            after = _os_thread_ids()
            if (
                left_tid
                and left_tid[0] in after
                and str(unrelated.native_id) not in after
            ):
                break
            time.sleep(0.01)
        assert left_tid, "the left thread never ran its body"
        assert str(unrelated.native_id) not in after, "the exit never landed"
        # The miss: counts net the left start against the unrelated exit.
        assert len(after) <= count_before
        # The catch: the id set names the left thread.
        assert left_tid[0] in after - before
    finally:
        unrelated_may_exit.set()
        left_may_exit.set()


def _new_threads(before):
    import threading

    return [t for t in threading.enumerate() if t not in before and t.is_alive()]


def _os_thread_ids():
    """The process's OS thread ids, or None where /proc does not list them.

    Unlike threading.enumerate(), the listing includes threads started with
    _thread.start_new_thread. Ids, not a count: a comparison of counts reads
    "one left behind while an unrelated one exited" as zero, and sees nothing.
    """
    try:
        return set(os.listdir("/proc/self/task"))
    except OSError:
        return None


@pytest.mark.parametrize("plugin_class", SHIPPED, ids=lambda cls: cls.__name__)
@pytest.mark.unit
def test_constructing_a_plugin_starts_nothing(plugin_class, plugin_context, recorders):
    import threading

    spawned, probed = recorders
    before = set(threading.enumerate())
    tids_before = _os_thread_ids()

    plugin = plugin_class(context=plugin_context)

    tids_after = _os_thread_ids()
    assert spawned == [], f"{plugin_class.__name__} started {spawned}"
    assert probed == [], f"{plugin_class.__name__} probed {probed}"
    assert _new_threads(before) == [], f"{plugin_class.__name__} left a thread"
    # A raw _thread.start_new_thread thread is in neither list above, and can start
    # a process once the recorders are gone. Compared as id sets: a count read
    # "one left while an unrelated one exited" as zero and passed. An unrelated
    # thread STARTING in this window fails the cell instead, the safe direction.
    assert tids_after is None or not (tids_after - tids_before), (
        f"{plugin_class.__name__} left an OS thread "
        f"(new tids {sorted(tids_after - tids_before)})"
    )
    assert plugin.tool_version is None or plugin_class.__name__ not in PROBED


@pytest.mark.parametrize("class_name", sorted(PROBED))
@pytest.mark.unit
def test_the_first_dependency_check_runs_the_probe_once(
    class_name, plugin_context, recorders
):
    _, probed = recorders
    (plugin_class,) = [cls for cls in SHIPPED if cls.__name__ == class_name]
    plugin = plugin_class(context=plugin_context)
    # What construction asked is test_constructing_a_plugin_starts_nothing's; here,
    # only what the dependency check asks.
    probed.clear()

    for _ in range(2):
        try:
            plugin.validate_plugin_dependencies()
        except Exception:  # nosec B110 - the tool is absent here; only the probe matters
            pass

    assert probed == [PROBED[class_name]]
    assert plugin.tool_version == f"{PROBED[class_name]} 0.0.0"


@pytest.mark.unit
def test_the_jupyter_probe_waits_for_a_notebook(plugin_context, recorders):
    """No notebook: the check passes and nbconvert is not asked about."""
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        JupyterConverter,
    )

    _, probed = recorders
    converter = JupyterConverter(context=plugin_context)

    assert converter.validate_plugin_dependencies() is True
    assert probed == []


@pytest.mark.parametrize("version, expected", [((1, 6, 0), 1), ((1, 30, 2), 0)])
@pytest.mark.unit
def test_opengrep_asks_its_version_when_the_arguments_are_resolved(
    plugin_context, monkeypatch, tmp_path, version, expected
):
    """``--metrics`` depends on the installed version, asked once, before the run.

    Construction asks nothing (test_constructing_a_plugin_starts_nothing); the
    first argument resolution asks, and the second reuses the answer. The
    resolution the scan runs is ``_resolve_scan_arguments`` (the base's per-target
    entry, which opengrep overrides to decide ``--metrics`` before the target's
    excludes are added); the inner ``_resolve_arguments`` is the base's and asks
    nothing.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
    )

    asked = []

    def _version(self):
        asked.append(True)
        return version

    monkeypatch.setattr(OpengrepScanner, "_get_opengrep_version", _version)
    scanner = OpengrepScanner(context=plugin_context)
    assert asked == []
    target = tmp_path / "target"
    target.mkdir()

    runs = [
        scanner._resolve_scan_arguments(target, tmp_path / "r.sarif") for _ in range(2)
    ]

    assert asked == [True]
    assert [argv.count("--metrics") for argv in runs] == [expected, expected], runs
    # Resolving the same target twice on one instance gives one command, not a
    # command plus the per-target excludes appended a second time.
    assert runs[0] == runs[1], runs


@pytest.mark.unit
def test_an_old_opengrep_gets_the_same_arguments_plus_metrics(
    plugin_context, monkeypatch, tmp_path
):
    """The arguments rebuilt for an opengrep older than 1.7.0 differ only by --metrics.

    They are rebuilt from scratch; built on top of construction's, every option
    (each --config and --exclude, --sarif) would appear twice.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
    )

    target = tmp_path / "target"
    target.mkdir()
    argvs = {}
    for version in ((1, 6, 0), (1, 30, 2)):
        monkeypatch.setattr(
            OpengrepScanner, "_get_opengrep_version", lambda self, v=version: v
        )
        scanner = OpengrepScanner(context=plugin_context)
        argvs[version] = scanner._resolve_scan_arguments(target, tmp_path / "r.sarif")

    old = list(argvs[(1, 6, 0)])
    at = old.index("--metrics")
    assert old[at + 1] in ("auto", "on", "off"), old
    del old[at : at + 2]
    assert old == argvs[(1, 30, 2)]


@pytest.mark.unit
def test_the_sarif_reader_runs_a_pending_probe(plugin_context, recorders, tmp_path):
    """A scanner whose dependency check never ran still reports its tool's version.

    The template's SARIF step runs the pending probe itself, so the version does not
    depend on how a subclass, or a test, implements the dependency check.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    _, probed = recorders
    scanner = BanditScanner(context=plugin_context)
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": []}],
        }
    )

    scanner._inject_invocation(
        report, final_args=["bandit", "-r", "."], target=tmp_path
    )

    assert probed == ["bandit"]
    assert report.runs[0].tool.driver.version == "bandit 0.0.0"


# ---------------------------------------------------------------------------
# A real scan of one scanner
# ---------------------------------------------------------------------------

DRIVER = reaching_the_stand_in(
    """
    import sys

    from automated_security_helper.cli.main import app

    sys.argv = ["ash", "scan", *sys.argv[1:]]
    app()
    """
)


@pytest.mark.skipif(
    sys.platform == "win32", reason="the stand-in uv is a POSIX shell script"
)
@pytest.mark.integration
def test_a_scan_of_one_scanner_probes_only_that_scanner(tmp_path):
    bin_dir, log = install_stand_in_uv(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    # The stand-in, and no directory that could hold a real tool.
    env = stand_in_env(bin_dir, log, {**os.environ, "PATH": "/usr/bin:/bin"})
    env.update({"HOME": str(tmp_path / "home"), "NO_COLOR": "1"})
    env.pop("ASH_OFFLINE", None)

    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(DRIVER),
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--mode",
            "local",
            "--scanners",
            "bandit",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=tmp_path,
    )

    calls = recorded_calls(log)
    results = tmp_path / "out" / "ash_aggregated_results.json"
    assert results.is_file(), completed.stdout[-3000:] + completed.stderr[-3000:]
    rows = json.loads(results.read_text(encoding="utf-8"))["scanner_results"]
    assert rows["checkov"]["status"] == "SKIPPED", rows["checkov"]
    # The child reached the stand-in, and the selected scanner is still asked about:
    # this is what makes the absence of the others mean something.
    assert_reached_the_stand_in(calls)
    assert calls_naming(calls, ["bandit"]), calls
    others = calls_naming(calls, [t for t in UV_PROBED_TOOLS if t != "bandit"])
    assert others == [], others


@pytest.mark.unit
def test_the_recorders_see_a_probe(plugin_context, recorders):
    """Control: the recorders catch the probe the old construction made."""
    _, probed = recorders
    plugin = MagicMock()
    plugin.use_uv_tool = True
    plugin._uv_from_spec.return_value = None

    from automated_security_helper.base.uv_tool_mixin import UVToolMixin

    UVToolMixin._get_uv_tool_version(plugin, "checkov")

    assert probed == ["checkov"]
