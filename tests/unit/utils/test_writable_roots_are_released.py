"""A guarded root is registered for as long as something writes below it, then released.

``fs_guard`` keeps the directories below which ASH's writes follow no link. One
process can run many scans, as the MCP server does, so a root is counted: each
registration is released by the scan or object that made it, and a root two
holders registered stays until both are done. While registered, a link below the
root is refused; once released, writes there are open() again.
"""

from __future__ import annotations

import gc
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils.sandbox import fs_guard
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import SpawnPlan

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX symlinks and directory descriptors"
)


def _guarded(path: Path) -> bool:
    """Whether a write at ``path`` is below a registered root."""
    path = Path(path).absolute()
    return any(root in path.parents for root in fs_guard.registered_roots())


def test_a_scoped_root_is_guarded_inside_its_scope_and_released_after(tmp_path):
    output = tmp_path / "output"

    with fs_guard.writable_root(output):
        assert _guarded(output / "reports" / "ash.sarif")

    assert not _guarded(output / "reports" / "ash.sarif")


def test_a_root_two_holders_registered_stays_until_both_release(tmp_path):
    output = tmp_path / "output"

    with fs_guard.writable_root(output):
        with fs_guard.writable_root(output):
            pass
        assert _guarded(output / "ash.log"), "the outer holder still writes there"

    assert not _guarded(output / "ash.log")


def test_releasing_a_root_never_registered_changes_nothing(tmp_path):
    fs_guard.release_writable_root(tmp_path / "never")

    assert tmp_path / "never" not in fs_guard.registered_roots()


def test_a_release_from_a_finalizer_does_not_wait_for_the_registry(tmp_path):
    """A collector finalizer can run while this thread holds the registry's lock.

    It queues its release instead of taking the lock, and the next registry call
    applies it. Run in a thread with a timeout, so a regression fails here rather
    than hanging the suite.
    """
    import threading

    root = fs_guard.register_writable_root(tmp_path / "output")
    finished = threading.Event()

    def finalizer_while_the_lock_is_held():
        with fs_guard._roots_lock:
            fs_guard.release_writable_root_later(root)
        finished.set()

    worker = threading.Thread(target=finalizer_while_the_lock_is_held, daemon=True)
    worker.start()
    worker.join(timeout=5)

    assert finished.is_set(), "the release waited for the lock its own thread held"
    assert root not in fs_guard.registered_roots()


def test_a_plugin_contexts_root_is_released_when_the_context_is_gone(tmp_path):
    output = tmp_path / "output"
    context = PluginContext(
        source_dir=tmp_path, output_dir=output, work_dir=output / ASH_WORK_DIR_NAME
    )
    assert _guarded(output / "ash_aggregated_results.json")

    del context
    gc.collect()

    assert not _guarded(output / "ash_aggregated_results.json")


class _Recorder:
    name = "recorder"

    def probe(self):
        return None

    def plan(self, argv, env, policy):
        return SpawnPlan(argv=list(argv), env=dict(env))


@pytest.fixture
def make_scope(tmp_path, monkeypatch):
    """A function returning a context and a scanner's sandbox scope in it.

    A function, so the test holds the only reference to the scope it gets.
    """
    scope_module.clear_backend_cache()
    monkeypatch.setitem(scope_module.BACKENDS, "bwrap", _Recorder)
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"

    class _Scanner:
        sandbox_requirements = None
        results_dir = output / "scanners" / "probe"

    def make():
        context = PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=AshConfig(project_name="roots", sandbox=SandboxConfig(mode="bwrap")),
        )
        return context, scope_module.scanner_sandbox_scope(_Scanner(), context, source)

    yield make
    scope_module.clear_backend_cache()


def _holders() -> dict:
    """How many holders each root has (the registry's own count)."""
    with fs_guard._roots_lock:
        return dict(fs_guard._writable_roots)


def test_a_scanner_scope_releases_its_results_directory_when_it_is_gone(
    make_scope,
):
    context, scope = make_scope()
    results_dir = Path(scope.results_dir).absolute()
    assert results_dir in fs_guard.registered_roots()

    del scope
    gc.collect()

    assert results_dir not in fs_guard.registered_roots()
    assert _guarded(results_dir / "out.log"), "the output directory still is"


def test_a_spawns_writable_directories_are_released_by_its_cleanup(make_scope):
    _context, scope = make_scope()
    before = _holders()

    with scope_module.sandbox_scope(scope):
        plan = scope_module.prepare_spawn([sys.executable, "-V"], {}, None)
    during = _holders()
    for cleanup in plan.cleanup:
        cleanup()

    assert during != before, "the spawn's writable directories were never registered"
    assert _holders() == before


@pytest.fixture
def logger_name():
    """A logger of the test's own, its handlers closed afterwards."""
    import logging
    import uuid

    name = f"roots-{uuid.uuid4().hex}"
    yield name
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


def _log_to(name: str, output: Path):
    from automated_security_helper.utils.log import get_logger

    return get_logger(
        name=name, output_dir=output, log_format="BOTH", show_progress=True
    )


def _close_handlers(name: str) -> None:
    import logging

    for handler in list(logging.getLogger(name).handlers):
        handler.close()


class TestTheLogFileHandlers:
    """Each log file's handler holds its directory's registration while it is open."""

    def test_an_open_log_holds_its_directory_and_closing_it_releases_it(
        self, tmp_path, logger_name
    ):
        output = (tmp_path / "out").absolute()
        before = fs_guard.registered_roots()

        _log_to(logger_name, output)
        assert output in fs_guard.registered_roots()

        _close_handlers(logger_name)
        assert fs_guard.registered_roots() == before

    def test_a_new_output_directory_releases_the_previous_one(
        self, tmp_path, logger_name
    ):
        """The MCP server sets the logger up again for each scan's output."""
        before = fs_guard.registered_roots()
        outputs = [(tmp_path / f"out{i}").absolute() for i in range(4)]

        for output in outputs:
            _log_to(logger_name, output)

        assert fs_guard.registered_roots() - before == {outputs[-1]}
        _close_handlers(logger_name)
        assert fs_guard.registered_roots() == before

    def test_a_reopen_after_the_run_s_own_root_is_gone_still_refuses_a_link(
        self, tmp_path, logger_name
    ):
        output = tmp_path / "out"
        victim = tmp_path / "victim.txt"
        victim.write_text("outside content\n")
        with fs_guard.writable_root(output):
            _log_to(logger_name, output)
        (handler,) = [
            h
            for h in __import__("logging").getLogger(logger_name).handlers
            if Path(getattr(h, "baseFilename", "")).name == f"{logger_name}.log"
        ]
        handler.close()
        (output / f"{logger_name}.log").unlink()
        (output / f"{logger_name}.log").symlink_to(victim)

        with pytest.raises(fs_guard.OutputLinkRefused):
            handler._open()

        assert victim.read_text() == "outside content\n"
