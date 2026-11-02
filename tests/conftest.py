"""Pytest configuration file for ASH tests."""

import atexit
import contextlib
import errno
import functools
import importlib.abc
import importlib.machinery
import ipaddress
import itertools
import json
import logging
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import pytest
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType
from typing import (
    Any,
    Iterator,
    List,
    Literal,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

from typing_extensions import Self

from tests.utils import real_home_guard
from tests.utils.home_rule import ROOT_CONFTEST_MODULE

# Under a key of its own as well as pytest's "conftest", which pytest gives the next
# conftest.py it imports: tests/utils/home_rule.py finds this module by it. The first
# import wins, which is pytest's; a copy executed outside sys.modules registers nothing.
if sys.modules.get(__name__) is not None:
    sys.modules.setdefault(ROOT_CONFTEST_MODULE, sys.modules[__name__])
from tests.utils.env_assertions import (
    EnvironmentValuesRedacted,
    NamesOnlyEnvironment,
    explain_comparisons_by_names,
    hide_environ_values,
    passed_reports_are_shown,
    redact_environment_values,
    redacted_environment_values,
    redacted_shown,
)
from tests.utils.helpers import get_ash_temp_path

# The hooks that run one shard of the suite under ASH_TEST_SHARD (no-ops without it).
# Imported by name so pytest registers them as this conftest's own hooks;
# pytest_configure_node is the one that hands the setting to xdist workers.
from tests.utils import sharding
from tests.utils.sharding import (  # noqa: F401
    pytest_configure_node,
    pytest_ignore_collect,
)

# A failure that prints os.environ (a frame's argument, or the receiver of
# os.environ.get in an explanation) shows its names, not their values.
hide_environ_values()

# A failing comparison that involves an environment mapping is explained by its
# names, before pytest's own explanation (``tryfirst``). The hook is
# tests/utils/env_assertions.py's, so the child sessions that measure it
# register this same function.
pytest_assertrepr_compare = explain_comparisons_by_names


# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))


# The jsii package cache: where it lives, how workers share it, and how big it gets.
#
# HISTORY. jsii extracts each assembly it loads (aws-cdk-lib is about 7,500 files and
# 160 MB) into a package cache, taking a lockfile while it extracts. Its waiter gives
# up after 12 randomized retries, about 13 s expected and 26 s worst case. On Windows
# CI, creating 7,500 files is slow enough that a second worker booting a kernel
# against the same cold entry exhausted that budget and died with
#
#     EEXIST: file already exists, open '...\package-cache\aws-cdk-lib\<v>\<sha>.lock'
#
# (zero occurrences in 1,772 Windows legs with one booting test, 12 in 583 with two).
# The first fix gave every xdist worker its own root under
# tempfile.gettempdir()/ash-jsii-package-cache/<worker>. That removed the race but
# wrote one full extraction per booting worker into the host's temp directory and
# never removed any of them. On a many-core host that directory reached about 665,000
# inodes, filled a 1,048,576-inode /tmp, and broke every process on the machine.
#
# NOW. One root, shared by every worker:
#   - <ASH_JSII_CACHE_DIR>/jsii-package-cache when the variable is set, otherwise
#     <repo>/.cache/jsii-package-cache, which is gitignored and in the ASH self-scan
#     ignore_paths. Never the temp directory. The override gets its own subdirectory
#     because it may name a cache shared with other tools, such as ~/.cache; its ~ is
#     the developer's home, not the one the run moves HOME to.
#   - Kernel.load is wrapped in an exclusive file lock (_JsiiKernelLoadLockHook). The
#     first worker to load an assembly extracts it while holding our lock, which has
#     no retry budget; the rest block on it and then get a cache hit, and jsii only
#     takes its own lock on a miss. So jsii's lock is never contended.
#   - At session end the controller keeps the newest _JSII_CACHE_KEEP entries per
#     package and removes the rest, so a checkout that has moved through several
#     aws-cdk-lib versions holds a bounded number of extractions, not all of them.
#     Only a directory holding jsii's _JSII_ENTRY_MARKER file counts as an entry;
#     anything else under the root is left alone, whatever its age.
#     jsii's own 30-day TTL prune still runs on top of that.
#
# A pre-existing JSII_RUNTIME_PACKAGE_CACHE_ROOT is overwritten for the test session
# on purpose: ASH_JSII_CACHE_DIR is the one supported override, so the location
# test can assert where the cache is.

_JSII_CACHE_ENV = "ASH_JSII_CACHE_DIR"
_JSII_CACHE_KEEP = 2
_JSII_LOAD_LOCK_NAME = ".ash-load.lock"
_JSII_CACHE_SUBDIR = "jsii-package-cache"
# jsii writes this file into every entry it extracts and touches it on every hit.
_JSII_ENTRY_MARKER = ".jsii-runtime-package-cache"
# What msvcrt.locking raises once LK_LOCK has used up its own retries on a lock
# another handle holds. Anything else is a real error and is raised.
# errno.EDEADLOCK, the name msvcrt documents, is the same number as EDEADLK.
_WIN_LOCK_CONTENTION_ERRNOS = frozenset({errno.EACCES, errno.EDEADLK})
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _jsii_package_cache_root() -> Path:
    """The single jsii package cache root for this test session.

    A ``~`` in ASH_JSII_CACHE_DIR is the developer's home. Read from HOME, it was the
    home the run moves HOME to, which the run deletes at the end, and the cache with
    it: every run extracted aws-cdk-lib again.
    """
    override = (os.environ.get(_JSII_CACHE_ENV) or "").strip()
    if override:
        return (
            Path(_expand_the_developers_home(override)).resolve() / _JSII_CACHE_SUBDIR
        )
    return _REPO_ROOT / ".cache" / _JSII_CACHE_SUBDIR


def _expand_the_developers_home(path: str) -> str:
    """``os.path.expanduser``, with ``~`` meaning the home the run started with."""
    if path == "~" or path.startswith(("~/", "~" + os.sep)):
        return _developer_record()["home"] + path[1:]
    return os.path.expanduser(path)


@contextlib.contextmanager
def _exclusive_file_lock(lock_path: Path) -> Iterator[None]:
    """Block until this process holds an exclusive lock on ``lock_path``.

    The lock belongs to the open file, so it is released if the holder dies, and two
    separate opens in one process exclude each other just as two processes do.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a+b") as handle:
        if sys.platform == "win32":
            import msvcrt

            while True:
                handle.seek(0)
                try:
                    # LK_LOCK retries for about 10 s and then raises; keep waiting
                    # while the lock is held elsewhere, and only then.
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError as exc:
                    if exc.errno not in _WIN_LOCK_CONTENTION_ERRNOS:
                        raise
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _wrap_kernel_load(kernel_cls: Any, lock_path: Path) -> None:
    """Make ``kernel_cls.load`` hold the cache lock for the whole load request."""
    original = kernel_cls.load
    if getattr(original, "__ash_jsii_cache_lock__", None):
        return

    @functools.wraps(original)
    def load(self: Any, *args: Any, **kwargs: Any) -> Any:
        with _exclusive_file_lock(lock_path):
            return original(self, *args, **kwargs)

    load.__ash_jsii_cache_lock__ = lock_path  # type: ignore[attr-defined]
    kernel_cls.load = load


class _PatchingLoader(importlib.abc.Loader):
    """Run the real loader, then wrap ``Kernel.load`` in the new module."""

    def __init__(self, inner: importlib.abc.Loader, lock_path: Path) -> None:
        self._inner = inner
        self._lock_path = lock_path

    def create_module(self, spec: ModuleSpec) -> Optional[ModuleType]:
        return self._inner.create_module(spec)

    def exec_module(self, module: ModuleType) -> None:
        self._inner.exec_module(module)
        _wrap_kernel_load(module.Kernel, self._lock_path)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _JsiiKernelLoadLockHook(importlib.abc.MetaPathFinder):
    """Patch ``jsii._kernel.Kernel.load`` when, and only when, jsii is imported.

    Not imported eagerly: most workers never touch jsii, and importing it early would
    also run its import-time environment reads before cdk_nag_wrapper has set the
    variables it relies on.
    """

    def __init__(self, lock_path: Path, module_name: str = "jsii._kernel") -> None:
        self._lock_path = lock_path
        self._module_name = module_name

    def find_spec(
        self,
        fullname: str,
        path: Optional[Sequence[str]],
        target: Optional[ModuleType] = None,
    ) -> Optional[ModuleSpec]:
        if fullname != self._module_name:
            return None
        if self in sys.meta_path:
            sys.meta_path.remove(self)
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if spec is not None and spec.loader is not None:
            spec.loader = _PatchingLoader(spec.loader, self._lock_path)
        return spec


def _configure_jsii_package_cache() -> Path:
    """Point jsii at the shared root and install the load lock. Returns the root.

    Must run before anything imports a jsii-backed package; jsii reads the variable
    in the Node runtime it spawns, so it only has to be set before the first kernel
    starts. The root itself is left for jsii to create, so a run that boots no
    kernel creates nothing.
    """
    root = _jsii_package_cache_root()
    if real_home_guard.is_guarded(root):
        # Every test that boots a jsii kernel takes the lock in this root, and the
        # guard on the real ~/.ash refuses it, so each would fail at its teardown.
        raise pytest.UsageError(
            f"{_JSII_CACHE_ENV}={os.environ.get(_JSII_CACHE_ENV)} puts the jsii "
            f"package cache in {root}, inside your ~/.ash, where the test run refuses "
            "to write. Point it outside ~/.ash."
        )
    os.environ["JSII_RUNTIME_PACKAGE_CACHE_ROOT"] = str(root)
    lock_path = root / _JSII_LOAD_LOCK_NAME
    kernel_module = sys.modules.get("jsii._kernel")
    if kernel_module is not None:
        _wrap_kernel_load(kernel_module.Kernel, lock_path)
    elif not any(isinstance(f, _JsiiKernelLoadLockHook) for f in sys.meta_path):
        sys.meta_path.insert(0, _JsiiKernelLoadLockHook(lock_path))
    return root


def _jsii_entry_last_used(entry: Path) -> Optional[float]:
    """When jsii last used a cache entry, or None if ``entry`` is not one.

    jsii touches the ``.jsii-runtime-package-cache`` marker inside an entry on every
    hit, not only on extraction, so its mtime is the last-use time. A directory
    without the marker is not a jsii entry, and there is deliberately no fallback to
    the directory's own mtime: the root may be shared, and a guess here deletes
    something jsii did not write.
    """
    try:
        marker = os.lstat(entry / _JSII_ENTRY_MARKER)
    except OSError:
        return None
    if not stat.S_ISREG(marker.st_mode):
        return None
    return marker.st_mtime


def _prune_jsii_package_cache(root: Path, keep: int = _JSII_CACHE_KEEP) -> List[Path]:
    """Keep the ``keep`` most recently used ``<package>/<version>/<digest>`` entries.

    Counted per package. Packages may be scoped (``@aws-cdk/asset-awscli-v1``), so a
    package directory is any directory whose children are version directories
    holding digest entries. Only directories carrying jsii's marker file are
    counted or removed. Returns the entries removed.
    """
    if not root.is_dir():
        return []
    removed: List[Path] = []
    package_dirs: List[Path] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if child.name.startswith("@"):
            package_dirs.extend(p for p in child.iterdir() if p.is_dir())
        else:
            package_dirs.append(child)
    for package_dir in package_dirs:
        dated: List[tuple[float, Path]] = []
        for version_dir in package_dir.iterdir():
            if not version_dir.is_dir():
                continue
            for entry in version_dir.iterdir():
                if not entry.is_dir() or entry.is_symlink():
                    continue
                last_used = _jsii_entry_last_used(entry)
                if last_used is not None:
                    dated.append((last_used, entry))
        dated.sort(key=lambda item: item[0], reverse=True)
        for _, stale in dated[keep:]:
            shutil.rmtree(stale, ignore_errors=True)
            removed.append(stale)
            version_dir = stale.parent
            if not any(version_dir.iterdir()):
                version_dir.rmdir()
    return removed


# The session temp directory.
#
# Measured with a private, empty /tmp and TMPDIR unset, a full unit run left about 270
# inodes behind even with the jsii cache moved out: tools the tests drive (Node's
# compile cache, semgrep rule files, a lark grammar cache, the MCP session workspace,
# mktemp in shell scripts under test) all write to the default temp directory and
# nothing removes what they write. None of them is a literal /tmp that could be fixed
# where it is written, so the session points TMPDIR (and TEMP/TMP, which Windows
# tools read) at a directory of its own and removes it at the end.
#
# The directory comes from tempfile.mkdtemp in the original temp directory rather
# than from the pytest basetemp: basetemp paths are long, and macOS caps AF_UNIX
# socket paths at 104 bytes, which multiprocessing and other socket users under
# TMPDIR would hit. The controller creates it before xdist starts workers, the workers
# inherit it through ASH_TEST_SESSION_TMPDIR, and only the creating process removes
# it, so a pytest run started from inside a test does not delete its parent's.

_SESSION_TMP_ENV = "ASH_TEST_SESSION_TMPDIR"
_TEMP_VARS = ("TMPDIR", "TEMP", "TMP")
# The temp variables as the session found them, before it pointed them at its own
# directory: a JSON object of the ones that were set. Exported so xdist workers,
# which inherit the overridden values, can still read the originals. Tests use it
# to name every temp directory the run could otherwise have written to.
_PRE_SESSION_TEMP_ENV = "ASH_TEST_PRE_SESSION_TEMP_ENV"
_created_session_tmpdir: Optional[Path] = None


def _pre_session_temp_env() -> dict:
    """TMPDIR/TEMP/TMP as they were before the session override; unset ones absent."""
    recorded = os.environ.get(_PRE_SESSION_TEMP_ENV)
    if recorded:
        return json.loads(recorded)
    return {var: os.environ[var] for var in _TEMP_VARS if os.environ.get(var)}


def _enter_session_tmpdir() -> Path:
    """Point this process's temp directory at the session one. Returns it."""
    global _created_session_tmpdir
    inherited = (os.environ.get(_SESSION_TMP_ENV) or "").strip()
    if inherited and Path(inherited).is_dir():
        path = Path(inherited)
    else:
        # pytest's own basetemp (tmp_path and friends) keeps its usual home and its
        # keep-the-last-three retention, rather than being deleted with this directory
        # at session end. PYTEST_DEBUG_TEMPROOT is pytest's documented knob for that
        # root; an explicit --basetemp overrides both.
        os.environ.setdefault("PYTEST_DEBUG_TEMPROOT", tempfile.gettempdir())
        os.environ[_PRE_SESSION_TEMP_ENV] = json.dumps(_pre_session_temp_env())
        path = Path(tempfile.mkdtemp(prefix="ash-pytest-"))
        os.environ[_SESSION_TMP_ENV] = str(path)
        _created_session_tmpdir = path
    for var in _TEMP_VARS:
        os.environ[var] = str(path)
    tempfile.tempdir = str(path)
    return path


# Roots and exclusions for a guard on the moved XDG directories.
#
# The guard installed at the end of this module watches ~/.ash of the passwd home and
# of the developer's home, and does not call these. They build the wider set a guard on
# the XDG directories the run moves would need: the roots (the caller's value of each
# directory, or its default place under their original HOME) and the paths under them
# that tests may write to. tests/unit/test_conftest_private_home.py pins both.
#
# _real_home_guard_roots reads _HOME_VARS, defined with the per-test home further down.
# That tuple names the XDG variables as well as HOME and USERPROFILE, so a recorded XDG
# value is taken for a home too, and its ``.ash`` is watched with the rest.
#: Each XDG directory the run moves into its home, and its default place under one.
_PRIVATE_XDG_DIRS = {
    "XDG_CONFIG_HOME": (".config",),
    "XDG_DATA_HOME": (".local", "share"),
    "XDG_STATE_HOME": (".local", "state"),
}
#: Shared on purpose; writes under them are not the guard's business.
_SHARED_CACHE_VARS = ("XDG_CACHE_HOME", "UV_CACHE_DIR")


def _real_home_guard_roots(previous: dict) -> List[str]:
    """What the guard watches, given the variables as they were before the session.

    ``~/.ash`` of the passwd home and of the original HOME/USERPROFILE, and each XDG
    directory the session moved: the caller's value, or its default place under the
    original HOME when the caller left it unset.
    """
    homes = [real_home_guard.passwd_home()]
    homes += [Path(previous[var]) for var in _HOME_VARS if previous.get(var)]
    roots = set(real_home_guard.guarded_roots(homes))
    original_home = previous.get("HOME")
    for var, parts in _PRIVATE_XDG_DIRS.items():
        if previous.get(var):
            roots.update(real_home_guard.both_spellings(Path(previous[var])))
        elif original_home:
            roots.update(
                real_home_guard.both_spellings(Path(original_home).joinpath(*parts))
            )
    return sorted(roots)


def _real_home_guard_exclusions(rootdir: Path) -> List[str]:
    """Paths under a guarded root that tests may write to.

    The interpreter's own installation (uv installs Python under XDG_DATA_HOME, and
    importing a module can write its bytecode there), the shared caches, and the
    checkout under test.
    """
    paths = {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix}
    paths.update(os.environ[var] for var in _SHARED_CACHE_VARS if os.environ.get(var))
    paths.add(str(rootdir))
    excluded = set()
    for path in paths:
        excluded.update(real_home_guard.both_spellings(Path(path)))
    return sorted(excluded)


def _make_writable_and_retry(func: Any, path: str, _exc: BaseException) -> None:
    """rmtree error hook: read-only files (git objects on Windows) block removal."""
    try:
        os.chmod(path, 0o700)
        func(path)
    except OSError:
        pass


def _remove_session_tmpdir() -> None:
    global _created_session_tmpdir
    path = _created_session_tmpdir
    if path is None:
        return
    _created_session_tmpdir = None
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_make_writable_and_retry)
    else:
        shutil.rmtree(
            path, onerror=lambda f, p, e: _make_writable_and_retry(f, p, e[1])
        )


def pytest_unconfigure(config):
    """Tidy up from the process that owns the session: bound the jsii cache, then
    remove the session temp directory."""
    if hasattr(config, "workerinput"):
        return
    # HOME first, so an ASH_JSII_CACHE_DIR spelled with ~ names the same root here as
    # it did when the session configured it.
    _leave_session_home()
    root = _jsii_package_cache_root()
    if root.is_dir():
        with _exclusive_file_lock(root / _JSII_LOAD_LOCK_NAME):
            _prune_jsii_package_cache(root)
    _leave_session_home()
    _remove_session_tmpdir()


def pytest_sessionstart(session: pytest.Session) -> None:
    """The live log (``log_cli`` in pytest.ini) shows each record as it is
    logged, outside any report, so its handler's formatter redacts the
    environment's values (EnvironmentValuesRedacted in
    tests/utils/env_assertions.py), as pytest_runtest_makereport has every
    report redacted. Here and not in pytest_configure: the logging plugin
    registers itself in its own trylast pytest_configure. With ``-p
    no:logging`` there is no live log; with log_cli off the handler is
    pytest's null one, which shows nothing -- pytest sets a formatter on it
    too, so the wrap is applied there as well, harmlessly. The None check
    guards a handler shape that carries no formatter at all."""
    plugin = session.config.pluginmanager.get_plugin("logging-plugin")
    _wrap_suite_property_adds(session.config)
    if plugin is None:
        return
    handler = plugin.log_cli_handler
    if handler.formatter is not None:
        handler.setFormatter(EnvironmentValuesRedacted(handler.formatter))


def _wrap_suite_property_adds(config) -> None:
    """Redact record_testsuite_property names and values BEFORE the junit
    plugin stores them: add_global_property keeps bin_xml_escape(value), so
    a value holding an XML-illegal character (ESC, say) is stored in its
    escaped spelling, which the end-of-run redaction cannot match against
    the raw environment value. The junit plugin builds its state in its own
    pytest_configure, so by sessionstart the instance is in the stash. The
    sessionfinish redaction below stays as the backstop for anything that
    reaches global_properties by another route."""
    try:
        from _pytest.junitxml import xml_key
    except Exception:  # noqa: BLE001 - no junit plugin, nothing stored
        return
    xml = config.stash.get(xml_key, None)
    add = getattr(xml, "add_global_property", None)
    if add is None:
        return

    def redacting_add(name, value, _add=add):
        _add(redacted_shown(name), redacted_shown(value))

    xml.add_global_property = redacting_add


def pytest_configure(config):
    """Configure pytest for ASH tests.

    The session temp directory, the run's own home and the jsii package cache are set
    up earlier, when pytest imports this module; see "Set up when pytest imports this
    module" below.
    """
    # Reads ASH_TEST_SHARD once and removes it from os.environ, so no child pytest a
    # test starts inherits it; see tests/utils/sharding.py.
    sharding.configure(config)
    # Register custom markers
    config.addinivalue_line(
        "markers", "unit: Unit tests that test individual components in isolation"
    )
    config.addinivalue_line(
        "markers",
        "integration: Tests of one component with a real dependency: the test starts a "
        "process (a child Python, git, the ash CLI, a real tool), opens a socket or "
        "runs git on any path (tests/NAMING_CONVENTIONS.md)",
    )
    config.addinivalue_line(
        "markers",
        "e2e: End-to-end tests that run the product as an operator would (the ash "
        "CLI, the container, the MCP server) against real tools",
    )
    config.addinivalue_line("markers", "slow: Tests that take a long time to run")
    config.addinivalue_line(
        "markers", "scanner: Tests related to scanner functionality"
    )
    config.addinivalue_line(
        "markers", "reporter: Tests related to reporter functionality"
    )
    config.addinivalue_line(
        "markers", "config: Tests related to configuration functionality"
    )
    config.addinivalue_line("markers", "model: Tests related to data models")
    config.addinivalue_line(
        "markers",
        f"{ALLOW_AWS_NETWORK_MARKER}: may send botocore requests off this machine; "
        "every other test has them refused",
    )
    config.addinivalue_line(
        "markers",
        "real_home: run with the HOME, USERPROFILE and XDG_* values the run started "
        "with, instead of a temporary home of the test's own",
    )
    config.addinivalue_line(
        "markers",
        "production_header_rule: do not read a test double's unset `headers` as no "
        "headers; session_identity.resolve_session_id applies its own rule to it",
    )
    for marker, flag in _RUNTIME_SNAPSHOT_MARKERS.items():
        config.addinivalue_line(
            "markers",
            f"{marker}: needs a real runtime this host may not have; deselected "
            f"unless {flag} is given",
        )


#: The workeroutput key an xdist worker sends its late writes under the real ~/.ash in.
_WORKER_WRITES_KEY = "ash_real_home_writes"
#: ``(worker id, event, path)`` for each write the workers sent; reported by the
#: controller's pytest_sessionfinish, once.
_writes_from_workers: List[Tuple[str, str, str]] = []


#: The workeroutput key an xdist worker sends the run log scopes still open at
#: its session's end in; reported by the controller's pytest_sessionfinish.
_WORKER_SCOPES_KEY = "ash_run_log_scopes_still_open"
#: ``(worker id, scope label)`` for each scope the workers sent.
_scopes_from_workers: List[Tuple[str, str]] = []


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
    """Keep what a worker drained at the end of its session, for the controller to report.

    A worker that crashed sent nothing, so what it wrote after its last test is lost.
    """
    output = getattr(node, "workeroutput", None) or {}
    worker = getattr(getattr(node, "gateway", None), "id", None) or "a worker"
    for event, path in output.get(_WORKER_WRITES_KEY, ()):
        _writes_from_workers.append((worker, event, path))
    for label in output.get(_WORKER_SCOPES_KEY, ()):
        _scopes_from_workers.append((worker, label))


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_sessionfinish(session, exitstatus):
    """Fail the session for what no test was charged with: writes under the
    real ~/.ash, and run log scopes still open. A wrapper, because this
    module's one impl needs both ends of the hook: the junit plugin writes
    its XML inside its own impl, so the suite-level properties
    (record_testsuite_property) must be redacted BEFORE any plain impl runs;
    and the two reporters must run after them all -- pytest's own teardown of
    the session's fixtures included, so a fixture that cleans up in its
    teardown is not misread as a leak.

    The redaction is in a try and the reporters in a finally: a raise in the
    first half aborted the whole hook, so no junit file was written and a
    planted leaked scope went unreported. Under pluggy's old-style wrapper
    protocol an inner impl's raise is handed back as the call outcome, never
    thrown into this generator, so the finally's extra cover begins only if
    this impl moves to the new-style wrapper form; that the reporters
    survive a raising inner impl is pinned by a child run either way. A
    property set the redaction
    cannot rewrite is not shown (dropped and replaced by a notice), the
    module's rule for every report it cannot redact. The host-name patch:
    the junit plugin reads platform.node() for the <testsuite hostname=...>
    attribute while it writes the file, inside its own impl, so a value from
    the set that IS the host name has to be redacted at that source; no
    other report part prints the host name."""
    try:
        _redact_suite_properties(session.config)
    except Exception:  # noqa: BLE001 - what it cannot redact is not shown
        _drop_suite_properties(session.config)
    restore_node = _redacting_platform_node(session.config)
    try:
        yield
    finally:
        if restore_node is not None:
            restore_node()
        _report_real_home_writes(session)
        _report_run_log_scopes_still_open(session)


def _redact_suite_properties(config) -> None:
    """Redact record_testsuite_property names and values where the junit
    plugin stores them: they go to the <testsuite> element through its own
    state and never pass through a report, so no report hook sees them.
    The sessionstart wrap above redacts them again before the plugin's
    escape; this end-of-run pass is the backstop for entries that reached
    global_properties by another route."""
    try:
        from _pytest.junitxml import xml_key
    except Exception:  # noqa: BLE001 - no junit plugin, nothing stored
        return
    xml = config.stash.get(xml_key, None)
    properties = getattr(xml, "global_properties", None)
    if not properties:
        return
    xml.global_properties = [
        (redacted_shown(name), redacted_shown(value)) for name, value in properties
    ]


def _drop_suite_properties(config) -> None:
    """A property set the redaction could not rewrite is not shown: the
    stored entries are replaced by one notice pair."""
    try:
        from _pytest.junitxml import xml_key

        xml = config.stash.get(xml_key, None)
        if xml is not None and getattr(xml, "global_properties", None):
            xml.global_properties = [
                (
                    "suite-properties",
                    "these properties could not be redacted, so they are not shown",
                )
            ]
    except Exception:  # noqa: BLE001 - nothing more this fallback can do
        pass


def _redacting_platform_node(config):
    """Patch platform.node for the junit write when the host name holds a
    value from the set (Docker sets HOSTNAME in every container, so a
    variable's value can BE the host name), and give back the undo, or None
    when nothing needs patching. Only while a junit file is being written:
    without the junit plugin's stored state nothing in this hook reads the
    name. A name the redaction cannot check is not shown (replaced by '').

    Two measured trade-offs, accepted by design: a value of up to seven word
    characters matches as whole words only (the module-wide rule), so such a
    value glued inside one piece of the name still prints; and a value that
    stands alone as a piece -- a dot-separated label, or a hyphen-separated
    piece within one -- masks that piece, so the attribute can print partly
    masked, a readability cost, not a leak, on hosts where a USER-like value
    is a hyphen-separated piece of the name."""
    import platform

    try:
        from _pytest.junitxml import xml_key

        if config.stash.get(xml_key, None) is None:
            return None
    except Exception:  # noqa: BLE001 - no junit plugin, nothing written
        return None
    try:
        name = platform.node()
        shown = redacted_shown(name)
        replacement = shown if isinstance(shown, str) else ""
        if replacement == name:
            return None
    except Exception:  # noqa: BLE001 - a name it cannot check is not shown
        replacement = ""
    real = platform.node
    platform.node = lambda: replacement

    def undo() -> None:
        platform.node = real

    return undo


def _report_real_home_writes(session) -> None:
    """Fail the session for writes under the real ~/.ash that no test was charged with.

    The teardown check below reports what a test's process wrote. A write after the
    last test's teardown (another plugin's pytest_sessionfinish, a thread a test left
    running), or in the xdist controller, which runs no tests, would otherwise go
    unreported. An xdist worker's session end
    is not the run's: it sends its record to the controller in its workeroutput
    (pytest_testnodedown above), and the controller reports the workers' with its own.
    A write after that, in config cleanup or an atexit handler, is refused but never
    reported.

    The printed message passes through the backstop's redaction, as the
    report channels do (the scopes reporter below prints this suite's own
    scope labels and exception type names; the one exception text its
    unreadable branch prints passes through the same redaction): in a plain
    run the real HOME's
    prefix is an environment value, so a path can print as ``<value>/...``;
    the event and the rest of the path still locate the stray write. A short
    value glued inside a path segment still prints (the whole-word rule),
    and a value standing between word boundaries inside a segment masks just
    that piece, so a segment can read like ``tool-<value>-cache``. A message
    the redaction cannot rewrite is not shown -- the count alone is.

    A worker redacts each drained path BEFORE sending it: the controller's
    pass redacts with its OWN environment's values, so one set only inside
    the worker is known only there; a path a worker cannot redact is sent as
    a per-path notice, never raw. The controller's pass stays as the second
    layer over what the workers send. The one limit, recorded by a cell of
    its own: a value only ANOTHER worker holds is known to neither the
    writing worker nor the controller, so a path holding one prints it --
    the suite has no known source of such a path, and shipping each worker's
    value set across the execnet channel into a reporter that must not raise
    was weighed and rejected.
    """
    drained = real_home_guard.drain()
    workeroutput = getattr(session.config, "workeroutput", None)
    if workeroutput is not None:
        sent = []
        for event, path in drained:
            try:
                sent.append([event, redacted_environment_values(path)])
            except Exception:  # noqa: BLE001 - a path it cannot redact is not shown
                sent.append(
                    [event, "a path that could not be redacted, so it is not shown"]
                )
        workeroutput[_WORKER_WRITES_KEY] = sent
        return
    writes = [("", event, path) for event, path in drained] + _writes_from_workers
    _writes_from_workers.clear()
    if not writes:
        return
    text = "wrote under the real user's ~/.ash outside any test:\n" + "\n".join(
        f"  {worker + ': ' if worker else ''}{event}: {path}"
        for worker, event, path in writes
    )
    try:
        message = redacted_environment_values(text)
    except Exception:  # noqa: BLE001 - paths it cannot redact are not shown
        message = (
            f"{len(writes)} write(s) under the real user's ~/.ash outside any"
            " test; the paths could not be redacted, so they are not shown"
        )
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(message, red=True)
    else:
        print(message, file=sys.stderr)
    session.exitstatus = pytest.ExitCode.TESTS_FAILED


def _report_run_log_scopes_still_open(session) -> None:
    """Fail the run for a run log scope still open when the session ends.

    The per-test and per-module guards (further down) see a scope their own
    block opened. One a session- or package-scoped fixture opened, or code
    run at import or collection, is open before any guard's count and still
    open after it -- and when no test ran at all (a collection error), no
    fixture-based guard even exists. This check runs after pytest's own
    teardown of the session's fixtures (trylast, so a fixture that closes
    its scope in teardown is not misread), on every way a session ends: a
    full run, ``-x``, a collection error, an interrupt. It reports and sets
    the exit status instead of raising, because a fail raised while pytest
    tears the session down outside any test's protocol (an interrupt)
    escaped as a bare traceback and skipped ``pytest_unconfigure``. Each
    scope is still closed, each on its own, so a close that raises leaves
    the others closed and is named rather than raised. An xdist worker's
    session end is not the run's: it sends the scope labels to the
    controller (pytest_testnodedown above), which reports them with its own.
    """
    log_module = sys.modules.get("automated_security_helper.utils.log")
    labels: List[str] = []
    if log_module is not None:
        try:
            left = sorted(_open_run_log_scopes() - _UNCLOSABLE_SCOPES_REPORTED)
        except Exception as error:  # noqa: BLE001 - reported, never raised here
            # A rename in utils/log.py fails the guards rather than turning
            # them off -- reported, because an exception raised from this
            # hook aborts the terminal summary other wrappers would render.
            # The exception's text is redacted here, and the composed
            # message is redacted ONCE MORE before it is written below: the
            # scope labels are not this module's own text either (a label is
            # whatever name the opening code chose, and a close failure adds
            # the raising code's type name), so no piece of this reporter's
            # output skips the redaction.
            left = []
            try:
                shown_error = redacted_environment_values(str(error))
            except Exception:  # noqa: BLE001 - text it cannot redact is not shown
                shown_error = "its text could not be redacted, so it is not shown"
            labels.append(
                "the open run log scopes could not be read"
                f" ({type(error).__name__}: {shown_error})"
            )
        for scope in left:
            try:
                log_module.close_run_log_scope(scope)
            except Exception as error:  # noqa: BLE001 - each close on its own
                labels.append(f"{scope} (could not be closed: {type(error).__name__})")
            else:
                labels.append(scope)
    workeroutput = getattr(session.config, "workeroutput", None)
    if workeroutput is not None:
        workeroutput[_WORKER_SCOPES_KEY] = labels
        return
    scopes = [("", label) for label in labels] + _scopes_from_workers
    _scopes_from_workers.clear()
    if not scopes:
        return
    unreadable = any("could not be read" in label for _, label in scopes)
    message = (
        (
            "the run log scope guard failed when the session ended:\n"
            if unreadable
            else "a run log scope was still open when the session ended:\n"
        )
        + "\n".join(
            f"  {worker + ': ' if worker else ''}{label}" for worker, label in scopes
        )
        + "\nEnd the scope where the run ends (end_run_log_scope, or the task or"
        " holder that owns it): a session- or package-scoped fixture left it"
        " open, or code run at import or collection did."
    )
    # The COMPOSED message is redacted once more before it is written: the
    # labels are not this module's own text -- a scope label is whatever
    # name the opening code chose (a uuid4 hex, a path), and a close
    # failure adds the raising code's type name -- so any of them can hold
    # an environment value. When even that redaction raises, the fallback
    # names only the COUNT, never the labels.
    try:
        shown_message = redacted_environment_values(message)
    except Exception:  # noqa: BLE001 - count-only, never the labels
        # Not "N scopes": an entry can also be the could-not-be-read notice
        # (the guard failed before any scope was listed) or a close failure,
        # so the count names the guard's entries, not open scopes.
        shown_message = (
            f"the run log scope guard had {len(scopes)} entr"
            f"{'y' if len(scopes) == 1 else 'ies'} to report when the "
            "session ended (open scopes, or failures reading or closing "
            "them); the labels could not be redacted, so they are not "
            "shown. End each scope where the run ends (end_run_log_scope, "
            "or the task or holder that owns it)."
        )
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(shown_message, red=True)
    else:
        print(shown_message, file=sys.stderr)
    if session.exitstatus in (pytest.ExitCode.OK, pytest.ExitCode.NO_TESTS_COLLECTED):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.hookimpl(tryfirst=True)
def pytest_collectreport(report):
    """A module that fails to collect, or skips at module level, prints its
    text through a collect report, which no test hook sees: redact every
    collect report that did not pass, like a test report. A module-level
    skip's ``(path, line, reason)`` longrepr keeps its shape with the reason
    redacted; a collect error's has no such shape, so the backstop's text
    fallback applies, and a report it cannot redact is not shown.

    tryfirst is load-bearing: the junit plugin registers in its own
    pytest_configure, after this conftest, so its impl of this hook runs
    first and writes str(longrepr) into the XML -- the <error> element held
    the value while the terminal was already clean (measured at -n 0 and
    -n 2)."""
    if not report.passed:
        redact_environment_values(report)


@pytest.hookimpl(tryfirst=True)
def pytest_warning_recorded(warning_message, when, nodeid, location):
    """The warnings summary prints each recorded warning outside every
    report: a value its message holds is redacted in place, by rewriting the
    warning object's text arguments, so whatever formats this message later
    shows the redacted text. A warning a test catches itself (``recwarn``,
    ``pytest.warns``) is caught inside the test's own context and never
    recorded here, so its arguments stay what the test raised. A message
    that cannot be redacted is replaced by a notice, like a report.

    tryfirst is load-bearing: the terminal plugin's own impl of this hook
    formats the message and stores the TEXT the summary later prints, and it
    ran before this conftest's impl (measured; without tryfirst the summary
    kept the original text). The rewrite has to come first."""
    message = warning_message.message
    if not isinstance(message, Warning):
        return
    try:
        redacted = tuple(
            redacted_environment_values(argument)
            if isinstance(argument, str)
            else argument
            for argument in message.args
        )
        if redacted != message.args:
            message.args = redacted
        # The summary prints str(message): a non-text argument (a path), a
        # __str__ that ignores the args, or a warning built with NO args
        # whose __str__ carries the value (an early return on empty args let
        # that one through unchecked) is a value the rewrite above cannot
        # reach. The replacement keeps the printed category, which the
        # summary takes from warning_message.category, not from the object.
        shown = str(message)
        hidden = redacted_environment_values(shown)
        if hidden != shown:
            warning_message.message = UserWarning(hidden)
    except Exception:  # noqa: BLE001 - an unredacted warning is not shown
        # The object is replaced, not only its args: a __str__ that ignores
        # the args would keep printing its own text.
        notice = "this warning could not be redacted, so it is not shown"
        message.args = (notice,)
        warning_message.message = UserWarning(notice)


def _sendable(text: str) -> str:
    """*text* with each lone surrogate written as its backslash escape.

    pytest-xdist sends a worker's reports to the controller over execnet, which
    encodes text as UTF-8, and a lone surrogate (a non-UTF-8 file name read with
    surrogateescape holds one) is no UTF-8: the worker stopped with an internal
    error, and the run ended with it. ASH's records reach pytest's own capture
    handler on the ``ash`` logger, since get_logger replaces only the handlers ASH
    added, so a test that logs such a name has one in its "Captured log" section.
    """
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """In an xdist worker, each report's sections as text xdist can send
    (_sendable); a test that wrote under the real ~/.ash failed (see
    tests/utils/real_home_guard.py); and, last, every report that did not pass
    holds no environment value (redact_environment_values in
    tests/utils/env_assertions.py), whatever printed it.

    Only a worker sends its reports, so only there are the sections rewritten. At
    -n 0, and in the controller, a later reader of a report's sections (a hook in a
    nested conftest) gets them as captured, a lone surrogate included.

    The write check is made on the teardown report, after every fixture has
    finished, so a write from a fixture's teardown is charged to the test that used
    it. Writes recorded before the first test (collection, session fixtures) are
    charged to that first test.
    """
    outcome = yield
    report = outcome.get_result()
    try:
        if hasattr(item.config, "workerinput"):
            report.sections = [
                (name, _sendable(text)) for name, text in report.sections
            ]
        if call.when != "teardown":
            return
        writes = real_home_guard.drain()
        if not writes:
            return
        report.outcome = "failed"
        report.longrepr = (
            "wrote under the real user's ~/.ash, which each test's own home exists "
            "to keep tests out of:\n"
            + "\n".join(f"  {event}: {path}" for event, path in writes)
        )
    finally:
        # Last, so what the lines above set is redacted too.
        redact_environment_values(report, passed_reports_are_shown(item.config))


def pytest_addoption(parser):
    """Add custom command-line options to pytest."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests",
    )
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration and e2e tests",
    )
    for marker, flag in _RUNTIME_SNAPSHOT_MARKERS.items():
        parser.addoption(
            flag,
            action="store_true",
            default=False,
            help=f"Run the {marker} tests (needs that runtime on this host)",
        )
    _add_ci_runner_options(parser)
    parser.addoption(
        "--run-changed-only",
        action="store_true",
        default=False,
        help="Run only tests for changed files",
    )
    parser.addoption(
        "--base-branch",
        default="main",
        help="Base branch for --run-changed-only option",
    )


#: Snapshot tests of output only a real container runtime or Nix can produce, and the
#: flag that selects each set. The CI legs that have the runtime pass the flag; every
#: other run DESELECTS these tests rather than skipping them. tryfirst because
#: syrupy's own pytest_collection_modifyitems records the items it is handed, and it
#: checks a test-less snapshot as unused only when every item it recorded was also
#: selected (SnapshotReport.unused in syrupy/report.py). Removing them first keeps a
#: default run's two sets equal, so that check stays on. The marked modules
#: also live in their own directory (tests/snapshot/container/runtime/), because
#: syrupy reads a whole __snapshots__ directory once any test beside it asserts.
#:
#: ``ci_runner`` marks tests/integration/docs/test_docs_ci_runners.py and its negative
#: controls, which run the CI pages' pipelines under their CI systems' runners. They run
#: only in the Docs CI Runners workflow, on GitHub-hosted runners, which passes the flag.
_RUNTIME_SNAPSHOT_MARKERS = {
    "container_runtime": "--run-container-snapshots",
    "nix_runtime": "--run-nix-snapshots",
    "ci_runner": "--run-ci-runners",
}

#: The CI-runner legs. Each ``ci_runner`` test of one block carries its leg and page as
#: the marker's ``runner`` and ``page``; --ci-runner and --ci-runner-page deselect the
#: others, so a leg's junit file holds exactly its blocks, none of them skipped.
_CI_RUNNER_LEGS = (
    "act",
    "gitlab-ci-local",
    "jenkinsfile-runner-lts",
    "jenkinsfile-runner-bundled",
    "codebuild-agent",
    "circleci",
)


def _add_ci_runner_options(parser):
    group = parser.getgroup(
        "ci-runner", "the CI pages' pipelines under their CI systems' runners"
    )
    group.addoption(
        "--ci-runner",
        choices=_CI_RUNNER_LEGS,
        default=None,
        help="run only the blocks of this leg",
    )
    group.addoption(
        "--ci-runner-page",
        default=None,
        help="run only the blocks of this page, a repository-relative path",
    )
    group.addoption(
        "--ci-runner-bin",
        default=None,
        help="the directory install_tools.py installed the leg's tools in",
    )
    group.addoption(
        "--ci-runner-jenkins-dir",
        default=None,
        help="the directory install_tools.py put the Jenkins core and plugins in",
    )
    group.addoption(
        "--ci-runner-wheel",
        default=None,
        help="the ASH wheel built from the checkout under test",
    )
    group.addoption(
        "--ci-runner-out",
        default=None,
        help="the directory every run's logs, pipelines and reports are written to",
    )
    group.addoption(
        "--ci-runner-launch-timeout",
        type=float,
        default=1800.0,
        help="seconds each runner launch may take before it is stopped (default 1800)",
    )


def _ci_runner_unselected(item, config) -> bool:
    """Whether --ci-runner or --ci-runner-page leaves out this test of one block."""
    leg = config.getoption("--ci-runner")
    page = config.getoption("--ci-runner-page")
    if leg is None and page is None:
        return False
    for mark in item.iter_markers("ci_runner"):
        if "runner" not in mark.kwargs and "page" not in mark.kwargs:
            continue
        return (leg is not None and mark.kwargs.get("runner") != leg) or (
            page is not None and mark.kwargs.get("page") != page
        )
    return False


#: The test tiers. Every collected test carries exactly one of these markers.
#:
#: Why this exists. The CI jobs select tests by tier: ``-m unit`` runs the in-process
#: tests and is not sharded, ``-m integration`` runs the tests that start a real tool or
#: a product subprocess and is sharded, and ``-m e2e`` runs the whole product as an
#: operator would. The request that set this up was to "separate our testing groups and
#: require categorizing tests as unit vs integration vs e2e", with integration sharded
#: and unit not. A test with no tier would be left out of every one of those jobs, and a
#: test with two would run in two of them.
#:
#: - unit: runs in-process; starts no subprocess, touches no network, runs no real
#:   external tool, and writes only under tmp_path.
#: - integration: starts a real external tool or a product subprocess, or exercises one
#:   component against a real dependency (a sandbox backend, boto3 with moto).
#: - e2e: drives the whole product as an operator would: the ash CLI against a real
#:   target tree, the container image, or the MCP server as a child process.
#:
#: Markers, not ``item.keywords``. The keywords also hold the names of the item's
#: directories, module and function, so a test under tests/integration/ or one named
#: test_integration_x would read as marked. ``get_closest_marker`` sees only markers: a
#: module-level ``pytestmark``, a class decorator or a function decorator. There is no
#: directory default, and none should be added: each author states the tier.
#:
#: A usage error, not a skip or a warning. An uncategorized test must never run green
#: or be left out of every tier job without anyone noticing; a usage error fails the
#: whole session before any test runs and names the offenders. The check is the first
#: thing the tryfirst hook below does, so it sees every collected item before -k, -m or
#: any deselection removes one.
#:
#: A second refusal, for a test marked both ``unit`` and ``slow``. The unit CI job runs
#: ``-m unit`` with neither ``--run-integration`` nor ``--run-slow``, so the ``--run-slow``
#: skip below would skip such a test there, and ``-m integration`` and ``-m e2e`` do not
#: select it. It would run in no CI job while every job stayed green. It is a usage
#: error for the same reason as the first: the loss is silent. A slow test belongs to the
#: integration tier, which runs with ``--run-slow``. This one keys on the markers too,
#: although the ``--run-slow`` skip also matches a keyword named ``slow``.
#:
#: tests/unit/test_every_test_carries_one_tier_marker.py pins both checks.
_TEST_TIERS = ("unit", "integration", "e2e")

#: How many offenders the refusal names. The count it prints is always the whole count.
_TIER_REFUSAL_LISTED = 50


def _items_without_one_tier(items) -> List[Tuple[str, List[str]]]:
    """``(node id, tiers carried)`` for every item without exactly one tier marker."""
    offenders = []
    for item in items:
        tiers = {
            name for name in _TEST_TIERS if item.get_closest_marker(name) is not None
        }
        if len(tiers) != 1:
            offenders.append((item.nodeid, sorted(tiers)))
    return offenders


def _tier_refusal_message(offenders: List[Tuple[str, List[str]]]) -> str:
    """The usage error's text: the count, the rule, and the first offenders."""
    listed = [
        f"{nodeid} -> {', '.join(tiers) if tiers else 'none'}"
        for nodeid, tiers in offenders[:_TIER_REFUSAL_LISTED]
    ]
    unlisted = len(offenders) - len(listed)
    if unlisted:
        listed.append(f"... and {unlisted} more")
    return (
        f"{len(offenders)} collected test(s) do not carry exactly one tier marker: "
        "every test needs exactly one of the unit, integration or e2e markers; "
        "see tests/NAMING_CONVENTIONS.md\n" + "\n".join(listed)
    )


def _unit_items_marked_slow(items) -> List[str]:
    """Node ids of the items that carry both the ``unit`` and the ``slow`` marker."""
    return [
        item.nodeid
        for item in items
        if item.get_closest_marker("unit") is not None
        and item.get_closest_marker("slow") is not None
    ]


def _unit_slow_refusal_message(nodeids: List[str]) -> str:
    """The usage error's text for unit tests that are also slow: count, rule, ids."""
    listed = nodeids[:_TIER_REFUSAL_LISTED]
    unlisted = len(nodeids) - len(listed)
    if unlisted:
        listed.append(f"... and {unlisted} more")
    return (
        f"{len(nodeids)} unit test(s) also carry the slow marker: the unit tier runs "
        "without --run-slow, so such a test would run in no CI job; mark it "
        "integration (which runs with --run-slow) or drop slow; "
        "see tests/NAMING_CONVENTIONS.md\n" + "\n".join(listed)
    )


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Modify the collected test items based on command-line options."""
    untiered = _items_without_one_tier(items)
    if untiered:
        raise pytest.UsageError(_tier_refusal_message(untiered))

    unit_and_slow = _unit_items_marked_slow(items)
    if unit_and_slow:
        raise pytest.UsageError(_unit_slow_refusal_message(unit_and_slow))

    deselected = [
        item
        for item in items
        if any(
            item.get_closest_marker(marker) is not None and not config.getoption(flag)
            for marker, flag in _RUNTIME_SNAPSHOT_MARKERS.items()
        )
        or _ci_runner_unselected(item, config)
    ]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [item for item in items if item not in deselected]

    # Skip slow tests unless --run-slow is specified
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="Need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)

    # Skip integration and e2e tests unless --run-integration is specified. The tier
    # marker is what selects them, not a name in the item's keywords. The tests under
    # tests/integration/ are covered because every file there carries a tier marker
    # (the check at the top of this hook), not because of the directory's name.
    if not config.getoption("--run-integration"):
        skip_integration = pytest.mark.skip(
            reason="Need --run-integration option to run"
        )
        for item in items:
            if item.get_closest_marker("integration") or item.get_closest_marker("e2e"):
                item.add_marker(skip_integration)


@pytest.fixture(scope="session", autouse=True)
def _keep_live_logging_off_the_ash_logger(request):
    """Detach pytest's live-logging handler from the ``ash`` logger.

    Why this exists. ``pytest.ini`` sets ``log_cli = True``, and
    ``automated_security_helper.utils.log`` sets ``ASH_LOGGER.propagate = False``.
    pytest adds its session-lifetime ``_LiveLoggingStreamHandler`` to the root
    logger and -- because a non-propagating logger would never reach root -- to
    every non-propagating logger that exists when the test loop starts
    (``catching_logs.__enter__`` in ``_pytest/logging.py``). So every ASH record at
    ``log_cli_level`` or above goes through that handler, and the handler suspends
    and resumes pytest's capture around its write, via
    ``CaptureManager.global_and_fixture_disabled``. Resuming assigns
    ``sys.stdout``/``sys.stderr`` (``SysCapture.suspend`` in
    ``_pytest/capture.py``).

    That assignment is fatal inside ``typer.testing.CliRunner.invoke``. Its
    ``isolation()`` puts a ``TextIOWrapper`` over each buffer it will read back
    afterwards and keeps no reference to the wrapper other than ``sys.stdout`` /
    ``sys.stderr``. Reassigning those drops the last reference, the wrapper is
    finalized, finalizing closes the wrapped buffer, and ``invoke``'s ``finally``
    clause raises ``ValueError: I/O operation on closed file`` where it would have
    returned a ``Result``. A CLI test on any code path that logs then dies in the
    harness instead of reporting what the CLI did -- and the CLI itself is fine,
    which is what makes the failure so hard to read.

    Only ``log_cli_handler`` is removed. ``LogCaptureHandler`` stays, so ``caplog``
    and the "Captured log call" report section still see ASH records; those
    handlers write to a ``StringIO`` and never touch capture.

    What was tried and rejected. Dropping ``capsys`` from the affected test does
    not help -- pytest's global fd-level capture reassigns the streams on suspend
    as well, and the failure reproduces byte for byte without the fixture. Setting
    ``log_cli = False`` in ``pytest.ini`` also works and is a shorter edit, but it
    turns live logging off for every logger rather than for the one that is
    incompatible with ``CliRunner``, and live logging is genuinely useful when
    running a single test with ``-n0``.

    Failure mode this prevents, and why it looked like a platform bug. Without
    this fixture the outcome is order-dependent, because any test that clears the
    ``ash`` logger's handlers permanently detaches the session-scoped handler for
    the rest of that worker process -- ``cli/main.py``'s ``reset_logging_config``
    and ``utils/log.py``'s ``get_logger`` both did, before they removed only the
    handlers ASH added, and seven files under ``tests/unit/cli`` reach one of
    them. Under ``-n auto`` the xdist worker
    count decides which tests share a process, so one commit was green on the
    4-worker Linux and Windows runners and red on the 3-worker macOS runners.
    """
    plugin = request.config.pluginmanager.get_plugin("logging-plugin")
    handler = getattr(plugin, "log_cli_handler", None)
    if handler is not None:
        logging.getLogger("ash").removeHandler(handler)
    yield


_ASH_LOGGER_NAMESPACES = ("ash", "automated_security_helper")


def _is_ash_logger_name(name: str) -> bool:
    return any(name == ns or name.startswith(ns + ".") for ns in _ASH_LOGGER_NAMESPACES)


def _ash_loggers() -> "dict[str, logging.Logger]":
    """Every real logger (not placeholder) in ASH's namespaces that exists now."""
    loggers = {
        name: logger
        for name, logger in logging.root.manager.loggerDict.items()
        if isinstance(logger, logging.Logger) and _is_ash_logger_name(name)
    }
    loggers.setdefault("ash", logging.getLogger("ash"))
    return loggers


class _AshLoggerSwitches:
    """Snapshot and restore ``level``/``propagate``/``disabled`` on ASH's loggers."""

    def __enter__(self) -> "Self":
        self._saved = {
            name: (logger.level, logger.propagate, logger.disabled)
            for name, logger in _ash_loggers().items()
        }
        return self

    def __exit__(self, *exc_info) -> None:
        for name, logger in _ash_loggers().items():
            if name in self._saved:
                logger.level, logger.propagate, logger.disabled = self._saved[name]
            else:
                logger.disabled = False
        # Each logger caches isEnabledFor's answer per level, and only setLevel
        # clears that cache. Restored by assignment, a level left the answers the
        # test's own level gave, so a later test that set its level the same way
        # had its records dropped as below the level it had just set.
        logging.Logger.manager._clear_cache()


@pytest.fixture(autouse=True)
def _fresh_mcp_scan_registry():
    """Give every test its own MCP scan registry.

    The registry is a process-global, and a test that starts a scan with its
    runner patched out (``asyncio.create_task`` replaced, say) leaves the entry
    PENDING for the rest of the worker. The MCP server refuses a scan beyond the
    operator's ``max_concurrent_scans`` (3 by default), so three such leftovers
    would make an unrelated test's scan fail as over the limit, on whichever worker
    happened to collect them. A test that wants a registry of its own installs one.

    A private ``MonkeyPatch``, as in ``_keep_install_receipts_out_of_the_developer_home``
    below: requesting the ``monkeypatch`` fixture from an autouse fixture sets it up
    before every test's own fixtures and so tears it down after them, which delays
    the undo of each test's ``monkeypatch.setenv`` past fixtures that check the
    environment (tests/unit/test_conftest_helpers.py).
    """
    from automated_security_helper.core.resource_management import scan_registry

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(scan_registry, "_scan_registry", scan_registry.ScanRegistry())
        yield


@pytest.fixture(autouse=True)
def _a_stand_in_context_with_unset_headers_is_the_in_process_caller(request):
    """A test double's unset ``headers`` is read as no headers at all.

    ``session_identity.resolve_session_id`` reads headers that are not a mapping
    as naming no session (the unidentified session, remote and with no sandbox),
    and not as the absence of headers, which is the in-process caller and the
    default session with its local trust. The doubles tests build for a tool's
    context (``MagicMock()``, ``MagicMock(spec=Context)``) have a ``headers`` that
    was never set: a mock the double made on access, which holds nothing and is
    not a mapping, and the cells that use them mean the in-process caller. The
    production function carries no clause for them; this wrapper maps a mock that
    is not a mapping to None for the callers that reach it through
    ``resolve_caller_session_id``. Anything else is the production rule's: a
    cell that sets ``headers`` (a dict, None, an object) is not touched, and a
    cell marked ``production_header_rule`` is not touched even when it sets a
    mock. The cells that pin the rule call the function they imported by name,
    which this does not replace.

    A private ``MonkeyPatch``, as in ``_fresh_mcp_scan_registry`` above. The
    module is imported here and not only patched when already loaded: a cell
    that imports the MCP tools in its own body (tests/unit/cli/test_mcp_server.py
    does) runs, alone or first on a worker, before anything has loaded it, and
    would get the real rule for its double. The import is the MCP package's, once
    per process, and the package needs nothing optional to import.
    """
    from collections.abc import Mapping
    from unittest.mock import NonCallableMock

    if request.node.get_closest_marker("production_header_rule") is not None:
        yield
        return

    try:
        from automated_security_helper.cli.mcp import session_identity
    except ImportError:
        yield
        return

    real = session_identity.resolve_session_id

    def with_unset_headers_read_as_none(headers):
        if isinstance(headers, NonCallableMock) and not isinstance(headers, Mapping):
            headers = None
        return real(headers)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            session_identity, "resolve_session_id", with_unset_headers_read_as_none
        )
        yield


@pytest.fixture(autouse=True)
def _event_streams_left_open():
    """sse-starlette's shutdown flag cleared, and uvicorn's exit handler put back.

    sse-starlette replaces uvicorn's ``Server.handle_exit`` with one that also
    sets the process-wide ``AppStatus.should_exit``, and from then on every event
    stream in the process ends at once. A test that calls a real server's
    handle_exit (test_server_exit_paths, among others) would set it for every
    later test in the same worker, and a tool call over streamable HTTP would get
    an empty event stream, not its result. So the flag is cleared before and after
    each test, and a handle_exit a test replaced is put back.

    Only modules already imported are touched: importing sse-starlette here would
    itself replace uvicorn's handle_exit for every test.
    """
    with _sse_flag_cleared_and_handle_exit_restored():
        yield


@contextlib.contextmanager
def _sse_flag_cleared_and_handle_exit_restored():
    """What ``_event_streams_left_open`` does around each test.

    sse-starlette's own replacement of handle_exit, made when a test imports it
    for the first time, is kept: the import happens once per process, so undoing
    it left every later test's servers without the shutdown flag.
    """
    import sys

    sse = sys.modules.get("sse_starlette.sse")
    if sse is not None:
        sse.AppStatus.should_exit = False
    server_module = sys.modules.get("uvicorn.server")
    handle_exit = (
        server_module.Server.__dict__.get("handle_exit")
        if server_module is not None
        else None
    )
    yield
    sse = sys.modules.get("sse_starlette.sse")
    if sse is not None:
        sse.AppStatus.should_exit = False
    if server_module is None or handle_exit is None:
        return
    current = server_module.Server.__dict__.get("handle_exit")
    if current is handle_exit:
        return
    if sse is not None and current is sse.AppStatus.handle_exit:
        # sse-starlette's import-time patch, not a test's replacement.
        return
    server_module.Server.handle_exit = handle_exit


@pytest.fixture(autouse=True)
def _no_recorded_process_group_outlives_its_test():
    """Kill and forget every process group a test left in subprocess_utils' record.

    A cancellable spawn's child stays recorded until it is reaped, so that the MCP
    server can kill it before it exits (kill_running_groups). A test whose child
    outlived it, such as one that stubs the stop out, handed the entry to the next
    test on the same xdist worker, and a test that counts the groups killed then
    counted it. Only this process's own children are recorded.

    The registry's mirror (core/cancellation._TOOL_GROUPS, the SIGTERM
    handler's die-now kill list) must hold nothing the registry does not: a
    stale entry outlives its reaped pid, and a later die-now cell would
    killpg(SIGKILL) whatever process group holds that id next. The guard
    fails the test that left one, then clears it so later cells in the worker
    are not the ones at risk.

    The die-now cleanup record (core/cancellation._CLEANUP_FILES, the files the
    handlers remove before the default kill) is held to the same rule: it must
    be empty when a test ends, since an entry names a path the die-now walk would
    unlink by name. A test that takes one drops it itself (the env-file context
    manager does, and the keeps-record cells reset the tuple through
    ``monkeypatch``, which restores it). The guard fails the test that left one
    and clears it.
    """
    yield
    import time

    from automated_security_helper.core import cancellation
    from automated_security_helper.utils import subprocess_utils
    from tests.utils.processes import forget_running_groups

    def _stale_mirror_entries():
        with subprocess_utils._RUNNING_GROUPS_LOCK:
            recorded = set(subprocess_utils._RUNNING_GROUPS)
        stale_groups = [g for g in cancellation._TOOL_GROUPS if g not in recorded]
        # The plain-pid mirror (launcher children that lead no group) is held
        # to the same registry: a stale plain pid is the same hazard, sharper,
        # since a single pid is reused faster than a pgid.
        stale_pids = [p for p in cancellation._TOOL_PIDS if p not in recorded]
        return stale_groups + stale_pids

    stale = _stale_mirror_entries()
    if stale:
        # A spawn mid-teardown can sit between its two records for a moment;
        # one re-read tells a window from a leak.
        time.sleep(0.05)
        stale = _stale_mirror_entries()
    forget_running_groups()
    leaked_files = tuple(cancellation._CLEANUP_FILES)
    for entry in leaked_files:
        cancellation.discard_die_now_cleanup(entry)
    if stale:
        # forget_running_groups clears the mirrors too, but this check must
        # not lean on that: were its clear to regress, one leak would error
        # every later test in the worker. Discarding the stale ids here keeps
        # the failure with the test that leaked. A discard of an id the other
        # mirror holds is a no-op.
        for entry in stale:
            cancellation.discard_tool_group(entry)
            cancellation.discard_tool_pid(entry)
        pytest.fail(
            "the test left process groups or pids in the SIGTERM handler's "
            f"mirrors with no registered child behind them: {stale}. A "
            "die-now cell later in this worker would SIGKILL those possibly "
            "reused ids. Forget children through the paths that discard "
            "their mirror entry."
        )
    if leaked_files:
        pytest.fail(
            "the test left files on the die-now cleanup record: "
            f"{list(leaked_files)}. A die-now ending later in this worker would "
            "unlink those paths by name. Take the file through "
            "run_ash_container._env_file, or discard the record "
            "(core/cancellation.discard_die_now_cleanup) once the file is gone."
        )


@pytest.fixture(autouse=True)
def _no_scanned_tree_scope_outlives_its_test():
    """A test that leaves a scanned-tree scope active fails, rather than its neighbors.

    The scope (utils/subprocess_utils.scanning_tree) makes every later lookup in the
    context refuse tools inside its tree, so one left behind changes what an
    unrelated test finds. ``ash mcp`` also turns off the operator's opt-in for the
    whole process, and a module-scoped fixture that starts the server would leave
    it off for every later test on the worker, so each test starts and ends with
    the process default, on.
    """
    from automated_security_helper.utils import subprocess_utils

    subprocess_utils._opt_in_honored = True
    yield
    leaked = subprocess_utils._TREE_SCOPE.get()
    subprocess_utils._opt_in_honored = True
    assert leaked is None, f"a scanned-tree scope was left active: {leaked.roots}"


@pytest.fixture(autouse=True)
def _restore_ash_logger_switches():
    """Stop one test's logging side effects from blinding another's ``caplog``.

    ``level``, ``propagate`` and ``disabled`` live on a process-global logger
    object, so a test that changes any of them changes it for every later test on
    the same xdist worker. ``disabled`` is the dangerous one: a disabled logger
    drops records inside ``Logger.handle``, before any handler is consulted, so
    ``caplog.records`` comes back empty and the assertion reads as the code under
    test not having logged at all. Nothing in the record says logging was off.

    No test sets ``disabled`` on purpose. It gets set from a distance: any
    ``logging.config.dictConfig`` call whose payload has
    ``disable_existing_loggers`` true -- the default -- disables every logger not
    named in that payload, and libraries do this at import time. ``commitizen``
    is one, at ``commitizen/__init__.py``, so a single ``import commitizen`` from
    inside a test disables the ``ash`` logger for the rest of that worker.

    That is how this was found, and the shape is worth remembering because none
    of the signals point at the cause. Two ``test_cdk_nag_wrapper_behavior``
    assertions went red on eleven CI cells after an unrelated test file was added
    in a different directory; they passed with that file removed, passed when run
    alone, and passed at a different ``-n`` because the worker count decides which
    tests share a process. The failing tests were not at fault, the added file did
    not touch logging, and nothing in either was near cdk-nag.

    It is not only the ``ash`` logger. ``dictConfig`` disables every logger that
    exists at the time, and ASH's modules also log through their own
    ``logging.getLogger(__name__)`` loggers -- ``run_ash_scan`` reports "Scan
    incomplete: ..." on one. The second instance of this bug: with
    ``run_ash_scan`` already imported on a worker, ``test_release_line_workflow``'s
    ``from commitizen import changelog`` disabled
    ``automated_security_helper.interactions.run_ash_scan``, and the container
    exit-code snapshots that ran later on the same worker captured an empty
    stderr. Two of five full local runs failed that way; replaying the failing
    worker's test order with ``-n0`` failed every time.

    So the switches are snapshotted for every logger in ASH's two namespaces
    (``ash`` and ``automated_security_helper``) and restored after each test, and
    an ASH logger first created during the test is re-enabled, because nothing in
    ASH disables its own loggers on purpose. That keeps the blast radius of any
    such import inside the test that caused it. Handlers are deliberately left alone:
    the session fixture above manages those, and rebuilding the handler list here
    would fight it.
    """
    with _AshLoggerSwitches():
        yield


_UV_TOOL_RUNNER_MODULE = "automated_security_helper.utils.uv_tool_runner"
_PLUGINS_MODULE = "automated_security_helper.plugins"
_PLUGIN_REGISTRIES = ("converters", "scanners", "reporters")

#: Module-level memos of an answer about the host: whether uv runs, where an
#: executable is, what version a tool reports, which sandbox backend works. Each
#: is computed once per process and then served to every caller, so a test that
#: reaches the probe through a stand-in leaves the stand-in's answer for every
#: later test on the same xdist worker. Each entry is a dict or list.
_PROCESS_WIDE_PROBE_MEMOS = (
    (_UV_TOOL_RUNNER_MODULE, "_uv_tool_version_cache"),
    (_UV_TOOL_RUNNER_MODULE, "_uv_command_cache"),
    (_UV_TOOL_RUNNER_MODULE, "_uv_executable_cache"),
    (_UV_TOOL_RUNNER_MODULE, "_executable_cache"),
    ("automated_security_helper.utils.subprocess_utils", "_find_executable_cache"),
    ("automated_security_helper.utils.pre_installed_tool", "_verdict_cache"),
    ("automated_security_helper.utils.sandbox.scope", "_resolved"),
    ("automated_security_helper.utils.sandbox.backends", "_trust_roots_cache"),
    (
        "automated_security_helper.interactions.run_ash_container",
        "_BUILDX_SUPPORT_CACHE",
    ),
)

#: The memos whose answers each cost a ``uv tool run <tool> --version``. A
#: successful answer that the code under test wrote into one of them outlives the
#: test; see "Cost" in ``_restore_process_wide_tool_state`` for why.
_UV_TOOL_RUN_MEMOS = frozenset(
    {
        (_UV_TOOL_RUNNER_MODULE, "_uv_tool_version_cache"),
        (_UV_TOOL_RUNNER_MODULE, "_uv_command_cache"),
    }
)


class _ProcessWideToolState:
    """Snapshot and restore the uv tool runner, the probe memos, and the plugin manager.

    On exit, puts back what was there on entry:

    * the ``get_uv_tool_runner()`` singleton: which object it is, and that object's
      attributes, including its memoized ``_uv_available_cache``;
    * every memo in ``_PROCESS_WIDE_PROBE_MEMOS``, except that a new *successful*
      answer in one of the ``_UV_TOOL_RUN_MEMOS`` is kept. Only an answer in the
      module's own memo object counts; a test that rebinds a memo to a dict of its
      own made up everything in it;
    * ``ash_plugin_manager``'s resolved-plugin memo, event handlers and plugin
      registrations, and the modules it has recorded the operator naming
      (``trust_plugin_modules``). Which registrations an untrusted import made
      is not rolled back: such a registration is kept or dropped by the rule
      below, and the record is ignored once its registration is gone.

    A module first imported during the test has no snapshot, so what its import
    built is the baseline: an empty memo, a fresh runner from
    ``reset_uv_tool_runner()``, and a plugin manager with nothing resolved.

    Plugin registrations and event handlers are not simply rolled back. The
    ``ash_*_plugin`` decorators register a plugin when its module is imported, and
    an import runs once per process. So one added during the test is kept when its
    module was first imported during the test, because nothing would ever add it
    again, and dropped otherwise, because then the test added it by hand
    (``register_plugin_module("converter", "test-plugin", ...)``) or declared the
    plugin inside the test. ``tests/snapshot/conftest.py``'s
    ``_merge_new_registrations`` applies the same rule.

    The manager's ``context`` is left alone. Nothing reads it, and
    ``tests/unit/workspace/test_project_isolation.py`` fails if anything starts to,
    so a context a test leaves behind cannot reach another test. That file's
    registry sweep also lists this one as allowed to reach the manager's state; the
    resolved-plugin memo is reached through ``getattr`` because its prose check
    requires the dotted spelling to appear nowhere in the repository.
    """

    def __enter__(self) -> "Self":
        self._modules_before = frozenset(sys.modules)
        self._memos = {}
        for module_name, attribute in _PROCESS_WIDE_PROBE_MEMOS:
            module = sys.modules.get(module_name)
            if module is not None:
                memo = getattr(module, attribute)
                self._memos[module_name, attribute] = (memo, type(memo)(memo))
        self._runner = None
        runner_module = sys.modules.get(_UV_TOOL_RUNNER_MODULE)
        if runner_module is not None:
            runner = runner_module._uv_tool_runner
            self._runner = (runner, dict(vars(runner)))
        self._plugins = None
        plugins = sys.modules.get(_PLUGINS_MODULE)
        if plugins is not None:
            ash_plugin_manager = plugins.ash_plugin_manager
            library = ash_plugin_manager.plugin_library
            self._plugins = {
                "manager": ash_plugin_manager,
                "library": library,
                "resolved": dict(getattr(ash_plugin_manager, "_resolved_plugins")),
                "operator_modules": set(
                    getattr(ash_plugin_manager, "_operator_modules")
                ),
                "event_handlers": (
                    library.event_handlers,
                    {
                        event: (callbacks, list(callbacks))
                        for event, callbacks in library.event_handlers.items()
                    },
                ),
                "registries": {
                    kind: (getattr(library, kind), dict(getattr(library, kind)))
                    for kind in _PLUGIN_REGISTRIES
                },
            }
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._restore_probe_memos()
        self._restore_uv_tool_runner()
        self._restore_plugin_manager()

    def _imported_during_the_test(self, module_name: str) -> bool:
        return module_name in sys.modules and module_name not in self._modules_before

    def _restore_probe_memos(self) -> None:
        for key in _PROCESS_WIDE_PROBE_MEMOS:
            module_name, attribute = key
            module = sys.modules.get(module_name)
            if module is None:
                continue
            current = getattr(module, attribute)
            memo, contents = self._memos.get(key, (current, type(current)()))
            successes = {}
            if key in _UV_TOOL_RUN_MEMOS:
                # Read from the module's own memo object. If the test rebound the
                # name to a dict of its own, nothing in that dict is kept.
                successes = {
                    name: answer
                    for name, answer in memo.items()
                    if name not in contents and answer is not None
                }
            setattr(module, attribute, memo)
            memo.clear()
            if isinstance(memo, dict):
                memo.update(contents)
                memo.update(successes)
            else:
                memo.extend(contents)

    def _restore_uv_tool_runner(self) -> None:
        if _UV_TOOL_RUNNER_MODULE not in sys.modules:
            return
        # Imported by name, not reached through sys.modules, so that a type checker
        # sees the real module and checks the name assigned below. The test above
        # keeps this from importing the module when the test did not.
        from automated_security_helper.utils import uv_tool_runner

        if self._runner is None:
            uv_tool_runner.reset_uv_tool_runner()
            return
        runner, attributes = self._runner
        uv_tool_runner._uv_tool_runner = runner
        # Under the runner's own probe lock: every ``_uv_available_cache`` write is
        # made while ``_uv_probe_lock`` is held, so a restore under the same lock
        # lands before or after an in-flight probe, never inside one. The dict is
        # repaired in place, saved attributes set and extras deleted; it is never
        # emptied first, because ``vars().clear()`` unbinds the probe lock itself
        # for a moment and a thread reaching the runner then finds no lock at all.
        lock = getattr(runner, "_uv_probe_lock", None)
        with lock if lock is not None else contextlib.nullcontext():
            state = vars(runner)
            for name in set(state) - set(attributes):
                del state[name]
            state.update(attributes)

    def _restore_plugin_manager(self) -> None:
        if _PLUGINS_MODULE not in sys.modules:
            return
        # By name for the same reason as in _restore_uv_tool_runner.
        from automated_security_helper import plugins

        saved = self._plugins
        if saved is None:
            ash_plugin_manager = plugins.ash_plugin_manager
            library = ash_plugin_manager.plugin_library
            saved = {
                "manager": ash_plugin_manager,
                "library": library,
                "resolved": {},
                "operator_modules": set(),
                "event_handlers": (library.event_handlers, {}),
                "registries": {
                    kind: (getattr(library, kind), {}) for kind in _PLUGIN_REGISTRIES
                },
            }

        ash_plugin_manager = saved["manager"]
        library = ash_plugin_manager.plugin_library
        # Read what the imports added before anything is put back: the dicts and
        # lists being restored may be the very objects the test added to.
        subscribed_by_an_import = [
            (event, callback)
            for event, callbacks in library.event_handlers.items()
            for callback in callbacks
            if self._imported_during_the_test(getattr(callback, "__module__", "") or "")
        ]
        registered_by_an_import = {
            kind: {
                name: registration
                for name, registration in getattr(library, kind).items()
                if name not in registrations
                and self._imported_during_the_test(registration.plugin_module_path)
            }
            for kind, (_, registrations) in saved["registries"].items()
        }

        plugins.ash_plugin_manager = ash_plugin_manager
        library = saved["library"]
        ash_plugin_manager.plugin_library = library
        resolved = getattr(ash_plugin_manager, "_resolved_plugins")
        resolved.clear()
        resolved.update(saved["resolved"])
        operator_modules = getattr(ash_plugin_manager, "_operator_modules")
        operator_modules.clear()
        operator_modules.update(saved["operator_modules"])

        handlers_by_event, saved_handlers = saved["event_handlers"]
        library.event_handlers = handlers_by_event
        handlers_by_event.clear()
        for event, (callbacks, subscribed) in saved_handlers.items():
            callbacks[:] = subscribed
            handlers_by_event[event] = callbacks
        for event, callback in subscribed_by_an_import:
            callbacks = handlers_by_event.setdefault(event, [])
            if callback not in callbacks:
                callbacks.append(callback)

        for kind, (registry, registrations) in saved["registries"].items():
            setattr(library, kind, registry)
            registry.clear()
            registry.update(registrations)
            registry.update(registered_by_an_import[kind])


@pytest.fixture(autouse=True)
def _restore_process_wide_tool_state() -> Iterator[None]:
    """Stop one test's tool probes and plugin registrations from leaking into the next.

    Why this exists. ``get_uv_tool_runner()`` returns one ``UVToolRunner`` per
    process, and its ``is_uv_available()`` memoizes the first answer forever. The
    ``TestHowNbconvertIsRun`` tests in
    ``test_jupyter_conversion_runs_outside_tree.py`` patched
    ``jupyter_converter.subprocess.run``, which is the standard library's
    ``subprocess.run`` and so every caller's, and then built a ``JupyterConverter``.
    Construction probes uv (``model_post_init`` asks for the tool version). The
    probe reached the stand-in, which raised ``IndexError`` on ``cmd[6]`` for
    ``["uv", "--version"]``, and ``is_uv_available`` caught it and memoized False.
    Every later test on that xdist worker that used the process-wide runner was
    told "UV is not available".
    ``test_subprocess_timeout.py::...::test_run_tool_forwards_the_timeout_on_the_results_dir_branch``
    failed that way on Windows py3.11 and py3.14 and passed everywhere else. Two
    per-file fixtures (``test_nix_provided_scanner_selection.py``,
    ``test_pre_installed_tool_offline.py``) reset the runner around their own tests,
    which cleared the poisoned answer whenever one ran between the two tests on the
    same worker. Both files are skipped on Windows, so there nothing cleared it.

    How the poisoners were found. A probe plugin recorded this state before and
    after every test of a full ``-n 8`` run, once as the suite runs and once with
    the runner reset before each test, so that a test is seen poisoning even when
    an earlier test on its worker had already warmed the memo. What it found:

    * ``is_uv_available`` memoized False: the four ``TestHowNbconvertIsRun`` tests
      above, and nothing else.
    * ``get_tool_version`` memoized None: ``test_converters.py``'s
      ``test_jupyter_converter_convert`` (the same stdlib patch, made before
      construction, whose stand-in exits 0 for ``uv --version`` too), and
      ``test_tool_version_is_a_version_specifier.py``'s
      ``test_the_refused_value_never_reaches_a_uv_argv``, which has to send the
      probe through its recorder to see the argv.
    * ``find_executable`` memoized stand-in answers (``test_cmd``, ``somecmd``, and
      None for an installed ``opengrep``).
    * ``ash_plugin_manager`` left with a ``test-plugin`` converter registration and
      with event handlers cleared or added.

    Each of those is a value one test made up and every later test on the worker
    is served. Fixing a poisoner in its own file, by building the object before
    patching and patching the module's own name rather than the standard
    library's, removes that one poisoner. This fixture is what keeps the next one
    from becoming an order-dependent failure on whichever platform's worker packing
    happens to run it before a victim.

    Cost, and the one exception it buys. Rolling every memo back makes each test
    that builds a uv-run scanner probe its tool again. The version probes are not
    cheap: measured locally, ``uv tool run --from checkov ... --version`` takes
    4.2 s and semgrep 2.5 s, and the comment on ``_pinned_uv_tool_probe`` in
    tests/snapshot/conftest.py records a semgrep probe on a Windows runner that
    took 25 s against a 15 s timeout. Rolled back in full, the suite at ``-n 8``
    took 307 s against 259 s without this fixture, run side by side, and every
    extra probe is another chance to time out on a loaded runner. So a successful
    answer the code wrote into ``_uv_tool_version_cache`` or ``_uv_command_cache``
    is kept, as it was before this fixture. With that exception, a second
    side-by-side pair of runs took 101 s against 100 s. Every poisoned value the
    probe plugin found is a failure (False or None) or lives in a memo that is
    cheap to recompute, and every successful answer it saw in those two memos,
    across the whole suite, was the real tool's version.

    Known limitation. A test that makes up a *successful* version answer by
    patching the subprocess layer under ``get_tool_version`` would still leak it.
    None does today. Patch ``UVToolRunner.get_tool_version`` itself, as
    ``_pinned_uv_tool_probe`` does, which never reaches the memo.

    What it deliberately does not cover. The MCP scan registry and the warn-once
    sets (``path_trust._WARNED``, ``options._REFUSED_TOOL_VERSIONS``) also outlive a
    test, but they record what happened rather than memoize an answer about the
    host, no test is known to read a stale entry, and an MCP scan's background
    thread can still be updating its registry entry after the test returns.
    """
    with _ProcessWideToolState():
        yield


@pytest.fixture(autouse=True)
def _no_ash_config_from_the_shell():
    """Unset ``ASH_CONFIG`` for every test; a test that needs it sets it itself.

    ``ASH_CONFIG`` names the config file ASH uses when none is named, and a file
    it names that does not exist refuses resolution (exit 3) rather than being
    replaced by the defaults. So a value left in the developer's shell, or in a
    CI job's environment, reaches every test that resolves a config: with
    ``ASH_CONFIG`` naming a missing file, 41 tests in six config, MCP and
    orchestrator test files failed, none of them about ``ASH_CONFIG``. Tests that
    exercise the variable set it with ``monkeypatch.setenv``, which runs after
    this fixture.

    A private ``MonkeyPatch``, for the reason ``_isolated_home`` gives: requesting
    the ``monkeypatch`` fixture from an autouse fixture sets it up before every
    test's own fixtures and tears it down after them, which delays the undo of
    each test's ``monkeypatch.setenv`` past fixtures that check the environment
    (tests/unit/test_conftest_helpers.py).
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.delenv("ASH_CONFIG", raising=False)
        yield


@pytest.fixture(autouse=True)
def _restore_writable_roots():
    """Give each test the guarded output roots it started with (``fs_guard``).

    The registry is process-global. A test that registers a root and does not
    release it, or makes a PluginContext the garbage collector has not reclaimed
    yet, would otherwise leave every later test on the same xdist worker writing
    below a root it never registered: those writes refuse links where the test
    expects open(). A finalizer that fires after the restore releases a root that
    is no longer there, which changes nothing.
    """
    from automated_security_helper.utils.sandbox import fs_guard

    with fs_guard._roots_lock:
        fs_guard._apply_pending_releases()
        saved = dict(fs_guard._writable_roots)
    yield
    with fs_guard._roots_lock:
        fs_guard._pending_releases.clear()
        fs_guard._writable_roots.clear()
        fs_guard._writable_roots.update(saved)


def _handlers_ash_added() -> "set[tuple[logging.Logger, logging.Handler]]":
    """Each (logger, handler) pair, on the root logger or any other, whose handler
    ASH added (``utils.log.ash_handler``). Empty until ``utils.log`` is imported:
    only it marks a handler, and this imports nothing of ASH's."""
    log_module = sys.modules.get("automated_security_helper.utils.log")
    if log_module is None:
        return set()
    loggers = [logging.getLogger()] + [
        logger
        for logger in list(logging.root.manager.loggerDict.values())
        if isinstance(logger, logging.Logger)
    ]
    return {
        (logger, handler)
        for logger in loggers
        for handler in list(logger.handlers)
        if log_module.added_by_ash(handler)
    }


@contextlib.contextmanager
def _ash_handlers_added_inside_taken_off():
    """Take off, and close, the handlers ASH added inside the block, and no other."""
    before = _handlers_ash_added()
    yield
    for logger, handler in _handlers_ash_added() - before:
        logger.removeHandler(handler)
        handler.close()


@pytest.fixture(autouse=True)
def _no_ash_handler_outlives_its_test():
    """Take off, and close, the logging handlers ASH added during a test.

    ``get_logger`` and the scan's progress display put their handlers on the
    process-wide ``ash`` logger, and they stay there until the next ``get_logger``
    replaces them. So a test that ran an ``ash`` command handed its console
    handler, its ash.log file handler (still open on a file under that test's
    tmp_path) and its progress handlers to the next test on the same xdist worker.
    A test of what ``get_logger`` keeps
    (tests/unit/utils/test_get_logger_keeps_a_host_handler.py) then found handlers
    it never put there, on whichever worker had run an ``ash`` command before it.
    Replaying one worker's order of the config, cli and utils folders with -n0
    showed 76 tests in 14 files leaving them, every one a handler ASH had marked,
    and three module-scoped fixtures doing the same.

    Fixing each of those tests was rejected: the next test written the same way
    would leave them again. Only handlers ASH marked and added during the test are
    taken off. A host's handler, pytest's, and an ASH handler there when the test
    started are left: one a module-scoped fixture set up outlives each test of the
    module, and the fixture below takes it off when the module ends.
    """
    with _ash_handlers_added_inside_taken_off():
        yield


@pytest.fixture(scope="module", autouse=True)
def _no_ash_handler_outlives_its_module():
    """What ``_no_ash_handler_outlives_its_test`` does, for the handlers a module- or
    class-scoped fixture added (tests/unit/config/test_plugin_config_reaches_the_plugin.py
    runs each phase once per module)."""
    with _ash_handlers_added_inside_taken_off():
        yield


def _open_run_log_scopes() -> "set[str]":
    """The run log scopes open in this process (``utils.log``). Empty until
    ``utils.log`` is imported; this imports nothing of ASH's. The set is read
    by its name with no fallback, so a rename there fails every guard rather
    than turning them off."""
    log_module = sys.modules.get("automated_security_helper.utils.log")
    if log_module is None:
        return set()
    return set(log_module._ACTIVE_RUN_LOG_SCOPES)


#: Scopes a guard below already failed a block for and could not close: a
#: later guard (the module's, the session's) sees the same scope still open at
#: its own end, and reporting it again would blame the module's or the
#: session's fixtures for a leak a test already answered for.
_UNCLOSABLE_SCOPES_REPORTED: "set[str]" = set()


@contextlib.contextmanager
def _run_log_scopes_opened_inside_closed(leaked_by: str) -> Iterator[None]:
    """Fail the block that leaked a run log scope, after cleaning up after it.

    A leaked scope is closed and the context variable put back, so the next
    test is not poisoned -- a scope opened on the test's own thread leaves the
    variable set, and closing by value cannot reset it, so without the
    restore the next test would run inside a closed scope. The variable is
    put back whether or not a scope leaked: a test that closed its own scope
    by value leaves no open scope behind, only the set variable, and the
    early return for "nothing leaked" skipped the restore, poisoning the
    worker the same way. Then a leak fails the block once, naming the scopes
    and *leaked_by*, what left them: a silent close let a test that leaks
    pass, and the leak it hid holds back every line no run owns for the rest
    of a real server process.

    Each scope is closed on its own, so a close that raises leaves none of
    the others open, and the failure names it instead of raising its error.
    The variable has a default (utils/log.py), so reading it raises nothing.
    A scope opened before the block (a session- or package-scoped fixture's,
    or one opened at import) is not this block's leak: the session-end check
    (_report_run_log_scopes_still_open) reports those.
    """
    log_module = sys.modules.get("automated_security_helper.utils.log")
    var_before = log_module._RUN_LOG_SCOPE.get() if log_module is not None else None
    before = _open_run_log_scopes()
    yield
    left = _open_run_log_scopes() - before - _UNCLOSABLE_SCOPES_REPORTED
    log_module = sys.modules.get("automated_security_helper.utils.log")
    if log_module is not None and log_module._RUN_LOG_SCOPE.get() != var_before:
        log_module._RUN_LOG_SCOPE.set(var_before)
    # No scope is open while utils.log is not imported, so left is empty then.
    if not left or log_module is None:
        return
    closed: "list[str]" = []
    unclosed: "list[str]" = []
    for scope in sorted(left):
        try:
            log_module.close_run_log_scope(scope)
        except Exception as error:  # noqa: BLE001 - each scope is closed on its own
            unclosed.append(f"{scope} ({type(error).__name__})")
            # Reported here, once: a later guard sees the scope still open.
            _UNCLOSABLE_SCOPES_REPORTED.add(scope)
        else:
            closed.append(scope)
    message = f"a run log scope outlived {leaked_by}"
    if closed:
        message += " and was closed here: " + ", ".join(closed)
    if unclosed:
        message += "; these could not be closed: " + ", ".join(unclosed)
    pytest.fail(
        message + ". End the scope where the run ends (end_run_log_scope, or "
        "the task or holder that owns it)."
    )


@pytest.fixture(autouse=True)
def _the_last_resorts_gate_is_restored():
    """Restore the last resort's configured level after every test.

    The gate is module-global mutable state (utils/log.py, _LAST_RESORT): a
    test that configures it and fails before its own restore poisons every
    later test on its xdist worker -- the order-dependent stderr class. The
    handler object seen at setup is the one restored, so a test that swapped
    in a stand-in through monkeypatch does not have its stub's level written
    onto the real handler.

    The module is read through ``sys.modules`` like the neighboring guards,
    so this fixture itself imports nothing and does nothing while the module
    is absent. The eager import it replaces was redundant -- this conftest's
    own module-level imports load utils.log (41 ASH modules measured in
    sys.modules before any test ran) -- but it was still a per-test import
    statement, and the one guard whose "not imported" branch was dead. The
    window the lazy read leaves: a test that first imports utils.log has no
    snapshot at its own setup, so a level it leaves configured is what the
    next test's snapshot starts from; unreachable while the conftest imports
    ASH at load, and a run with no ASH at all has no test that could touch
    the gate.
    """
    log_module = sys.modules.get("automated_security_helper.utils.log")
    if log_module is None:
        yield
        return
    handler = log_module._LAST_RESORT
    level_before = handler.level
    yield
    handler.setLevel(level_before)


@pytest.fixture(autouse=True)
def _no_run_log_scope_outlives_its_test():
    """Fail a test that leaves a run log scope open, after closing the scope.

    The MCP tools open a scan's scope and its runner task closes it. A test
    that replaces the runner, ``_start_scan_task`` or ``asyncio.create_task``
    so that no scan runs leaves the scope open, and while a scope the server
    opened is open, a line logged outside every run reaches no run's handlers
    (utils/log.py): a CLI scan the next test on the same xdist worker ran lost
    its workspace projects' lines. The scope is closed here, so the next test
    is not poisoned, and the test errors at teardown, naming it, so the leak
    is fixed where it is made: a stub ends the scan's scope as the production
    code it replaces does (tests/utils/scan_task_stubs.py), which is how the
    tests that once left one end it.
    """
    with _run_log_scopes_opened_inside_closed("this test"):
        yield


@pytest.fixture(scope="module", autouse=True)
def _no_run_log_scope_outlives_its_module():
    """What ``_no_run_log_scope_outlives_its_test`` does, for a scope a module-
    or class-scoped fixture opened. pytest shows this failure on the module's
    last test, which need not be the one that opened the scope, so the
    failure names the module's fixtures, not a test."""
    with _run_log_scopes_opened_inside_closed(
        "the module- and class-scoped fixtures of this module"
    ):
        yield


@pytest.fixture
def receipt_home(tmp_path, monkeypatch):
    """A home directory of the test's own, so install receipts stay out of the real one.

    ``download_utils.receipt_root()`` is ``Path.home()/.ash/install-receipts``, and a
    module that installs pinned tools without patching the home wrote its receipts
    into the developer's real ``~/.ash``. Use it module-wide with
    ``pytestmark = pytest.mark.usefixtures("receipt_home")``. A test that patches
    ``Path.home`` or sets HOME itself still wins, since it does so later.
    """
    home = tmp_path / "receipt-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # Path.home() reads USERPROFILE on Windows.
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def ash_temp_path():
    """Create a temporary directory using the gitignored tests/pytest-temp directory.

    This fixture provides a consistent temporary directory that is gitignored
    and located within the tests directory structure.

    Returns:
        Path to the temporary directory
    """
    import shutil

    temp_dir = get_ash_temp_path()
    yield temp_dir

    # Cleanup after the test
    if temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def temp_config_dir(ash_temp_path):
    """Create a temporary directory for configuration files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary configuration directory
    """
    config_dir = ash_temp_path / "config"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def temp_output_dir(ash_temp_path):
    """Create a temporary directory for output files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary output directory
    """
    output_dir = ash_temp_path / "output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def temp_project_dir(ash_temp_path):
    """Create a temporary directory for project files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary project directory
    """
    project_dir = ash_temp_path / "project"
    project_dir.mkdir()

    # Create a basic project structure
    (project_dir / "src").mkdir()
    (project_dir / "tests").mkdir()
    (project_dir / ".ash").mkdir()

    return project_dir


@pytest.fixture
def temp_env_vars(monkeypatch):
    """Set environment variables for the duration of a test.

    Returns a function: ``temp_env_vars(NAME="value", COUNT=3)`` sets each variable to
    ``str(value)``. At teardown every variable it set is back to the value it had before
    the test, or unset if it had none, and nothing else in the environment is touched.

    Built on ``monkeypatch.setenv``, which records each variable's value the first time
    it is set, so teardown deletes no variable the fixture did not set -- ``PATH``
    included -- from the worker running the test.
    """

    def _set_env_vars(**kwargs):
        for key, value in kwargs.items():
            monkeypatch.setenv(key, str(value))

    return _set_env_vars


# ---------------------------------------------------------------------------
# A temporary home for the run and for each test
# ---------------------------------------------------------------------------
#
# ASH keeps per-user state under Path.home(): install receipts in
# ~/.ash/install-receipts, the default bin directory ~/.ash/bin, the MCP server's session
# configs in ~/.cache/ash-mcp; and the scanners it runs keep theirs (~/.semgrep,
# ~/.cache/checkov, uv's tool directory under $XDG_DATA_HOME). Tests wrote all of it into
# the home of whoever ran them: one host had 22,241 install receipts, almost all fixture
# installs from tests/unit/utils.
#
# So when pytest imports this module, before it loads any other conftest under tests/,
# HOME, USERPROFILE (what Path.home() reads on Windows) and the XDG base directories are
# pointed at a directory inside the session temp directory. That covers what a module
# captures at import (core.constants.ASH_BIN_PATH is one, and four conftests import ASH
# at module level) and what session and module fixtures write. _isolated_home then points
# them at a fresh directory for each test. @pytest.mark.real_home gives a test the
# starting values.
#
# HOME alone does not move what tools keep under XDG_CONFIG_HOME, XDG_DATA_HOME and
# XDG_STATE_HOME when a contributor has set them: uv's tool environments and Python
# installs, gem and pnpm data, and semgrep's settings would still be written into the
# contributor's own directories. Measured with the three set: a unit run wrote
# semgrep's settings and log under XDG_CONFIG_HOME, and uv's tool directory, gem's
# spec cache and pnpm's store under XDG_DATA_HOME, all from child processes the
# audit-hook guard cannot see; nothing under XDG_STATE_HOME. So the XDG directories are
# pointed at their default places inside the home too (_home_layout).
#
# One thing is kept from the developer's environment: uv's cache. Under a fresh home a
# child uv would start with an empty cache and fetch every package it needs again, from
# the network, in every test. UV_CACHE_DIR is pinned to the cache uv would have used,
# unless it is already set; a unit test gets one inside its own home instead, from
# tests/unit/conftest.py, whose tool guard lets no unit test start a real uv but the
# few it lists. uv's tool and interpreter directories are not pinned: uv's own
# variables for them (_UV_DIR_VARS) are unset for the run and for each test, so they
# follow XDG_DATA_HOME into the test's home, and a test cannot install into, or rely on,
# the developer's uv tools. On Windows they are under %APPDATA%, and the cache under
# %LOCALAPPDATA%; neither is moved, so neither needs pinning, and neither is isolated.
# jsii's package cache is already outside HOME, at JSII_RUNTIME_PACKAGE_CACHE_ROOT
# (above).

_HOME_VARS = (
    "HOME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
)
#: uv's directory variables, and the XDG one it puts tool executables in (per `uv help
#: tool dir` and `uv help python dir`). Each takes precedence over the home, so a value
#: from the developer's environment would point past the test's: with UV_TOOL_DIR set,
#: two CLI test modules wrote uv's .gitignore and .lock into it.
_UV_DIR_VARS = (
    "UV_TOOL_DIR",
    "UV_TOOL_BIN_DIR",
    "UV_PYTHON_INSTALL_DIR",
    "UV_PYTHON_BIN_DIR",
    "XDG_BIN_HOME",
)
#: What the run records of the developer's environment, and restores when it is done.
_RECORDED_VARS = (*_HOME_VARS, *_UV_DIR_VARS, "UV_CACHE_DIR")
#: The developer's values of _RECORDED_VARS, and the home they resolve to, as JSON.
#: Exported so xdist workers, which inherit the redirected values, still know them, and
#: so does a pytest a test starts.
_DEVELOPER_HOME_ENV = "ASH_TEST_DEVELOPER_HOME"
#: The pid of the process that entered the session home this environment points at.
_HOME_OWNER_PID_ENV = "ASH_TEST_HOME_OWNER_PID"
#: Set by an xdist worker to its own pid. pytest-xdist marks its workers with
#: PYTEST_XDIST_WORKER, which each worker sets for itself, but a pytest that a worker's
#: test starts with a copy of os.environ inherits that too. It inherits this as well,
#: naming the worker rather than itself, and that tells the two apart. The parent's pid
#: does not: execnet starts a worker with the controller's sys.executable, and in a
#: Windows venv that is CPython's launcher, which runs the real interpreter as its
#: child, so a worker's parent is the launcher.
_XDIST_WORKER_PID_ENV = "ASH_TEST_XDIST_WORKER_PID"
#: The pid of the process that last ran this module's import-time setup. A second import
#: of this file in the same process, as ``from tests.conftest import ...`` does (pytest
#: imports it as ``conftest``), sees its own pid here and does nothing.
_SET_UP_PID_ENV = "ASH_TEST_SET_UP_PID"
#: What _enter_session_home changes, besides the home layout: it saves these with
#: _RECORDED_VARS.
_SESSION_MARKER_VARS = (
    _DEVELOPER_HOME_ENV,
    _HOME_OWNER_PID_ENV,
    _XDIST_WORKER_PID_ENV,
    "PYTEST_XDIST_WORKER",
)
#: This process's values of _RECORDED_VARS and _SESSION_MARKER_VARS from before it
#: entered its session home, or None if it has not; _leave_session_home puts them back.
_saved_session_env: Optional[dict] = None
#: Names the per-test homes; see _isolated_home.
_HOME_COUNTER = itertools.count()


def _developer_record() -> dict:
    """``{"env": {var: value}, "home": path}`` as the run found them; unset vars absent."""
    recorded = os.environ.get(_DEVELOPER_HOME_ENV)
    if recorded:
        return json.loads(recorded)
    return {
        "env": {
            name: os.environ[name] for name in _RECORDED_VARS if name in os.environ
        },
        "home": os.path.realpath(os.path.expanduser("~")),
    }


def _developer_uv_cache(env: dict) -> Optional[str]:
    """The cache uv would use for the developer, where moving HOME would move it.

    UV_CACHE_DIR if the developer set it, and otherwise, per ``uv help cache dir``,
    "$XDG_CACHE_HOME/uv or $HOME/.cache/uv on macOS and Linux, and
    %LOCALAPPDATA%\\uv\\cache on Windows". LOCALAPPDATA is not moved, so Windows needs
    nothing pinned.
    """
    if env.get("UV_CACHE_DIR"):
        return env["UV_CACHE_DIR"]
    if os.name == "nt":
        return None
    base = env.get("XDG_CACHE_HOME") or os.path.join(
        env.get("HOME") or os.path.expanduser("~"), ".cache"
    )
    return os.path.join(base, "uv")


def _home_layout(home: Path) -> "dict[str, str]":
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "XDG_CACHE_HOME": str(home / ".cache"),
    }


def _is_xdist_worker() -> bool:
    """A worker of the run that owns this environment's session home.

    It has PYTEST_XDIST_WORKER, which the worker sets for itself before it loads any
    conftest, in an environment a run has redirected, and no worker's mark but its
    own (_XDIST_WORKER_PID_ENV).
    """
    if not os.environ.get("PYTEST_XDIST_WORKER"):
        return False
    if not os.environ.get(_HOME_OWNER_PID_ENV):
        return False
    return os.environ.get(_XDIST_WORKER_PID_ENV, str(os.getpid())) == str(os.getpid())


def _enter_session_home(session_tmpdir: Path) -> None:
    """Point HOME, the XDG directories and uv's at this run's own home, once per process.

    An xdist worker of this run marks itself and does nothing else: it inherited the
    controller's environment, already redirected. Any other pytest enters a home of its
    own, including one a test started with a copy of os.environ, which inherits
    ASH_TEST_DEVELOPER_HOME and, from a worker's test, PYTEST_XDIST_WORKER and the
    worker's mark. It keeps that record, since it names the developer of the outermost
    run, rather than recording its parent's temporary home, and drops the other two
    while it runs, so its own tests' children are not taken for workers either.
    """
    global _saved_session_env
    if _saved_session_env is not None:
        return
    if _is_xdist_worker():
        os.environ[_XDIST_WORKER_PID_ENV] = str(os.getpid())
        return
    _saved_session_env = {
        name: os.environ.get(name) for name in (*_RECORDED_VARS, *_SESSION_MARKER_VARS)
    }
    os.environ.pop("PYTEST_XDIST_WORKER", None)
    os.environ.pop(_XDIST_WORKER_PID_ENV, None)
    os.environ[_HOME_OWNER_PID_ENV] = str(os.getpid())
    if not os.environ.get(_DEVELOPER_HOME_ENV):
        os.environ[_DEVELOPER_HOME_ENV] = json.dumps(_developer_record())
    if not os.environ.get("UV_CACHE_DIR"):
        uv_cache = _developer_uv_cache(_developer_record()["env"])
        if uv_cache:
            os.environ["UV_CACHE_DIR"] = uv_cache
    if session_tmpdir == _created_session_tmpdir:
        home = session_tmpdir / "home"
        home.mkdir(exist_ok=True)
    else:
        # A nested run shares its parent's session directory, and with it the parent's
        # "home"; it takes one of its own beside that.
        home = Path(tempfile.mkdtemp(prefix="home-", dir=session_tmpdir))
    for name in _UV_DIR_VARS:
        os.environ.pop(name, None)
    os.environ.update(_home_layout(home))


def _leave_session_home() -> None:
    """Put back this process's values from before it entered its session home."""
    global _saved_session_env
    saved = _saved_session_env
    if saved is None:
        return
    _saved_session_env = None
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _clear_the_callers_display_variables() -> None:
    """Take the caller's terminal display variables out of the run's environment.

    ``process_env.DISPLAY_VARIABLES``, the product's own list: COLUMNS, LINES,
    FORCE_COLOR, CLICOLOR_FORCE, TTY_COMPATIBLE and TTY_INTERACTIVE. Under COLUMNS=10
    a typer usage panel, a Rich table or a log line came out wrapped, and under
    FORCE_COLOR or TTY_COMPATIBLE with color codes, so a cell that matched the text
    failed for the terminal the suite ran in, not for ASH. A test of one of them sets
    it itself. TERM and NO_COLOR are left as they are.

    For the whole run rather than per test, because a console reads COLUMNS when it is
    made, and some are made when their module is imported (cli/dependencies.py's) or
    on first use (rich's own): cleared only around each test, the width those had
    already taken stayed. tests/unit/test_display_variables_are_cleared.py runs a
    child pytest with all six set and checks that a test there sees none of them,
    and that a console its module builds when it is imported is not sized or
    colored by them.

    typer forces a terminal, escape codes into a pipe included, when GITHUB_ACTIONS,
    FORCE_COLOR or PY_COLORS is set (typer.rich_utils.FORCE_TERMINAL, read once when
    typer is imported), and ASH's typer_console (utils/console.py) follows the same
    rule at each call. On a GitHub runner every usage error then carried escape
    codes: a line read as "\\x1b[1;31mError: ", and "--mode" came out as three styled
    segments, so a test that read "Error: " at the start of a line, an option as one
    token or no ESC in the output failed for the runner, not for ASH. Both honor the
    same opt-out, set here for the run, before any test module imports typer, and
    inherited by the children the tests start. GITHUB_ACTIONS itself stays: the
    in_ci fixture and the command-reading-runner check read it. A test of the
    forcing builds its own Console(force_terminal=True).
    """
    from automated_security_helper.utils.process_env import DISPLAY_VARIABLES

    for name in DISPLAY_VARIABLES:
        os.environ.pop(name, None)
    os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"
    # typer read its constant already if something imported it before this ran.
    rich_utils = sys.modules.get("typer.rich_utils")
    if rich_utils is not None:
        rich_utils.FORCE_TERMINAL = False


# Set up when pytest imports this module.
#
# pytest imports tests/conftest.py before any other conftest under tests/, and four of
# those import ASH at module level (snapshot/errors, snapshot/mcp, and the trivy and
# ferret plugin directories), so core.constants computes ASH_BIN_PATH from HOME while
# pytest loads them, before any hook of this file runs. Entering the session home in
# pytest_configure was too late for them in a single-process run (-n 0, -p no:xdist,
# --pdb): ASH_BIN_PATH pointed into the developer's home. Under xdist that went unnoticed,
# because the workers inherit the controller's environment, redirected by then. The guard
# on the real ~/.ash starts here as well, so a write during collection is caught too:
# moving HOME keeps out what finds the home through $HOME, and the guard catches what
# finds it another way (tests/utils/real_home_guard.py; pytest_runtest_makereport fails
# the test). The jsii package cache is set up here too, since anything that boots a jsii
# kernel has to see JSII_RUNTIME_PACKAGE_CACHE_ROOT first, and the caller's display
# variables are cleared before any console reads them. pytest_unconfigure undoes the
# home and the temp directory; the atexit calls cover a process that imports this
# module and exits without it, and do nothing once it has run. It all happens once per
# process: a second import of this file, under another module name, would otherwise
# move HOME again mid-run, add a second jsii hook and register two more atexit calls,
# one of which restored a HOME that pointed into a session directory already deleted.
if os.environ.get(_SET_UP_PID_ENV) != str(os.getpid()):
    os.environ[_SET_UP_PID_ENV] = str(os.getpid())
    _enter_session_home(_enter_session_tmpdir())
    real_home_guard.install(
        real_home_guard.guarded_roots(
            [real_home_guard.passwd_home(), Path(_developer_record()["home"])]
        )
    )
    _configure_jsii_package_cache()
    _clear_the_callers_display_variables()
    atexit.register(_remove_session_tmpdir)
    atexit.register(_leave_session_home)


@pytest.fixture(autouse=True)
def _isolated_home(request, tmp_path_factory):
    """Give each test a fresh, empty home: HOME, USERPROFILE and the XDG directories.

    uv's directory variables (_UV_DIR_VARS) are unset too, so uv derives its tool and
    Python directories from that home. ``@pytest.mark.real_home`` sets all of them back
    to the values the run started with
    instead, for a test that really needs the developer's home; nothing does today.
    What a module computed from HOME at import still points into the session's home.

    A private ``MonkeyPatch`` rather than the ``monkeypatch`` fixture: requesting that
    from an autouse fixture would set it up before every test's own fixtures, and so
    tear it down after them, which reorders the undo of every ``monkeypatch.setenv``.
    A test's own ``monkeypatch.setenv("HOME", ...)`` still wins for that test.
    tests/unit/test_home_isolation.py runs a module in a child pytest whose home is a
    sentinel directory and fails if anything lands in it.
    """
    with pytest.MonkeyPatch.context() as patch:
        if request.node.get_closest_marker("real_home"):
            env = _developer_record()["env"]
            for name in (*_HOME_VARS, *_UV_DIR_VARS):
                if name in env:
                    patch.setenv(name, env[name])
                else:
                    patch.delenv(name, raising=False)
        else:
            # In a directory of their own, numbered by a counter: tmp_path is a
            # numbered mktemp, which lists the whole base directory to pick the next
            # number, and a home per test beside each tmp_path would double that
            # listing. Each xdist worker has a base directory of its own.
            home = tmp_path_factory.getbasetemp() / "homes" / str(next(_HOME_COUNTER))
            home.mkdir(parents=True)
            for name in _UV_DIR_VARS:
                patch.delenv(name, raising=False)
            for name, value in _home_layout(home).items():
                patch.setenv(name, value)
        yield


@pytest.fixture(autouse=True)
def _isolated_container_state_dir(request, tmp_path_factory, _isolated_home):
    """Container records go where the test's home is, never where Path.home() might point.

    A container-mode run records the container it starts under the ASH state
    directory, and the next container-mode start removes the ones whose creator is
    gone. ``_isolated_home`` already puts the default location (``$HOME/.ash/state/
    containers``) under the test's own home. This names it outright, so the records
    stay put if a test replaces HOME with something else, and a ``real_home`` test,
    whose HOME is the developer's, gets a directory of its own under the base temp
    directory instead.

    A private ``MonkeyPatch``, for the reason ``_isolated_home`` gives. A test's own
    ``monkeypatch.setenv`` of the variable still wins for that test.
    """
    from automated_security_helper.interactions.container_leftovers import (
        STATE_DIR_ENV,
    )

    if request.node.get_closest_marker("real_home"):
        target = (
            tmp_path_factory.getbasetemp()
            / "container-state"
            / str(next(_HOME_COUNTER))
        )
    else:
        target = Path(os.environ["HOME"]) / ".ash" / "state" / "containers"
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(STATE_DIR_ENV, str(target))
        yield


def _on_path(directory: Path) -> bool:
    wanted = os.path.normcase(os.path.realpath(directory))
    return any(
        os.path.normcase(os.path.realpath(entry)) == wanted
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry
    )


def pytest_report_header(config):
    """Say so when the developer has ASH tools installed that this run will not see.

    ASH looks for a tool on PATH, then in ASH_BIN_PATH, or in ~/.ash/bin when that is
    unset, and during a run ~/.ash/bin is in the run's own home. The integration tests
    that need such a tool skip without it, so a run that stopped seeing the developer's
    tools would otherwise look like one with less to test. The advice is PATH, not
    ASH_BIN_PATH: tests that install to the default directory install into
    ASH_BIN_PATH, and nothing installs onto PATH. An ASH_BIN_PATH already in the home
    gets its own line, since the installer guard refuses every child aimed there; one in
    the run's own temp directories does not, because the guard lets those through (the
    same _in_the_developers_home).
    """
    developer_home = _developer_record()["home"]
    ash_bin_path = os.environ.get("ASH_BIN_PATH")
    if ash_bin_path:
        temp_roots = _run_temp_roots(config.getoption("basetemp"))
        if not _in_the_developers_home(ash_bin_path, temp_roots):
            return None
        return (
            f"ASH_BIN_PATH={ash_bin_path} is in your home, and tests that install to "
            "the default directory would install there, so the tests that start a tool "
            "installer will be refused. Unset it, and to use the tools in it run with "
            f"{_path_prefixed_with(ash_bin_path)}"
        )
    developer_bin = Path(developer_home) / ".ash" / "bin"
    try:
        has_tools = any(entry.is_file() for entry in developer_bin.iterdir())
    except OSError:
        return None
    if not has_tools or _on_path(developer_bin):
        return None
    return (
        f"each test has its own home, so this run does not find the tools in "
        f"{developer_bin}; run with {_path_prefixed_with(developer_bin)} to run the "
        "tests that need them"
    )


def _path_prefixed_with(directory: Any, windows: Optional[bool] = None) -> str:
    """How to put ``directory`` first on PATH in this platform's shells.

    On Windows in PowerShell and in cmd, which take different syntax; ``windows``
    picks the platform, by default this one.
    """
    if os.name == "nt" if windows is None else windows:
        return (
            f'$env:PATH = "{directory};$env:PATH" (PowerShell), or '
            f'set "PATH={directory};%PATH%" (cmd)'
        )
    return f'PATH="{directory}:$PATH"'


@pytest.fixture
def developer_environment() -> "dict[str, str]":
    """The developer's HOME, USERPROFILE, XDG_*, uv directory variables and UV_CACHE_DIR.

    As the outermost run found them; a variable that was unset is absent. A
    NamesOnlyEnvironment, so a failing test given it shows the names only.
    """
    return NamesOnlyEnvironment(_developer_record()["env"])


@pytest.fixture
def developer_home() -> Path:
    """The home directory of whoever runs the suite."""
    return Path(_developer_record()["home"])


#: The function the ``python -c`` installer children of ``ash dependencies install`` call.
_TOOL_INSTALLER = "install_pinned_tool"

_HOME_GUARD_VIOLATIONS = pytest.StashKey[List[str]]()
#: How a refusal names a child left with no HOME: an env without one is given the
#: test's, so what is left is a command that removes it itself, or a real_home test.
_HOME_UNSET = (
    "HOME unset (by its own command line, as env -i, env -u HOME and unset HOME do, "
    "or in a real_home test, which has no temporary home to give it)"
)


def _argv_of(args: Any) -> List[str]:
    if isinstance(args, (str, bytes, os.PathLike)):
        text = os.fsdecode(args)
        try:
            return shlex.split(text, posix=os.name != "nt")
        except ValueError:
            return text.split()
    return [os.fsdecode(a) for a in args]


#: ASH's console scripts (pyproject.toml's [project.scripts]): each runs the same CLI.
_ASH_PROGRAMS = frozenset({"ash", "ashv3", "automated-security-helper"})


def _installs_tools(argv: List[str]) -> bool:
    """A child that installs pinned tools, and so writes receipts under its HOME."""
    if any(_TOOL_INSTALLER in a for a in argv):
        return True
    runs_ash = any(_program([a]) in _ASH_PROGRAMS for a in argv) or any(
        a == "-m" and nxt.startswith("automated_security_helper")
        for a, nxt in zip(argv, argv[1:])
    )
    return runs_ash and "dependencies" in argv and "install" in argv


#: The names a Python interpreter runs under: python, python3, python3.14, pythonw.
_PYTHON_PROGRAM = re.compile(r"python[0-9.]*w?")


def _runs_python_or_ash(argv: List[str]) -> bool:
    """A child that runs Python, ASH included, so can write under Path.home().

    Not only installers write receipts: a child calling write_receipt does too, and a
    child with HOME unset finds the passwd home, the developer's real one. A Python or
    ASH name in any word counts, not only the program's: ``taskset -c 0 python``,
    ``ionice python`` and any other runner the guard does not unwrap run it too.
    """
    return any(
        name in _ASH_PROGRAMS or _PYTHON_PROGRAM.fullmatch(name)
        for name in (_program([word]) for word in argv)
    )


def _env_view(env: Optional[Any]) -> "dict[str, str]":
    """The environment a child gets, as text: ``env``, or this process's when it is None.

    POSIX accepts an env of bytes.
    """
    if env is None:
        return dict(os.environ)
    return {os.fsdecode(name): os.fsdecode(value) for name, value in env.items()}


def _child_home(env: "dict[str, str]") -> Optional[str]:
    return env.get("USERPROFILE" if os.name == "nt" else "HOME")


# Wrappers the installer guard reads through: what a child runs is not always its argv.
#
# ``env NAME=VALUE cmd`` changes the environment on the command line, ``nice``,
# ``timeout`` and the like run the rest of theirs, a shell's ``-c STRING`` holds a whole
# command line in one argument, and a shell expands $NAME and ~/, runs ``NAME=VALUE
# cmd`` with that variable and ``cd DIR && cmd`` in DIR, and ``unset HOME;`` or
# ``HOME=DIR;`` changes the HOME of every command after it. The guard turns a child into
# the commands it runs, each with its environment and directory, and checks every one.
# It is not a shell: it drops comments and here-document bodies as sh does, splits at
# operators, and does not run command substitutions or follow conditionals. In a command that installs tools, a word it cannot read (``$1``,
# ``${X:-...}``, ``$(...)``, backticks, ``~user``, ``$'...'``), a directory it cannot
# follow, or a shell option it does not know is refused rather than guessed at. A
# shell that reads its commands from standard input (no -c and no script file, or
# -s: ``echo ... | sh``, ``sh <<< ...``) is refused whatever it runs.
# Windows' ``cmd /c`` and ``powershell -Command`` are not read through; the shell=True
# string on Windows has its %NAME% expanded and is read as one command.

#: Shells whose ``-c`` runs its first operand as a command line. Not BusyBox's ``ash``,
#: since that is this project's CLI here.
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "mksh"})
#: Shell options whose value is the next argument, not where the options end.
_SHELL_OPTIONS_WITH_A_VALUE = frozenset(
    {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
)
#: Short option letters whose value is the next argument wherever they sit in a
#: cluster: ``bash -euo pipefail -c STRING`` runs STRING, with pipefail the value of
#: the o inside ``-euo``, and ``bash -co pipefail STRING`` does too.
_SHELL_CLUSTER_LETTERS_WITH_A_VALUE = frozenset("oO")
#: Long shell options that take no value. Any other might take one, and then where
#: the options end is unknown.
_SHELL_LONG_FLAGS = frozenset(
    {
        "--norc",
        "--noprofile",
        "--login",
        "--posix",
        "--noediting",
        "--restricted",
        "--verbose",
        "--debugger",
        "--protected",
    }
)
#: Commands that run the rest of their argv: their options that take a value, and how
#: many operands come before the command (timeout's DURATION).
_PREFIX_COMMANDS = {
    "nice": (frozenset({"-n", "--adjustment"}), 0),
    "timeout": (frozenset({"-s", "--signal", "-k", "--kill-after"}), 1),
    "stdbuf": (frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}), 0),
    "setsid": (frozenset(), 0),
    "nohup": (frozenset(), 0),
    "exec": (frozenset({"-a"}), 0),
    "command": (frozenset(), 0),
    "time": (frozenset({"-f", "--format", "-o", "--output"}), 0),
}
#: What is left of a shell word the guard could not expand.
_SHELL_LEFTOVER = re.compile(r"[$`]")
#: Python options that take no value, so ``-uc`` and ``-Iuc`` are ``-c`` with others.
_PYTHON_C_OPTION = re.compile(r"-[bBdEhiIOPqRsSuvVx]*c")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_SHELL_VARIABLE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)
_CMD_VARIABLE = re.compile(r"%([^%]+)%")
_SHELL_PUNCTUATION = frozenset("();<>|&")
#: Reserved words that start no command of their own: the command after them runs.
_SHELL_RESERVED = frozenset(
    {"{", "}", "!", "if", "then", "else", "elif", "fi", "while", "until", "do", "done"}
)
#: Builtins that run code this reader does not see, so after one the variables the
#: guard checks are taken as unreadable: an eval of text it cannot read
#: (_evaluated_words), and ``.`` or source of a file it cannot read (_sourced_words).
#: Text and a file it can read are read where they run.
_SHELL_OPAQUE_BUILTINS = frozenset({"eval", ".", "source"})
#: The commands that test their operands and start nothing (_test_runs_nothing).
_SHELL_TEST_COMMANDS = frozenset({"[", "[[", "test"})
#: Their operators whose operand is evaluated as a name, subscript and all.
_TEST_NAME_OPERATORS = frozenset({"-v", "-R"})
#: Their operators whose operands are evaluated as arithmetic, in [[ at least.
_TEST_ARITHMETIC_OPERATORS = frozenset({"-eq", "-ne", "-lt", "-le", "-gt", "-ge"})
#: The shells whose [ and test evaluate those operands as arithmetic too.
_KSH_SHELLS = frozenset({"ksh", "ksh93", "mksh", "pdksh"})
#: Builtins that set the variables they name. One that names a variable the checks
#: read, a name the guard cannot read, or ``-n`` (a name for another variable) leaves
#: the checked variables unreadable; one that names only others changes none.
_SHELL_DECLARING_BUILTINS = frozenset({"readonly", "declare", "typeset", "local"})
#: How deep ``.``, source and eval are read through: a file that sources itself, or a
#: text nested deeper, is opaque past this.
_MAX_SOURCED_DEPTH = 8
#: How many files and eval texts are read in one command line in all; past this the
#: rest are opaque, so that a file sourcing several files that do the same ends.
_MAX_SOURCED_FILES = 64
#: The largest sourced file the guard reads; a larger one is opaque.
_MAX_SOURCED_BYTES = 1 << 20
#: The variables an installer's or a Python child's checks read.
_GUARDED_VARIABLES = frozenset(
    {"HOME", "USERPROFILE", "ASH_BIN_PATH", "XDG_DATA_HOME", *_UV_DIR_VARS}
)
#: How many wrappers deep the guard reads (env in sh -c in env ...); deeper is text.
_MAX_WRAPPER_DEPTH = 8

#: A command as the guard checks it: its argv, environment and working directory.
_Command = Tuple[List[str], "dict[str, str]", Optional[str]]


def _program(argv: List[str]) -> str:
    name = os.path.basename(argv[0]).lower() if argv else ""
    return name.removesuffix(".exe")


def _unwrap_env(argv: List[str], env: "dict[str, str]", cwd: Optional[str]) -> _Command:
    """The command ``env [OPTION]... [NAME=VALUE]... COMMAND`` runs, and its env and cwd.

    The options GNU and BSD env share that change either: -i (and ``-``), -u NAME,
    -C DIR and -S STRING, in their short and long forms.
    """
    env = dict(env)
    rest = list(argv[1:])

    def take(attached: str) -> str:
        return attached or (rest.pop(0) if rest else "")

    while rest and rest[0].startswith("-"):
        arg = rest.pop(0)
        if arg == "--":
            break
        if arg in ("-", "--ignore-environment"):
            env = {}
        elif arg.startswith("--"):
            name, _, value = arg.partition("=")
            if name == "--unset":
                env.pop(take(value), None)
            elif name == "--chdir":
                cwd = os.path.join(cwd or os.getcwd(), take(value))
            elif name == "--split-string":
                rest[:0] = shlex.split(take(value))
        else:
            for index, flag in enumerate(arg[1:], start=2):
                if flag == "i":
                    env = {}
                elif flag in "uCS":
                    value = take(arg[index:])
                    if flag == "u":
                        env.pop(value, None)
                    elif flag == "C":
                        cwd = os.path.join(cwd or os.getcwd(), value)
                    else:
                        rest[:0] = shlex.split(value)
                    break
    while rest and _ASSIGNMENT.match(rest[0]):
        name, _, value = rest.pop(0).partition("=")
        env[name] = value
    return rest, env, cwd


def _shell_command_string(argv: List[str]) -> Tuple[Optional[int], bool]:
    """Where the command line ``sh [OPTION]... -c STRING`` is, and if its options read.

    The index is None without -c. The options do not read when one is a long option the
    guard does not know: it might take a value, and then STRING could be anywhere. A
    lone ``-`` ends the options as ``--`` does, so ``sh -c - STRING`` runs STRING. An
    o or O inside a short cluster takes the next argument as its value, as the whole
    word ``-o`` does, so ``bash -euo pipefail -c STRING`` and ``bash -co pipefail
    STRING`` both run STRING; read without that, pipefail was where the options
    ended, and STRING was never read.
    """
    given_c = False
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in ("--", "-"):
            index += 1
            break
        if arg in _SHELL_OPTIONS_WITH_A_VALUE:
            index += 2
        elif arg.startswith("--"):
            if arg not in _SHELL_LONG_FLAGS:
                return None, False
            index += 1
        elif len(arg) > 1 and arg[0] in "-+":
            flags = arg[1:]
            given_c = given_c or "c" in flags
            index += 1 + sum(
                flags.count(letter) for letter in _SHELL_CLUSTER_LETTERS_WITH_A_VALUE
            )
        else:
            break
    return (index if given_c and index < len(argv) else None), True


def _unprefixed(argv: List[str]) -> List[str]:
    """What a command from _PREFIX_COMMANDS runs: the rest of its argv, past its options.

    Empty for one that runs nothing, such as ``command -v``.
    """
    program = _program(argv)
    with_value, operands = _PREFIX_COMMANDS[program]
    index = 1
    while index < len(argv):
        option = argv[index]
        if option == "--":
            index += 1
            break
        if not option.startswith("-") or option == "-":
            break
        if program == "command" and option in ("-v", "-V"):
            return []
        if option.split("=", 1)[0] in with_value and "=" not in option:
            index += 2
        else:
            index += 1  # a flag, an attached value (-n5, -oL, --signal=KILL) or nice -5
    return argv[index + operands :]


def _words(args: List[str]) -> List[str]:
    """Every shell word in ``args``, each split as a POSIX shell would split it."""
    words: List[str] = []
    for arg in args:
        try:
            words += shlex.split(arg)
        except ValueError:
            words += arg.split()
    return words


def _unreadable(word: str) -> bool:
    return bool(_SHELL_LEFTOVER.search(word)) or word.startswith("~")


def _expand_tilde(word: str, env: "dict[str, str]") -> str:
    """``~`` and ``~/...`` as the child's HOME; ``~user`` is left for _unreadable."""
    home = env.get("HOME")
    if home and (word == "~" or word.startswith("~/")):
        return home + word[1:]
    return word


def _without_line_continuations(text: str) -> str:
    """``text`` with each backslash-newline the shell removes taken out.

    Outside single quotes a backslash before a newline joins the two lines, so
    ``un\\<newline>set HOME`` is ``unset HOME``; inside them it is two characters of
    the word. A backslash before anything else is kept, with what it escapes. In a
    comment (a ``#`` that starts a word outside quotes, to the end of its line) a
    backslash is part of the comment, so a backslash-newline at its end joins
    nothing: the newline still ends the comment, and the next line runs.
    """
    out: List[str] = []
    index = 0
    quote = ""
    word_start = True
    while index < len(text):
        char = text[index]
        if quote == "'":
            out.append(char)
            quote = "" if char == "'" else quote
            index += 1
        elif char == "\\" and index + 1 < len(text):
            if text[index + 1] != "\n":
                out.append(text[index : index + 2])
                word_start = False
            index += 2
        elif char == "#" and word_start and not quote:
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
            out.append(text[index:end])
            index = end
        else:
            if char == "'" and not quote:
                quote = "'"
            elif char == '"':
                quote = "" if quote == '"' else '"'
            out.append(char)
            word_start = not quote and char in _SHELL_WORD_ENDS
            index += 1
    return "".join(out)


#: What ends a shell word, so that a ``#`` right after one starts a comment.
_SHELL_WORD_ENDS = frozenset(" \t\n();<>|&")
#: A shell operator, or a word between them, for a line shlex cannot split.
_SHELL_TOKEN = re.compile(r"[();<>|&]+|[^\s();<>|&]+")
#: Stand-ins for a $ and a backtick that expand nothing (in single quotes or $'...',
#: or escaped), so that a word can say whether it expands; _shell_word puts them back.
#: Private-use code points, which no command line here holds.
_LITERAL = {"$": chr(0xE000), "`": chr(0xE001)}
_UNLITERAL = str.maketrans({stand_in: char for char, stand_in in _LITERAL.items()})


def _literal(chars: str) -> str:
    return "".join(_LITERAL.get(char, char) for char in chars)


class _ShellWord(str):
    """A shell word after quote removal, with whether it expands: it holds a $ or a
    backtick outside single quotes and not escaped, so the shell puts a variable's
    value or a command's output there. A plain str is taken to expand. ``depth`` is
    how many ``.``, source or eval reads it came through."""

    __slots__ = ("expands", "depth")


def _shell_word(lexed: str) -> _ShellWord:
    word = _ShellWord(lexed.translate(_UNLITERAL))
    word.expands = "$" in lexed or "`" in lexed
    word.depth = 0
    return word


def _as_one_line(text: str) -> str:
    """``text`` without its comments, and with each newline between commands as ";".

    sh starts a comment at a ``#`` that begins a word outside quotes and ends it at
    the end of the line, so ``a#b``, ``$#``, ``a\\ #b`` and a quoted ``#`` are part of
    a word. A newline inside quotes is part of its word and is kept: a ``-c`` command
    line in one keeps its own lines, and its own comments end at them. bash's
    ``$'...'``, in which a backslash escapes a quote, is read as such. A $ or a
    backtick that expands nothing is marked (_LITERAL).
    """
    out: List[str] = []
    index = 0
    quote = ""  # "'", '"', or "$'"
    word_start = True
    while index < len(text):
        char = text[index]
        if quote == "'":
            out.append(_literal(char))
            quote = "" if char == "'" else quote
            index += 1
        elif char == "\\" and index + 1 < len(text):
            out.append("\\" + _literal(text[index + 1]))
            index += 2
            word_start = False
        elif quote:
            out.append(_literal(char) if quote == "$'" else char)
            if char == ('"' if quote == '"' else "'"):
                quote = ""
            index += 1
        elif char == "#" and word_start:
            end = text.find("\n", index)
            index = len(text) if end == -1 else end
        elif word_start and (end := _io_number_end(text, index)):
            # ``0<``, ``2>``: the digits pick the redirect's file descriptor; they are
            # no word of the command, so ``sh 0< f`` is a shell given no script file.
            index = end
        else:
            if text.startswith("$'", index):
                quote = "$'"
                out.append("$")
                index += 1
                char = "'"
            elif char in "'\"":
                quote = char
            out.append(";" if char == "\n" else char)
            word_start = char in _SHELL_WORD_ENDS
            index += 1
    return "".join(out)


def _io_number_end(text: str, index: int) -> int:
    """Where the redirect operator starts, when ``text[index:]`` is an IO number: a
    word of digits right before ``<`` or ``>``, with nothing between them. 0 when it
    is not one. A word after ``(`` is not taken, so ``$((1<2))`` stays arithmetic."""
    if index > 0 and text[index - 1] not in " \t\n;&|":
        return 0
    end = index
    while end < len(text) and text[end].isdigit():
        end += 1
    if end > index and end < len(text) and text[end] in "<>":
        return end
    return 0


def _shell_word_end(text: str, index: int) -> int:
    """Where the shell word that starts at ``index`` ends, quotes and escapes in it."""
    while index < len(text) and text[index] not in _SHELL_WORD_ENDS:
        if text[index] == "\\":
            index += 2
        elif text[index] in "'\"":
            close = text.find(text[index], index + 1)
            if close == -1:
                return len(text)
            index = close + 1
        else:
            index += 1
    return min(index, len(text))


def _here_document_end(
    text: str, start: int, delimiter: str, strip_tabs: bool, quoted: bool
) -> Optional[int]:
    """Just past the line that ends the here-document whose body starts at ``start``,
    or None when no line does.

    As sh reads one (bash, dash, ksh and zsh agree): a line that is the delimiter
    ends it, after its leading tabs are removed for ``<<-``; when the delimiter is
    not quoted, a backslash-newline first joins a line to the next, so ``foo\\``
    before the delimiter makes the body line ``foo<delimiter>``.
    """
    index = start
    while index < len(text):
        end = text.find("\n", index)
        end = len(text) if end == -1 else end
        line = text[index:end]
        while (
            not quoted
            and (len(line) - len(line.rstrip("\\"))) % 2 == 1
            and end < len(text)
        ):
            following = text.find("\n", end + 1)
            following = len(text) if following == -1 else following
            line = line[:-1] + text[end + 1 : following]
            end = following
        if (line.lstrip("\t") if strip_tabs else line) == delimiter:
            return min(end + 1, len(text))
        index = end + 1
    return None


def _without_here_documents(text: str) -> str:
    """``text`` without the bodies of its here-documents, which are data.

    A ``<<WORD`` or ``<<-WORD`` outside quotes, comments and arithmetic starts one;
    its body is the lines after the line it is on, up to its delimiter, WORD without
    its quotes (_here_document_end). The rest of that line is kept. A body whose
    delimiter never comes is kept, so it is read as commands, which is stricter than
    sh: sh reads it as data to the end. A here-string, ``<<< WORD``, is one word;
    _shell_commands passes over it.
    """
    out: List[str] = []
    pending: List[Tuple[str, bool, bool]] = []  # (delimiter, strip_tabs, quoted)
    index = 0
    quote = ""  # "'", '"', or "$'"
    word_start = True
    arithmetic = 0  # $(( or (( not yet closed: << there is a shift
    while index < len(text):
        char = text[index]
        if quote == "'":
            out.append(char)
            quote = "" if char == "'" else quote
            index += 1
        elif char == "\\" and index + 1 < len(text):
            out.append(text[index : index + 2])
            index += 2
            word_start = False
        elif quote:
            out.append(char)
            if char == ('"' if quote == '"' else "'"):
                quote = ""
            index += 1
        elif char == "#" and word_start:
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
            out.append(text[index:end])  # _as_one_line drops it
            index = end
        elif char == "\n" and pending:
            out.append(char)
            index += 1
            for delimiter, strip_tabs, quoted in pending:
                end = _here_document_end(text, index, delimiter, strip_tabs, quoted)
                if end is None:
                    break
                index = end
            pending = []
            word_start = True
        elif text.startswith("<<<", index):
            out.append("<<<")
            index += 3
            word_start = True
        elif text.startswith("<<", index) and not arithmetic:
            start = index
            index += 2
            strip_tabs = text.startswith("-", index)
            index += strip_tabs
            while index < len(text) and text[index] in " \t":
                index += 1
            end = _shell_word_end(text, index)
            word = text[index:end]
            if word and "\n" not in word:
                delimiter = re.sub(r"[\"'\\]", "", word)
                pending.append((delimiter, strip_tabs, delimiter != word))
            out.append(text[start:end])
            index = end
            word_start = False
        elif text.startswith("$((", index) or (
            word_start and text.startswith("((", index)
        ):
            width = 3 if char == "$" else 2
            arithmetic += 1
            out.append(text[index : index + width])
            index += width
            word_start = False
        elif arithmetic and text.startswith("))", index):
            arithmetic -= 1
            out.append("))")
            index += 2
            word_start = False
        else:
            if text.startswith("$'", index):
                quote = "$'"
                out.append("$")
                index += 1
                char = "'"
            elif char in "'\"":
                quote = char
            out.append(char)
            word_start = char in _SHELL_WORD_ENDS
            index += 1
    return "".join(out)


def _shell_words(text: str) -> List[str]:
    """The words and operators of a shell command line, as _shell_commands reads it,
    each a _ShellWord.

    Here-document bodies go first: they are data, and their delimiter is matched
    against the lines as sh reads them. A backslash before a newline joins the two
    lines (outside single quotes), so it goes next. Then comments go, and a newline
    outside quotes ends a command as ";" does (_as_one_line); shlex's own comments are
    off, since it would start one inside a word and end it only at a newline. A line
    shlex cannot split (bash's $'...' escapes) is split at the operators.
    """
    one_line = _as_one_line(_without_line_continuations(_without_here_documents(text)))
    lexer = shlex.shlex(one_line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        lexed = list(lexer)
    except ValueError:
        lexed = _SHELL_TOKEN.findall(one_line)
    return [_shell_word(word) for word in lexed]


def _sourced_words(
    words: List[str], cwd: Optional[str], lost_directory: bool
) -> Optional[List[str]]:
    """The words of the file ``. FILE`` or ``source FILE`` runs, or None when the
    guard cannot read it.

    Not readable: a FILE word it could not expand, a name without a slash (the shell
    looks it up on PATH), a relative one after a cd it could not follow, and a FILE
    that is not a regular file it can open or is over _MAX_SOURCED_BYTES.
    """
    operands = words[1:]
    if operands[:1] == ["--"]:
        operands = operands[1:]
    name = operands[0] if operands else ""
    if not name or _unreadable(name) or "/" not in name:
        return None
    if lost_directory and not os.path.isabs(name):
        return None
    path = os.path.join(cwd or os.getcwd(), name)
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return None
        with open(path, "rb") as handle:
            data = handle.read(_MAX_SOURCED_BYTES + 1)
    except OSError:
        return None
    if len(data) > _MAX_SOURCED_BYTES:
        return None
    return _shell_words(os.fsdecode(data))


def _may_read_further(command_word: str, read_so_far: int) -> bool:
    """Whether the ``.``, source or eval named by ``command_word`` may be read: within
    _MAX_SOURCED_DEPTH of the line, and _MAX_SOURCED_FILES for the line."""
    depth = getattr(command_word, "depth", _MAX_SOURCED_DEPTH)
    return depth < _MAX_SOURCED_DEPTH and read_so_far < _MAX_SOURCED_FILES


def _one_deeper(words: List[str], command_word: str) -> List[str]:
    """``words``, read for ``command_word``, marked one read deeper than it."""
    depth = getattr(command_word, "depth", _MAX_SOURCED_DEPTH) + 1
    for word in words:
        word.depth = depth  # type: ignore[attr-defined]  # each a _ShellWord
    return words


def _command_words(words: List[str]) -> Iterator[str]:
    """The word that names the command in each simple command of ``words``: past
    reserved words, assignments, ``function NAME``, and command or builtin and their
    options."""
    position = 0
    starting = True
    while position < len(words):
        word = words[position]
        position += 1
        if word and set(word) <= _SHELL_PUNCTUATION:
            starting = True
        elif not starting or word in _SHELL_RESERVED or _ASSIGNMENT.match(word):
            continue
        elif word == "function":
            position += 1
        elif word in ("command", "builtin"):
            while position < len(words) and words[position].startswith("-"):
                position += 1
        else:
            starting = False
            yield word


def _evaluated_words(arguments: List[str]) -> Optional[List[str]]:
    """The words of the command line ``eval ARGUMENTS`` runs, or None when the guard
    cannot read it.

    eval joins its arguments, as the shell left them after quote removal, with
    spaces, and runs that text; the guard reads it with the same reader. Not when the
    text is not what the line says or runs what the guard does not see: an argument
    that expands (``"$x"``, ``"a$x"``, ``"$(cmd)"``, bash's ``$'...'``), a $( or a
    backtick anywhere in the text (a substitution, in a subscript too), or a command
    word in it that the guard cannot read.
    """
    if any(getattr(argument, "expands", True) for argument in arguments):
        return None
    text = " ".join(arguments)
    if "$(" in text or "`" in text:
        return None
    words = _shell_words(text)
    if any(_unreadable(word) for word in _command_words(words)):
        return None
    return words


#: What makes a value run a command when the shell evaluates it as a name or as
#: arithmetic: a subscript, which may hold a substitution, or a substitution.
_EVALUATED_MARKS = ("[", "$(", "`")
#: Expansions that are always a number, which no evaluation can make run anything: a
#: length (${#NAME}), and $?, $#, $$ and $!.
_NUMERIC_EXPANSION = re.compile(r"\$\{#[A-Za-z_][A-Za-z0-9_]*\}|\$\{?[?#$!]\}?")


def _could_run_something(
    raw: str, value: str, variables: "dict[str, str]", unread_names: set
) -> bool:
    """Whether an operand the shell evaluates as a name or as arithmetic could run a
    command. ``raw`` is the word as written and ``value`` as the guard expanded it.

    One that does not expand could only by its text (a subscript holding a
    substitution). One that does could unless every expansion in it is a number
    (_NUMERIC_EXPANSION) or a variable the guard knows and can read ($NAME or
    ${NAME}), and the value holds none of _EVALUATED_MARKS: an unknown variable may
    be set where the guard does not look.
    """
    if not getattr(raw, "expands", True):
        return any(mark in raw for mark in _EVALUATED_MARKS)
    raw = _NUMERIC_EXPANSION.sub("0", raw)
    value = _NUMERIC_EXPANSION.sub("0", value)
    names = [m.group(1) or m.group(2) for m in _SHELL_VARIABLE.finditer(raw)]
    if any(name not in variables or name in unread_names for name in names):
        return True
    if "$" in _SHELL_VARIABLE.sub("", raw) or "`" in raw:
        return True  # $1, $@, ${X:-...}, $(...): not a variable the guard knows
    return _unreadable(value) or any(mark in value for mark in _EVALUATED_MARKS)


def _test_runs_nothing(
    raw: List[str],
    expanded: List[str],
    variables: "dict[str, str]",
    unread_names: set,
    arithmetic: bool,
) -> bool:
    """Whether a ``[``, ``[[`` or ``test`` command runs nothing: no operand it
    evaluates could run a command (_could_run_something). The operand of -v or -R is
    evaluated as a name, subscript and all (``test -v 'a[$(cmd)]'`` runs cmd), and
    with ``arithmetic`` the operands of a comparison are evaluated as arithmetic:
    ``[[`` does, and so do ``[`` and test in ksh (measured: bash, dash and zsh report
    "integer expression expected" or "Illegal number" there, and run nothing).
    ``raw`` and ``expanded`` are the command's words as written and as expanded, one
    for one."""
    for index, word in enumerate(expanded):
        if word in _TEST_NAME_OPERATORS:
            places = [index + 1]
        elif arithmetic and word in _TEST_ARITHMETIC_OPERATORS:
            places = [index - 1, index + 1]
        else:
            continue
        for place in places:
            if 0 < place < len(expanded) and _could_run_something(
                raw[place], expanded[place], variables, unread_names
            ):
                return False
    return True


def _declared_names(words: List[str]) -> Optional[set]:
    """The variables a ``readonly``, ``declare``, ``typeset`` or ``local`` command
    names, or None when the guard cannot tell: a name it cannot read, or ``-n``."""
    names = set()
    for word in words[1:]:
        if word[:1] in ("-", "+"):
            if "n" in word[1:]:
                return None
            continue
        name = word.partition("=")[0]
        if _unreadable(name) or not _ASSIGNMENT.match(f"{name}="):
            return None
        names.add(name)
    return names


def _runs_the_builtin_after(words: List[str]) -> int:
    """How many words ``command [-p] [--]`` or ``builtin [--]`` take before the
    builtin it runs, or 0 when it runs none the guard follows (``command -v``)."""
    index = 1
    while index < len(words) and (
        words[index] == "--" or (words[0] == "command" and words[index] == "-p")
    ):
        index += 1
    if index < len(words) and not words[index].startswith("-"):
        return index
    return 0


def _shell_reads_stdin(argv: List[str]) -> bool:
    """Whether ``sh [OPTION]...`` reads its commands from standard input: it is given
    no -c and no script file, or -s. The guard cannot read those commands. A lone
    ``-`` ends the options as ``--`` does (bash, dash and POSIX sh), so ``sh -``
    reads standard input too, and so does ``sh -euo pipefail``: the o inside the
    cluster takes pipefail as its value (_SHELL_CLUSTER_LETTERS_WITH_A_VALUE), which
    leaves no script file."""
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in ("--", "-"):
            index += 1
            break
        if arg in _SHELL_OPTIONS_WITH_A_VALUE:
            index += 2
        elif arg.startswith("--"):
            index += 1
        elif len(arg) > 1 and arg[0] in "-+":
            flags = arg[1:]
            if "c" in flags:
                return False
            if arg[0] == "-" and "s" in flags:
                return True
            index += 1 + sum(
                flags.count(letter) for letter in _SHELL_CLUSTER_LETTERS_WITH_A_VALUE
            )
        else:
            break
    return index >= len(argv)


def _shell_commands(
    text: str,
    env: "dict[str, str]",
    cwd: Optional[str],
    depth: int,
    shell: str = "sh",
) -> List[_Command]:
    """The simple commands of a POSIX shell command line, each as it would run.

    Here-document bodies and here-strings are data and are passed over. Lines a
    backslash-newline joins are joined and comments are dropped, then the line is
    split at the shell's operators and at newlines outside quotes. Leading
    NAME=VALUE words set that command's env; ``export NAME=VALUE``, ``export NAME``,
    ``unset NAME``, ``cd DIR`` and ``pushd DIR`` change the env and directory of
    those after it, and so does a command of
    NAME=VALUE words alone, for a NAME already exported (HOME is); one that is not is
    seen by $NAME and given to no child; bash's ``export -n NAME`` unexports it. A
    command's leading reserved words (``{``, ``if``, ``then``, ``else``, ``do``,
    ``while``, ``!`` ...) are passed over, so the command after them is read, in every
    branch, which can only make the guard stricter; so are ``command`` and ``builtin``
    before the builtin they run (``command unset HOME``, ``command -p unset HOME``) and
    bash's ``function NAME``. eval, ``.``, source, readonly,
    declare, typeset and local can set or export any variable, so after one every
    variable the checks read is taken as unreadable. $NAME and ${NAME} are expanded, in single
    quotes too, which can only make the guard stricter, and ``~``/``~/`` as its HOME.
    A command that installs tools and still holds a word the guard cannot read
    (``$1``, ``${X:-...}``, ``$(...)``, backticks, ``~user``), or runs in a directory
    it could not follow, raises _UnreadableInstaller, and so does a Python or ASH
    command whose HOME (USERPROFILE) is such a word.
    """
    words = [*_shell_words(text), ";"]
    sourced_files = 0  # files read for `. FILE` so far
    env = dict(env)  # the exported variables: what each command's child is given
    unexported: "dict[str, str]" = {}  # set by the line, seen by $NAME, given to none
    unread_names: set = set()  # set or exported with a value the guard could not read
    lost_directory = False  # after a cd it could not follow
    commands: List[_Command] = []
    current: List[str] = []
    data_word = False  # the word after << (a delimiter) or <<< (a here-string)
    position = 0
    while position < len(words):
        word = words[position]
        position += 1
        if not word or not set(word) <= _SHELL_PUNCTUATION:
            if data_word:
                data_word = False
            else:
                current.append(word)
            continue
        data_word = "<<" in word
        variables = {**env, **unexported}
        expanded = [
            _expand_tilde(
                _SHELL_VARIABLE.sub(
                    lambda m: variables.get(m.group(1) or m.group(2), ""), w
                ),
                variables,
            )
            for w in current
        ]
        raw = current  # the same words before expansion, each a _ShellWord
        current = []
        while expanded:
            if expanded[0] in _SHELL_RESERVED:
                expanded.pop(0)
            elif expanded[0] == "function" and len(expanded) > 1:
                del expanded[:2]  # bash's `function NAME`, as NAME() starts one
            elif expanded[0] in ("command", "builtin") and (
                skipped := _runs_the_builtin_after(expanded)
            ):
                # Runs the builtin after it: `command unset HOME`, `command -p unset
                # HOME` (-p only picks the PATH it searches).
                del expanded[:skipped]
            else:
                break
        if not expanded:
            continue
        raw = raw[len(raw) - len(expanded) :]  # only leading words were passed over
        if all(_ASSIGNMENT.match(w) for w in expanded):
            # NAME=VALUE with no command sets the shell's variable: exported (HOME is)
            # if it already was, so every later command gets it, and otherwise not.
            for assignment in expanded:
                name, _, value = assignment.partition("=")
                (env if name in env else unexported)[name] = value
                if _unreadable(value):
                    unread_names.add(name)
                else:
                    unread_names.discard(name)
        elif expanded[0] == "unset":
            # -f unsets functions; -v, the default, variables.
            if "-f" not in expanded[1:]:
                for name in expanded[1:]:
                    if not name.startswith("-"):
                        env.pop(name, None)
                        unexported.pop(name, None)
                        unread_names.discard(name)
        elif expanded[0] in ("cd", "pushd", "popd"):
            if expanded[0] == "cd" and len(expanded) == 1:
                target = env.get("HOME", "")
            else:
                target = (
                    expanded[1] if expanded[0] != "popd" and len(expanded) > 1 else ""
                )
            if not target or _unreadable(target):
                lost_directory = True
            else:
                cwd = os.path.join(cwd or os.getcwd(), target)
        elif (
            expanded[0] in (".", "source")
            and _may_read_further(raw[0], sourced_files)
            and ((sourced := _sourced_words(expanded, cwd, lost_directory)) is not None)
        ):
            # The file's commands run here, in this shell, so they are read here.
            sourced_files += 1
            words[position:position] = [*_one_deeper(sourced, raw[0]), ";"]
        elif (
            expanded[0] == "eval"
            and _may_read_further(raw[0], sourced_files)
            and ((evaluated := _evaluated_words(raw[1:])) is not None)
        ):
            # eval runs its text as a command line in this shell; it is read here.
            sourced_files += 1
            words[position:position] = [*_one_deeper(evaluated, raw[0]), ";"]
        elif expanded[0] in _SHELL_OPAQUE_BUILTINS:
            # It can set or export any of them: what follows has none the guard reads.
            unread_names |= _GUARDED_VARIABLES
        elif expanded[0] in _SHELL_TEST_COMMANDS:
            # They start nothing, unless an operand they evaluate runs a substitution.
            arithmetic = expanded[0] == "[[" or shell in _KSH_SHELLS
            if not _test_runs_nothing(
                raw, expanded, variables, unread_names, arithmetic=arithmetic
            ):
                unread_names |= _GUARDED_VARIABLES
        elif expanded[0] in _SHELL_DECLARING_BUILTINS:
            declared = _declared_names(expanded)
            if declared is None:
                unread_names |= _GUARDED_VARIABLES
            else:
                unread_names |= declared & _GUARDED_VARIABLES
        elif expanded[0] == "export" and "-n" in expanded[1:]:
            # bash's `export -n NAME`: still set, no longer given to a child.
            for argument in expanded[1:]:
                name = argument.partition("=")[0]
                if not argument.startswith("-") and name in env:
                    unexported[name] = env.pop(name)
        elif expanded[0] == "export":
            for argument in expanded[1:]:
                if _ASSIGNMENT.match(argument):
                    name, _, value = argument.partition("=")
                    unexported.pop(name, None)
                    env[name] = value
                    if _unreadable(value):
                        unread_names.add(name)
                    else:
                        unread_names.discard(name)
                elif argument in unexported:  # `export NAME` of a variable set before
                    env[argument] = unexported.pop(argument)
        else:
            # A shell -c in the command is read with its operands where the guard can
            # (_child_commands), so its command line is no unreadable word then; one it
            # cannot read, or one built from an expansion, is.
            start = next(
                (k for k, w in enumerate(expanded) if not _ASSIGNMENT.match(w)),
                len(expanded),
            )
            nested = _nested_shell(expanded, start)
            script_read = (
                nested is not None
                and nested.text is not None
                and nested.operands_read
                and not getattr(raw[nested.index], "expands", True)
            )

            def unreadable_word(place: int, word: str) -> bool:
                if nested is not None and place == nested.index:
                    return not script_read
                return _unreadable(word)

            if _installs_tools(expanded) and (
                lost_directory
                or any(unreadable_word(k, w) for k, w in enumerate(expanded))
                or unread_names & _GUARDED_VARIABLES
            ):
                raise _UnreadableInstaller(
                    f"{expanded[:4]} installs tools, from a shell command line with a "
                    "word or a directory this guard cannot read ($1, ${X:-...}, $(...), "
                    "backticks, ~user, a cd it could not follow, or eval, source, "
                    "readonly, declare, typeset or local before it), so where it "
                    "installs is unknown. Spell the paths out."
                )
            own_env = dict(env)
            own_unread = set(unread_names)
            while expanded and _ASSIGNMENT.match(expanded[0]):
                name, _, value = expanded.pop(0).partition("=")
                own_env[name] = value
                if _unreadable(value):
                    own_unread.add(name)
                else:
                    own_unread.discard(name)
            # What Path.home() reads in the child: HOME, or USERPROFILE on Windows.
            home_variable = "USERPROFILE" if os.name == "nt" else "HOME"
            if (
                expanded
                and _runs_python_or_ash(expanded)
                and home_variable in own_unread
            ):
                raise _UnreadableInstaller(
                    f"{expanded[:4]} runs Python or ASH with a HOME this guard cannot "
                    "read ($(...), backticks, ${X:-...}, or eval, source, readonly, "
                    "declare, typeset or local before it), so where it writes under "
                    "Path.home() is unknown. Spell the path out."
                )
            if expanded:
                # A word whose $ the shell leaves alone (single-quoted or escaped)
                # reaches the child as written, so a shell -c in it expands it itself
                # and sees a variable the guard does not know as unknown, not empty.
                argv = [
                    value
                    if getattr(written, "expands", True)
                    else _expand_tilde(str(written), variables)
                    for written, value in zip(raw[len(raw) - len(expanded) :], expanded)
                ]
                commands += _child_commands(argv, own_env, cwd, depth + 1)
    return commands


#: What a script does with its positional parameters that the guard does not follow:
#: shift, set --, getopts, a ${@:...} or ${*:...} slice, ${N} with N of two digits.
_POSITIONAL_SHUFFLES = re.compile(
    r"\bshift\b|\bset\s+--|\bgetopts\b|\$\{[@*]:|\$\{\d{2,}"
)
#: A positional parameter: $0..$9, $@, $*, $#, each also in braces.
_POSITIONAL = re.compile(r"\$(?:\{([@*#0-9])\}|([@*#0-9]))")
#: One that is a whole double-quoted word: "$1", "${1}", "$@", "$*".
_QUOTED_POSITIONAL = re.compile(r'"\$(?:\{([@*0-9])\}|([@*0-9]))"')
#: Characters that word splitting or a glob would act on in an unquoted expansion.
_SPLIT_OR_GLOB = re.compile(r"[\s*?\[]")


def _with_positional_parameters(
    script: str, operands: List[str], shell: str
) -> Optional[Tuple[str, bool]]:
    """``script`` with $0, $1..$9, "$@", "$*" and $# filled in from ``operands``
    (``$0`` first, then ``$1`` and on), as the shell would expand them, and whether
    every operand it used could be read; or None when the guard cannot fill them in:
    the script shuffles them (_POSITIONAL_SHUFFLES), uses one no operand gives, uses
    one unquoted that word splitting or a glob would change, or puts one inside a
    longer quoted word. ``shell`` is $0 when no operand gives it. An operand the guard
    cannot read is filled in as written, so the script's reader sees a word it cannot
    read where the shell puts the value.
    """
    if _POSITIONAL_SHUFFLES.search(script):
        return None
    parameters = operands[1:]
    used_unreadable = False

    def values(name: str) -> Optional[List[str]]:
        nonlocal used_unreadable
        if name in "@*":
            chosen = parameters
        elif name == "0":
            chosen = [operands[0] if operands else shell]
        elif int(name) <= len(parameters):
            chosen = [parameters[int(name) - 1]]
        else:
            return None  # no operand gives it: the guard does not guess
        used_unreadable = used_unreadable or any(_unreadable(v) for v in chosen)
        return chosen

    out: List[str] = []
    index = 0
    quote = ""
    while index < len(script):
        char = script[index]
        if quote == "'":
            out.append(char)
            quote = "" if char == "'" else quote
            index += 1
            continue
        if char == "\\" and index + 1 < len(script):
            out.append(script[index : index + 2])
            index += 2
            continue
        whole = (
            _QUOTED_POSITIONAL.match(script, index)
            if char == '"' and not quote
            else None
        )
        if whole:
            # "$N", "$@" or "$*" as a whole quoted word: its values, unsplit.
            name = whole.group(1) or whole.group(2)
            found = values(name)
            if found is None:
                return None
            joined = [" ".join(found)] if name == "*" else found
            out.append(" ".join(shlex.quote(value) for value in joined))
            index = whole.end()
            continue
        positional = _POSITIONAL.match(script, index) if char == "$" else None
        if positional:
            name = positional.group(1) or positional.group(2)
            if name == "#":
                out.append(str(len(parameters)))
            elif quote:
                return None  # inside a longer quoted word
            else:
                found = values(name)
                if found is None or any(_SPLIT_OR_GLOB.search(v) for v in found):
                    return None
                out.append(" ".join(shlex.quote(value) for value in found if value))
            index = positional.end()
            continue
        if char == "'" and not quote:
            quote = "'"
        elif char == '"':
            quote = "" if quote == '"' else '"'
        out.append(char)
        index += 1
    return "".join(out), not used_unreadable


class _NestedShell(NamedTuple):
    """A ``SHELL [OPTION]... -c SCRIPT [ARG0 [ARG]...]`` in an argv."""

    #: Where SCRIPT is in the argv, or the shell's own word when its options do not
    #: read.
    index: int
    #: The shell's name.
    shell: str
    #: The command line it runs, operands filled in; None when the guard cannot.
    text: Optional[str]
    #: Whether every operand the command line uses could be read.
    operands_read: bool


def _nested_shell(argv: List[str], first: int) -> Optional[_NestedShell]:
    """The first shell -c in ``argv`` from position ``first`` on, or None."""
    for index in range(first, len(argv)):
        program = _program([argv[index]])
        if program not in _SHELLS:
            continue
        script, options_read = _shell_command_string(argv[index:])
        if not options_read:
            return _NestedShell(index, program, None, False)
        if script is None:
            continue
        where = index + script
        filled = _with_positional_parameters(argv[where], argv[where + 1 :], program)
        if filled is None:
            return _NestedShell(where, program, None, False)
        return _NestedShell(where, program, filled[0], filled[1])
    return None


def _child_commands(
    argv: List[str], env: "dict[str, str]", cwd: Optional[str], depth: int = 0
) -> List[_Command]:
    """The commands ``argv`` runs, through env, prefix and shell wrappers."""
    if depth > _MAX_WRAPPER_DEPTH or not argv:
        return [(argv, env, cwd)]
    program = _program(argv)
    if program == "env":
        inner, env, cwd = _unwrap_env(argv, env, cwd)
        return _child_commands(inner, env, cwd, depth + 1) if inner else []
    if program in _PREFIX_COMMANDS:
        inner = _unprefixed(argv)
        return _child_commands(inner, env, cwd, depth + 1) if inner else []
    if program in _SHELLS:
        script, options_read = _shell_command_string(argv)
        if not options_read:
            if _installs_tools(_words(argv[1:])):
                raise _UnreadableInstaller(
                    f"{argv[:4]} installs tools after a shell option this guard "
                    "does not know, so it cannot read where the command line is, or "
                    "where it installs. Leave the option out, or teach this guard it."
                )
            return [(argv, env, cwd)]
        if script is None and _shell_reads_stdin(argv):
            raise _UnreadableInstaller(
                f"{argv[:4]} reads its commands from standard input (a pipe, a "
                "here-string or a redirect), which this guard cannot read, so "
                "whether one runs Python or ASH with the developer's HOME is "
                "unknown. Pass the command line with -c."
            )
        if script is not None:
            # The operands after the command line are its $0, $1, ...: read with them
            # filled in where the guard can (`sh -c 'exec "$@"' sh CMD...` runs CMD).
            filled = _with_positional_parameters(
                argv[script], argv[script + 1 :], program
            )
            text = argv[script] if filled is None else filled[0]
            commands = _shell_commands(text, env, cwd, depth + 1, program)
            if script + 1 < len(argv):
                # And the argv as written counts too.
                commands.append((argv, env, cwd))
            return commands
    # A shell -c further on, as in `with_commands_stopped bash -c SCRIPT ARG0...`,
    # runs its command line in a child too: read it, operands filled in, where the
    # guard can. Where it cannot, _shell_commands counts SCRIPT as a word it cannot
    # read.
    nested = _nested_shell(argv, 1)
    if nested is not None and nested.text is not None:
        inner = _shell_commands(nested.text, env, cwd, depth + 1, nested.shell)
        return [*inner, (argv, env, cwd)]
    return [(argv, env, cwd)]


def _commands_of(
    args: Any,
    shell: bool,
    env: Optional[Any],
    cwd: Optional[str],
    executable: Optional[Any] = None,
) -> List[_Command]:
    """The commands ``subprocess.Popen(args, shell=, env=, cwd=, executable=)`` runs.

    Without a shell, ``executable`` is the program that runs, whatever argv[0] says.
    Raises _UnreadableInstaller for a tool-installing command it cannot read.
    """
    env_view = _env_view(env)
    if not shell:
        argv = _argv_of(args)
        if executable is not None and argv:
            argv = [os.fsdecode(executable), *argv[1:]]
        return _child_commands(argv, env_view, cwd)
    if isinstance(args, (str, bytes, os.PathLike)):
        text = os.fsdecode(args)
    else:
        parts = [os.fsdecode(a) for a in args]
        # On POSIX the first item is the command line and the rest its $0, $1, ...
        text = subprocess.list2cmdline(parts) if os.name == "nt" else parts[0]
    if os.name != "nt":
        # Popen's shell is /bin/sh, or the executable given; named as it really is.
        sh = os.path.realpath(os.fsdecode(executable) if executable else "/bin/sh")
        commands = _shell_commands(text, env_view, cwd, 0, _program([sh]))
        if not isinstance(args, (str, bytes, os.PathLike)) and len(parts) > 1:
            commands.append((parts, env_view, cwd))  # its $0, $1, ..., as written
        return commands
    by_name = {name.upper(): value for name, value in env_view.items()}
    argv = [
        _CMD_VARIABLE.sub(lambda m: by_name.get(m.group(1).upper(), m.group(0)), word)
        for word in _argv_of(text)
    ]
    return _child_commands(argv, env_view, cwd)


@functools.lru_cache(maxsize=1)
def _ash_install_command() -> Any:
    """The click command behind ``ash dependencies install``."""
    import typer.main

    from automated_security_helper.cli.main import app

    group = typer.main.get_command(app)
    return group.commands["dependencies"].commands["install"]


def _ash_install_bin_path(argv: List[str]) -> Optional[str]:
    """The --bin-path an ``ash dependencies install`` argv gives, read as ash reads it.

    click's own parser, so ``-bX``, ``-vb X``, ``--bin-path=X`` and a repeated option
    (the last one counts) come out as they would in the child. Only a value from the
    command line counts here; one click took from this process's ASH_BIN_PATH is not
    the child's, whose env is checked separately. Typer ships its own copy of click, so
    its classes are matched by name, not imported from ``click``.
    """
    for index in range(len(argv) - 1):
        if argv[index] == "dependencies" and argv[index + 1] == "install":
            arguments = argv[index + 2 :]
            break
    else:
        return None
    try:
        context = _ash_install_command().make_context(
            "install", list(arguments), resilient_parsing=True
        )
    except Exception as exc:
        if any(cls.__name__ == "ClickException" for cls in type(exc).__mro__):
            return None  # ash would stop on the same error, before installing anything
        raise
    source = context.get_parameter_source("bin_path")
    if getattr(source, "name", None) != "COMMANDLINE":
        return None
    value = context.params.get("bin_path")
    return os.fspath(value) if value is not None else None


class _UnreadableInstaller(Exception):
    """A child the guard cannot read well enough to check, so it is refused.

    A tool installer whose destination, directory or HOME it cannot read, or a Python
    or ASH child whose HOME it cannot.
    """


def _installer_script_index(argv: List[str]) -> Optional[int]:
    """Where the ``python -c`` script that calls install_pinned_tool is in ``argv``.

    ``-c`` may come in a cluster of Python's flags (``-uc``), and after other options.
    """
    for index in range(1, len(argv) - 1):
        option = argv[index]
        if (option == "-c" or _PYTHON_C_OPTION.fullmatch(option)) and (
            _TOOL_INSTALLER in argv[index + 1]
        ):
            return index + 1
    return None


def _install_destination(argv: List[str], env: "dict[str, str]") -> Optional[tuple]:
    """``(where, how it was given)`` for a tool-installing child, when known up front.

    ``download_utils.create_pinned_tool_install_command`` builds ``[python, "-c",
    script, tool, platform, arch, destination]``; interpreter options such as ``-u`` may
    come before ``-c``. That child installs where its argument says and never reads
    ASH_BIN_PATH. Any other way of calling install_pinned_tool, a fifth argument
    included, raises _UnreadableInstaller: the destination could be anywhere. ``ash
    dependencies install`` takes ``--bin-path``/``-b``, then ASH_BIN_PATH, and otherwise
    its own HOME, which the HOME check covers.
    """
    if any(_TOOL_INSTALLER in arg for arg in argv):
        script = _installer_script_index(argv)
        arguments = argv[script + 1 :] if script is not None else None
        if arguments is None or len(arguments) != 4:
            shape = (
                f"with {len(arguments)} arguments after its script, not the 4"
                if arguments is not None
                else "other than as `python -c SCRIPT` with the 4 arguments"
            )
            raise _UnreadableInstaller(
                f"{argv[:4]} calls {_TOOL_INSTALLER} {shape} (tool, platform, arch, "
                "destination) that download_utils.create_pinned_tool_install_command "
                "gives it, so where it installs is unknown. Build the command with "
                "that function, or teach this guard the new shape."
            )
        return arguments[3], "its destination argument"
    explicit = _ash_install_bin_path(argv)
    if explicit is not None:
        return explicit, "--bin-path"
    from_env = env.get("ASH_BIN_PATH")
    if from_env:
        return from_env, "ASH_BIN_PATH"
    return None


def _within(
    path: str, root: str, cwd: Optional[str] = None, *, resolve: bool = True
) -> bool:
    """Whether ``path`` is ``root`` or inside it.

    A relative ``path`` is taken from ``cwd``, the directory the child starts in. With
    ``resolve`` its symbolic links are resolved first, each one wherever it is in the
    path (and ``..`` after it, which on POSIX leaves the link's target, not the link),
    so a path under a temp directory as text that leads into the home is in the home;
    without it the path is taken as written, so one under the home as text is in the
    home even where a link leads out of it. Then its existing ancestors are compared
    with ``root`` by identity (os.path.samestat), which sees through a case-insensitive
    file system, where /Users/Dev and /users/dev are one directory, and through Windows
    short names; a path that does not exist yet is judged by its nearest existing
    ancestor. A root that does not exist is compared as text.
    """
    joined = os.path.join(cwd or os.getcwd(), os.fspath(path))
    full = os.path.realpath(joined) if resolve else os.path.abspath(joined)
    try:
        root_stat = os.stat(root)
    except OSError:
        root_text = os.path.normcase(os.path.realpath(root))
        try:
            return os.path.commonpath([os.path.normcase(full), root_text]) == root_text
        except ValueError:  # different drives on Windows
            return False
    current = full
    while True:
        try:
            if os.path.samestat(os.stat(current), root_stat):
                return True
        except OSError:
            pass
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def _run_temp_roots(basetemp: Optional[Any]) -> List[str]:
    """The directories this run writes into, wherever they are.

    On Windows %TEMP% is inside %USERPROFILE%, and anywhere TMPDIR or --basetemp may be
    under $HOME, so these are inside the developer's home and still the run's own: the
    temp directories the run started with, pytest's temp root, the session directory
    and the base temp directory. A root that holds the developer's home itself (HOME
    inside /tmp, say) would excuse all of the home, so it does not count, and neither
    does one inside the developer's ~/.ash, where the receipts and the default bin
    directory are.
    """
    developer_home = _developer_record()["home"]
    dot_ash = os.path.join(developer_home, ".ash")
    candidates = [
        *_pre_session_temp_env().values(),
        os.environ.get("PYTEST_DEBUG_TEMPROOT"),
        os.environ.get(_SESSION_TMP_ENV),
        os.fspath(basetemp) if basetemp else None,
    ]
    return [
        root
        for root in candidates
        if root
        and not _within(developer_home, root)
        and not _within(root, dot_ash)
        and not _within(root, dot_ash, resolve=False)
    ]


def _in_the_developers_home(
    path: str, temp_roots: List[str], cwd: Optional[str] = None
) -> bool:
    """In the developer's home, and in none of the run's own temp directories.

    In the home once its links are resolved, or as written: ~/.ash or ~/.local may be
    a link out of the home (a dotfile manager's, or onto a bigger volume), and ~/.ash/bin
    is still the developer's install directory. The temp-directory exemption looks at
    the resolved path only, so a link from a temp directory into the home excuses
    nothing. The installer guard refuses a child aimed at such a path, and the run's
    header warns about an ASH_BIN_PATH that is one; both ask this.
    """
    developer_home = _developer_record()["home"]
    in_home = _within(path, developer_home, cwd) or _within(
        path, developer_home, cwd, resolve=False
    )
    return in_home and not any(_within(path, root, cwd) for root in temp_roots)


def _command_refusal(
    argv: List[str], env: "dict[str, str]", cwd: Optional[str], temp_roots: List[str]
) -> Optional[str]:
    """Why one command, run with ``env`` in ``cwd``, breaks the HOME rule, or None.

    A tool installer needs a HOME, XDG_DATA_HOME, uv directories and a destination
    outside the developer's home; any other Python or ASH child needs a HOME outside it.
    """

    def in_developer_home(path: str) -> bool:
        return _in_the_developers_home(path, temp_roots, cwd)

    home = _child_home(env)
    if _installs_tools(argv):
        if home is None or in_developer_home(home):
            return (
                f"{argv[:4]} installs tools and would write install receipts under "
                f"the developer's home ({_HOME_UNSET if home is None else 'HOME'}). "
                "Pass env with HOME and USERPROFILE set to a temporary directory."
            )
        for name in ("XDG_DATA_HOME", *_UV_DIR_VARS):
            value = env.get(name)
            if value and in_developer_home(value):
                return (
                    f"{argv[:4]} installs tools, and its {name}={value} is in the "
                    "developer's home, where uv would install them. Unset it, or "
                    "point it at a temporary directory."
                )
        try:
            destination = _install_destination(argv, env)
        except _UnreadableInstaller as exc:
            return str(exc)
        if destination is not None and in_developer_home(destination[0]):
            return (
                f"{argv[:4]} would install tools into {destination[0]}, in the "
                f"developer's home ({destination[1]}). Give it a temporary "
                "directory; to find installed tools, put their directory on PATH."
            )
        return None
    if _runs_python_or_ash(argv) and (home is None or in_developer_home(home)):
        return (
            f"{argv[:4]} runs Python or ASH with "
            f"{_HOME_UNSET if home is None else 'HOME in the developer home'}, so "
            "anything it writes under Path.home() (install receipts, ~/.ash) lands "
            "in the developer's real home. Pass env with HOME and USERPROFILE set "
            "to a temporary directory."
        )
    return None


def home_rule_refusal(
    args: Any,
    env: Optional[Any] = None,
    cwd: Optional[Any] = None,
    *,
    basetemp: Optional[Any] = None,
    shell: bool = False,
    executable: Optional[Any] = None,
) -> Optional[str]:
    """Why starting ``args`` breaks the HOME rule, or None when it does not.

    The rule the installer guard below enforces at subprocess.Popen, for a start that
    does not go through it: ``args``, ``env`` (None for this process's), ``cwd``,
    ``shell`` and ``executable`` as Popen takes them, so ``os.system(line)`` is
    ``home_rule_refusal(line, shell=True)`` and ``os.posix_spawn(path, argv, env)`` is
    ``home_rule_refusal(argv, env, executable=path)``. ``basetemp`` is the run's base
    temp directory (tmp_path_factory.getbasetemp()), one of the run's own directories
    (_run_temp_roots). Read through wrappers as Popen's guard reads them. Popen's guard
    first gives an env with no HOME the test's home; this answers for the start as
    given. tests/utils/home_rule.py makes it importable from outside this conftest.
    """
    cwd = os.fsdecode(cwd) if cwd is not None else None
    try:
        commands = _commands_of(args, bool(shell), env, cwd, executable)
    except _UnreadableInstaller as exc:
        return str(exc)
    temp_roots = _run_temp_roots(basetemp)
    for argv, child_env, child_cwd in commands:
        refusal = _command_refusal(argv, child_env, child_cwd, temp_roots)
        if refusal is not None:
            return refusal
    return None


@pytest.fixture(autouse=True)
def _refuse_tool_installs_into_the_developer_home(request, tmp_path_factory):
    """Fail a test that starts a tool-installing child aimed at the developer's home.

    A child inherits the test's temporary home from os.environ. A Python or ASH child
    given an ``env`` with no HOME at all (USERPROFILE on Windows) would find the
    password database's, the developer's real one, so the test's home is added to that
    env before it starts: ASH's own probes start ``python -I`` with only PATH. This
    catches the ways a child still reaches the developer's home: an ``env`` built from
    something other than os.environ that carries the developer's HOME or a directory
    inside it (a copy saved before the redirect, or a ``real_home`` test); a command
    line that removes HOME itself (``env -i``, ``env -u HOME``, ``unset HOME``), or a
    ``real_home`` test, which has no temporary home to give; uv's tool directories
    pointed into it, since the ash child runs ``uv tool
    install``; and an install destination in it: the installer's destination argument,
    ``--bin-path``, or an ASH_BIN_PATH naming the developer's ~/.ash/bin, which would
    make it the install target of every test that installs to the default directory.
    ``ash dependencies install`` installs each pinned tool in a ``python -c`` child that
    calls ``install_pinned_tool`` and writes an install receipt under its home, so all
    of it is checked where every child starts, ``subprocess.Popen``, before it runs.
    It is checked in each command the child runs, read through ``env`` and shell
    wrappers (see _commands_of), with the environment and directory that command gets.
    The run's own temp directories are not the developer's, even when they are inside
    the home (on Windows they always are); see _run_temp_roots. Code that swallows the
    exception does not hide it: the refusal is recorded and the test fails at teardown.
    The rule itself is home_rule_refusal, importable as tests/utils/home_rule.py.

    Not covered here: a child that is not started through subprocess.Popen.
    os.posix_spawn, os.system, os.exec* and os.spawn*, a fork, and multiprocessing's
    spawn and forkserver starts (forkserver is 3.14's default on Linux), which call
    _posixsubprocess directly, are not seen here. tests/utils/tool_guard.py's
    recorder sees each of them wherever its guard is in, in every unit test, and
    applies this rule to them (``_hold_to_the_home_rule``); outside it nothing does.
    """
    violations: List[str] = []
    request.node.stash[_HOME_GUARD_VIOLATIONS] = violations
    original_init = subprocess.Popen.__init__
    basetemp = tmp_path_factory.getbasetemp()

    def refuse(self: Any, message: str) -> None:
        violations.append(message)
        # Popen.__del__ reads this, and __init__ is about to stop early.
        self._child_created = False
        pytest.fail(message)

    def with_the_tests_home(env: Any) -> Optional[Any]:
        """``env`` with the test's own home in it, or None when the test has none to give.

        HOME on POSIX, USERPROFILE on Windows: what Path.home() reads. A real_home
        test's home is the developer's, so it has none.
        """
        name = "USERPROFILE" if os.name == "nt" else "HOME"
        home = os.environ.get(name)
        if not home or _in_the_developers_home(home, _run_temp_roots(basetemp)):
            return None
        if any(isinstance(key, bytes) for key in env):
            return {**env, os.fsencode(name): os.fsencode(home)}
        return {**env, name: home}

    def runs_python_or_ash(args: Any, shell: bool, env: Any, cwd: Any, executable: Any):
        try:
            commands = _commands_of(args, shell, env, cwd, executable)
        except _UnreadableInstaller:
            return True  # only a tool-installing command raises it, and that is ASH's
        return any(
            _installs_tools(argv) or _runs_python_or_ash(argv)
            for argv, _, _ in commands
        )

    def guarded_init(self: Any, args: Any, *rest: Any, **kwargs: Any) -> None:
        env = kwargs["env"] if "env" in kwargs else (rest[9] if len(rest) > 9 else None)
        cwd = kwargs["cwd"] if "cwd" in kwargs else (rest[8] if len(rest) > 8 else None)
        cwd = os.fsdecode(cwd) if cwd is not None else None
        shell = kwargs["shell"] if "shell" in kwargs else (len(rest) > 7 and rest[7])
        executable = kwargs.get("executable", rest[1] if len(rest) > 1 else None)
        if env is not None and _child_home(_env_view(env)) is None:
            # Given an env without a HOME, a Python child would find the password
            # database's, the developer's real one, where one that inherited would
            # have had the test's. So it is given the test's. ASH's own Landlock probe
            # is such a child.
            given = with_the_tests_home(env)
            if given is not None and runs_python_or_ash(
                args, bool(shell), given, cwd, executable
            ):
                env = given
                if len(rest) > 9:
                    rest = (*rest[:9], env, *rest[10:])
                else:
                    kwargs["env"] = env
        # What the child runs, through env, prefix and shell wrappers, each with its
        # own environment and directory.
        refusal = home_rule_refusal(
            args,
            env,
            cwd,
            basetemp=basetemp,
            shell=bool(shell),
            executable=executable,
        )
        if refusal is not None:
            refuse(self, refusal)
        original_init(self, args, *rest, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", guarded_init)
        yield
    if violations:
        pytest.fail(
            "this test started a tool-installing child aimed at the developer's home: "
            + "; ".join(violations)
        )


@pytest.fixture
def home_guard_violations(request) -> List[str]:
    """The refusals the guard above recorded in this test; a test of the guard clears it."""
    return request.node.stash[_HOME_GUARD_VIOLATIONS]


#: The marker of a test that may send botocore requests off this machine.
ALLOW_AWS_NETWORK_MARKER = "allow_aws_network"

_AWS_NETWORK_VIOLATIONS = pytest.StashKey[List[str]]()


def _is_loopback_url(url: str) -> bool:
    """Whether *url* names this machine: localhost, or a loopback address."""
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _refuse_botocore_requests_off_this_machine(request):
    """Fail a test whose code sends a botocore request anywhere but this machine.

    A test that builds a real boto3 client without a Stubber, with whatever
    credentials the environment running the suite holds, talks to AWS: it imports
    findings into the developer's Security Hub or writes to their bucket, and in
    CI it fails or passes by what the runner's account allows. So the request is
    refused where botocore sends it, ``Endpoint._send``. That is after the
    ``before-call`` event a ``botocore.stub.Stubber`` answers and the
    ``before-send`` event other fakes answer, so a stubbed client never gets
    there; a loopback endpoint (a local fake service) is let through. A test that
    has to reach AWS carries ``@pytest.mark.allow_aws_network``.

    The refusal is ``pytest.fail``, which ``except Exception`` in the code under
    test does not catch, and it is also recorded, so a broader handler that
    swallows it still fails the test at teardown, as the HOME guard above does.
    A private ``MonkeyPatch``, for the reason ``_fresh_mcp_scan_registry`` gives.

    Not covered: requests a child process makes, and credential providers that
    fetch over HTTP without botocore's endpoint (the instance metadata service);
    tests that could reach those set AWS_EC2_METADATA_DISABLED themselves.
    """
    violations: List[str] = []
    request.node.stash[_AWS_NETWORK_VIOLATIONS] = violations
    if request.node.get_closest_marker(ALLOW_AWS_NETWORK_MARKER) is not None:
        yield
        return
    import botocore.endpoint

    original_send = botocore.endpoint.Endpoint._send

    def guarded_send(self: Any, http_request: Any) -> Any:
        url = str(getattr(http_request, "url", "") or "")
        if not _is_loopback_url(url):
            where = urllib.parse.urlsplit(url).netloc or url
            message = (
                f"a botocore request to {where} would have left this machine. Stub "
                "the client (botocore.stub.Stubber), point it at a loopback "
                f"endpoint, or mark the test {ALLOW_AWS_NETWORK_MARKER}."
            )
            violations.append(message)
            pytest.fail(message)
        return original_send(self, http_request)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(botocore.endpoint.Endpoint, "_send", guarded_send)
        yield
    if violations:
        pytest.fail(
            "this test sent botocore requests off this machine: "
            + "; ".join(violations)
        )


@pytest.fixture
def aws_network_violations(request) -> List[str]:
    """The refusals the guard above recorded in this test; a test of the guard clears it."""
    return request.node.stash[_AWS_NETWORK_VIOLATIONS]


@pytest.fixture
def test_plugin_context(ash_temp_path):
    """Create a test plugin context for testing.

    Returns:
        A mock plugin context for testing
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from pathlib import Path

    # Create a real PluginContext object instead of a mock
    source_dir = Path(f"{ash_temp_path}/test_source_dir")
    output_dir = Path(f"{ash_temp_path}/test_output_dir")
    work_dir = Path(f"{ash_temp_path}/test_work_dir")

    # Use a proper AshConfig object
    from automated_security_helper.config.default_config import get_default_config

    # Use default config to ensure all required fields are present
    config = get_default_config()

    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=config,
    )

    return context


@pytest.fixture
def test_source_dir(ash_temp_path):
    """Create a test source directory with sample files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the test source directory
    """
    source_dir = ash_temp_path / "source"
    Path(source_dir).mkdir(exist_ok=True, parents=True)

    # Create a sample file
    test_file = source_dir / "test.py"
    test_file.write_text("print('Hello, world!')")

    return source_dir


@pytest.fixture
def sample_ash_model():
    """Create a mock ASH model for testing."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    # Create a real model instead of a mock
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.config.ash_config import AshConfig

    # First define AshConfig and rebuild the model
    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()

    # Now create the model
    model = AshAggregatedResults()
    model.metadata.scanner_name = "test_scanner"
    model.metadata.scan_id = "test_scan_id"
    model.ash_config = get_default_config()

    return model


@pytest.fixture
def test_data_dir(ash_temp_path):
    """Create a test data directory with sample files."""
    data_dir = ash_temp_path / "test_data"
    Path(data_dir).mkdir(exist_ok=True, parents=True)

    # Create a sample CloudFormation template
    cfn_dir = data_dir / "cloudformation"
    cfn_dir.mkdir()
    cfn_file = cfn_dir / "template.yaml"
    cfn_file.write_text("""
    Resources:
      MyBucket:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: my-test-bucket
    """)

    # Create a sample Terraform file
    tf_dir = data_dir / "terraform"
    tf_dir.mkdir()
    tf_file = tf_dir / "main.tf"
    tf_file.write_text("""
    resource "aws_s3_bucket" "my_bucket" {
      bucket = "my-test-bucket"
    }
    """)

    return data_dir


@pytest.fixture
def test_output_dir(ash_temp_path):
    """Create a test output directory."""
    output_dir = ash_temp_path / "output"
    Path(output_dir).mkdir(exist_ok=True, parents=True)
    return output_dir


# Add fixtures for the test plugin classes to fix validation errors
@pytest.fixture
def dummy_scanner_config():
    """Create a dummy scanner config for testing."""
    from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase

    class DummyConfig(ScannerPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"

    return DummyConfig()


@pytest.fixture
def dummy_reporter_config():
    """Create a dummy reporter config for testing."""
    from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase

    class DummyConfig(ReporterPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"
        extension: str = ".txt"

    return DummyConfig()


@pytest.fixture
def dummy_converter_config():
    """Create a dummy converter config for testing."""
    from automated_security_helper.base.converter_plugin import (
        ConverterPluginConfigBase,
    )

    class DummyConfig(ConverterPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"

    return DummyConfig()


@pytest.fixture
def dummy_scanner(test_plugin_context, dummy_scanner_config):
    """Create a dummy scanner for testing."""
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from pathlib import Path

    class DummyScanner(ScannerPluginBase):
        """Dummy scanner for testing."""

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
            """Abstract stub — DummyScanner overrides scan() directly."""
            raise NotImplementedError(
                f"{self.__class__.__name__} overrides scan() directly."
            )

        def scan(
            self,
            target: Path,
            target_type: Literal["source", "converted"],
            global_ignore_paths: List | None = None,
            config=None,
            *args,
            **kwargs,
        ):
            if global_ignore_paths is None:
                global_ignore_paths = []

            self.output.append("hello world")
            return SarifReport(
                version="2.1.0",
                runs=[],
            )

    # Initialize with required config
    scanner = DummyScanner(config=dummy_scanner_config, context=test_plugin_context)
    return scanner


@pytest.fixture
def dummy_reporter(test_plugin_context, dummy_reporter_config):
    """Create a dummy reporter for testing."""
    from automated_security_helper.base.reporter_plugin import ReporterPluginBase
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    class DummyReporter(ReporterPluginBase):
        """Dummy reporter for testing."""

        def validate_plugin_dependencies(self) -> bool:
            return True

        def report(self, model: AshAggregatedResults) -> str:
            return '{"report": "complete"}'

    # Initialize with required config
    reporter = DummyReporter(config=dummy_reporter_config, context=test_plugin_context)
    return reporter


@pytest.fixture
def dummy_converter(test_plugin_context, dummy_converter_config):
    """Create a dummy converter for testing."""
    from automated_security_helper.base.converter_plugin import ConverterPluginBase
    from pathlib import Path

    class DummyConverter(ConverterPluginBase):
        """Dummy converter for testing."""

        def validate_plugin_dependencies(self) -> bool:
            return True

        def convert(self) -> list[Path]:
            return [Path("test.txt")]

    # Initialize with required config
    converter = DummyConverter(
        config=dummy_converter_config, context=test_plugin_context
    )
    return converter


@pytest.fixture
def no_cdk_kernel(monkeypatch):
    """Let a unit test call into ``cdk_nag_wrapper`` without booting a jsii kernel.

    WHY THIS EXISTS. ``run_cdk_nag_against_cfn_template`` opens with ``import
    cdk_nag``, then ``from aws_cdk import ...``, before it touches any argument or
    helper. Both are real jsii packages, so importing them starts a Node kernel that
    extracts the ``aws-cdk-lib`` assembly -- 7,457 files, ~133 MB -- into a per-user
    cache under a lock. Patching a collaborator like ``get_model_from_template``
    happens far too late to prevent that; the imports have already run.

    WHAT THAT COSTS. jsii holds the cache lock for the whole extraction and its
    waiter gives up after 12 randomised retries (~13 s expected, ~26 s worst case).
    On Windows CI the suite runs under ``-n auto`` = 4 workers, so two tests that
    each boot a kernel can land on different workers, race the same cache entry, and
    the loser dies with ``EEXIST ... aws-cdk-lib/<version>/<sha>.lock``. That was
    measured: zero occurrences across 1,772 Windows legs while exactly one test
    booted a kernel, then 12 occurrences once a second one did.

    SO: any test that calls into the wrapper but is not testing real cdk-nag
    behaviour should request this fixture. It installs doubles under the names the
    wrapper imports, which is the only thing that stops the import.

    NOT A BEHAVIOUR HARNESS. These doubles carry just enough shape to get past the
    import block and the ``WrapperStack`` class body. Tests that exercise what the
    wrapper *does* -- synth, nag packs, report parsing -- want the far richer
    ``cdk_doubles`` in ``tests/unit/utils/test_cdk_nag_wrapper_behavior.py``, which
    mirrors the real cdk-nag 3.x signatures on purpose. Do not grow this one into
    that; pick the right one.
    """
    import types

    class _Stack:
        """Subclassable: the wrapper declares ``class WrapperStack(Stack)``."""

        def __init__(self, *args, **kwargs):
            pass

    class _App:
        def __init__(self, *args, **kwargs):
            pass

    class _Validations:
        @staticmethod
        def of(_scope):
            raise AssertionError(
                "no_cdk_kernel is import-level only; a test that reaches synth "
                "wants cdk_doubles instead"
            )

    class _CfnInclude:
        def __init__(self, *args, **kwargs):
            pass

    class _Construct:
        pass

    class _DefaultStackSynthesizer:
        """``WrapperStack`` passes one to ``Stack.__init__``.

        Present because the wrapper imports the name at the top of its import block,
        alongside App, Stack and Validations, so its absence is an ImportError before
        any of these doubles gets a chance to matter. It records nothing: the
        ``generate_bootstrap_version_rule=False`` argument is about what the REAL
        synthesizer emits into a synthesized template, which only the behaviour
        doubles in test_cdk_nag_wrapper_behavior.py reach.
        """

        def __init__(self, *args, **kwargs):
            pass

    aws_cdk = types.ModuleType("aws_cdk")
    aws_cdk.App = _App
    aws_cdk.Stack = _Stack
    aws_cdk.Validations = _Validations
    aws_cdk.DefaultStackSynthesizer = _DefaultStackSynthesizer

    cfn_include = types.ModuleType("aws_cdk.cloudformation_include")
    cfn_include.CfnInclude = _CfnInclude
    aws_cdk.cloudformation_include = cfn_include

    constructs = types.ModuleType("constructs")
    constructs.Construct = _Construct

    # No NagPack attribute: get_nag_packs() is defined but not called on the paths
    # this fixture is for, and leaving it absent makes a test that does reach it
    # fail loudly rather than pass against a silently wrong double.
    cdk_nag = types.ModuleType("cdk_nag")

    doubles = {
        "cdk_nag": cdk_nag,
        "aws_cdk": aws_cdk,
        "aws_cdk.cloudformation_include": cfn_include,
        "constructs": constructs,
    }
    for name, module in doubles.items():
        monkeypatch.setitem(sys.modules, name, module)

    # Snapshot AFTER the doubles are in place, so the doubles themselves do not read
    # as newly imported. Compared against a snapshot rather than asserting the names
    # are simply absent, because another test sharing this xdist worker may already
    # have imported them for its own reasons -- only what the test under
    # measurement causes should be able to fail its assertion.
    installed = set(sys.modules)

    def newly_imported_cdk() -> set:
        """Real jsii-backed module names imported since this fixture ran."""
        return {
            name
            for name in set(sys.modules) - installed
            if name == "jsii"
            or name.startswith(("jsii.", "aws_cdk", "cdk_nag", "constructs"))
        }

    ns = types.SimpleNamespace(
        **{k.replace(".", "_"): v for k, v in doubles.items()},
    )
    ns.newly_imported_cdk = newly_imported_cdk
    return ns


@pytest.fixture(autouse=True)
def _mcp_workspace_root_outside_home(tmp_path_factory):
    """Keep MCP session workspaces out of the developer's own cache directory.

    An MCP HTTP app removes a session's workspace when the session ends, and
    sweeps workspaces nobody used for a day, under ``ASH_MCP_WORKSPACE_ROOT``,
    which otherwise resolves to ``$XDG_CACHE_HOME/ash-mcp`` or
    ``~/.cache/ash-mcp``. A test that builds an app without naming a root would
    act on that real directory. Set whatever the environment says, so a developer
    who exports their own root never runs the tests against it; a test that needs
    a particular root sets its own.

    A private ``MonkeyPatch``, for the reason ``_isolated_home`` gives: the
    ``monkeypatch`` fixture requested here would be torn down after every test's
    own fixtures. A test's own ``monkeypatch.setenv`` of the variable still wins.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(
            "ASH_MCP_WORKSPACE_ROOT",
            str(tmp_path_factory.getbasetemp() / "mcp-workspace-root"),
        )
        yield


def _drop_mcp_session_state() -> None:
    # Looked up rather than imported: a worker that never imported the module
    # has no session state, and importing it here would load ASH's config models
    # on every worker before its first test.
    sessions = sys.modules.get("automated_security_helper.cli.mcp.sessions")
    if sessions is None:
        return
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()


@pytest.fixture(autouse=True)
def _no_mcp_session_state_outlives_its_test():
    """Start and end every test with no MCP session state in the process.

    The session registry (``cli/mcp/sessions.get_default_registry``) is
    process-wide. For each session id it holds the scan claim
    (``MCPSession.try_claim_scan``) that makes set_source_git, set_source_zip_*
    and clear_source refuse with ``source_delivery_busy`` while a scan runs, and
    the scan's place in the per-session limit. A scan's task gives both back when
    it returns. A test that stands in for ``_run_scan_async``, or whose
    ``asyncio.run`` returns before the task it started has run at all, never
    gives them back, so its session id stays busy for every later test on the
    same worker.

    That is how this was found.
    ``test_mcp_config_confinement.py::TestInsideTheRootsStillWorks::test_set_source_git_with_a_remote_url_reaches_git``
    failed once with ``source_delivery_busy`` in a ``tests/unit -n 8`` run and
    passed alone. Earlier on the same worker,
    ``test_discovered_config_outside_the_grant.py``'s
    ``test_control_a_tree_whose_config_is_inside_the_grant_starts_the_scan`` had
    started a scan with ``_run_scan_async`` patched out, for the same session id,
    ``client-one``. With ``-n 0`` and that order it fails every time. Which tests
    share a worker depends on ``-n`` and on how xdist hands out work, so the
    failure came and went.

    Sessions whose removal waits for a scan (``_ended_while_scanning``) are
    process-wide too, and are cleared with the registry. So is the latch that
    keeps a refused scan presence guard to one warning
    (``sessions.reset_guard_refusal_warning_for_tests``): a test that meets a
    refused guard does not leave it set for the next.
    """
    _drop_mcp_session_state()
    yield
    _drop_mcp_session_state()
