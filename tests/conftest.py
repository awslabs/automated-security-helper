"""Pytest configuration file for ASH tests."""

import contextlib
import errno
import functools
import importlib.abc
import importlib.machinery
import logging
import os
import shutil
import stat
import sys
import tempfile
import pytest
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator, List, Literal, Optional, Sequence

from tests.utils.helpers import get_ash_temp_path

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
#     because it may name a cache shared with other tools, such as ~/.cache.
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
    """The single jsii package cache root for this test session."""
    override = (os.environ.get(_JSII_CACHE_ENV) or "").strip()
    if override:
        return Path(override).expanduser().resolve() / _JSII_CACHE_SUBDIR
    return _REPO_ROOT / ".cache" / _JSII_CACHE_SUBDIR


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
_created_session_tmpdir: Optional[Path] = None


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
        path = Path(tempfile.mkdtemp(prefix="ash-pytest-"))
        os.environ[_SESSION_TMP_ENV] = str(path)
        _created_session_tmpdir = path
    for var in _TEMP_VARS:
        os.environ[var] = str(path)
    tempfile.tempdir = str(path)
    return path


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
    root = _jsii_package_cache_root()
    if root.is_dir():
        with _exclusive_file_lock(root / _JSII_LOAD_LOCK_NAME):
            _prune_jsii_package_cache(root)
    _remove_session_tmpdir()


def pytest_configure(config):
    """Configure pytest for ASH tests."""
    # Must happen before anything imports a jsii-backed package. pytest_configure is
    # the earliest per-worker hook, and collection -- which imports test modules --
    # runs after it.
    _enter_session_tmpdir()
    _configure_jsii_package_cache()

    # Register custom markers
    config.addinivalue_line(
        "markers", "unit: Unit tests that test individual components in isolation"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests that test component interactions"
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
    config.addinivalue_line("markers", "serial: Tests that should not run in parallel")


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
        help="Run integration tests",
    )
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


def pytest_collection_modifyitems(config, items):
    """Modify the collected test items based on command-line options."""
    # Skip slow tests unless --run-slow is specified
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="Need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)

    # Skip integration tests unless --run-integration is specified
    if not config.getoption("--run-integration"):
        skip_integration = pytest.mark.skip(
            reason="Need --run-integration option to run"
        )
        for item in items:
            if "integration" in item.keywords:
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
    and ``utils/log.py``'s ``get_logger`` both do exactly that, and seven files
    under ``tests/unit/cli`` reach one of them. Under ``-n auto`` the xdist worker
    count decides which tests share a process, so one commit was green on the
    4-worker Linux and Windows runners and red on the 3-worker macOS runners.
    """
    plugin = request.config.pluginmanager.get_plugin("logging-plugin")
    handler = getattr(plugin, "log_cli_handler", None)
    if handler is not None:
        logging.getLogger("ash").removeHandler(handler)
    yield


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

    Snapshotting the three switches per test keeps the blast radius of any such
    import inside the test that caused it. Handlers are deliberately left alone:
    the session fixture above manages those, and rebuilding the handler list here
    would fight it.
    """
    ash_logger = logging.getLogger("ash")
    level, propagate, disabled = (
        ash_logger.level,
        ash_logger.propagate,
        ash_logger.disabled,
    )
    try:
        yield
    finally:
        ash_logger.level = level
        ash_logger.propagate = propagate
        ash_logger.disabled = disabled


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
def temp_env_vars():
    """Create a fixture for temporarily setting environment variables.

    Returns:
        Function that sets environment variables for the duration of a test
    """
    original_env = {}

    def _set_env_vars(**kwargs):
        for key, value in kwargs.items():
            if key in os.environ:
                original_env[key] = os.environ[key]
            os.environ[key] = str(value)

    yield _set_env_vars

    # Restore original environment variables
    for key in original_env:
        os.environ[key] = original_env[key]

    # Remove environment variables that were not originally set
    for key in os.environ.keys() - original_env.keys():
        if key in os.environ:
            del os.environ[key]


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
