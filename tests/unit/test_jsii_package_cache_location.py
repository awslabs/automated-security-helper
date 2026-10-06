"""Where tests/conftest.py puts the jsii package cache, and how workers share it.

The cache used to live at ``<tempdir>/ash-jsii-package-cache/<xdist worker>``: one
full extraction of aws-cdk-lib (about 7,500 files) per booting worker, in the host's
temp directory, never removed. On a many-core host that reached about 665,000
inodes and exhausted /tmp for every process on the machine. These tests pin the
replacement: one repo-local root shared by every worker, a file lock that
serializes assembly loads, and a size bound applied at session end.
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / ".cache" / "jsii-package-cache"


@pytest.fixture
def ash_conftest(pytestconfig):
    """The tests/conftest.py module pytest actually loaded and ran hooks from.

    Not ``from tests import conftest``: pytest imports it as ``conftest``, so that
    import would execute a second copy whose classes and state are not the live ones.
    """
    target = REPO_ROOT / "tests" / "conftest.py"
    for plugin in pytestconfig.pluginmanager.get_plugins():
        if Path(getattr(plugin, "__file__", "") or "").resolve() == target:
            return plugin
    raise AssertionError("tests/conftest.py is not registered as a plugin")


def _under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _temp_roots() -> list[Path]:
    roots = [Path(tempfile.gettempdir())]
    if os.name != "nt":
        roots.append(Path("/tmp"))
    # A checkout that itself lives in a temp directory cannot avoid one; only a
    # cache placed there by conftest, outside the checkout, is the defect.
    return [r for r in roots if not _under(REPO_ROOT, r)]


def test_live_cache_root_is_repo_local_and_not_in_a_temp_dir():
    """The root this very process was configured with, as jsii will read it."""
    configured = os.environ.get("JSII_RUNTIME_PACKAGE_CACHE_ROOT")
    assert configured, "conftest did not pin JSII_RUNTIME_PACKAGE_CACHE_ROOT"
    root = Path(configured)

    override = (os.environ.get("ASH_JSII_CACHE_DIR") or "").strip()
    if override:
        assert root == Path(override).expanduser().resolve()
    else:
        assert root == DEFAULT_ROOT
        for temp_root in _temp_roots():
            assert not _under(root, temp_root), (
                f"jsii package cache resolved under {temp_root}: {root}"
            )

    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    if worker:
        assert worker not in root.parts, f"cache is per-worker again: {root}"


@pytest.mark.parametrize("worker", ["", "gw0", "gw3"])
def test_default_root_is_shared_and_ignores_tmpdir(
    monkeypatch, tmp_path, worker, ash_conftest
):
    monkeypatch.delenv("ASH_JSII_CACHE_DIR", raising=False)
    monkeypatch.setenv("PYTEST_XDIST_WORKER", worker)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    root = ash_conftest._jsii_package_cache_root()

    assert root == DEFAULT_ROOT
    assert not _under(root, tmp_path)


def test_override_is_honored(monkeypatch, tmp_path, ash_conftest):
    monkeypatch.setenv("ASH_JSII_CACHE_DIR", str(tmp_path / "jsii"))
    assert ash_conftest._jsii_package_cache_root() == (tmp_path / "jsii").resolve()


def test_blank_override_falls_back_to_default(monkeypatch, ash_conftest):
    monkeypatch.setenv("ASH_JSII_CACHE_DIR", "   ")
    assert ash_conftest._jsii_package_cache_root() == DEFAULT_ROOT


def test_lock_excludes_a_second_holder(tmp_path, ash_conftest):
    """Two independent opens of the lock file exclude each other.

    flock and msvcrt.locking both lock per open file, so two threads opening the file
    separately contend exactly as two xdist workers do.
    """
    lock_path = tmp_path / "load.lock"
    first_held = threading.Event()
    release_first = threading.Event()
    events: list[str] = []

    def first():
        with ash_conftest._exclusive_file_lock(lock_path):
            events.append("first acquired")
            first_held.set()
            release_first.wait(10)
            events.append("first released")

    def second():
        first_held.wait(10)
        with ash_conftest._exclusive_file_lock(lock_path):
            events.append("second acquired")

    t1 = threading.Thread(target=first)
    t2 = threading.Thread(target=second)
    t1.start()
    t2.start()
    assert first_held.wait(10)
    # Give the second thread time to reach the lock; it must still be waiting.
    t2.join(0.5)
    assert t2.is_alive()
    assert events == ["first acquired"]
    release_first.set()
    t1.join(10)
    t2.join(10)
    assert events == ["first acquired", "first released", "second acquired"]


def test_import_hook_wraps_kernel_load_under_the_lock(
    monkeypatch, tmp_path, ash_conftest
):
    """The hook patches Kernel.load when the module is first imported, not before."""
    pkg = tmp_path / "fakejsii"
    (pkg / "_kernel").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "_kernel" / "__init__.py").write_text(
        "class Kernel:\n"
        "    def load(self, name, version, tarball):\n"
        "        return (name, version, tarball)\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    for name in ("fakejsii", "fakejsii._kernel"):
        monkeypatch.delitem(sys.modules, name, raising=False)

    lock_path = tmp_path / "cache" / ".ash-load.lock"
    hook = ash_conftest._JsiiKernelLoadLockHook(lock_path, "fakejsii._kernel")
    monkeypatch.setattr(sys, "meta_path", [hook, *sys.meta_path])

    import fakejsii._kernel as kernel_module  # type: ignore[import-not-found]

    assert hook not in sys.meta_path, "hook should remove itself after one use"
    kernel_cls = kernel_module.Kernel
    assert getattr(kernel_cls.load, "__ash_jsii_cache_lock__", None) == lock_path

    held_during_call: list[bool] = []

    def probe(*_args):
        # A second, independent open must not get the lock while load runs.
        acquired = threading.Event()

        def contender():
            with ash_conftest._exclusive_file_lock(lock_path):
                acquired.set()

        t = threading.Thread(target=contender, daemon=True)
        t.start()
        held_during_call.append(not acquired.wait(0.3))
        return "loaded"

    class Probe:
        def load(self, name, version, tarball):
            return probe(name, version, tarball)

    ash_conftest._wrap_kernel_load(Probe, lock_path)
    assert Probe().load("aws-cdk-lib", "2.0.0", "x.tgz") == "loaded"
    assert held_during_call == [True]
    assert kernel_cls().load("a", "1", "t") == ("a", "1", "t")


def test_real_jsii_kernel_is_patched_once_imported(ash_conftest):
    module = sys.modules.get("jsii._kernel")
    if module is not None:
        assert getattr(module.Kernel.load, "__ash_jsii_cache_lock__", None)
    else:
        assert any(
            isinstance(f, ash_conftest._JsiiKernelLoadLockHook) for f in sys.meta_path
        ), "jsii._kernel is not imported yet, so the hook must still be pending"


def _make_entry(root: Path, package: str, version: str, digest: str, age: float):
    entry = root / package / version / digest
    (entry / "package").mkdir(parents=True)
    (entry / "package" / "index.js").write_text("x")
    marker = entry / ".jsii-runtime-package-cache"
    marker.write_text("")
    stamp = time.time() - age
    os.utime(marker, (stamp, stamp))
    # The directory's own mtime says the opposite, so only the marker can order these.
    os.utime(entry, (time.time() - 10_000 + age, time.time() - 10_000 + age))
    return entry


def test_prune_keeps_the_newest_entries_per_package(tmp_path, ash_conftest):
    root = tmp_path / "cache"
    newest = _make_entry(root, "aws-cdk-lib", "2.3.0", "c" * 8, age=10)
    middle = _make_entry(root, "aws-cdk-lib", "2.2.0", "b" * 8, age=100)
    oldest = _make_entry(root, "aws-cdk-lib", "2.1.0", "a" * 8, age=1000)
    scoped = _make_entry(root, "@aws-cdk/asset-awscli-v1", "2.2.0", "d" * 8, age=1000)
    lone = _make_entry(root, "cdk-nag", "2.0.0", "e" * 8, age=5000)

    removed = ash_conftest._prune_jsii_package_cache(root, keep=2)

    assert removed == [oldest]
    assert newest.is_dir() and middle.is_dir() and scoped.is_dir() and lone.is_dir()
    assert not oldest.exists()
    assert not (root / "aws-cdk-lib" / "2.1.0").exists(), "empty version dir left"


def test_prune_of_a_missing_root_is_a_no_op(tmp_path, ash_conftest):
    assert ash_conftest._prune_jsii_package_cache(tmp_path / "absent", keep=2) == []


def test_live_session_runs_in_its_own_temp_directory():
    session = os.environ.get("ASH_TEST_SESSION_TMPDIR")
    assert session, "conftest did not set up a session temp directory"
    assert Path(session).is_dir()
    assert Path(session).name.startswith("ash-pytest-")
    assert tempfile.gettempdir() == session
    for var in ("TMPDIR", "TEMP", "TMP"):
        assert os.environ[var] == session


def _isolate_session_state(monkeypatch, ash_conftest, tmp_path):
    for var in ("ASH_TEST_SESSION_TMPDIR", "TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(var, os.environ.get(var, ""))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(ash_conftest, "_created_session_tmpdir", None)


def test_session_tmpdir_is_created_owned_and_removed(
    monkeypatch, tmp_path, ash_conftest
):
    _isolate_session_state(monkeypatch, ash_conftest, tmp_path)
    monkeypatch.delenv("ASH_TEST_SESSION_TMPDIR")

    path = ash_conftest._enter_session_tmpdir()

    assert path.parent == tmp_path and path.is_dir()
    assert os.environ["ASH_TEST_SESSION_TMPDIR"] == str(path)
    assert tempfile.gettempdir() == str(path)
    (path / "left-behind").mkdir()
    (path / "left-behind" / "f").write_text("x")
    os.chmod(path / "left-behind" / "f", 0o400)

    ash_conftest._remove_session_tmpdir()
    assert not path.exists()


def test_inherited_session_tmpdir_is_reused_and_not_removed(
    monkeypatch, tmp_path, ash_conftest
):
    """A worker, or a pytest run started by a test, must not delete its parent's."""
    _isolate_session_state(monkeypatch, ash_conftest, tmp_path)
    parent = tmp_path / "parent-session"
    parent.mkdir()
    monkeypatch.setenv("ASH_TEST_SESSION_TMPDIR", str(parent))

    assert ash_conftest._enter_session_tmpdir() == parent
    ash_conftest._remove_session_tmpdir()

    assert parent.is_dir()
    assert list(tmp_path.iterdir()) == [parent], "a second directory was created"
