# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The backends' plans, read as text: what each one mounts, hides, grants and leaves.

bwrap: a probe that failed no longer satisfies plan()'s guard; a cache on a
filesystem that refuses to be an overlay's lower layer is mounted read-only; a
policy read path of "/" no longer hides every link; a link whose target passes
through another link is recreated with it; a link covered by a tmpfs is recreated
in it; no link is recreated over the shared temp directories; an unread directory
inside an unshown one gets its own empty directory; a home missing from the host
under a read-only bind gets no tmpfs, and the passwd entry's home gets one; the
resolver file is bound, not its directory. firejail: a passwd home of "/" names no
home, a path firejail would read as a pattern is refused, and uv's lock is
writable. Landlock: a plan that raises leaves no private root, the scan's data is
granted read without exec, uv's lock is writable, and a spawn with no working
directory gets the private one. sandbox-exec: a root home denies nothing, the
third shared temp directory is denied, shared memory is named, uv's lock is not
executable, an operator's SSL_CERT_FILE is readable, and a refused profile leaves
no temp directory. The environment list: every backend passes one list, an entry
sets or passes a variable as a docker-compose ``environment`` entry does, a
credential-shaped name is refused with its name, and every backend gives back
what the operator's CA-bundle settings name. Nothing here starts a sandbox:
``_probe_run`` is replaced where a plan would probe, and every assertion reads a
command line or a profile.
"""

from __future__ import annotations

import codecs
import json
import locale
import logging
import os
import re
import subprocess  # nosec B404 - CompletedProcess is built by hand, nothing runs
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox import backends
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox.backends import (
    BwrapBackend,
    FirejailBackend,
    LandlockBackend,
    SandboxExecBackend,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxPolicy,
    SandboxUnavailable,
)

pytestmark = pytest.mark.unit

#: The tests that make symlinks, or hand a POSIX program path to the Landlock plan:
#: a Windows runner may not create links, resolves "/" to a drive, and on Python
#: 3.13 reads "/bin/true" as relative, so the sibling carve file skips them too.
POSIX = pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks and POSIX program paths"
)


def _real(path) -> Path:
    return Path(os.path.realpath(path))


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """A home, a system directory and a results directory, with the passwd home pinned.

    Built under the resolved temporary directory, so a link above it (macOS's
    /tmp) does not make a spelled path and its resolved one differ in the
    assertions below; the shared temp root firejail reads is moved out of it.
    """
    tmp = Path(os.path.realpath(tmp_path))
    home = tmp / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for module in (policy_module, backends):
        monkeypatch.setattr(module, "_passwd_home", Path.home, raising=False)
    fake_tmp_root = tmp / "fake-tmp-root"
    fake_tmp_root.mkdir()
    monkeypatch.setattr(backends, "_TMP_ROOT", fake_tmp_root, raising=False)
    system = tmp / "sys"
    system.mkdir()
    results = tmp / "out" / "results"
    results.mkdir(parents=True)

    class _Layout:
        pass

    found = _Layout()
    found.home, found.system, found.results, found.tmp = home, system, results, tmp
    return found


def _policy(layout, **fields) -> SandboxPolicy:
    values = {
        "scanner_name": "probe",
        "read_only": (layout.system,),
        "writable": (layout.results,),
        "cache": (),
        "network": False,
        "home": layout.home,
        "cwd": None,
    }
    values.update(fields)
    return SandboxPolicy(**values)


def _bwrap(overlay=False) -> BwrapBackend:
    backend = BwrapBackend()
    backend._executable = "/usr/bin/bwrap"
    backend._overlay = overlay
    return backend


def _symlinks(argv) -> dict:
    """The --symlink options of a bwrap plan: where each link is made -> its target."""
    return {
        Path(argv[i + 2]): argv[i + 1] for i, a in enumerate(argv) if a == "--symlink"
    }


def _mounts(argv, flag) -> list:
    return [Path(argv[i + 1]) for i, a in enumerate(argv) if a == flag]


# ---------------------------------------------------------------------------
# probes and failures
# ---------------------------------------------------------------------------


def test_exit_failure_reads_stdout_when_stderr_is_only_whitespace():
    def result(stdout, stderr):
        return subprocess.CompletedProcess([], 1, stdout=stdout, stderr=stderr)

    assert backends._exit_failure(result("boom\n", "  \n\t")) == "exit 1: boom"
    assert backends._exit_failure(result("out", "err\n")) == "exit 1: err"
    assert backends._exit_failure(result("", "")) == "exit 1: no output"
    assert backends._exit_failure(subprocess.CompletedProcess([], 0)) is None


def test_a_probe_whose_output_is_not_text_still_answers():
    """A probe's stderr holding a byte UTF-8 does not decode is a reason, not a
    traceback out of the plan that asked (the per-filesystem overlay probe runs
    inside plan(), and a UnicodeDecodeError there would fail the spawn).

    The one process this file starts is this interpreter, writing one such byte;
    no sandbox program is involved.
    """
    script = "import sys; sys.stderr.buffer.write(b'refused \\x81\\n'); sys.exit(3)"

    failure = backends._probe_run(
        [sys.executable, "-c", script], env=snapshot_environ()
    )

    assert failure is not None
    assert failure.startswith("exit 3: refused ")
    # 0x81 is undefined in UTF-8 and replaced there; a single-byte locale codec
    # (ISO-8859-1) decodes it as U+0081 and nothing is replaced, which is not a
    # failure of what is tested here.
    if codecs.lookup(locale.getpreferredencoding(False)).name == "utf-8":
        assert chr(0xFFFD) in failure


def test_a_failed_root_export_is_tried_again(layout, monkeypatch):
    keychain = layout.tmp / "roots.keychain"
    keychain.write_text("")
    monkeypatch.setattr(backends, "_TRUST_ROOT_KEYCHAINS", (str(keychain),))
    monkeypatch.setattr(backends, "_trust_roots_cache", [])
    # A failed export records that it was warned of; the list is the module's, so
    # it is replaced here and the warning state of later tests is left as it was.
    monkeypatch.setattr(backends, "_trust_roots_warned", [])
    answers = [
        subprocess.CompletedProcess([], 1, stdout="", stderr="export refused"),
        subprocess.CompletedProcess([], 0, stdout="BEGIN CERTIFICATE\n", stderr=""),
    ]
    monkeypatch.setattr(
        backends.subprocess, "run", lambda *args, **kwargs: answers.pop(0)
    )

    assert backends._system_trust_roots() is None
    assert backends._system_trust_roots() == "BEGIN CERTIFICATE\n"
    assert backends._system_trust_roots() == "BEGIN CERTIFICATE\n"


def test_a_failed_root_export_warns_once_per_run(layout, monkeypatch, caplog):
    """The export is tried again at every spawn when it failed in time, so the
    warning that it failed is logged once; later failures are logged at DEBUG."""
    keychain = layout.tmp / "roots.keychain"
    keychain.write_text("")
    monkeypatch.setattr(backends, "_TRUST_ROOT_KEYCHAINS", (str(keychain),))
    monkeypatch.setattr(backends, "_trust_roots_cache", [])
    monkeypatch.setattr(backends, "_trust_roots_warned", [])
    monkeypatch.setattr(
        backends.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 1, stdout="", stderr="refused"
        ),
    )

    with caplog.at_level(logging.DEBUG, logger="ash"):
        for _ in range(3):
            assert backends._system_trust_roots() is None

    about = [
        record
        for record in caplog.records
        if "Could not export the system root certificates" in record.getMessage()
    ]
    assert [record.levelno for record in about] == [
        logging.WARNING,
        logging.DEBUG,
        logging.DEBUG,
    ]


def test_a_root_export_that_ran_out_of_time_is_not_tried_again(layout, monkeypatch):
    """A hang costs one spawn the probe timeout, not every spawn of the run."""
    keychain = layout.tmp / "roots.keychain"
    keychain.write_text("")
    monkeypatch.setattr(backends, "_TRUST_ROOT_KEYCHAINS", (str(keychain),))
    monkeypatch.setattr(backends, "_trust_roots_cache", [])
    monkeypatch.setattr(backends, "_trust_roots_warned", [])
    calls = []

    def hanging(*args, **kwargs):
        calls.append(args)
        raise subprocess.TimeoutExpired(cmd="security", timeout=1)

    monkeypatch.setattr(backends.subprocess, "run", hanging)

    assert backends._system_trust_roots() is None
    assert backends._system_trust_roots() is None
    assert len(calls) == 1


def test_a_private_cache_that_cannot_be_made_leaves_no_directory(layout):
    """Two cache variables that differ only in case collide on one directory name.

    The second ``mkdir`` raises after the cache root was made under the results
    directory; nothing is returned, so no cleanup step would ever remove it.
    """
    policy = _policy(layout, cache_env=("UV_CACHE_DIR", "uv_cache_dir"))

    with pytest.raises(FileExistsError):
        backends._private_caches(policy, {})

    assert list(layout.results.iterdir()) == []


def test_a_failed_bwrap_probe_leaves_the_plan_guard_unsatisfied(layout, monkeypatch):
    programs = {"bwrap": "/fake/bwrap", "true": "/fake/true"}
    monkeypatch.setattr(backends, "_sandbox_program", lambda name: programs.get(name))
    monkeypatch.setattr(backends, "_probe_run", lambda argv, env=None: "exit 1: no")
    backend = BwrapBackend()

    assert backend._probe() is not None
    assert backend._executable is None
    with pytest.raises(RuntimeError, match="probe"):
        backend.plan(["/fake/true"], {}, _policy(layout))


# ---------------------------------------------------------------------------
# bwrap
# ---------------------------------------------------------------------------


def test_a_cache_whose_filesystem_refuses_an_overlay_is_mounted_read_only(
    layout, monkeypatch
):
    cache = layout.tmp / "cache"
    cache.mkdir()
    probes = []

    def probe_run(argv, env=None):
        probes.append(list(argv))
        return "exit 1: refused" if "--overlay-src" in argv else None

    monkeypatch.setattr(backends, "_probe_run", probe_run)
    monkeypatch.setattr(backends, "_true", lambda: "/fake/true")
    policy = _policy(layout, cache=(cache,), cache_env=("UV_CACHE_DIR",))

    plan = _bwrap(overlay=True).plan(["/bin/true"], {}, policy)
    try:
        assert "--overlay-src" not in plan.argv
        assert _real(cache) in _mounts(plan.argv, "--ro-bind")
        assert Path(plan.env["UV_CACHE_DIR"]).is_dir()
    finally:
        plan.run_cleanup()
    assert len([p for p in probes if "--overlay-src" in p]) == 1

    # The control: a filesystem that takes the overlay keeps it.
    monkeypatch.setattr(backends, "_probe_run", lambda argv, env=None: None)
    plan = _bwrap(overlay=True).plan(["/bin/true"], {}, policy)
    try:
        assert "--overlay-src" in plan.argv
        assert "UV_CACHE_DIR" not in plan.env
    finally:
        plan.run_cleanup()


def test_only_the_caches_on_a_refusing_filesystem_get_a_private_directory(
    layout, monkeypatch
):
    """Two caches, one on a filesystem that refuses an overlay and one that takes
    it: the refusing one is mounted read-only and its variable gets a private
    directory; the other keeps its overlay and its variable keeps its value, so
    the tool goes on writing into the overlay, which is discarded with the spawn.
    """
    taking = layout.tmp / "uv-cache"
    taking.mkdir()
    refusing = layout.tmp / "other-cache"
    refusing.mkdir()
    backend = _bwrap(overlay=True)
    monkeypatch.setattr(backend, "_overlay_over", lambda real: real != _real(refusing))
    policy = _policy(
        layout,
        cache=(taking, refusing),
        cache_env=("UV_CACHE_DIR", "OTHER_CACHE_DIR"),
        env_names=("OTHER_CACHE_DIR",),
    )
    env = {"UV_CACHE_DIR": str(taking), "OTHER_CACHE_DIR": str(refusing)}

    plan = backend.plan(["/bin/true"], env, policy)
    try:
        assert _real(taking) in _mounts(plan.argv, "--overlay-src")
        assert _real(refusing) in _mounts(plan.argv, "--ro-bind")
        assert plan.env["UV_CACHE_DIR"] == str(taking)
        private = Path(plan.env["OTHER_CACHE_DIR"])
        assert private.is_dir()
        assert _real(layout.results) in _real(private).parents
        assert len(plan.private_dirs) == 1
    finally:
        plan.run_cleanup()


def test_a_cache_inside_an_overlaid_one_that_is_read_only_gets_a_private_directory(
    layout, monkeypatch
):
    """A mount of another filesystem inside an overlaid cache is bound read-only on
    top of the overlay, so a variable naming a path in it is redirected although
    the path is also under the overlaid cache. A variable naming a path that only
    the overlaid cache covers keeps its value (the control).
    """
    taking = layout.tmp / "cache"
    refusing = taking / "uv"
    refusing.mkdir(parents=True)
    (taking / "other").mkdir()
    backend = _bwrap(overlay=True)
    monkeypatch.setattr(backend, "_overlay_over", lambda real: real != _real(refusing))
    policy = _policy(
        layout,
        cache=(taking, refusing),
        cache_env=("UV_CACHE_DIR", "OTHER_CACHE_DIR"),
        env_names=("OTHER_CACHE_DIR",),
    )
    env = {
        "UV_CACHE_DIR": str(refusing / "wheels"),
        "OTHER_CACHE_DIR": str(taking / "other"),
    }

    plan = backend.plan(["/bin/true"], env, policy)
    try:
        assert _real(taking) in _mounts(plan.argv, "--overlay-src")
        assert _real(refusing) in _mounts(plan.argv, "--ro-bind")
        assert plan.env["OTHER_CACHE_DIR"] == str(taking / "other")
        private = Path(plan.env["UV_CACHE_DIR"])
        assert private.is_dir()
        assert _real(layout.results) in _real(private).parents
        assert len(plan.private_dirs) == 1
    finally:
        plan.run_cleanup()


def test_the_throwaway_property_is_false_once_a_cache_filesystem_refuses(
    layout, monkeypatch
):
    """The property says every cache plans so far was mounted as an overlay: a plan
    that mounted one read-only (its filesystem refused) makes it False, and a
    backend whose caches all took an overlay keeps True. Before any plan has met a
    cache filesystem it says nothing is known, which is False for both."""
    cache = layout.tmp / "cache"
    cache.mkdir()
    monkeypatch.setattr(backends, "_true", lambda: "/fake/true")
    policy = _policy(layout, cache=(cache,), cache_env=("UV_CACHE_DIR",))

    monkeypatch.setattr(backends, "_probe_run", lambda argv, env=None: None)
    taking = _bwrap(overlay=True)
    assert taking.caches_are_throwaway is False
    plan = taking.plan(["/bin/true"], {}, policy)
    try:
        assert taking.caches_are_throwaway is True
    finally:
        plan.run_cleanup()

    monkeypatch.setattr(
        backends,
        "_probe_run",
        lambda argv, env=None: "exit 1: refused" if "--overlay-src" in argv else None,
    )
    refusing = _bwrap(overlay=True)
    assert refusing.caches_are_throwaway is False
    plan = refusing.plan(["/bin/true"], {}, policy)
    try:
        assert refusing.caches_are_throwaway is False
    finally:
        plan.run_cleanup()


def test_the_throwaway_property_is_false_until_a_filesystem_has_been_probed(
    layout, monkeypatch
):
    """An empty record of probed filesystems is not a record of no refusals.

    ``all()`` over nothing is True, so the property read True for a backend that
    had planned nothing, and the first spawn to meet a refusing filesystem was
    trusted to write into a cache that was mounted read-only. It is False on an
    empty record, False for a backend whose probe found no overlays, False after
    a plan with no cache to probe, and True only once a plan has probed a
    filesystem and the filesystem took the overlay. The stand-in probe records
    what it is asked and answers; nothing is mounted or started.
    """
    cache = layout.tmp / "cache"
    cache.mkdir()
    probes = []

    def probe_run(argv, env=None):
        probes.append(list(argv))
        return None

    monkeypatch.setattr(backends, "_probe_run", probe_run)
    monkeypatch.setattr(backends, "_true", lambda: "/fake/true")

    backend = _bwrap(overlay=True)
    assert backend._overlay_devices == {}
    assert backend.caches_are_throwaway is False

    # A plan with no cache never asks about a filesystem: still nothing known.
    plan = backend.plan(["/bin/true"], {}, _policy(layout))
    plan.run_cleanup()
    assert [p for p in probes if "--overlay-src" in p] == []
    assert backend.caches_are_throwaway is False

    # The backend whose probe found no overlay at all is False after a plan too.
    without_overlay = _bwrap(overlay=False)
    plan = without_overlay.plan(["/bin/true"], {}, _policy(layout, cache=(cache,)))
    plan.run_cleanup()
    assert without_overlay.caches_are_throwaway is False

    # Once a plan has probed a cache's filesystem and it took the overlay: True.
    plan = backend.plan(
        ["/bin/true"], {}, _policy(layout, cache=(cache,), cache_env=("UV_CACHE_DIR",))
    )
    plan.run_cleanup()
    assert len([p for p in probes if "--overlay-src" in p]) == 1
    assert list(backend._overlay_devices.values()) == [True]
    assert backend.caches_are_throwaway is True


@pytest.mark.parametrize(
    "raised",
    [OSError(2, "bwrap is gone"), subprocess.TimeoutExpired(["bwrap"], 20)],
    ids=["oserror", "timeout"],
)
def test_a_cache_overlay_probe_that_raises_mounts_the_cache_read_only(
    layout, monkeypatch, raised
):
    """The probe of a cache's filesystem cannot run, or does not finish.

    The answer is the one a refusal gives: the cache is mounted read-only and a
    tool that writes one gets a private directory; the spawn is not refused, and
    the filesystem is not probed again on the next plan.
    """
    cache = layout.tmp / "cache"
    cache.mkdir()
    probes = []

    def probe_run(argv, env=None):
        probes.append(list(argv))
        if "--overlay-src" in argv:
            raise raised
        return None

    monkeypatch.setattr(backends, "_probe_run", probe_run)
    monkeypatch.setattr(backends, "_true", lambda: "/fake/true")
    policy = _policy(layout, cache=(cache,), cache_env=("UV_CACHE_DIR",))
    backend = _bwrap(overlay=True)

    for _ in range(2):
        plan = backend.plan(["/bin/true"], {}, policy)
        try:
            assert "--overlay-src" not in plan.argv
            assert _real(cache) in _mounts(plan.argv, "--ro-bind")
            assert Path(plan.env["UV_CACHE_DIR"]).is_dir()
        finally:
            plan.run_cleanup()
    assert len([p for p in probes if "--overlay-src" in p]) == 1


def test_concurrent_plans_probe_a_filesystem_once(layout, monkeypatch):
    """Two scanner threads meeting the same filesystem share one probe and one answer.

    The first worker is held inside the probe; the second is released only once
    it has looked the filesystem up in the record (or, under the lock, has been
    waiting for it for a second), so without the lock the second look-up always
    finds the record empty and probes again.
    """
    cache = layout.tmp / "cache"
    cache.mkdir()
    entered = threading.Event()
    looked_up_twice = threading.Event()
    release = threading.Event()
    probes = []

    class Watched(dict):
        looks = 0

        def __contains__(self, key):
            Watched.looks += 1
            if Watched.looks >= 2:
                looked_up_twice.set()
            return super().__contains__(key)

    def probe_run(argv, env=None):
        probes.append(list(argv))
        entered.set()
        assert release.wait(5)
        return "exit 1: refused"

    monkeypatch.setattr(backends, "_probe_run", probe_run)
    monkeypatch.setattr(backends, "_true", lambda: "/fake/true")
    backend = _bwrap(overlay=True)
    backend._overlay_devices = Watched()
    answers = []
    workers = [
        threading.Thread(target=lambda: answers.append(backend._overlay_over(cache)))
        for _ in range(2)
    ]
    workers[0].start()
    assert entered.wait(5)
    workers[1].start()
    # Without the lock this returns at once with the second look-up made; with it
    # the second worker waits at the lock and the second has not happened yet.
    looked_up_twice.wait(1)
    release.set()
    for worker in workers:
        worker.join(5)

    assert answers == [False, False]
    assert len(probes) == 1


@POSIX
def test_a_root_read_path_hides_no_link(layout, monkeypatch):
    # No shared temp directory stands in for the missing bind: on a runner whose
    # temporary directory is /tmp, a tmpfs over /tmp covered the link more closely
    # than a bind of "/" and had it recreated with or without the fix.
    monkeypatch.setattr(backends, "_SHARED_TMPFS", ())
    real = layout.tmp / "real"
    (real / "out").mkdir(parents=True)
    alias = layout.tmp / "alias"
    alias.symlink_to(real, target_is_directory=True)
    policy = _policy(
        layout, read_only=(Path("/"), layout.system), writable=(alias / "out",)
    )

    links = _symlinks(_bwrap().plan(["/bin/true"], {}, policy).argv)

    assert _real(layout.tmp) / "alias" in links


@POSIX
def test_a_link_whose_target_passes_through_another_link_is_recreated(layout):
    real = layout.tmp / "real"
    (real / "out").mkdir(parents=True)
    (layout.tmp / "b").symlink_to(real, target_is_directory=True)
    (layout.tmp / "a").symlink_to(layout.tmp / "b", target_is_directory=True)
    policy = _policy(layout, writable=(layout.tmp / "a" / "out",))

    links = _symlinks(_bwrap().plan(["/bin/true"], {}, policy).argv)

    assert _real(layout.tmp) / "a" in links
    assert _real(layout.tmp) / "b" in links, links


@POSIX
def test_a_link_covered_by_an_unread_tmpfs_is_recreated_in_it(layout):
    root = layout.tmp / "root"
    tree = root / "tree"
    (tree / "realdir" / "wd").mkdir(parents=True)
    (tree / "link").symlink_to(tree / "realdir", target_is_directory=True)
    (root / "other").mkdir()
    (root / "otherlink").symlink_to(root / "other", target_is_directory=True)
    policy = _policy(
        layout,
        read_only=(root, root / "otherlink"),
        unread=(tree,),
        cwd=tree / "link" / "wd",
    )

    argv = _bwrap().plan(["/bin/true"], {}, policy).argv
    links = _symlinks(argv)

    assert _real(tree) in _mounts(argv, "--tmpfs")
    assert _real(tree) / "link" in links, links
    # A link the bind of root already shows is left to it.
    assert _real(root) / "otherlink" not in links


@POSIX
def test_no_link_is_recreated_over_a_shared_tmpfs(layout, monkeypatch):
    realtmp = layout.tmp / "realtmp"
    (realtmp / "out").mkdir(parents=True)
    tmplink = layout.tmp / "tmplink"
    tmplink.symlink_to(realtmp, target_is_directory=True)
    monkeypatch.setattr(backends, "_SHARED_TMPFS", (tmplink,))
    policy = _policy(layout, writable=(tmplink / "out",))

    argv = _bwrap().plan(["/bin/true"], {}, policy).argv

    assert tmplink in _mounts(argv, "--tmpfs")
    assert _real(layout.tmp) / "tmplink" not in _symlinks(argv)


def test_an_unread_directory_inside_an_unshown_one_gets_its_own_tmpfs(layout):
    root = layout.tmp / "root"
    (root / "sub" / "x").mkdir(parents=True)
    policy = _policy(
        layout, read_only=(root / "sub",), unread=(root, root / "sub" / "x")
    )

    tmpfs = _mounts(_bwrap().plan(["/bin/true"], {}, policy).argv, "--tmpfs")

    assert _real(root / "sub" / "x") in tmpfs
    assert _real(root) not in tmpfs


def test_a_home_missing_under_a_read_only_bind_gets_no_tmpfs(layout):
    missing = layout.system / "home"
    policy = _policy(layout, home=missing)
    assert _real(missing) not in _mounts(
        _bwrap().plan(["/bin/true"], {}, policy).argv, "--tmpfs"
    )
    # The control: a home that exists is hidden as always.
    assert _real(layout.home) in _mounts(
        _bwrap().plan(["/bin/true"], {}, _policy(layout)).argv, "--tmpfs"
    )


def test_the_passwd_home_gets_a_tmpfs_too(layout, monkeypatch):
    passwd = layout.tmp / "passwd-home"
    passwd.mkdir()
    for module in (policy_module, backends):
        monkeypatch.setattr(module, "_passwd_home", lambda: passwd, raising=False)

    tmpfs = _mounts(_bwrap().plan(["/bin/true"], {}, _policy(layout)).argv, "--tmpfs")

    assert _real(passwd) in tmpfs
    assert _real(layout.home) in tmpfs


def test_a_root_home_gets_no_tmpfs(layout):
    tmpfs = _mounts(
        _bwrap().plan(["/bin/true"], {}, _policy(layout, home=Path("/"))).argv,
        "--tmpfs",
    )
    assert Path("/") not in tmpfs


def _option_at(argv, flag, path):
    """The position of ``flag`` followed by ``path`` among the options of a plan."""
    return next(
        i for i, a in enumerate(argv) if a == flag and argv[i + 1] == path.as_posix()
    )


def test_bwrap_binds_the_uv_tool_lock_read_write(layout):
    """The lock is inside the read-only tools directory, the case the grant is for:
    its bind comes after the directory's, or the directory's would cover the lock
    and uv would get EROFS."""
    lock = layout.tmp / "tools" / ".lock"
    lock.parent.mkdir()
    lock.write_text("")
    policy = _policy(
        layout, read_only=(layout.system, lock.parent), uv_tool_locks=(lock,)
    )

    argv = _bwrap().plan(["/bin/true"], {}, policy).argv

    assert _real(lock) in _mounts(argv, "--bind")
    assert _real(lock) not in _mounts(argv, "--ro-bind")
    assert _real(lock.parent) in _mounts(argv, "--ro-bind")
    assert _option_at(argv, "--ro-bind", _real(lock.parent)) < _option_at(
        argv, "--bind", _real(lock)
    )


@POSIX
def test_the_resolver_file_is_bound_not_its_directory(layout, monkeypatch):
    (layout.tmp / "run" / "resolve").mkdir(parents=True)
    stub = layout.tmp / "run" / "resolve" / "stub-resolv.conf"
    stub.write_text("nameserver 127.0.0.53\n")
    (layout.tmp / "etc").mkdir()
    conf = layout.tmp / "etc" / "resolv.conf"
    conf.symlink_to(Path("..") / "run" / "resolve" / "stub-resolv.conf")
    monkeypatch.setattr(backends, "_RESOLV_CONF", conf)

    argv = _bwrap().plan(["/bin/true"], {}, _policy(layout, network=True)).argv

    binds = _mounts(argv, "--ro-bind")
    assert _real(stub) in binds
    assert _real(stub).parent not in binds


# ---------------------------------------------------------------------------
# firejail
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="firejail's plan reads os.getuid()")
def test_a_passwd_home_of_root_names_no_home_for_firejail(layout, monkeypatch):
    for module in (policy_module, backends):
        monkeypatch.setattr(module, "_passwd_home", lambda: Path("/"), raising=False)
    backend = FirejailBackend()
    backend._executable = "/fj"

    argv = backend.plan(["/bin/true"], {}, _policy(layout)).argv

    # Nothing is whitelisted against the root, --private is not asked of a home
    # firejail cannot make private, and HOME's directory, which firejail does not
    # treat as the home, is hidden the way a HOME beside the passwd home is.
    assert "--private" not in argv
    assert not [a for a in argv if a.startswith("--whitelist=")], argv
    assert f"--blacklist={_real(layout.home).as_posix()}" in argv, argv


@pytest.mark.skipif(os.name == "nt", reason="firejail's plan reads os.getuid()")
def test_firejail_hides_a_sibling_whose_name_it_would_read_as_a_pattern(layout):
    """A name among the user's own files is hidden, with ``?`` for the odd character.

    ~/.local links to a directory elsewhere; the policy grants a tool inside it, so
    the siblings beside the way to the tool are blacklisted. One of them is named
    ``notes~``: a blacklist that hides more than it is the safe direction, so the
    spawn is not refused, and the value matches the name.
    """
    persist = layout.tmp / "persist" / "local"
    (persist / "tool" / "bin").mkdir(parents=True)
    (persist / "notes~").mkdir()
    (layout.home / ".local").symlink_to(persist, target_is_directory=True)
    backend = FirejailBackend()
    backend._executable = "/fj"

    argv = backend.plan(
        ["/bin/true"], {}, _policy(layout, read_only=(layout.system, persist / "tool"))
    ).argv

    assert f"--blacklist={_real(persist).as_posix()}/notes?" in argv, argv
    assert not [a for a in argv if "~" in a and a.startswith("--blacklist=")], argv


@pytest.mark.skipif(os.name == "nt", reason="firejail's plan reads os.getuid()")
def test_firejail_refuses_a_hidden_pattern_that_would_also_hide_a_granted_path(
    layout,
):
    """``too~`` beside the granted ``tool`` would become ``too?``, which hides the tool.

    firejail expands the blacklist with glob(3), where ``?`` matches exactly one
    character, so the substituted value matches the granted path too and the scanner
    could not start. The plan is refused, naming both paths, instead.
    """
    persist = layout.tmp / "persist" / "local"
    (persist / "tool" / "bin").mkdir(parents=True)
    (persist / "too~").mkdir()
    (layout.home / ".local").symlink_to(persist, target_is_directory=True)
    backend = FirejailBackend()
    backend._executable = "/fj"

    with pytest.raises(SandboxUnavailable, match="too") as refused:
        backend.plan(
            ["/bin/true"],
            {},
            _policy(layout, read_only=(layout.system, persist / "tool")),
        )
    assert _real(persist / "tool").as_posix() in str(refused.value)


@pytest.mark.skipif(os.name == "nt", reason="firejail's plan reads os.getuid()")
@pytest.mark.parametrize("needed", ["cwd", "program"])
def test_firejail_refuses_a_hidden_pattern_that_would_hide_the_cwd_or_program(
    layout, needed
):
    """The working directory and the program are needed as the policy's paths are.

    HOME names ``wor~``, a directory firejail does not treat as the home, so it is
    blacklisted; spelled ``wor?`` the value also matches ``work`` beside it, which is
    the scan's working directory, or holds its program. Neither is in the policy's
    read paths here, and the plan is refused all the same, naming the matched path.
    """
    odd_home = layout.tmp / "wor~"
    odd_home.mkdir()
    work = layout.tmp / "work"
    (work / "bin").mkdir(parents=True)
    program = work / "bin" / "scan"
    program.write_bytes(b"\x7fELF")
    program.chmod(0o755)
    backend = FirejailBackend()
    backend._executable = "/fj"
    if needed == "cwd":
        argv, policy = ["/bin/true"], _policy(layout, home=odd_home, cwd=work)
    else:
        argv, policy = [program.as_posix()], _policy(layout, home=odd_home)

    with pytest.raises(SandboxUnavailable, match="wor") as refused:
        backend.plan(argv, {}, policy)
    assert _real(work).as_posix() in str(refused.value)


@pytest.mark.skipif(os.name == "nt", reason="firejail's plan reads os.getuid()")
def test_firejail_refuses_a_path_it_would_read_as_a_pattern(layout):
    odd = layout.tmp / "out[1]"
    odd.mkdir()
    backend = FirejailBackend()
    backend._executable = "/fj"
    with pytest.raises(SandboxUnavailable, match="pattern") as refused:
        backend.plan(["/bin/true"], {}, _policy(layout, writable=(odd,)))
    # The characters are listed as the operator would type them: only the first
    # piece of the message is an f-string, so a doubled brace in a later piece
    # would be printed doubled.
    assert "*, ?, [, ], {, }, ~ and $" in str(refused.value)
    assert "}}" not in str(refused.value)


@pytest.mark.skipif(os.name == "nt", reason="firejail's plan reads os.getuid()")
def test_firejail_grants_the_uv_tool_lock(layout):
    """The lock is inside the read-only tools directory, the case the grant is for:
    the read-write option comes after the directory's read-only one, or firejail
    would make the lock read-only again."""
    lock = layout.tmp / "tools" / ".lock"
    lock.parent.mkdir()
    lock.write_text("")
    backend = FirejailBackend()
    backend._executable = "/fj"
    policy = _policy(
        layout, read_only=(layout.system, lock.parent), uv_tool_locks=(lock,)
    )

    argv = backend.plan(["/bin/true"], {}, policy).argv

    assert f"--read-write={_real(lock).as_posix()}" in argv
    assert argv.index(f"--read-only={_real(lock.parent).as_posix()}") < argv.index(
        f"--read-write={_real(lock).as_posix()}"
    )


# ---------------------------------------------------------------------------
# Landlock
# ---------------------------------------------------------------------------


def _landlock_document(plan) -> dict:
    return json.loads(plan.argv[plan.argv.index("--policy") + 1])


@POSIX
def test_a_landlock_plan_that_raises_leaves_no_private_root(layout, monkeypatch):
    scratch = layout.tmp / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))

    def raising(private_home, policy):
        raise OSError("cannot link")

    monkeypatch.setattr(backends, "_link_policy_paths_into", raising)

    with pytest.raises(OSError, match="cannot link"):
        LandlockBackend().plan(["/bin/true"], {}, _policy(layout))

    assert list(scratch.iterdir()) == []


@POSIX
def test_landlock_grants_a_read_path_outside_executable_read_without_exec(
    layout, monkeypatch
):
    """The backend reads ``read_only`` and ``executable``: a read path that is not
    executable (the scanned tree) is granted read alone, whatever ``scan_data``
    says, so the policy here does not set it."""
    monkeypatch.setattr(tempfile, "tempdir", str(layout.tmp))
    source = layout.tmp / "src"
    source.mkdir()
    lock = layout.tmp / "tools" / ".lock"
    lock.parent.mkdir()
    lock.write_text("")
    policy = _policy(
        layout,
        read_only=(layout.system, source),
        executable=(layout.system,),
        uv_tool_locks=(lock,),
    )

    plan = LandlockBackend().plan(["/bin/true"], {}, policy)
    try:
        document = _landlock_document(plan)
        assert _real(source).as_posix() in document["read_data"]
        assert _real(source).as_posix() not in document["read_only"]
        assert _real(layout.system).as_posix() in document["read_only"]
        assert _real(lock).as_posix() in document["writable"]
        assert document["cwd"] == plan.env["TMPDIR"]
    finally:
        plan.run_cleanup()


@POSIX
def test_landlock_data_under_an_executable_root_stays_executable_through_it(
    layout, monkeypatch
):
    """The limit the plan's comment names: rules add up, so a read path inside a
    path granted read and exec is read-only in its own rule and executable through
    the root's. A path under no executable root (the control) is not."""
    monkeypatch.setattr(tempfile, "tempdir", str(layout.tmp))
    nested = layout.system / "src"
    nested.mkdir()
    apart = layout.tmp / "apart"
    apart.mkdir()
    policy = _policy(
        layout,
        read_only=(layout.system, nested, apart),
        executable=(layout.system,),
    )

    plan = LandlockBackend().plan(["/bin/true"], {}, policy)
    try:
        document = _landlock_document(plan)
    finally:
        plan.run_cleanup()

    read_and_run = [Path(p) for p in document["read_only"]]
    for data in (nested, apart):
        assert _real(data).as_posix() in document["read_data"]
        assert _real(data).as_posix() not in document["read_only"]
    assert any(_real(nested).is_relative_to(p) for p in read_and_run)
    assert not any(_real(apart).is_relative_to(p) for p in read_and_run)


@POSIX
def test_landlock_grants_exec_on_the_policys_executable_paths_as_listed(
    layout, monkeypatch
):
    """An executable path the policy lists outside its read paths is still granted.

    build_scanner_policy draws ``executable`` from ``read_only``, so for its
    policies the two readings agree; a policy built by hand with a tool prefix in
    ``executable`` alone used to get no grant for it at all.
    """
    monkeypatch.setattr(tempfile, "tempdir", str(layout.tmp))
    tool = layout.tmp / "opt" / "tool"
    tool.mkdir(parents=True)
    policy = _policy(layout, read_only=(layout.system,), executable=(tool,))

    plan = LandlockBackend().plan(["/bin/true"], {}, policy)
    try:
        document = _landlock_document(plan)
        assert _real(tool).as_posix() in document["read_only"]
        assert _real(tool).as_posix() not in document["read_data"]
        assert _real(layout.system).as_posix() in document["read_data"]
    finally:
        plan.run_cleanup()


@POSIX
def test_landlock_links_nothing_into_the_private_home_for_a_root_home(
    layout, monkeypatch
):
    monkeypatch.setattr(tempfile, "tempdir", str(layout.tmp))
    plan = LandlockBackend().plan(["/bin/true"], {}, _policy(layout, home=Path("/")))
    try:
        assert list(Path(plan.env["HOME"]).iterdir()) == []
    finally:
        plan.run_cleanup()


# ---------------------------------------------------------------------------
# sandbox-exec
# ---------------------------------------------------------------------------


def _profile(layout, policy) -> str:
    return SandboxExecBackend().profile(policy, layout.tmp / "private-tmp")


def test_a_root_home_denies_nothing_under_sandbox_exec(layout):
    profile = _profile(layout, _policy(layout, home=Path("/")))
    assert '(deny file-read* (subpath "/"))' not in profile
    # The control: a real home is denied.
    assert f'(deny file-read* (subpath "{_real(layout.home).as_posix()}"))' in _profile(
        layout, _policy(layout)
    )


def test_the_profile_denies_the_third_shared_temp_directory_and_names_shm(layout):
    profile = _profile(layout, _policy(layout))
    assert '(subpath "/private/var/tmp")' in profile
    assert "(allow ipc-posix-shm)" not in profile
    assert "ipc-posix-name-regex" in profile
    assert "apple.shm.notification_center" in profile


def _last_exec_rule(lines, path):
    """The last process-exec rule whose subpaths or literals cover ``path``: in SBPL
    the last matching rule decides."""
    covering = [
        line
        for line in lines
        if line.startswith(("(allow process-exec", "(deny process-exec"))
        and (
            any(
                path == Path(subpath) or Path(subpath) in path.parents
                for subpath in re.findall(r'\(subpath "([^"]*)"\)', line)
            )
            or any(
                path == Path(literal)
                for literal in re.findall(r'\(literal "([^"]*)"\)', line)
            )
        )
    ]
    return covering[-1]


def test_the_uv_tool_lock_is_writable_but_not_executable(layout):
    """The lock sits inside an executable tools directory, so an allow covers it;
    the rule that decides, the last one covering the lock, is the deny."""
    lock = layout.tmp / "tools" / ".lock"
    lock.parent.mkdir()
    lock.write_text("")
    policy = _policy(
        layout,
        read_only=(layout.system, lock.parent),
        executable=(lock.parent,),
        uv_tool_locks=(lock,),
    )
    lines = _profile(layout, policy).splitlines()
    literal = f'(literal "{_real(lock).as_posix()}")'
    allowed = [
        line
        for line in lines
        if line.startswith("(allow process-exec")
        and f'(subpath "{_real(lock.parent).as_posix()}")' in line
    ]
    assert allowed, lines
    deciding = _last_exec_rule(lines, _real(lock))
    assert deciding.startswith("(deny process-exec") and literal in deciding, lines
    assert any(
        line.startswith("(allow file-read* file-write*") and literal in line
        for line in lines
    )


def test_an_operators_ssl_cert_file_is_readable(layout, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(layout.tmp))
    pem = layout.home / "certs.pem"
    pem.write_text("")
    # The operator's value is the one ASH started with.
    monkeypatch.setattr(
        backends, "startup_environ", lambda: {"SSL_CERT_FILE": str(pem)}
    )
    policy = _policy(layout, system_trust_roots=True)

    plan = SandboxExecBackend().plan(["/bin/true"], {"SSL_CERT_FILE": str(pem)}, policy)
    try:
        profile = plan.argv[plan.argv.index("-p") + 1]
        assert plan.env["SSL_CERT_FILE"] == str(pem)
        assert f'(allow file-read* (literal "{_real(pem).as_posix()}"))' in profile
    finally:
        plan.run_cleanup()


def test_an_ssl_cert_file_set_after_startup_opens_nothing(layout, monkeypatch):
    """A value in the live environment that ASH did not start with is a scanner
    thread's (set while others spawn), not the operator's: passed through, with
    no read granted for it."""
    monkeypatch.setattr(tempfile, "tempdir", str(layout.tmp))
    pem = layout.home / "certs.pem"
    pem.write_text("")
    monkeypatch.setenv("SSL_CERT_FILE", str(pem))
    # The condition, stated outright: ASH started with no SSL_CERT_FILE. The plan
    # compares the spawn's value with this snapshot and never reads os.environ, so
    # the setenv above is only the live value a scanner thread would have set.
    monkeypatch.setattr(backends, "startup_environ", dict)
    policy = _policy(layout, system_trust_roots=True)

    plan = SandboxExecBackend().plan(["/bin/true"], {"SSL_CERT_FILE": str(pem)}, policy)
    try:
        profile = plan.argv[plan.argv.index("-p") + 1]
        assert plan.env["SSL_CERT_FILE"] == str(pem)
        assert f'(allow file-read* (literal "{_real(pem).as_posix()}"))' not in profile
    finally:
        plan.run_cleanup()


def test_an_ssl_cert_file_that_is_not_the_operators_opens_nothing(layout, monkeypatch):
    """A value the spawn's environment carries from elsewhere is passed through,
    and the profile grants no read for it where it denies reads."""
    monkeypatch.setattr(tempfile, "tempdir", str(layout.tmp))
    pem = layout.home / ".ssh" / "id_rsa"
    pem.parent.mkdir()
    pem.write_text("")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    policy = _policy(layout, system_trust_roots=True)

    plan = SandboxExecBackend().plan(["/bin/true"], {"SSL_CERT_FILE": str(pem)}, policy)
    try:
        profile = plan.argv[plan.argv.index("-p") + 1]
        assert plan.env["SSL_CERT_FILE"] == str(pem)
        assert f'(allow file-read* (literal "{_real(pem).as_posix()}"))' not in profile
    finally:
        plan.run_cleanup()


def test_a_refused_profile_leaves_no_temp_directory(layout, monkeypatch):
    scratch = layout.tmp / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))

    def refusing(self, *args, **kwargs):
        raise SandboxUnavailable("cannot express the profile")

    monkeypatch.setattr(SandboxExecBackend, "profile", refusing)

    with pytest.raises(SandboxUnavailable):
        SandboxExecBackend().plan(["/bin/true"], {}, _policy(layout))

    assert list(scratch.iterdir()) == []


def test_a_refused_profile_leaves_no_cache_roots_or_unpack_directory(
    layout, monkeypatch
):
    """The plan makes four directories before the profile is built: the private
    TMPDIR, the private cache under the results directory, the one that holds the
    system trust roots and the unpack directory. A profile that is refused leaves
    none of them, so each is removed through the one cleanup list the plan fills in
    place."""
    scratch = layout.tmp / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    monkeypatch.setattr(backends, "_system_trust_roots", lambda: "BEGIN CERTIFICATE\n")

    def refusing(self, *args, **kwargs):
        raise SandboxUnavailable("cannot express the profile")

    monkeypatch.setattr(SandboxExecBackend, "profile", refusing)
    policy = _policy(
        layout,
        cache_env=("UV_CACHE_DIR",),
        unpack_dir_env="UNPACK_DIR",
        system_trust_roots=True,
    )

    with pytest.raises(SandboxUnavailable):
        SandboxExecBackend().plan(["/bin/true"], {}, policy)

    assert list(scratch.iterdir()) == []
    assert list(layout.results.iterdir()) == []


# ---------------------------------------------------------------------------
# the environment list and the CA-bundle settings
# ---------------------------------------------------------------------------

_BACKEND_KINDS = ["bwrap", "firejail", "landlock", "sandbox-exec"]
_PROXY_NAMES = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
}
_CA_FILE_NAMES = (
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
)
_CA_NAMES = {*_CA_FILE_NAMES, "SSL_CERT_DIR"}


def _plan_of(kind, layout, monkeypatch, policy, env):
    """One backend's plan for ``policy`` and ``env``, built without starting anything.

    The caller runs the plan's cleanup. Landlock and sandbox-exec make their private
    directories under the layout's temporary directory.
    """
    monkeypatch.setattr(tempfile, "tempdir", str(layout.tmp))
    if kind == "bwrap":
        return _bwrap().plan(["/bin/true"], env, policy)
    if kind == "firejail":
        backend = FirejailBackend()
        backend._executable = "/fj"
        return backend.plan(["/bin/true"], env, policy)
    if kind == "landlock":
        return LandlockBackend().plan(["/bin/true"], env, policy)
    return SandboxExecBackend().plan(["/bin/true"], env, policy)


def _read_grants(kind, plan) -> set:
    """Every path a plan lists as readable, resolved, as text."""
    if kind == "bwrap":
        return {path.as_posix() for path in _mounts(plan.argv, "--ro-bind")}
    if kind == "firejail":
        return {
            arg.split("=", 1)[1] for arg in plan.argv if arg.startswith("--read-only=")
        }
    if kind == "landlock":
        document = _landlock_document(plan)
        return set(document["read_only"]) | set(document["read_data"])
    profile = plan.argv[plan.argv.index("-p") + 1]
    return {
        found
        for line in profile.splitlines()
        if line.startswith("(allow file-read*")
        for found in re.findall(r'\((?:literal|subpath) "([^"]*)"\)', line)
    }


def _granted_for(kind, layout, monkeypatch, policy, env) -> set:
    plan = _plan_of(kind, layout, monkeypatch, policy, env)
    try:
        return _read_grants(kind, plan)
    finally:
        plan.run_cleanup()


@POSIX
@pytest.mark.parametrize("kind", _BACKEND_KINDS)
def test_every_backend_reads_back_what_the_operators_ca_settings_name(
    layout, monkeypatch, kind
):
    """A bundle kept under the home is readable on bwrap, firejail and Landlock too.

    Only sandbox-exec granted the operator's SSL_CERT_FILE, and no backend granted
    the others, so under the three that hide the home a bundle there was passed
    through and unreadable. The settings are the operator's: the values ASH started
    with. SSL_CERT_DIR holds two directories joined with the path separator.
    """
    env = {}
    files = []
    for name in _CA_FILE_NAMES:
        bundle = layout.home / f"{name.lower()}.pem"
        bundle.write_text("")
        env[name] = str(bundle)
        files.append(bundle)
    first, second = layout.home / "certs-a", layout.home / "certs-b"
    first.mkdir()
    second.mkdir()
    env["SSL_CERT_DIR"] = os.pathsep.join([str(first), str(second)])
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))

    granted = _granted_for(
        kind, layout, monkeypatch, _policy(layout, network=True), env
    )

    for path in (*files, first, second):
        assert _real(path).as_posix() in granted, (kind, path.name)


@POSIX
@pytest.mark.parametrize("kind", _BACKEND_KINDS)
def test_a_ca_value_that_is_not_the_operators_opens_nothing(layout, monkeypatch, kind):
    """The control of the test above: the same variables, a value ASH did not start
    with (a scanner thread's), are passed through and open nothing."""
    secret = layout.home / ".ssh" / "id_rsa"
    secret.parent.mkdir()
    secret.write_text("")
    monkeypatch.setattr(backends, "startup_environ", dict)
    env = {name: str(secret) for name in _CA_FILE_NAMES}

    plan = _plan_of(kind, layout, monkeypatch, _policy(layout, network=True), env)
    try:
        assert plan.env["REQUESTS_CA_BUNDLE"] == str(secret)
        assert _real(secret).as_posix() not in _read_grants(kind, plan)
    finally:
        plan.run_cleanup()


@POSIX
@pytest.mark.parametrize("kind", _BACKEND_KINDS)
def test_a_scanner_with_no_network_is_granted_no_ca_read(layout, monkeypatch, kind):
    """A trust root is read to verify a TLS peer, and a scanner with no network never
    reaches one, so the grant would only widen what it can read. The settings are
    still passed through as listed; the same settings give a scanner with a network
    the reads.

    ``SSL_CERT_FILE`` is not among the names here: sandbox-exec has a rule of its own
    for it, outside the grant this test covers."""
    bundle = layout.home / "corp.pem"
    bundle.write_text("")
    certs = layout.home / "certs"
    certs.mkdir()
    env = {"REQUESTS_CA_BUNDLE": str(bundle), "SSL_CERT_DIR": str(certs)}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))

    plan = _plan_of(kind, layout, monkeypatch, _policy(layout), env)
    try:
        offline = _read_grants(kind, plan)
        assert plan.env["REQUESTS_CA_BUNDLE"] == str(bundle)
        assert plan.env["SSL_CERT_DIR"] == str(certs)
    finally:
        plan.run_cleanup()
    online = _granted_for(kind, layout, monkeypatch, _policy(layout, network=True), env)

    for path in (bundle, certs):
        assert _real(path).as_posix() not in offline, (kind, path.name)
        assert _real(path).as_posix() in online, (kind, path.name)


@POSIX
@pytest.mark.parametrize("kind", _BACKEND_KINDS)
def test_a_ca_directory_that_holds_a_home_is_not_granted(
    layout, monkeypatch, caplog, kind
):
    """SSL_CERT_DIR naming a directory above the home would show the whole home."""
    env = {"SSL_CERT_DIR": str(layout.tmp)}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))
    monkeypatch.setattr(backends, "_ca_unspelled_warned", set())

    with caplog.at_level(logging.WARNING, logger="ash"):
        granted = _granted_for(
            kind, layout, monkeypatch, _policy(layout, network=True), env
        )

    assert _real(layout.tmp).as_posix() not in granted
    assert any(
        "SSL_CERT_DIR" in record.getMessage() and "expose" in record.getMessage()
        for record in caplog.records
    ), [record.getMessage() for record in caplog.records]


@POSIX
def test_a_ca_directory_that_holds_a_home_is_warned_of_once(
    layout, monkeypatch, caplog
):
    """Every scanner spawn plans again; the warning is for the first of them."""
    env = {"SSL_CERT_DIR": str(layout.tmp)}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))
    monkeypatch.setattr(backends, "_ca_unspelled_warned", set())

    with caplog.at_level(logging.WARNING, logger="ash"):
        for _ in range(3):
            _granted_for(
                "bwrap", layout, monkeypatch, _policy(layout, network=True), env
            )

    warned = [
        record
        for record in caplog.records
        if "SSL_CERT_DIR" in record.getMessage() and "expose" in record.getMessage()
    ]
    assert len(warned) == 1, [record.getMessage() for record in caplog.records]


@POSIX
def test_a_visible_ca_directory_that_holds_a_home_is_not_warned_of(
    layout, monkeypatch, caplog
):
    """A directory the policy shows already is readable even when a home sits under
    it (``/opt``, with a ``HOME`` below), so a warning that it is not readable would
    be false. The same directory with nothing showing it keeps the warning."""
    env = {"SSL_CERT_DIR": str(layout.tmp)}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))
    monkeypatch.setattr(backends, "_ca_unspelled_warned", set())
    shown = _policy(layout, network=True, read_only=(layout.system, layout.tmp))
    hidden = _policy(layout, network=True)

    def warnings():
        return [
            record.getMessage()
            for record in caplog.records
            if "SSL_CERT_DIR" in record.getMessage()
        ]

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert backends._operator_ca_reads(shown, env) == []
    assert warnings() == [], warnings()

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert backends._operator_ca_reads(hidden, env) == []
    assert len(warnings()) == 1, warnings()
    assert "expose" in warnings()[0]


@POSIX
@pytest.mark.parametrize("kind", _BACKEND_KINDS)
def test_a_ca_path_that_cannot_be_examined_is_passed_on_and_fails_no_plan(
    layout, monkeypatch, kind
):
    """A bundle below a directory this user cannot search opens nothing and breaks nothing.

    Python 3.10 to 3.12 raise PermissionError from Path.is_file and Path.is_dir for
    such a path. The grant is a convenience, so the plan must not fail over it: the
    setting is passed through as it was before the grant existed. Here both methods
    refuse the two paths as the older pathlib does, and os.stat refuses them as the
    kernel does, so the answer left is the one os.path gives.
    """
    bundle = layout.home / "private" / "corp.pem"
    bundle.parent.mkdir()
    bundle.write_text("")
    certs = layout.home / "private-certs"
    certs.mkdir()
    refused = {_real(bundle), _real(certs)}
    env = {"SSL_CERT_FILE": str(bundle), "SSL_CERT_DIR": str(certs)}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))
    for method in ("is_file", "is_dir"):
        original = getattr(Path, method)

        def refusing(self, *args, _original=original, **kwargs):
            if self in refused:
                raise PermissionError(13, "Permission denied", str(self))
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(Path, method, refusing)
    real_stat = os.stat

    def stat(path, *args, **kwargs):
        if not isinstance(path, int) and Path(os.fsdecode(path)) in refused:
            raise PermissionError(13, "Permission denied", os.fsdecode(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat)

    plan = _plan_of(kind, layout, monkeypatch, _policy(layout, network=True), env)
    try:
        assert plan.env["SSL_CERT_FILE"] == str(bundle)
        assert plan.env["SSL_CERT_DIR"] == str(certs)
        granted = _read_grants(kind, plan)
        assert not {_real(bundle).as_posix(), _real(certs).as_posix()} & granted
    finally:
        plan.run_cleanup()


@POSIX
@pytest.mark.parametrize(
    ("kind", "odd_name"),
    [("firejail", "certs~old"), ("sandbox-exec", "certs\x01old")],
)
def test_a_ca_entry_the_backend_cannot_spell_is_left_out_not_refused(
    layout, monkeypatch, caplog, kind, odd_name
):
    """One entry firejail or sandbox-exec cannot write must not refuse every spawn.

    firejail reads ``~`` in a path option as a macro and sandbox-exec cannot write a
    control character in a profile; both refused the whole plan for the grant of
    such a directory in SSL_CERT_DIR, where the bundle used to be passed through
    unreadable. The entry is left out with a warning, once, the setting still
    reaches the scanner as written, and the other entry is still granted.
    """
    odd, fine = layout.home / odd_name, layout.home / "certs-fine"
    odd.mkdir()
    fine.mkdir()
    value = os.pathsep.join([str(odd), str(fine)])
    env = {"SSL_CERT_DIR": value}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))
    monkeypatch.setattr(backends, "_ca_unspelled_warned", set())

    with caplog.at_level(logging.WARNING, logger="ash"):
        for _ in range(2):
            plan = _plan_of(
                kind, layout, monkeypatch, _policy(layout, network=True), env
            )
            try:
                assert plan.env["SSL_CERT_DIR"] == value
                granted = _read_grants(kind, plan)
            finally:
                plan.run_cleanup()
            assert _real(fine).as_posix() in granted
            assert _real(odd).as_posix() not in granted

    warnings = [
        record.getMessage()
        for record in caplog.records
        if "SSL_CERT_DIR" in record.getMessage()
        and "not readable" in record.getMessage()
    ]
    assert len(warnings) == 1, warnings


def _linked_bundle(layout, directory):
    """A CA bundle in the shown system directory, linked to from ``directory``.

    Returns (the link as the operator would write it, the file it names).
    """
    target = layout.system / "corp.pem"
    target.write_text("")
    link = directory / "ca.pem"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    return link, target


@POSIX
def test_bwrap_recreates_a_ca_link_nested_under_the_home(layout, monkeypatch):
    """A link below the hidden home to a file the policy shows is written inside.

    ``SSL_CERT_FILE=~/.config/corp/ca.pem`` pointing into a read-only system path:
    the file is visible, so the grant used to end there, and nothing wrote the
    link into the sandbox's private home. The scanner's open of the written path
    failed with ENOENT as it did before the CA settings were granted at all.
    """
    link, target = _linked_bundle(layout, layout.home / ".config" / "corp")
    env = {"SSL_CERT_FILE": str(link)}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))

    plan = _plan_of("bwrap", layout, monkeypatch, _policy(layout, network=True), env)
    try:
        assert plan.env["SSL_CERT_FILE"] == str(link)
        assert _symlinks(plan.argv).get(link) == str(target), plan.argv
        assert _real(layout.system) in _mounts(plan.argv, "--ro-bind")
    finally:
        plan.run_cleanup()


@POSIX
def test_a_ca_link_outside_the_home_adds_no_link_and_no_warning(
    layout, monkeypatch, caplog
):
    """The control of the two tests around it: the link sits in a shown directory.

    Nothing hides it, so bwrap writes no link for it and firejail has nothing to
    warn about; the setting is passed through as written.
    """
    link, _ = _linked_bundle(layout, layout.system / "links")
    env = {"SSL_CERT_FILE": str(link)}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))
    monkeypatch.setattr(backends, "_ca_unspelled_warned", set())

    with caplog.at_level(logging.WARNING, logger="ash"):
        for kind in ("bwrap", "firejail"):
            plan = _plan_of(
                kind, layout, monkeypatch, _policy(layout, network=True), env
            )
            try:
                assert plan.env["SSL_CERT_FILE"] == str(link)
                if kind == "bwrap":
                    assert link not in _symlinks(plan.argv), plan.argv
            finally:
                plan.run_cleanup()

    assert not [r for r in caplog.records if "symlink" in r.getMessage()]


@POSIX
def test_firejail_warns_once_of_a_ca_link_it_cannot_show_in_the_home(
    layout, monkeypatch, caplog
):
    """firejail cannot write a link, so the written path stays unreadable: say so.

    The file the link names is still granted, the setting is passed through, and
    the plan does not fail. One warning for the entry, however many spawns.
    """
    link, target = _linked_bundle(layout, layout.home / ".config" / "corp")
    env = {"SSL_CERT_FILE": str(link)}
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))
    monkeypatch.setattr(backends, "_ca_unspelled_warned", set())

    with caplog.at_level(logging.WARNING, logger="ash"):
        for _ in range(2):
            plan = _plan_of(
                "firejail", layout, monkeypatch, _policy(layout, network=True), env
            )
            try:
                assert plan.env["SSL_CERT_FILE"] == str(link)
            finally:
                plan.run_cleanup()

    warnings = [
        record.getMessage()
        for record in caplog.records
        if "SSL_CERT_FILE" in record.getMessage() and "symlink" in record.getMessage()
    ]
    assert len(warnings) == 1, warnings
    assert repr(str(link)) in warnings[0]


def test_the_default_environment_list_is_the_proxy_family_and_the_ca_set(layout):
    """With no list written, exactly these are passed, and nothing else the caller has."""
    expected = _PROXY_NAMES | _CA_NAMES
    assert set(policy_module.DEFAULT_ENVIRONMENT) == expected
    env = dict.fromkeys(expected, "value")
    env.update({"MY_VAR": "mine", "GITHUB_TOKEN": "t", "AWS_REGION": "r"})

    online = _policy(layout, network=True).filter_env(env)
    offline = _policy(layout).filter_env(env)

    assert set(online) == expected | {"HOME"}
    # A proxy setting is passed only to a scanner that has a network.
    assert set(offline) == _CA_NAMES | {"HOME"}


def test_the_baseline_names_the_reference_documents_are_unchanged():
    """The scanner reference is generated from BASE_ENV_NAMES, so moving the CA-bundle
    names into the environment list must leave that set as it was."""
    assert policy_module.BASE_ENV_NAMES == {
        "PATH",
        "LANG",
        "LANGUAGE",
        "TERM",
        "TZ",
        "NO_COLOR",
        "FORCE_COLOR",
        "COLUMNS",
        "VIRTUAL_ENV",
        "JAVA_HOME",
        "GEM_HOME",
        "GEM_PATH",
        "SYSTEMROOT",
        *_CA_NAMES,
    }


def test_a_listed_name_passes_the_callers_value_and_an_entry_with_a_value_sets_one(
    layout,
):
    env = {
        "MY_VAR": "mine",
        "OTHER": "the caller's",
        "HTTP_PROXY": "http://proxy:3128",
        "SSL_CERT_FILE": "/etc/ssl/corp.pem",
        "UNLISTED": "x",
    }
    entries = ("MY_VAR", "OTHER=1", "HTTP_PROXY", "ADDED=2")

    online = _policy(layout, network=True, environment=entries).filter_env(env)
    offline = _policy(layout, environment=entries).filter_env(env)

    home = layout.home.as_posix()
    # The value an entry carries wins over the caller's, and sets a variable the
    # caller does not have; the list replaces the default, so the CA setting the
    # caller has is dropped, and a proxy setting still needs a network.
    assert online == {
        "MY_VAR": "mine",
        "OTHER": "1",
        "HTTP_PROXY": "http://proxy:3128",
        "ADDED": "2",
        "HOME": home,
    }
    assert offline == {"MY_VAR": "mine", "OTHER": "1", "ADDED": "2", "HOME": home}


@pytest.mark.parametrize(
    "entry",
    [
        "HTTPS_PROXY=http://MARKER-user:MARKER-pw@proxy:3128",
        "https_proxy=https://MARKER-user@proxy",
        "MY_TOOL_URL=socks5://MARKER-user:MARKER-pw@host:1080",
    ],
)
def test_an_entry_that_sets_a_url_with_a_user_name_is_refused_not_dropped(
    layout, entry
):
    """``filter_env`` drops such a value from every scanner, so an entry that sets
    one passed validation and did nothing, and a networked scanner failed with a
    connection error that named no cause. It is refused with the variable named; the
    value is never shown."""
    name = entry.partition("=")[0]
    with pytest.raises(ValueError, match=name) as refused:
        policy_module.parse_environment(["MY_VAR", entry])
    assert "MARKER" not in str(refused.value)

    with pytest.raises(SandboxUnavailable, match=name) as unavailable:
        _policy(layout, network=True, environment=("MY_VAR", entry))
    assert "MARKER" not in str(unavailable.value)


def test_control_a_proxy_entry_without_a_user_name_is_accepted_and_passed(layout):
    policy = _policy(
        layout, network=True, environment=("HTTPS_PROXY=http://proxy:3128/a@b",)
    )

    assert policy.filter_env({})["HTTPS_PROXY"] == "http://proxy:3128/a@b"


def test_control_a_listed_name_with_a_user_name_in_the_callers_value_is_dropped(
    layout,
):
    """The caller's own value is not an entry of the list: it is dropped as before,
    and the list that names the variable is not refused for it."""
    policy = _policy(layout, network=True, environment=("HTTPS_PROXY",))

    env = policy.filter_env({"HTTPS_PROXY": "http://MARKER-user:MARKER-pw@proxy:3128"})

    assert "HTTPS_PROXY" not in env


@POSIX
def test_the_four_backends_pass_one_identical_list(layout, monkeypatch):
    env = {
        "MY_VAR": "mine",
        "HTTP_PROXY": "http://proxy:3128",
        "SSL_CERT_FILE": "/etc/ssl/corp.pem",
        "UNLISTED": "x",
    }
    monkeypatch.setattr(backends, "startup_environ", dict)
    policy = _policy(
        layout, network=True, environment=("MY_VAR", "OTHER=1", "HTTP_PROXY")
    )
    names = {"MY_VAR", "OTHER", "HTTP_PROXY", "SSL_CERT_FILE", "UNLISTED"}

    passed = {}
    for kind in _BACKEND_KINDS:
        plan = _plan_of(kind, layout, monkeypatch, policy, env)
        try:
            passed[kind] = {k: v for k, v in plan.env.items() if k in names}
        finally:
            plan.run_cleanup()

    expected = {"MY_VAR": "mine", "OTHER": "1", "HTTP_PROXY": "http://proxy:3128"}
    assert passed == dict.fromkeys(_BACKEND_KINDS, expected)


@pytest.mark.parametrize(
    "entry, name",
    [
        ("GITHUB_TOKEN", "GITHUB_TOKEN"),
        ("DB_PASSWORD=hunter2", "DB_PASSWORD"),
        ("npm_config__authToken", "npm_config__authToken"),
        (OUTER_RUN_ID_ENV, OUTER_RUN_ID_ENV),
    ],
)
def test_a_credential_shaped_name_is_refused_with_its_name_even_when_listed(
    layout, entry, name
):
    with pytest.raises(ValueError) as refused:
        policy_module.parse_environment(["MY_VAR", entry])
    assert name in str(refused.value)
    assert "hunter2" not in str(refused.value)

    with pytest.raises(SandboxUnavailable, match=name):
        _policy(layout, environment=("MY_VAR", entry))


@pytest.mark.parametrize(
    "entry",
    ["", "1BAD", "A B=c", "=value", "TWO=1\x00", "MY_VAR\n", "MY_VAR\n=1"],
)
def test_an_entry_that_is_not_a_variable_is_refused(entry):
    with pytest.raises(ValueError):
        policy_module.parse_environment([entry])


@POSIX
@pytest.mark.parametrize("entry", ["TMPDIR", "TMPDIR=/somewhere"])
@pytest.mark.parametrize("kind", _BACKEND_KINDS)
def test_a_listed_tmpdir_is_refused_so_no_backend_passes_it(
    layout, monkeypatch, kind, entry
):
    """Landlock and sandbox-exec replace TMPDIR with a private directory after the
    list is applied; bwrap and firejail do not, so a listed TMPDIR would have
    reached the scanner under those two. It is refused at the one validator, which
    every backend's policy goes through, and the caller's own TMPDIR is not passed
    by any of the four."""
    with pytest.raises(ValueError, match="TMPDIR"):
        policy_module.parse_environment(["MY_VAR", entry])
    with pytest.raises(SandboxUnavailable, match="TMPDIR"):
        _policy(layout, environment=("MY_VAR", entry))

    plan = _plan_of(kind, layout, monkeypatch, _policy(layout), {"TMPDIR": "/caller"})
    try:
        assert plan.env.get("TMPDIR") != "/caller"
    finally:
        plan.run_cleanup()


@pytest.mark.parametrize("entry", ["TEMP", "TEMP=/somewhere", "TMP", "TMP=/somewhere"])
def test_a_listed_temp_or_tmp_is_refused_like_tmpdir(layout, entry):
    """Python's ``tempfile`` reads TMPDIR, then TEMP, then TMP. bwrap and firejail set
    none, so a listed TEMP or TMP would be the scanner's temporary directory there;
    the caller's own are passed by no backend."""
    name = entry.partition("=")[0]
    with pytest.raises(ValueError, match=name) as refused:
        policy_module.parse_environment(["MY_VAR", entry])
    assert "/somewhere" not in str(refused.value)

    with pytest.raises(SandboxUnavailable, match=name):
        _policy(layout, environment=("MY_VAR", entry))

    passed = _policy(layout).filter_env(
        {"TMPDIR": "/caller", "TEMP": "/caller", "TMP": "/caller"}
    )
    assert not {"TMPDIR", "TEMP", "TMP"} & set(passed)


@pytest.mark.parametrize("entry", ["HOME", "HOME=/somewhere"])
def test_a_listed_home_is_refused_because_the_sandbox_sets_it(layout, entry):
    """``filter_env`` sets HOME to the sandbox's private home after the list is
    applied, so a listed value would pass validation and change nothing."""
    with pytest.raises(ValueError, match="HOME") as refused:
        policy_module.parse_environment(["MY_VAR", entry])
    assert "/somewhere" not in str(refused.value)

    with pytest.raises(SandboxUnavailable, match="HOME"):
        _policy(layout, environment=("MY_VAR", entry))

    passed = _policy(layout).filter_env({"HOME": "/caller"})
    assert passed["HOME"] == layout.home.as_posix()


def test_the_tmpdir_refusal_says_what_each_backend_does():
    """Only Landlock and sandbox-exec set TMPDIR; bwrap and firejail give each
    scanner a private /tmp and set no variable, so the text must not say that every
    backend gives each scanner a private TMPDIR."""
    with pytest.raises(ValueError, match="TMPDIR") as refused:
        policy_module.parse_environment(["TMPDIR=/somewhere"])

    text = str(refused.value)
    assert "Landlock and sandbox-exec" in text
    assert "bwrap and firejail give each scanner a private /tmp" in text
    assert "every scanner gets a private TMPDIR" not in text
    assert "/somewhere" not in text


@pytest.mark.parametrize(
    "entry",
    [
        "MARKER value with spaces",
        "A B=MARKER-value",
        "MARKER-not-a-name=MARKER-value",
        "MARKER-scheme://MARKER-user:MARKER-pw@MARKER-host/x?MARKER-key=MARKER-value",
        "MARKER+padded/ref==",
    ],
)
def test_the_refusal_of_a_malformed_entry_names_its_position_and_shows_none_of_it(
    layout, entry
):
    """An entry whose part before the first ``=`` is not a variable name may be a
    value written without its name (a URL, a padded key), so it is named by its place
    in the list, never by that part."""
    shown_before_the_equals = entry.partition("=")[0]
    with pytest.raises(ValueError) as refused:
        policy_module.parse_environment(["MY_VAR", entry])
    text = str(refused.value)
    assert "number 2" in text
    assert shown_before_the_equals not in text
    assert "MARKER" not in text

    with pytest.raises(SandboxUnavailable, match="number 2") as unavailable:
        _policy(layout, environment=("MY_VAR", entry))
    assert shown_before_the_equals not in str(unavailable.value)
    assert "MARKER" not in str(unavailable.value)


def test_a_variable_name_before_the_equals_is_all_an_entry_may_show():
    assert policy_module.entry_variable_name("MY_VAR=MARKER-value") == "MY_VAR"
    assert policy_module.entry_variable_name("MY_VAR") == "MY_VAR"
    assert policy_module.entry_variable_name("A B=MARKER-value") is None
    assert policy_module.entry_variable_name("MY_VAR\n=MARKER-value") is None
    assert policy_module.entry_variable_name("") is None


@pytest.mark.parametrize("shape", ["MY_VAR", b"MY_VAR", {"MY_VAR": "1"}])
def test_a_list_that_is_a_string_or_a_mapping_is_refused_with_its_shape(layout, shape):
    """A bare string would pass the variables M, Y, _, V, A and R, and a mapping
    would pass its keys with the values gone."""
    with pytest.raises(ValueError, match="list of entries"):
        policy_module.parse_environment(shape)

    with pytest.raises(SandboxUnavailable, match="list of entries"):
        _policy(layout, environment=shape)

    with pytest.raises(SandboxUnavailable, match="list of entries"):
        _build_policy(layout, environment=shape)


def test_a_name_listed_twice_takes_its_last_entry():
    names, values = policy_module.parse_environment(["A=1", "B", "A", "B=2", "C=3"])

    assert names == ("A", "B", "C")
    assert values == {"B": "2", "C": "3"}


def _build_policy(layout, **kwargs) -> SandboxPolicy:
    """``build_scanner_policy`` for a probe scanner over the layout's results."""
    source = layout.tmp / "src"
    source.mkdir(exist_ok=True)
    return policy_module.build_scanner_policy(
        "probe",
        policy_module.SandboxRequirements(),
        argv0=sys.executable,
        source_dir=source,
        output_dir=layout.results.parent,
        results_dir=layout.results,
        scan_target=source,
        cwd=source,
        offline=False,
        network_scanners=None,
        **kwargs,
    )


def test_the_policy_builder_carries_the_environment_list(layout):
    assert _build_policy(layout).environment == policy_module.DEFAULT_ENVIRONMENT
    built = _build_policy(layout, environment=["MY_VAR", "OTHER=1"])
    assert built.environment == ("MY_VAR", "OTHER=1")
    with pytest.raises(SandboxUnavailable, match="GITHUB_TOKEN"):
        _build_policy(layout, environment=["GITHUB_TOKEN"])


@POSIX
@pytest.mark.parametrize("kind", _BACKEND_KINDS)
def test_a_ca_value_the_list_sets_is_the_operators_and_is_granted(
    layout, monkeypatch, kind
):
    """The other half of the operator's value: ASH started with no such setting, and
    the environment list sets it with a ``NAME=value`` entry."""
    bundle = layout.home / "corp.pem"
    bundle.write_text("")
    monkeypatch.setattr(backends, "startup_environ", dict)
    policy = _policy(layout, network=True, environment=(f"SSL_CERT_FILE={bundle}",))

    granted = _granted_for(kind, layout, monkeypatch, policy, {})

    assert _real(bundle).as_posix() in granted


@POSIX
def test_a_landlock_plan_reads_the_ca_settings_and_never_runs_them(layout, monkeypatch):
    """The CA files and directories are the scan's data: read, never executable, and
    a relative, missing, wrong-kind or already visible entry is left out."""
    bundle = layout.home / "corp.pem"
    bundle.write_text("")
    certs = layout.home / "certs"
    certs.mkdir()
    not_a_file = layout.home / "not-a-file"
    not_a_file.mkdir()
    missing = layout.home / "missing.pem"
    visible = layout.system / "certs"
    visible.mkdir()
    env = {
        "SSL_CERT_FILE": str(bundle),
        "REQUESTS_CA_BUNDLE": "relative/corp.pem",
        "CURL_CA_BUNDLE": str(missing),
        "NODE_EXTRA_CA_CERTS": str(not_a_file),
        "SSL_CERT_DIR": os.pathsep.join([str(certs), str(visible)]),
    }
    monkeypatch.setattr(backends, "startup_environ", lambda: dict(env))

    plan = _plan_of("landlock", layout, monkeypatch, _policy(layout, network=True), env)
    try:
        document = _landlock_document(plan)
    finally:
        plan.run_cleanup()

    read_data, read_and_run = set(document["read_data"]), set(document["read_only"])
    for granted in (bundle, certs):
        assert _real(granted).as_posix() in read_data
        assert _real(granted).as_posix() not in read_and_run
    for left_out in (not_a_file, missing, visible):
        assert _real(left_out).as_posix() not in read_data
    assert not any(path.endswith("relative/corp.pem") for path in read_data)


@POSIX
@pytest.mark.parametrize("kind", _BACKEND_KINDS)
def test_a_scanner_that_wrote_the_uv_tool_lock_is_warned_of(
    layout, monkeypatch, caplog, kind
):
    """The lock is the one host file outside the results directory a sandbox may
    write, and it outlives the spawn. Every plan's cleanup says so when its size or
    time changed while the scanner ran; a lock left as it was draws no warning (the
    control), and the warning names the file and the scanner without quoting what
    was written."""
    lock = layout.tmp / "tools" / ".lock"
    lock.parent.mkdir()
    lock.write_text("")
    policy = _policy(layout, uv_tool_locks=(lock,))

    def lock_warnings():
        return [
            record.getMessage()
            for record in caplog.records
            if "uv tools lock" in record.getMessage()
        ]

    with caplog.at_level(logging.WARNING, logger="ash"):
        plan = _plan_of(kind, layout, monkeypatch, policy, {})
        plan.run_cleanup()
        assert lock_warnings() == []

        plan = _plan_of(kind, layout, monkeypatch, policy, {})
        lock.write_text("MARKER-left-for-a-later-run")
        plan.run_cleanup()

    [warning] = lock_warnings()
    assert lock.as_posix() in warning, warning
    assert "sandboxed scanner probe" in warning, warning
    assert "MARKER-left-for-a-later-run" not in warning, warning
