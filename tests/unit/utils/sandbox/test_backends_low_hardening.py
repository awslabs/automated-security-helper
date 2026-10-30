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
no temp directory. Nothing here starts a sandbox: ``_probe_run`` is replaced where
a plan would probe, and every assertion reads a command line or a profile.
"""

from __future__ import annotations

import json
import os
import re
import subprocess  # nosec B404 - CompletedProcess is built by hand, nothing runs
import sys
import tempfile
import threading
from pathlib import Path

import pytest

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


def test_a_failed_root_export_is_tried_again(layout, monkeypatch):
    keychain = layout.tmp / "roots.keychain"
    keychain.write_text("")
    monkeypatch.setattr(backends, "_TRUST_ROOT_KEYCHAINS", (str(keychain),))
    monkeypatch.setattr(backends, "_trust_roots_cache", [])
    answers = [
        subprocess.CompletedProcess([], 1, stdout="", stderr="timed out"),
        subprocess.CompletedProcess([], 0, stdout="BEGIN CERTIFICATE\n", stderr=""),
    ]
    monkeypatch.setattr(
        backends.subprocess, "run", lambda *args, **kwargs: answers.pop(0)
    )

    assert backends._system_trust_roots() is None
    assert backends._system_trust_roots() == "BEGIN CERTIFICATE\n"
    assert backends._system_trust_roots() == "BEGIN CERTIFICATE\n"


def test_a_root_export_that_ran_out_of_time_is_not_tried_again(layout, monkeypatch):
    """A hang costs one spawn the probe timeout, not every spawn of the run."""
    keychain = layout.tmp / "roots.keychain"
    keychain.write_text("")
    monkeypatch.setattr(backends, "_TRUST_ROOT_KEYCHAINS", (str(keychain),))
    monkeypatch.setattr(backends, "_trust_roots_cache", [])
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
    """Two scanner threads meeting the same filesystem share one probe and one answer."""
    cache = layout.tmp / "cache"
    cache.mkdir()
    entered = threading.Event()
    release = threading.Event()
    probes = []

    def probe_run(argv, env=None):
        probes.append(list(argv))
        entered.set()
        assert release.wait(5)
        return "exit 1: refused"

    monkeypatch.setattr(backends, "_probe_run", probe_run)
    monkeypatch.setattr(backends, "_true", lambda: "/fake/true")
    backend = _bwrap(overlay=True)
    answers = []
    workers = [
        threading.Thread(target=lambda: answers.append(backend._overlay_over(cache)))
        for _ in range(2)
    ]
    workers[0].start()
    assert entered.wait(5)
    workers[1].start()
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


def test_bwrap_binds_the_uv_tool_lock_read_write(layout):
    lock = layout.tmp / "tools" / ".lock"
    lock.parent.mkdir()
    lock.write_text("")
    argv = _bwrap().plan(["/bin/true"], {}, _policy(layout, uv_tool_locks=(lock,))).argv
    assert _real(lock) in _mounts(argv, "--bind")
    assert _real(lock) not in _mounts(argv, "--ro-bind")


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
    with pytest.raises(SandboxUnavailable, match="pattern"):
        backend.plan(["/bin/true"], {}, _policy(layout, writable=(odd,)))


@pytest.mark.skipif(os.name == "nt", reason="firejail's plan reads os.getuid()")
def test_firejail_grants_the_uv_tool_lock(layout):
    lock = layout.tmp / "tools" / ".lock"
    lock.parent.mkdir()
    lock.write_text("")
    backend = FirejailBackend()
    backend._executable = "/fj"
    argv = backend.plan(["/bin/true"], {}, _policy(layout, uv_tool_locks=(lock,))).argv
    assert f"--read-write={_real(lock).as_posix()}" in argv


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
def test_landlock_grants_the_scans_data_read_without_exec(layout, monkeypatch):
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
        scan_data=(source,),
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
    policy = _policy(layout, system_trust_roots=True)

    plan = SandboxExecBackend().plan(["/bin/true"], {"SSL_CERT_FILE": str(pem)}, policy)
    try:
        profile = plan.argv[plan.argv.index("-p") + 1]
        assert plan.env["SSL_CERT_FILE"] == str(pem)
        assert f'(allow file-read* (literal "{_real(pem).as_posix()}"))' in profile
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
