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
import subprocess  # nosec B404 - CompletedProcess is built by hand, nothing runs
import tempfile
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


def test_a_root_read_path_hides_no_link(layout):
    real = layout.tmp / "real"
    (real / "out").mkdir(parents=True)
    alias = layout.tmp / "alias"
    alias.symlink_to(real, target_is_directory=True)
    policy = _policy(
        layout, read_only=(Path("/"), layout.system), writable=(alias / "out",)
    )

    links = _symlinks(_bwrap().plan(["/bin/true"], {}, policy).argv)

    assert _real(layout.tmp) / "alias" in links


def test_a_link_whose_target_passes_through_another_link_is_recreated(layout):
    real = layout.tmp / "real"
    (real / "out").mkdir(parents=True)
    (layout.tmp / "b").symlink_to(real, target_is_directory=True)
    (layout.tmp / "a").symlink_to(layout.tmp / "b", target_is_directory=True)
    policy = _policy(layout, writable=(layout.tmp / "a" / "out",))

    links = _symlinks(_bwrap().plan(["/bin/true"], {}, policy).argv)

    assert _real(layout.tmp) / "a" in links
    assert _real(layout.tmp) / "b" in links, links


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

    assert "--private" in argv
    assert not [a for a in argv if a.startswith("--whitelist=")], argv


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


def test_the_uv_tool_lock_is_writable_but_not_executable(layout):
    lock = layout.tmp / "tools" / ".lock"
    lock.parent.mkdir()
    lock.write_text("")
    lines = _profile(layout, _policy(layout, uv_tool_locks=(lock,))).splitlines()
    literal = f'(literal "{_real(lock).as_posix()}")'
    assert any(
        line.startswith("(deny process-exec") and literal in line for line in lines
    )
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
