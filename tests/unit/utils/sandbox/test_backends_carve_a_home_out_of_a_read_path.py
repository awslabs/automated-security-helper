"""A granted system read path that holds the home directory does not reopen it.

The policy keeps a system read path that holds a home (``/opt`` with a HOME of
``/opt/app/home``: dropping it would take away a tool's installation prefix), so
each backend has to take the home back out of that path itself. Landlock rules
only grant, so its plan grants what sits beside the way to the home instead of the
path holding it; sandbox-exec's profile allows the policy's paths after it denies
the homes, and the last matching rule wins, so it denies a home again after that
allow and gives back the policy's own paths inside it. Every test reads the built
rule list; none runs a backend.
"""

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox.backends import (
    LandlockBackend,
    SandboxExecBackend,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    SandboxUnavailable,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


def _real(path):
    return Path(os.path.realpath(path))


@pytest.fixture
def prefix(tmp_path, monkeypatch):
    """A system read path that holds the home, with a tool beside the way to it.

    ``<prefix>/app/home`` is HOME's directory and the passwd entry's; ``<prefix>/tool``
    and ``<prefix>/app/other`` sit beside the way to it. The only system read path is
    the prefix, PATH names one system directory, and uv's directory variables are
    cleared so nothing from the environment running the tests lands in the policy.
    """
    root = tmp_path / "opt"
    home = root / "app" / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id").write_text("not a key")
    (root / "tool" / "bin").mkdir(parents=True)
    (root / "app" / "other").mkdir()
    monkeypatch.setenv("HOME", str(home))
    # Path.home() reads USERPROFILE on Windows, where these tests run too: the
    # profile and the plan document are path logic, independent of the platform.
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("PATH", "/usr/bin")
    for variable in (
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "UV_TOOL_DIR",
        "UV_PYTHON_INSTALL_DIR",
        "UV_CACHE_DIR",
    ):
        monkeypatch.delenv(variable, raising=False)
    # backends imports policy's _passwd_home by name, so each module has its own
    # binding, and the passwd home is faked in both. Both bindings must exist: a
    # rename would otherwise leave a dead attribute here and the real passwd home
    # in use.
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", Path.home)
    monkeypatch.setattr(policy_module, "SYSTEM_READ_PATHS", (root.as_posix(),))
    return SimpleNamespace(root=root, home=home)


def _policy(source):
    """The policy of one scanner scanning ``source``, offline, with no network."""
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    return build_scanner_policy(
        "probe",
        SandboxRequirements(),
        argv0=sys.executable,
        source_dir=source,
        output_dir=output,
        results_dir=output / "scanners" / "probe",
        scan_target=source,
        cwd=source,
        offline=True,
        network_scanners=None,
    )


def test_the_policy_keeps_the_path_holding_the_home(prefix, tmp_path):
    """The premise: the prefix stays in the read set, and the home is not listed.

    Dropping the prefix would take away a tool's installation prefix, so the policy
    keeps it (``_under_home`` drops a path that is a home or sits under one) and the
    backends have to carve the home out of it.
    """
    read_only = {_real(p) for p in _policy(tmp_path / "src").read_only}

    assert _real(prefix.root) in read_only
    assert _real(prefix.home) not in read_only


def _landlock_read_grants(policy, tmp_path, monkeypatch):
    """The paths the Landlock plan's document grants reading, resolved.

    Both read lists: ``read_only`` (read and exec, the tool paths) and
    ``read_data`` (read alone, the scan's own data, the scanned tree among them).
    """
    # The plan makes its private root with tempfile; keep it under tmp_path.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    plan = LandlockBackend().plan([sys.executable], {"PATH": "/usr/bin"}, policy)
    try:
        document = json.loads(plan.argv[plan.argv.index("--policy") + 1])
    finally:
        plan.run_cleanup()
    return {Path(p) for p in document["read_only"] + document.get("read_data", [])}


def _holding(granted, home):
    """The grants that are ``home`` or a directory holding it: each reads the home."""
    return sorted(str(p) for p in granted if p == home or p in home.parents)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Landlock is a Linux backend; its plan document is read on POSIX hosts",
)
def test_landlock_grants_what_sits_beside_the_home_not_the_path_holding_it(
    prefix, tmp_path, monkeypatch
):
    """No grant is the home or holds it; the entries beside the way to it are granted.

    A link beside the way that points into the home adds no grant: links are passed
    over before any real path is read, and the one in this tree would be passed
    over by the home check as well (the next test is the one that tells the two
    apart).
    """
    policy = _policy(tmp_path / "src")
    baseline = _landlock_read_grants(policy, tmp_path, monkeypatch)
    (prefix.root / "link").symlink_to(prefix.home / ".ssh")
    granted = _landlock_read_grants(policy, tmp_path, monkeypatch)
    home = _real(prefix.home)

    assert granted - baseline == set()
    assert _holding(granted, home) == []
    assert _real(prefix.root / "tool") in granted
    assert _real(prefix.root / "app" / "other") in granted
    inside = sorted(str(p) for p in granted if home in p.parents)
    assert inside == [], inside


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Landlock is a Linux backend; its plan document is read on POSIX hosts",
)
def test_landlock_grants_no_link_beside_the_way_by_what_it_names(
    prefix, tmp_path, monkeypatch
):
    """A link beside the way to the home grants neither its target nor the root.

    The entries beside the way are granted by their real paths, and a link's real
    path is whatever it names: a scanned tree that holds the home could place
    ``<prefix>/escape -> /srv/secrets`` or ``<prefix>/app/all -> /`` and be granted
    them. Links are passed over; a tool beside the way is still granted.

    The grants are built once without the links and once with them, and the links
    add none. A link to "/" that was followed would walk the root and grant its
    top-level entries, and one to the directory beside ``secrets`` would grant the
    directory that holds it; neither shows in a check of one path (``/`` is never
    granted whole, because it holds the home), so no grant may cover the secrets
    directory either, by being it, holding it or lying inside it.
    """
    secrets = tmp_path / "srv" / "secrets"
    secrets.mkdir(parents=True)
    policy = _policy(tmp_path / "src")
    baseline = _landlock_read_grants(policy, tmp_path, monkeypatch)
    (prefix.root / "escape").symlink_to(secrets, target_is_directory=True)
    (prefix.root / "app" / "all").symlink_to(Path("/"), target_is_directory=True)
    granted = _landlock_read_grants(policy, tmp_path, monkeypatch)
    real_secrets = _real(secrets)

    assert granted - baseline == set(), sorted(map(str, granted - baseline))
    assert not [
        p
        for p in granted
        if p == real_secrets or p in real_secrets.parents or real_secrets in p.parents
    ]
    assert _real(prefix.root / "tool") in granted
    assert _real(prefix.root / "app" / "other") in granted


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Landlock is a Linux backend; its plan document is read on POSIX hosts",
)
def test_landlock_keeps_the_policys_own_path_inside_the_home(
    prefix, tmp_path, monkeypatch
):
    """Positive control: the scanned tree under the home is granted, the home is not."""
    source = prefix.home / "proj"
    source.mkdir()
    granted = _landlock_read_grants(_policy(source), tmp_path, monkeypatch)
    home = _real(prefix.home)

    assert _real(source) in granted
    assert _holding(granted, home) == []


def _landlock_plan(policy, tmp_path, monkeypatch):
    """The Landlock plan of ``policy``, its private root made under ``tmp_path``."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return LandlockBackend().plan([sys.executable], {"PATH": "/usr/bin"}, policy)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Landlock is a Linux backend; its plan document is read on POSIX hosts",
)
def test_landlock_refuses_a_document_longer_than_one_argument_can_be(
    prefix, tmp_path, monkeypatch
):
    """A path holding a home is granted as every entry beside the way to the home.

    The document travels as one command-line argument, which the kernel limits to
    128 KiB, so a path with thousands of entries would fail every spawn with
    "Argument list too long" before the wrapper started. The plan is refused
    instead, naming the cause, and the private directory it made is removed. The
    limit is set to the size of this tree's own document so the tree stays small:
    one byte less refuses it, and the size itself plans it.
    """
    for number in range(20):
        (prefix.root / f"entry-{number}").mkdir()
    policy = _policy(tmp_path / "src")
    plan = _landlock_plan(policy, tmp_path, monkeypatch)
    try:
        size = len(plan.argv[plan.argv.index("--policy") + 1])
    finally:
        plan.run_cleanup()
    assert list(tmp_path.glob("ash-sandbox-*")) == []
    monkeypatch.setattr(backends_module, "_LANDLOCK_POLICY_LIMIT", size - 1)

    with pytest.raises(SandboxUnavailable, match="one command-line") as refused:
        _landlock_plan(policy, tmp_path, monkeypatch)

    assert f"({size} bytes)" in str(refused.value), str(refused.value)
    assert "narrower path" in str(refused.value), str(refused.value)
    assert list(tmp_path.glob("ash-sandbox-*")) == []

    monkeypatch.setattr(backends_module, "_LANDLOCK_POLICY_LIMIT", size)
    plan = _landlock_plan(policy, tmp_path, monkeypatch)
    try:
        assert len(plan.argv[plan.argv.index("--policy") + 1]) == size
    finally:
        plan.run_cleanup()


def _last_file_read_rule(lines, path):
    """The last file-read rule whose subpaths cover ``path``: the one that decides."""
    covering = [
        line
        for line in lines
        if line.startswith(("(allow file-read*", "(deny file-read*"))
        and any(
            path == Path(subpath) or Path(subpath) in path.parents
            for subpath in re.findall(r'\(subpath "([^"]*)"\)', line)
        )
    ]
    return covering[-1]


def test_sandbox_exec_denies_the_home_again_after_the_path_holding_it(prefix, tmp_path):
    """The rule that decides a read of the home, and of a file in it, is a deny.

    The profile allows reading from "/", denies the home, then allows the policy's
    paths, the prefix among them, which covers the home again. A later deny of the
    home has to be the last word on it, while the tool beside it stays readable.
    """
    lines = (
        SandboxExecBackend()
        .profile(_policy(tmp_path / "src"), tmp_path / "private-tmp")
        .splitlines()
    )
    home = _real(prefix.home)

    assert _last_file_read_rule(lines, home).startswith("(deny file-read*")
    assert _last_file_read_rule(lines, home / ".ssh" / "id").startswith(
        "(deny file-read*"
    )
    assert _last_file_read_rule(lines, _real(prefix.root / "tool")).startswith(
        "(allow file-read*"
    )


def test_sandbox_exec_gives_back_the_policys_own_path_inside_the_home(prefix, tmp_path):
    """Positive control: the scanned tree under the home is readable, the home is not."""
    source = prefix.home / "proj"
    source.mkdir()
    lines = (
        SandboxExecBackend()
        .profile(_policy(source), tmp_path / "private-tmp")
        .splitlines()
    )
    home = _real(prefix.home)

    assert _last_file_read_rule(lines, _real(source)).startswith("(allow file-read*")
    assert _last_file_read_rule(lines, home).startswith("(deny file-read*")
    assert _last_file_read_rule(lines, home / ".ssh" / "id").startswith(
        "(deny file-read*"
    )


def _backend_reads(backend, policy, path, prefix, tmp_path, monkeypatch):
    """Whether the rules ``backend`` builds for ``policy`` let a scanner read ``path``.

    Landlock: some grant is the path or holds it. sandbox-exec: the last file-read
    rule that covers it is an allow. firejail, which blacklists rather than
    grants: ``_hidden_around`` hides nothing of it. The stand-in for /tmp keeps
    firejail's own skip of everything under /tmp from answering for these paths.
    """
    path = _real(path)
    if backend == "landlock":
        granted = _landlock_read_grants(policy, tmp_path, monkeypatch)
        return any(p == path or p in path.parents for p in granted)
    if backend == "sandbox-exec":
        profile = SandboxExecBackend().profile(policy, tmp_path / "private-tmp")
        return _last_file_read_rule(profile.splitlines(), path).startswith(
            "(allow file-read*"
        )
    monkeypatch.setattr(backends_module, "_TMP_ROOT", tmp_path / "stand-in-tmp")
    shown = [_real(p) for p in policy.read_only]
    return backends_module._hidden_around(path, shown, [_real(prefix.home)]) == []


@pytest.mark.parametrize(
    "backend",
    [
        pytest.param(
            "landlock",
            marks=pytest.mark.skipif(
                sys.platform == "win32",
                reason="Landlock is a Linux backend; its plan document is read on "
                "POSIX hosts",
            ),
        ),
        "sandbox-exec",
        "firejail",
    ],
)
def test_every_backend_reads_a_file_a_home_link_names_inside_the_scanned_tree(
    prefix, tmp_path, monkeypatch, backend
):
    """~/.gitconfig -> <tree>/gitconfig, with <tree> the tree being scanned.

    The target is outside the home and outside every system read path, so a path
    that holds it is one the policy lists for the scan: it is read like the rest of
    that path under every backend, as firejail reads it. A file a home link names
    beside the tree is a file of the user's the policy lists nowhere, and stays
    unread under every backend (the control).
    """
    tree = tmp_path / "persist" / "dotfiles"
    inside = tree / "gitconfig"
    beside = tmp_path / "persist" / "netrc"
    tree.mkdir(parents=True)
    inside.write_text("[user]\n\tname = me\n")
    beside.write_text("machine example login me password x\n")
    try:
        (prefix.home / ".gitconfig").symlink_to(inside)
        (prefix.home / ".netrc").symlink_to(beside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")
    policy = _policy(tree)

    assert _backend_reads(backend, policy, inside, prefix, tmp_path, monkeypatch)
    assert not _backend_reads(backend, policy, beside, prefix, tmp_path, monkeypatch)
