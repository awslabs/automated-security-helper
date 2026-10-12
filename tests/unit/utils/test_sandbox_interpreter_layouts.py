# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Common Python installations still get a scanner policy, with no home in it.

_ash_paths mounts ASH's own interpreter for every scanner, and refuses the spawn
when those paths would mount a home directory. Each case here fakes one
installation layout, with its files and links, and points sys.prefix,
sys.base_prefix, sys.exec_prefix and sys.executable at it. The scanner's policy
then has to build without a refusal, and no home directory may be among its
read-only paths, nor any directory holding one. The controls are layouts the
refusal exists for. An interpreter directly in a top-level directory has "/" above
its bin directory; that is left out, while a sys.prefix of "/" is still refused.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.sandbox import (
    SandboxRequirements,
    SandboxUnavailable,
)
from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox.policy import build_scanner_policy

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def _python(path: Path) -> Path:
    """A stand-in interpreter file; nothing here executes it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF")
    path.chmod(0o755)
    return path


def _link(link: Path, target) -> Path:
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    return link


def _set_passwd_home(monkeypatch, world, path):
    world.passwd_home = path
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: path, raising=False)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A filesystem root with a user's home at home/alice, as HOME and in passwd."""
    home = tmp_path / "home" / "alice"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for variable in ("XDG_DATA_HOME", "UV_TOOL_DIR", "UV_PYTHON_INSTALL_DIR"):
        monkeypatch.delenv(variable, raising=False)
    world = SimpleNamespace(root=tmp_path, home=home, passwd_home=home)
    world.set_passwd_home = lambda path: _set_passwd_home(monkeypatch, world, path)
    _set_passwd_home(monkeypatch, world, home)
    source = tmp_path / "work" / "repo"
    (source / ".ash" / "ash_output").mkdir(parents=True)
    world.source = source
    world.output = source / ".ash" / "ash_output"
    return world


def _build(world, monkeypatch, executable, prefix, base_prefix=None, argv0="/bin/sh"):
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(sys, "exec_prefix", str(prefix))
    monkeypatch.setattr(sys, "base_prefix", str(base_prefix or prefix))
    return build_scanner_policy(
        "grype",
        SandboxRequirements(),
        argv0=str(argv0),
        source_dir=world.source,
        output_dir=world.output,
        results_dir=world.output / "scanners" / "grype",
        scan_target=world.source,
        cwd=world.source,
        offline=True,
        network_scanners=None,
    )


def _assert_no_home_mounted(world, policy):
    """No grant is a home or holds one, and none covers what a home keeps private.

    A grant of ~/.ssh or ~/.local/share alone, or of any directory above them in
    the home such as ~/.local, would pass the first check and still expose keys and
    keyrings, so each of those is checked too.
    """
    homes = {
        Path(os.path.realpath(world.home)),
        Path(os.path.realpath(world.passwd_home)),
    }
    private = [home / name for home in homes for name in (".ssh", ".local/share")]
    for granted in [*policy.read_only, *policy.cache]:
        real = Path(os.path.realpath(granted))
        for home in homes:
            assert real != home and real not in home.parents, (granted, home)
        for kept in private:
            assert real != kept and real not in kept.parents, (granted, kept)


def _venv(directory: Path, base_python: Path) -> Path:
    """A venv as ``python -m venv`` makes one: bin/python links to the base one."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pyvenv.cfg").write_text(f"home = {base_python.parent}\n")
    _link(directory / "bin" / "python3", base_python)
    _link(directory / "bin" / "python", "python3")
    return directory / "bin" / "python"


def _conda(prefix: Path) -> Path:
    """A conda installation or environment: its own python, and conda-meta."""
    (prefix / "conda-meta").mkdir(parents=True)
    _python(prefix / "bin" / "python3.12")
    return _link(prefix / "bin" / "python", "python3.12")


def _pyenv(world):
    prefix = world.home / ".pyenv" / "versions" / "3.12.1"
    real = _python(prefix / "bin" / "python3.12")
    _link(prefix / "bin" / "python3", "python3.12")
    return prefix, real


def _uv_managed(world):
    patch = world.home / ".local/share/uv/python/cpython-3.12.4-linux-x86_64-gnu"
    _python(patch / "bin" / "python3.12")
    minor = _link(
        world.home / ".local/share/uv/python/cpython-3.12-linux-x86_64-gnu", patch
    )
    return minor, minor / "bin" / "python3.12"


def _system_python(world):
    usr = world.root / "usr"
    real = _python(usr / "bin" / "python3.12")
    _link(usr / "bin" / "python3", "python3.12")
    return usr, real


def case_pyenv_direct(world):
    """pyenv's shims exec the real interpreter, so sys.executable is this one."""
    prefix, _real = _pyenv(world)
    return prefix / "bin" / "python3", prefix, None


def case_pyenv_venv_in_the_tree(world):
    prefix, real = _pyenv(world)
    venv = world.source / ".venv"
    return _venv(venv, real), venv, prefix


def case_asdf(world):
    prefix = world.home / ".asdf" / "installs" / "python" / "3.12.1"
    _python(prefix / "bin" / "python3.12")
    _link(prefix / "bin" / "python3", "python3.12")
    return prefix / "bin" / "python3", prefix, None


def case_uv_managed_through_local_bin(world):
    minor, python = _uv_managed(world)
    executable = _link(world.home / ".local" / "bin" / "python3.12", python)
    return executable, minor, None


def case_uv_venv_in_the_tree(world):
    minor, python = _uv_managed(world)
    venv = world.source / ".venv"
    return _venv(venv, python), venv, minor


def case_uv_tool_environment(world):
    minor, python = _uv_managed(world)
    venv = world.home / ".local/share/uv/tools/automated-security-helper"
    return _venv(venv, python), venv, minor


def case_conda_base(world):
    prefix = world.home / "miniconda3"
    return _conda(prefix), prefix, None


def case_conda_env(world):
    _conda(world.home / "miniconda3")
    prefix = world.home / "miniconda3" / "envs" / "scan"
    return _conda(prefix), prefix, None


def case_homebrew(world):
    cellar = world.root / "opt/homebrew/Cellar/python@3.12/3.12.4"
    _python(cellar / "bin" / "python3.12")
    _link(cellar / "bin" / "python3", "python3.12")
    executable = _link(
        world.root / "opt/homebrew/bin/python3",
        "../Cellar/python@3.12/3.12.4/bin/python3",
    )
    return executable, cellar, None


def case_linuxbrew_beside_the_home(world):
    """/home/linuxbrew sits beside /home/alice, not inside it."""
    cellar = world.root / "home/linuxbrew/.linuxbrew/Cellar/python@3.12/3.12.4"
    _python(cellar / "bin" / "python3.12")
    _link(cellar / "bin" / "python3", "python3.12")
    executable = _link(
        world.root / "home/linuxbrew/.linuxbrew/bin/python3",
        "../Cellar/python@3.12/3.12.4/bin/python3",
    )
    return executable, cellar, None


def case_hostedtoolcache_linux(world):
    prefix = world.root / "opt/hostedtoolcache/Python/3.12.4/x64"
    real = _python(prefix / "bin" / "python3.12")
    _link(prefix / "bin" / "python3", "python3.12")
    venv = world.source / ".venv"
    return _venv(venv, real), venv, prefix


def case_hostedtoolcache_macos_in_the_passwd_home(world):
    """macOS runners keep the toolcache in the runner's home, and the escape
    suite's HOME is a directory of its own, so that home is the passwd one."""
    runner = world.root / "Users" / "runner"
    runner.mkdir(parents=True)
    world.set_passwd_home(runner)
    prefix = runner / "hostedtoolcache/Python/3.12.4/arm64"
    real = _python(prefix / "bin" / "python3.12")
    venv = runner / "work" / "ash" / "ash" / ".venv"
    return _venv(venv, real), venv, prefix


def case_pipx_venv(world):
    usr, real = _system_python(world)
    venv = world.home / ".local" / "pipx" / "venvs" / "automated-security-helper"
    return _venv(venv, real), venv, usr


def case_venv_directly_under_the_home(world):
    usr, real = _system_python(world)
    venv = world.home / "env"
    return _venv(venv, real), venv, usr


def case_nix_profile(world):
    store = world.root / "nix/store/aaaa-python3-3.12.4"
    _python(store / "bin" / "python3.12")
    _link(store / "bin" / "python3", "python3.12")
    profile = world.root / "nix/store/bbbb-user-environment"
    _link(profile / "bin" / "python3", store / "bin" / "python3")
    _link(world.home / ".nix-profile", profile)
    return world.home / ".nix-profile" / "bin" / "python3", store, None


def case_mise(world):
    patch = world.home / ".local/share/mise/installs/python/3.12.4"
    _python(patch / "bin" / "python3.12")
    minor = _link(world.home / ".local/share/mise/installs/python/3.12", patch)
    return minor / "bin" / "python3.12", minor, None


def case_a_sys_prefix_that_names_no_directory(world):
    """An installation moved after it was built, whose sys.prefix names the old,
    missing directory: only the real binary's install prefix mounts its library."""
    prefix = world.root / "moved" / "python3.12"
    real = _python(prefix / "bin" / "python3.12")
    (prefix / "lib" / "python3.12").mkdir(parents=True)
    return real, world.root / "build" / "install", None


LAYOUTS = {
    name[len("case_") :]: function
    for name, function in dict(globals()).items()
    if name.startswith("case_")
}


def _assert_interpreter_mounted(policy, executable, prefix, base_prefix):
    """Positive: the interpreter's own directories are granted, not only no home.

    Its real install prefix (above the real binary's bin directory) is covered, and
    so is every sys prefix that exists. A policy that grants too little fails here.
    """
    granted = _real_grants(policy)

    def covered(path):
        real = Path(os.path.realpath(path))
        return any(real == grant or grant in real.parents for grant in granted)

    real_prefix = Path(os.path.realpath(executable)).parent.parent
    assert covered(real_prefix), (real_prefix, sorted(map(str, granted)))
    for named in (prefix, base_prefix or prefix):
        if os.path.isdir(named):
            assert covered(named), (named, sorted(map(str, granted)))


@pytest.mark.parametrize("layout_name", sorted(LAYOUTS))
def test_a_common_interpreter_layout_is_mounted_without_a_home(
    world, monkeypatch, layout_name
):
    executable, prefix, base_prefix = LAYOUTS[layout_name](world)

    try:
        policy = _build(world, monkeypatch, executable, prefix, base_prefix)
    except SandboxUnavailable as refused:
        pytest.fail(f"{layout_name} was refused: {refused}")

    _assert_no_home_mounted(world, policy)
    _assert_interpreter_mounted(policy, executable, prefix, base_prefix)


def test_a_python_linked_straight_into_the_home_is_refused_with_a_remedy(
    world, monkeypatch
):
    """Control: a venv made by ``~/python3 -m venv`` reaches it through the home."""
    usr, real = _system_python(world)
    executable = _link(world.home / "python3", real)

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, executable, usr)

    message = str(refused.value)
    assert repr(world.home.as_posix()) in message, message
    assert "outside the home directory" in message, message
    assert "from the interpreter's real path" in message, message


def test_a_prefix_directly_in_the_home_that_is_no_venv_is_refused(world, monkeypatch):
    """Control: a Python built with --prefix=$HOME/.local, whose prefix holds
    ~/.local/share and the keyrings in it."""
    prefix = world.home / ".local"
    executable = _python(prefix / "bin" / "python3.12")

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, executable, prefix)

    assert repr(prefix.as_posix()) in str(refused.value), str(refused.value)


def test_a_python_built_with_its_prefix_directly_in_the_home_is_refused(
    world, monkeypatch
):
    """Pin: ./configure --prefix=$HOME/py312 stays refused, and says what to do.

    Its prefix is a real installation (lib/python3.12/os.py), but nothing tells it
    apart from any other directory directly in the home, so it is not mounted.
    """
    prefix = world.home / "py312"
    executable = _python(prefix / "bin" / "python3.12")
    (prefix / "lib" / "python3.12").mkdir(parents=True)
    (prefix / "lib" / "python3.12" / "os.py").write_text("")

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, executable, prefix)

    message = str(refused.value)
    assert repr(prefix.as_posix()) in message, message
    assert "more of one than a single Python installation" in message, message
    assert "outside the home directory" in message, message


def _in_which_home(world, which_home):
    """HOME's directory, or a passwd entry's home that HOME is not."""
    if which_home == "HOME":
        return world.home
    passwd_home = world.root / "passwd-home"
    (passwd_home / ".ssh").mkdir(parents=True)
    world.set_passwd_home(passwd_home)
    return passwd_home


@pytest.mark.parametrize("which_home", ["HOME", "passwd home"])
@pytest.mark.parametrize("marker", ["pyvenv.cfg", "conda-meta"])
@pytest.mark.parametrize(
    "root, keyrings", [(".local", False), ("data", True)], ids=[".local", "keyrings"]
)
def test_a_planted_venv_marker_does_not_admit_dot_local(
    world, monkeypatch, which_home, marker, root, keyrings
):
    """A marker alone does not make ~/.local one installation.

    ~/.local holds ~/.local/share and the keyrings in it, and a pyvenv.cfg or a
    conda-meta directory there (``conda create -p ~/.local``, or one written by any
    program run as the user) would otherwise admit it as a venv or conda root. The
    same for any directory directly in a home that holds share/keyrings.
    """
    home = _in_which_home(world, which_home)
    prefix = home / root
    if keyrings:
        (prefix / "share" / "keyrings").mkdir(parents=True)
    executable = _python(prefix / "bin" / "python3.12")
    if marker == "pyvenv.cfg":
        (prefix / "pyvenv.cfg").write_text("home = /usr/bin\n")
    else:
        (prefix / "conda-meta").mkdir()

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, executable, prefix)

    assert repr(prefix.as_posix()) in str(refused.value), str(refused.value)


def _a_real_file_at(monkeypatch, executable):
    """Model a real interpreter file at ``executable``, with no link on the way.

    As on a system without a merged /usr, where /bin is a directory of its own. The
    tests cannot create a file directly in a top-level directory, so that one path
    resolves to itself and is no symlink; every other path resolves as usual.
    """
    real_realpath = os.path.realpath
    real_hops = policy_module._symlink_hops

    def realpath(path, *args, **kwargs):
        if os.fspath(path) == executable:
            return executable
        return real_realpath(path, *args, **kwargs)

    def symlink_hops(path):
        if os.fspath(path) == executable:
            return [Path(executable)]
        return real_hops(path)

    monkeypatch.setattr(os.path, "realpath", realpath)
    monkeypatch.setattr(policy_module, "_symlink_hops", symlink_hops)


def _real_grants(policy):
    return {Path(os.path.realpath(path)) for path in policy.read_only}


@pytest.mark.parametrize("executable", ["/bin/python3", "/opt/python3"])
def test_an_interpreter_directly_in_a_system_directory_grants_nothing_new(
    world, monkeypatch, executable
):
    """Above such an interpreter's bin directory is "/", which names no installation.

    Its own directory is already a system read path, so the "/" read from it is left
    out, and the policy grants nothing that an interpreter elsewhere would not: the
    binary's directory, and the system read paths.
    """
    prefix = world.root / "prefix"
    prefix.mkdir()
    _usr, ordinary = _system_python(world)
    baseline = _real_grants(_build(world, monkeypatch, ordinary, prefix))
    _a_real_file_at(monkeypatch, executable)

    try:
        policy = _build(world, monkeypatch, executable, prefix)
    except SandboxUnavailable as refused:
        pytest.fail(f"{executable} was refused: {refused}")

    granted = _real_grants(policy)
    system = {Path(os.path.realpath(p)) for p in policy_module.SYSTEM_READ_PATHS}
    assert Path("/") not in granted, sorted(map(str, granted))
    assert Path(os.path.realpath(Path(executable).parent)) in granted
    assert granted - baseline <= system, sorted(map(str, granted - baseline - system))
    _assert_no_home_mounted(world, policy)


@pytest.mark.parametrize("executable", ["/mnt/python3", "/srv/python3"])
def test_an_interpreter_directly_in_another_top_level_directory_is_refused(
    world, monkeypatch, executable
):
    """Leaving out the "/" here would mount the binary's whole directory, /mnt or
    /srv, for every scanner, and nothing marks either as a system directory."""
    prefix = world.root / "prefix"
    prefix.mkdir()
    _a_real_file_at(monkeypatch, executable)

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, executable, prefix)

    assert repr("/") in str(refused.value), str(refused.value)


def test_a_sys_prefix_of_root_is_still_refused(world, monkeypatch):
    """Control: "/" named by sys.prefix itself would mount every directory."""
    _a_real_file_at(monkeypatch, "/opt/python3")

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, "/opt/python3", Path("/"), world.root / "usr")

    assert repr("/") in str(refused.value), str(refused.value)


# A directory spelled bin, sbin or Scripts is exempt from the breadth rules only
# when it really is one: the exemption is judged on the directory a link resolves
# to, so ~/bin -> ~/.aws, or $WORK/bin -> . with HOME=$WORK/home, is not.


def _covered(policy, path):
    real = Path(os.path.realpath(path))
    return any(real == grant or grant in real.parents for grant in _real_grants(policy))


def _work_holding(world, which_home):
    """A directory that holds HOME's directory, or one holding only the passwd home."""
    if which_home == "HOME":
        return world.home.parent
    passwd_home = world.root / "pwork" / "pw"
    (passwd_home / ".ssh").mkdir(parents=True)
    world.set_passwd_home(passwd_home)
    return passwd_home.parent


@pytest.mark.parametrize("which_home", ["HOME", "passwd home"])
def test_a_tool_in_a_bin_link_to_the_directory_holding_a_home_mounts_none_of_it(
    world, monkeypatch, which_home
):
    """$WORK/bin -> . with the home in $WORK: the tool's bin directory is $WORK."""
    work = _work_holding(world, which_home)
    tool = _python(work / "tool")
    _link(work / "bin", ".")
    usr, system_python = _system_python(world)

    policy = _build(
        world, monkeypatch, system_python, usr, argv0=work / "bin" / tool.name
    )

    assert Path(os.path.realpath(work)) not in _real_grants(policy)
    assert not _covered(policy, world.passwd_home / ".ssh")
    _assert_no_home_mounted(world, policy)


@pytest.mark.parametrize("which_home", ["HOME", "passwd home"])
def test_a_tool_directly_in_a_directory_holding_a_home_mounts_none_of_it(
    world, monkeypatch, which_home
):
    """$WORK/tool with the home in $WORK: the tool's directory, named nothing like
    bin, is $WORK itself, which holds the home."""
    work = _work_holding(world, which_home)
    tool = _python(work / "tool")
    usr, system_python = _system_python(world)

    policy = _build(world, monkeypatch, system_python, usr, argv0=tool)

    assert Path(os.path.realpath(work)) not in _real_grants(policy)
    assert not _covered(policy, world.passwd_home / ".ssh")
    _assert_no_home_mounted(world, policy)


@pytest.mark.parametrize("which_home", ["HOME", "passwd home"])
def test_a_tool_in_a_bin_link_to_a_config_directory_mounts_none_of_it(
    world, monkeypatch, which_home
):
    """~/bin -> ~/.aws: the tool's directory is the configuration directory."""
    home = _in_which_home(world, which_home)
    _python(home / ".aws" / "tool")
    (home / ".aws" / "credentials").write_text("[default]\n")
    _link(home / "bin", home / ".aws")
    usr, system_python = _system_python(world)

    policy = _build(world, monkeypatch, system_python, usr, argv0=home / "bin" / "tool")

    assert not _covered(policy, home / ".aws" / "credentials")
    _assert_no_home_mounted(world, policy)


@pytest.mark.parametrize("which_home", ["HOME", "passwd home"])
def test_ashs_python_in_a_bin_link_to_a_config_directory_is_refused(
    world, monkeypatch, which_home
):
    """~/bin -> ~/.aws, with ASH's python3 link inside it: mounting that link's
    directory would mount ~/.aws for every scanner."""
    home = _in_which_home(world, which_home)
    usr, system_python = _system_python(world)
    _link(home / ".aws" / "python3", system_python)
    _link(home / "bin", home / ".aws")

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, home / "bin" / "python3", usr)

    assert repr((home / "bin").as_posix()) in str(refused.value), str(refused.value)


@pytest.mark.parametrize("which_home", ["HOME", "passwd home"])
def test_a_path_entry_spelled_bin_that_resolves_elsewhere_in_a_home_is_skipped(
    world, monkeypatch, which_home
):
    """~/.config/tool/bin -> . on PATH names the configuration directory."""
    home = _in_which_home(world, which_home)
    (home / ".config" / "tool").mkdir(parents=True)
    (home / ".config" / "tool" / "token").write_text("x")
    _link(home / ".config" / "tool" / "bin", ".")
    monkeypatch.setenv("PATH", str(home / ".config" / "tool" / "bin"))
    usr, system_python = _system_python(world)

    policy = _build(world, monkeypatch, system_python, usr)

    assert not _covered(policy, home / ".config" / "tool" / "token")


@pytest.mark.parametrize("which_home", ["HOME", "passwd home"])
def test_an_ash_bin_path_spelled_bin_that_resolves_to_a_config_directory_is_refused(
    world, monkeypatch, which_home
):
    """ASH_BIN_PATH=~/bin with ~/bin -> ~/.aws."""
    home = _in_which_home(world, which_home)
    (home / ".aws").mkdir()
    _link(home / "bin", home / ".aws")
    monkeypatch.setenv("ASH_BIN_PATH", str(home / "bin"))
    usr, system_python = _system_python(world)

    with pytest.raises(SandboxUnavailable) as refused:
        _build(world, monkeypatch, system_python, usr)

    assert "ASH_BIN_PATH" in str(refused.value), str(refused.value)


@pytest.mark.parametrize("which_home", ["HOME", "passwd home"])
def test_a_real_bin_directory_in_a_home_is_still_mounted(
    world, monkeypatch, which_home
):
    """Control: ~/bin that is a directory, with a tool in it, is mounted as before,
    for the tool, on PATH and as ASH_BIN_PATH."""
    home = _in_which_home(world, which_home)
    tool = _python(home / "bin" / "tool")
    monkeypatch.setenv("PATH", str(home / "bin"))
    monkeypatch.setenv("ASH_BIN_PATH", str(home / "bin"))
    usr, system_python = _system_python(world)

    policy = _build(world, monkeypatch, system_python, usr, argv0=tool)

    assert Path(os.path.realpath(home / "bin")) in _real_grants(policy)
    _assert_no_home_mounted(world, policy)
