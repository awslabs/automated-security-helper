# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox policy's reading of its inputs: homes, XDG, PATH, shebangs and grants.

Each test pins one reading of ``utils/sandbox/policy.py`` that was loose before:
a relative HOME or XDG value named a directory under the scanned repository; a
relative PYTHONPATH entry reached the scanner; a declared read path naming the home
was mounted whole; a declared read path inside the scanned tree stayed executable;
a shebang's ``env`` assignment was read as the program; an empty ``sys.executable``
mounted the working directory; a top-level link directory was mounted for every
scanner; a results directory under the source tree was examined at its last
component only. Everything reads the built policy in-process; nothing runs.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    SandboxUnavailable,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


def _real(paths) -> set:
    return {Path(os.path.realpath(p)) for p in paths}


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """A home of its own, a source tree with its output directory, a bare PATH."""
    home = tmp_path / "home"
    (home / ".local" / "share").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("PATH", "/usr/bin")
    for variable in (
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "UV_TOOL_DIR",
        "UV_PYTHON_INSTALL_DIR",
        "UV_CACHE_DIR",
        "GEM_HOME",
    ):
        monkeypatch.delenv(variable, raising=False)
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", Path.home, raising=False)
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)

    class _Layout:
        pass

    found = _Layout()
    found.home, found.source, found.output = home, source, output
    found.results = output / "scanners" / "probe"
    return found


def _policy(layout, requirements=SandboxRequirements(), **overrides):
    kwargs = {
        "argv0": "/bin/true",
        "source_dir": layout.source,
        "output_dir": layout.output,
        "results_dir": layout.results,
        "scan_target": layout.source,
        "cwd": layout.source,
        "offline": True,
        "network_scanners": None,
    }
    kwargs.update(overrides)
    return build_scanner_policy("probe", requirements, **kwargs)


def test_all_proxy_passes_only_with_a_network(layout):
    online = _policy(layout, SandboxRequirements(network=True), offline=False)
    env = online.filter_env({"ALL_PROXY": "p", "all_proxy": "q"})
    assert env["ALL_PROXY"] == "p" and env["all_proxy"] == "q"
    assert "ALL_PROXY" not in _policy(layout).filter_env({"ALL_PROXY": "p"})


def _anchored(layout):
    """Two absolute entries of the host's own shape (a drive-rooted path on
    Windows, where a bare ``/abs/x`` is relative to the current drive and Python
    3.13+ reads it as relative), the relative and empty entries around them, and
    the two lists the filter is expected to make of them."""
    abs_x, abs_y = str(layout.home / "x"), str(layout.home / "y")
    mixed = os.pathsep.join(["rel", abs_x, "", ".", abs_y])
    relative_only = os.pathsep.join(["rel", "."])
    return mixed, os.pathsep.join([abs_x, abs_y]), relative_only


def test_pythonpath_keeps_only_its_anchored_entries(layout):
    policy = _policy(layout)
    mixed, anchored, relative_only = _anchored(layout)
    assert policy.filter_env({"PYTHONPATH": mixed})["PYTHONPATH"] == anchored
    assert "PYTHONPATH" not in policy.filter_env({"PYTHONPATH": relative_only})


def test_a_pythonpath_named_by_the_scanner_is_anchored_too(layout):
    """A PYTHONPATH the scanner declares (or is granted) by name is held to the
    same rule as one the PYTHON prefix passes: a relative or empty entry would be
    read against the scanned tree whichever list let the variable through."""
    policy = _policy(layout, SandboxRequirements(env_names=("PYTHONPATH",)))
    assert "PYTHONPATH" in policy.env_names
    mixed, anchored, relative_only = _anchored(layout)
    assert policy.filter_env({"PYTHONPATH": mixed})["PYTHONPATH"] == anchored
    assert "PYTHONPATH" not in policy.filter_env({"PYTHONPATH": relative_only})


def test_a_relative_xdg_value_is_ignored_as_uv_ignores_it(layout, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "rel-data")
    monkeypatch.setenv("XDG_CACHE_HOME", "rel-cache")
    tools, pythons = policy_module._uv_data_directories()
    assert tools == layout.home / ".local" / "share" / "uv" / "tools"
    assert pythons == layout.home / ".local" / "share" / "uv" / "python"
    assert policy_module.uv_cache_directory() == layout.home / ".cache" / "uv"


def test_a_tools_directory_that_cannot_exist_gives_no_lock(layout, monkeypatch):
    """A name past the system's limit: the directory is not there, so nothing is
    mounted and no lock is granted. The guards themselves are measured by the
    test below; on Python 3.13 and later ``Path.exists`` swallows the error this
    name raises, so this case alone would pass with the guards deleted."""
    monkeypatch.setenv("XDG_DATA_HOME", str(layout.home.parent / ("x" * 300)))
    assert policy_module._uv_tool_locks() == []
    assert policy_module._uv_directories() == []


@pytest.mark.parametrize("code", [errno.ENAMETOOLONG, errno.EACCES])
def test_an_unexaminable_tools_directory_is_no_error(layout, monkeypatch, code):
    """A tools directory whose lock cannot be stat'ed and whose entries cannot be
    listed (a name past the limit, a permission refusal) contributes no lock and
    no tool, and raises nothing: the reads are made to fail with the errno, so the
    guarded paths run whatever the interpreter's own path checks swallow."""
    data = layout.home.parent / "data"
    tools = data / "uv" / "tools"
    tools.mkdir(parents=True)
    (tools / ".lock").write_text("")
    (tools / "tool" / "bin").mkdir(parents=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    real_lstat = os.lstat
    real_iterdir = Path.iterdir

    def refusing_lstat(path, *args, **kwargs):
        if Path(path).name == ".lock":
            raise OSError(code, os.strerror(code), str(path))
        return real_lstat(path, *args, **kwargs)

    def refusing_iterdir(self):
        if self == tools:
            raise OSError(code, os.strerror(code), str(self))
        return real_iterdir(self)

    monkeypatch.setattr(os, "lstat", refusing_lstat)
    monkeypatch.setattr(Path, "iterdir", refusing_iterdir)

    assert policy_module._uv_tool_locks() == []
    mounted = policy_module._uv_directories()
    assert tools.absolute() in mounted
    assert len(mounted) == 1, mounted


@pytest.mark.skipif(
    os.name == "nt", reason="hard links need os.link on a POSIX filesystem"
)
def test_a_uv_lock_with_another_name_on_disk_is_not_granted(layout, monkeypatch):
    """A hard-linked .lock is left out; the same file with one name is granted (control)."""
    data = layout.home.parent / "data"
    tools = data / "uv" / "tools"
    tools.mkdir(parents=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    lock = tools / ".lock"
    lock.write_text("")

    assert policy_module._uv_tool_locks() == [lock.absolute()]

    other = layout.home.parent / "other-name"
    os.link(lock, other)
    assert policy_module._uv_tool_locks() == []

    other.unlink()
    assert policy_module._uv_tool_locks() == [lock.absolute()]


def test_the_spelled_prefix_of_a_linked_interpreter_is_mounted_too(layout, monkeypatch):
    """A tool's bin/python passes through a symlinked minor-version directory."""
    data = layout.home.parent / "data"
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    installation = layout.home.parent / "pythons" / "3.12.7"
    (installation / "bin").mkdir(parents=True)
    (installation / "lib" / "python3.12").mkdir(parents=True)
    (installation / "bin" / "python3.12").write_text("")
    alias = installation.parent / "3.12"
    alias.symlink_to(installation, target_is_directory=True)
    tool_bin = data / "uv" / "tools" / "tool" / "bin"
    tool_bin.mkdir(parents=True)
    (tool_bin / "python").symlink_to(alias / "bin" / "python3.12")

    mounted = policy_module._uv_directories()

    assert Path(os.path.realpath(installation)) in _real(mounted)
    assert alias in mounted, mounted


def test_a_relative_link_target_is_read_against_the_links_real_directory(tmp_path):
    (tmp_path / "x" / "y").mkdir(parents=True)
    (tmp_path / "x" / "b").mkdir()
    (tmp_path / "x" / "b" / "python3").write_text("")
    (tmp_path / "a").symlink_to(tmp_path / "x" / "y", target_is_directory=True)
    (tmp_path / "a" / "link").symlink_to(Path("..") / "b" / "python3")

    hops = policy_module._symlink_hops(tmp_path / "a" / "link")

    assert hops[-1].exists(), hops
    assert _real([hops[-1]]) == _real([tmp_path / "x" / "b" / "python3"])


def test_a_venv_directly_in_the_home_is_mounted_with_its_tool(layout):
    venv = layout.home / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    tool = venv / "bin" / "tool"
    tool.write_bytes(b"\x7fELF")
    tool.chmod(0o755)

    prefixes = _real(policy_module._executable_prefix(str(tool)))

    assert Path(os.path.realpath(venv / "bin")) in prefixes
    assert Path(os.path.realpath(venv)) in prefixes


@pytest.mark.parametrize(
    "words, program",
    [
        (["python3"], "python3"),
        (["FOO=bar", "python3", "-u"], "python3"),
        (["-u", "FOO", "python3"], "python3"),
        (["--unset", "FOO", "python3"], "python3"),
        (["-uFOO", "python3"], "python3"),
        (["--unset=FOO", "-i", "python3"], "python3"),
        (["-S", "python3", "-u"], "python3"),
        (["-C", "/dir", "ruby"], "ruby"),
        (["--chdir=/dir", "ruby"], "ruby"),
        (["-a", "argv0", "python3"], "python3"),
        (["--argv0", "argv0", "python3"], "python3"),
        (["-", "python3"], "python3"),
        (["--", "python3"], "python3"),
        (["-i", "--", "FOO=bar", "python3"], "python3"),
        # BSD and macOS env: -P takes the search path, -L the login class.
        (["-P", "/opt/bin", "python3"], "python3"),
        (["-L", "daemon", "python3"], "python3"),
        ([], None),
        (["FOO=bar"], None),
        (["-u", "FOO"], None),
    ],
)
def test_the_env_shebang_program_follows_envs_own_grammar(words, program):
    assert policy_module._env_program(words) == program


def test_an_empty_sys_executable_mounts_no_working_directory(layout, monkeypatch):
    nested = layout.home.parent / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setattr(sys, "executable", "")

    paths, _data = policy_module._ash_paths()

    mounted = _real(paths)
    real_nested = Path(os.path.realpath(nested))
    # Neither the working directory ("" resolved), nor what a prefix walk would
    # read as its bin directory and its prefix, nor any directory above it.
    for leaked in (real_nested, real_nested.parent, real_nested.parent.parent):
        assert leaked not in mounted, mounted
    assert not any(p == real_nested or p in real_nested.parents for p in mounted), (
        mounted
    )


def test_a_link_directory_at_the_top_level_is_refused(layout):
    """The rule reads the directory's place, not the filesystem: a top-level
    directory that is not a system read path is refused whether or not it exists
    (a real top-level link cannot be made without root), and a system read path
    or a directory below the top level is not. The /opt control holds where /opt
    is a directory; a host that makes /opt a link (OSTree) would read it the
    same, since nothing here follows links."""
    homes = [Path(os.path.realpath(layout.home))]
    with pytest.raises(SandboxUnavailable, match="top-level"):
        policy_module._refuse_a_home_among(
            [], [Path("/no-such-top-level-dir-for-this-test")], None, homes, []
        )
    # A system read path, and a directory below the top level, are not.
    policy_module._refuse_a_home_among(
        [], [Path("/opt"), Path("/usr/bin")], None, homes, []
    )


def test_the_xdg_data_home_is_broader_than_a_tool(layout):
    home = Path(os.path.realpath(layout.home))
    share = layout.home / ".local" / "share"
    assert policy_module._broader_than_a_tool(share, [home]) is True
    assert policy_module._broader_than_a_tool(share / "uv" / "tools", [home]) is False
    holder = layout.home / ".config" / "holder"
    (holder / "keyrings").mkdir(parents=True)
    (layout.home / ".config" / "tool").mkdir()
    assert policy_module._broader_than_a_tool(holder, [home]) is True
    assert (
        policy_module._broader_than_a_tool(layout.home / ".config" / "tool", [home])
        is False
    )


def test_a_declared_read_path_naming_the_home_is_refused(layout, monkeypatch):
    """The home itself, and a directory above it, which would expose the home
    with everything beside it: neither, nor anything above the home, is mounted.
    A directory directly in the home (~/.gem) is admitted (the control)."""
    requirements = SandboxRequirements(read_paths=("$GEM_HOME",))
    home = Path(os.path.realpath(layout.home))
    for named in (layout.home, layout.home.parent):
        monkeypatch.setenv("GEM_HOME", str(named))
        mounted = _real(_policy(layout, requirements).read_only)
        assert not any(p == home or p in home.parents for p in mounted), mounted
    gems = layout.home / ".gem"
    gems.mkdir()
    monkeypatch.setenv("GEM_HOME", str(gems))
    assert Path(os.path.realpath(gems)) in _real(
        _policy(layout, requirements).read_only
    )


def test_a_path_entry_inside_another_scanned_root_is_not_mounted(layout, monkeypatch):
    other = layout.home.parent / "other-root"
    tools = other / "bin"
    tools.mkdir(parents=True)
    monkeypatch.setenv("PATH", os.pathsep.join([str(tools), "/usr/bin"]))

    with_root = _policy(layout, scanned_trees=(other,))
    without = _policy(layout)

    assert Path(os.path.realpath(tools)) not in _real(with_root.read_only)
    assert Path(os.path.realpath(tools)) in _real(without.read_only)


def test_a_declared_read_path_inside_the_tree_is_data(layout):
    vendor = layout.source / "vendor"
    vendor.mkdir()
    policy = _policy(layout, SandboxRequirements(read_paths=(str(vendor),)))
    assert Path(os.path.realpath(vendor)) in _real(policy.read_only)
    assert Path(os.path.realpath(vendor)) not in _real(policy.executable)


def test_an_operators_read_path_a_scanner_also_declares_stays_executable(layout):
    """A declared read path that names the operator's ``extra_read_paths`` entry
    exactly is the operator's grant, not the repository's: it stays executable,
    as the entry does when no scanner names it (the control)."""
    tools = layout.source / "tools"
    tools.mkdir()
    requirements = SandboxRequirements(read_paths=(str(tools),))

    declared_too = _policy(layout, requirements, extra_read_paths=(str(tools),))
    operator_only = _policy(layout, extra_read_paths=(str(tools),))
    declared_only = _policy(layout, requirements)

    assert Path(os.path.realpath(tools)) in _real(operator_only.executable)
    assert Path(os.path.realpath(tools)) in _real(declared_too.executable)
    assert Path(os.path.realpath(tools)) not in _real(declared_only.executable)


def test_a_too_broad_uv_tool_dir_is_warned_about_once_per_policy(layout, monkeypatch):
    """The three readers of uv's directories (the mounts, the environment hints,
    the tools lock) take one screened reading, so the warning is logged once."""
    from automated_security_helper.utils.log import ASH_LOGGER

    monkeypatch.setenv("UV_TOOL_DIR", str(layout.home))
    warned = []
    monkeypatch.setattr(
        ASH_LOGGER, "warning", lambda message, *args, **kwargs: warned.append(message)
    )

    policy = _policy(layout)

    about_tools = [m for m in warned if "UV_TOOL_DIR" in m]
    assert len(about_tools) == 1, warned
    assert Path(os.path.realpath(layout.home)) not in _real(policy.read_only)


def test_a_staged_tool_does_not_read_an_import_entry_inside_the_tree(
    layout, monkeypatch
):
    entry = layout.source / "lib"
    entry.mkdir()
    monkeypatch.setattr(policy_module, "_ash_paths", lambda: ([entry], [entry]))
    staged = _policy(
        layout,
        SandboxRequirements(staged_input_only=True),
        scan_target=layout.home.parent / "staging",
        cwd=None,
    )
    plain = _policy(layout)
    assert Path(os.path.realpath(entry)) not in _real(staged.read_only)
    assert Path(os.path.realpath(entry)) in _real(plain.read_only)


def test_a_results_directory_linked_inside_the_source_is_refused(layout, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (layout.source / "other").mkdir()
    (layout.source / "other" / "link").symlink_to(elsewhere, target_is_directory=True)
    results = layout.source / "other" / "link" / "results"

    with pytest.raises(SandboxUnavailable, match="symlink"):
        policy_module._refuse_symlinked_results_dir(
            layout.output, results, layout.source
        )
    with pytest.raises(SandboxUnavailable, match="symlink"):
        _policy(layout, results_dir=results)


def test_uv_is_pointed_at_the_mounted_directories(layout, monkeypatch):
    data = layout.home.parent / "data"
    (data / "uv" / "tools").mkdir(parents=True)
    (data / "uv" / "python").mkdir()
    cache = layout.home.parent / "cache"
    (cache / "uv").mkdir(parents=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))

    env = _policy(layout).filter_env({})

    assert Path(env["UV_TOOL_DIR"]) == data / "uv" / "tools"
    assert Path(env["UV_PYTHON_INSTALL_DIR"]) == data / "uv" / "python"
    assert Path(env["UV_CACHE_DIR"]) == cache / "uv"


def test_a_uv_variable_the_environment_sets_is_left_alone(layout, monkeypatch):
    """A set UV_TOOL_DIR is kept as given while the unset sibling is still hinted."""
    data = layout.home.parent / "data"
    (data / "uv" / "python").mkdir(parents=True)
    (data / "uv" / "tools").mkdir()
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    tools = layout.home.parent / "my-tools"
    tools.mkdir()
    monkeypatch.setenv("UV_TOOL_DIR", str(tools))

    # A spelling the policy would never derive itself (a trailing separator), so
    # a value overwritten with the derived directory could not read as kept.
    as_given = str(tools) + os.sep
    env = _policy(layout).filter_env({"UV_TOOL_DIR": as_given})

    assert env["UV_TOOL_DIR"] == as_given
    assert Path(env["UV_PYTHON_INSTALL_DIR"]) == data / "uv" / "python"


def test_an_unusable_home_is_the_passwd_home_or_the_root(layout, monkeypatch):
    passwd = layout.home.parent / "passwd-home"
    passwd.mkdir()
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: passwd, raising=False)
    monkeypatch.setenv("HOME", "relative/home")
    assert policy_module._policy_home() == passwd
    assert _policy(layout).home == passwd

    monkeypatch.setenv("HOME", "/")
    assert policy_module._policy_home() == Path("/")
    assert _policy(layout).home == Path("/")

    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: None, raising=False)
    monkeypatch.setenv("HOME", "")
    assert policy_module._policy_home() == Path("/")


@pytest.mark.skipif(os.name == "nt", reason="Windows reads USERPROFILE, not HOME")
def test_an_empty_home_falls_to_the_passwd_home(layout, monkeypatch):
    """HOME="" is unset to the policy, as to usable_home: Path.home() alone reads it as the root."""
    passwd = layout.home.parent / "passwd-home"
    passwd.mkdir()
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: passwd, raising=False)
    monkeypatch.setenv("HOME", "")

    assert policy_module._policy_home() == passwd
    assert _policy(layout).home == passwd
    assert policy_module._homes() == [Path(os.path.realpath(passwd))]


def test_a_faked_home_is_the_policys_home(layout, monkeypatch):
    """A test that fakes the home by patching Path.home is honored, as the system-read tests do."""
    faked = layout.home.parent / "faked-home"
    faked.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: faked))
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: None, raising=False)

    assert policy_module._policy_home() == faked
    assert policy_module._homes() == [Path(os.path.realpath(faked))]


def test_an_anchored_bin_path_inside_the_tree_is_data(layout, monkeypatch):
    tools = layout.source / "bin"
    tools.mkdir()
    monkeypatch.setattr(subprocess_utils, "_bin_path", lambda: tools)
    policy = _policy(layout)
    assert Path(os.path.realpath(tools)) in _real(policy.read_only)
    assert Path(os.path.realpath(tools)) not in _real(policy.executable)
