# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The backend-neutral sandbox policy and the scope that decides when it applies."""

import json
import os
import re
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox import (
    SandboxRequirements,
    SandboxUnavailable,
    clear_backend_cache,
    prepare_spawn,
    sandbox_scope,
    scanner_sandbox_scope,
)
from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import (
    BACKENDS,
    LANDLOCK_EXEC,
    BwrapBackend,
    FirejailBackend,
    LandlockBackend,
    SandboxExecBackend,
    SpawnPlan,
)
from automated_security_helper.utils.sandbox.policy import (
    build_scanner_policy,
    refuse_symlinked_output_dir,
)


def _fake_passwd_home(monkeypatch, home):
    """Make ``home`` the passwd entry's home everywhere it is read.

    backends imports policy's _passwd_home by name, so each module has its own
    binding, and a test that fakes only one sees two different passwd homes.
    """
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: home, raising=False)


@pytest.fixture(autouse=True)
def _home_is_the_passwd_home(monkeypatch):
    """HOME is the passwd entry's home here, as on most hosts.

    Every test sets HOME to a directory of its own; the cases where the two differ
    are TestFirejailHidesBothHomes, TestHomeElsewhereThanThePasswdEntry and the
    tests after it, which override this.
    """
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", Path.home, raising=False)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".local" / "share" / "keyrings").mkdir(parents=True)
    (home / ".local" / "bin").mkdir(parents=True)
    (home / ".ssh").mkdir()
    monkeypatch.setenv("HOME", str(home))
    # Path.home() reads USERPROFILE on Windows, where these tests run too: the
    # policy builder is path logic, independent of the platform it runs on.
    monkeypatch.setenv("USERPROFILE", str(home))
    # uv's directories follow these before $HOME, so a value from the environment
    # running the tests would move them away from the ones planted under home.
    for variable in (
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "UV_TOOL_DIR",
        "UV_PYTHON_INSTALL_DIR",
        "UV_CACHE_DIR",
    ):
        monkeypatch.delenv(variable, raising=False)
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    results = output / "scanners" / "grype"
    output.mkdir(parents=True)
    return SimpleNamespace(home=home, source=source, output=output, results=results)


def _policy(layout, requirements=SandboxRequirements(), **overrides):
    kwargs = {
        "argv0": sys.executable,
        "source_dir": layout.source,
        "output_dir": layout.output,
        "results_dir": layout.results,
        "scan_target": layout.source,
        "cwd": layout.source,
        "offline": False,
        "network_scanners": None,
    }
    kwargs.update(overrides)
    return build_scanner_policy("grype", requirements, **kwargs)


def _as_argv(path):
    """A path spelled the way the backends put it on a command line."""
    return Path(os.path.realpath(path)).as_posix()


def _resolved(paths):
    return {Path(os.path.realpath(p)) for p in paths}


@pytest.mark.unit
class TestUvDirectoriesAreScreened:
    """uv's directories named in ASH's environment get the breadth rule too.

    UV_TOOL_DIR, UV_PYTHON_INSTALL_DIR and UV_CACHE_DIR name directories mounted for
    every scanner, so uv can run tools. A value that is "/", a home or a directory
    holding one would mount far more than uv's files, so it is not mounted, with a
    warning, the way the rule cache variables are treated.
    """

    @pytest.fixture
    def warnings(self, monkeypatch):
        from automated_security_helper.utils import log

        said = []
        monkeypatch.setattr(
            log.ASH_LOGGER, "warning", lambda message, *a, **k: said.append(message)
        )
        return said

    @pytest.mark.parametrize("named", ["home", "holding-home", "root"])
    @pytest.mark.parametrize(
        "variable", ["UV_TOOL_DIR", "UV_PYTHON_INSTALL_DIR", "UV_CACHE_DIR"]
    )
    def test_a_broad_value_is_not_mounted(
        self, layout, monkeypatch, warnings, variable, named
    ):
        value = {
            "home": layout.home,
            "holding-home": layout.home.parent,
            "root": Path(os.path.abspath(os.sep)),
        }[named]
        monkeypatch.setenv(variable, str(value))

        policy = _policy(layout)

        granted = _resolved([*policy.read_only, *policy.cache])
        assert Path(os.path.realpath(value)) not in granted
        assert any(variable in str(said) for said in warnings), warnings

    @pytest.mark.parametrize(
        "variable", ["UV_TOOL_DIR", "UV_PYTHON_INSTALL_DIR", "UV_CACHE_DIR"]
    )
    def test_a_directory_of_uvs_own_is_still_mounted(
        self, layout, monkeypatch, warnings, variable
    ):
        value = layout.home / ".local" / "share" / "uv" / variable.lower()
        value.mkdir(parents=True)
        monkeypatch.setenv(variable, str(value))

        policy = _policy(layout)

        granted = _resolved([*policy.read_only, *policy.cache])
        assert Path(os.path.realpath(value)) in granted
        assert not any(variable in str(said) for said in warnings), warnings


@pytest.mark.unit
class TestNetwork:
    def test_off_unless_declared(self, layout):
        assert _policy(layout).network is False

    def test_declared_need_is_granted_online(self, layout):
        assert _policy(layout, SandboxRequirements(network=True)).network is True

    def test_never_under_offline(self, layout):
        policy = _policy(layout, SandboxRequirements(network=True), offline=True)
        assert policy.network is False

    def test_the_config_list_replaces_declarations(self, layout):
        declared = SandboxRequirements(network=True)
        assert _policy(layout, declared, network_scanners=[]).network is False
        assert _policy(layout, network_scanners=["grype"]).network is True
        assert (
            _policy(layout, network_scanners=["grype"], offline=True).network is False
        )

    def test_no_network_tells_uv_to_stay_offline(self, layout):
        assert _policy(layout).extra_env["UV_OFFLINE"] == "1"
        assert (
            "UV_OFFLINE"
            not in _policy(layout, SandboxRequirements(network=True)).extra_env
        )


@pytest.mark.unit
class TestPaths:
    def test_only_the_results_directory_is_writable(self, layout):
        policy = _policy(layout)
        assert _resolved(policy.writable) == _resolved([layout.results])
        assert layout.results.is_dir()

    def test_home_and_its_secrets_are_not_exposed(self, layout):
        exposed = _resolved(_policy(layout).read_only)
        for hidden in (
            layout.home,
            layout.home / ".ssh",
            layout.home / ".local",
            layout.home / ".local" / "share",
            layout.home / ".local" / "share" / "keyrings",
        ):
            assert Path(os.path.realpath(hidden)) not in exposed, hidden

    def test_source_and_output_are_read_only(self, layout):
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(layout.source)) in exposed
        assert Path(os.path.realpath(layout.output)) in exposed

    def test_a_cwd_inside_the_results_directory_is_not_mounted_read_only(self, layout):
        layout.results.mkdir(parents=True)
        policy = _policy(layout, cwd=layout.results)
        assert Path(os.path.realpath(layout.results)) not in _resolved(policy.read_only)

    def test_a_path_entry_of_home_itself_is_skipped(self, layout, monkeypatch):
        monkeypatch.setenv(
            "PATH",
            os.pathsep.join([str(layout.home), str(layout.home / ".local" / "bin")]),
        )
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(layout.home)) not in exposed
        assert Path(os.path.realpath(layout.home / ".local" / "bin")) in exposed

    def test_an_executable_in_home_local_bin_does_not_expose_home_local(self, layout):
        tool = layout.home / ".local" / "bin" / "tool"
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)
        exposed = _resolved(_policy(layout, argv0=str(tool)).read_only)
        assert Path(os.path.realpath(layout.home / ".local")) not in exposed

    def test_extra_read_paths_expand(self, layout, monkeypatch, tmp_path):
        extra = tmp_path / "ca"
        extra.mkdir()
        monkeypatch.setenv("ASH_TEST_CA", str(extra))
        policy = _policy(layout, extra_read_paths=["$ASH_TEST_CA", "/does/not/exist"])
        assert Path(os.path.realpath(extra)) in _resolved(policy.read_only)


@pytest.mark.unit
class TestExecutable:
    def test_tool_paths_are_executable_and_the_scan_data_is_not(self, layout):
        policy = _policy(layout)
        executable = _resolved(policy.executable)
        assert Path(os.path.realpath(sys.executable)).parent in executable
        for data in (layout.source, layout.output):
            assert Path(os.path.realpath(data)) not in executable
            assert Path(os.path.realpath(data)) in _resolved(policy.scan_data)

    def test_system_configuration_is_readable_and_not_executable(self, layout):
        policy = _policy(layout)
        if not Path("/etc").is_dir():
            pytest.skip("no /etc on this platform")
        etc = Path(os.path.realpath("/etc"))
        assert etc in _resolved(policy.read_only)
        assert etc not in _resolved(policy.executable)

    def test_a_relative_ash_bin_path_is_not_a_tool_path(
        self, layout, monkeypatch, tmp_path
    ):
        """ASH_BIN_PATH=bin, run from the repository, named the repository's bin/.

        _existing made it absolute against the cwd, so a bin/ the repository
        committed became a read-only and executable path, and the sandbox-exec
        profile gave it back last, after the deny on the scanned tree. Tool lookup
        does not search a relative ASH_BIN_PATH, and neither does the sandbox.
        """
        planted = layout.source / "bin"
        planted.mkdir()
        monkeypatch.chdir(layout.source)
        monkeypatch.setenv("ASH_BIN_PATH", "bin")
        policy = _policy(layout)
        real = Path(os.path.realpath(planted))
        assert real not in _resolved(policy.executable)
        assert real not in _resolved(policy.read_only)
        profile = SandboxExecBackend().profile(policy, tmp_path / "private-tmp")
        allowed = [
            line
            for line in profile.splitlines()
            if line.startswith("(allow process-exec")
        ]
        assert not any(_as_argv(planted) in line for line in allowed), allowed

    def test_an_absolute_ash_bin_path_is_a_tool_path(
        self, layout, monkeypatch, tmp_path
    ):
        """Positive control: the bin directory, named absolutely, is executable."""
        bin_dir = tmp_path / "ash-bin"
        bin_dir.mkdir()
        monkeypatch.chdir(layout.source)
        monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
        policy = _policy(layout)
        assert Path(os.path.realpath(bin_dir)) in _resolved(policy.executable)

    def test_nothing_writable_or_cached_is_executable(
        self, layout, monkeypatch, tmp_path
    ):
        uv_cache = tmp_path / "uv-cache"
        other_cache = tmp_path / "grype-cache"
        uv_cache.mkdir()
        other_cache.mkdir()
        monkeypatch.setenv("UV_CACHE_DIR", str(uv_cache))
        policy = _policy(layout, SandboxRequirements(cache_paths=(str(other_cache),)))
        executable = _resolved(policy.executable)
        # The host caches are read-only wherever exec is restricted; uv runs from
        # the spawn's private cache, which the backend makes executable.
        for path in (uv_cache, other_cache, layout.results):
            assert Path(os.path.realpath(path)) not in executable, path


@pytest.mark.unit
class TestEnvironment:
    def test_credentials_are_dropped_and_declared_prefixes_kept(self, layout):
        policy = _policy(layout, SandboxRequirements(env_prefixes=("GRYPE_",)))
        env = policy.filter_env(
            {
                "PATH": "/usr/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C",
                "AWS_SECRET_ACCESS_KEY": "s",
                "AWS_SESSION_TOKEN": "s",
                "GITHUB_TOKEN": "s",
                "DB_PASSWORD": "s",
                "GRYPE_DB_CACHE_DIR": "/x",
                "TRIVY_TOKEN": "s",
                "HTTPS_PROXY": "http://proxy",
            }
        )
        assert env["PATH"] == "/usr/bin"
        assert env["GRYPE_DB_CACHE_DIR"] == "/x"
        assert Path(env["HOME"]) == Path(layout.home)
        for dropped in (
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "TRIVY_TOKEN",
            "HTTPS_PROXY",
        ):
            assert dropped not in env, dropped

    def test_the_outer_run_id_is_dropped_even_when_named(self, layout):
        """A scanner never gets the ID its run writes into the results file."""
        policy = _policy(layout, SandboxRequirements(env_names=("ASH_OUTER_RUN_ID",)))
        env = policy.filter_env(
            {"ASH_OUTER_RUN_ID": "0" * 32, "ASH_OFFLINE": "YES", "PATH": "/usr/bin"}
        )
        assert "ASH_OUTER_RUN_ID" not in env
        assert env["ASH_OFFLINE"] == "YES"

    def test_proxy_settings_pass_only_with_a_network(self, layout):
        online = _policy(layout, SandboxRequirements(network=True))
        assert online.filter_env({"HTTPS_PROXY": "p"})["HTTPS_PROXY"] == "p"


@pytest.mark.unit
class TestBwrapCommandLine:
    def test_mount_order_and_namespaces(self, layout):
        backend = BwrapBackend()
        backend._executable = "/usr/bin/bwrap"
        policy = _policy(layout)
        plan = backend.plan(["/usr/bin/true"], {"PATH": "/usr/bin"}, policy)
        argv = plan.argv
        assert argv[0] == "/usr/bin/bwrap"
        for flag in ("--unshare-net", "--die-with-parent", "--new-session"):
            assert flag in argv
        assert argv[-2:] == ["--", "/usr/bin/true"]
        home = _as_argv(layout.home)
        results = _as_argv(layout.results)
        source = _as_argv(layout.source)
        home_tmpfs = argv.index(home) - 1
        assert argv[home_tmpfs] == "--tmpfs"
        source_bind = [
            i for i, a in enumerate(argv) if a == "--ro-bind" and argv[i + 1] == source
        ]
        results_bind = [
            i for i, a in enumerate(argv) if a == "--bind" and argv[i + 1] == results
        ]
        assert source_bind and results_bind
        # The writable results directory sits inside the read-only source here, so it
        # has to be mounted after it or the read-only bind would cover it.
        assert results_bind[0] > source_bind[0]

    def test_network_is_shared_only_when_granted(self, layout):
        backend = BwrapBackend()
        backend._executable = "/usr/bin/bwrap"
        policy = _policy(layout, SandboxRequirements(network=True))
        plan = backend.plan(["/usr/bin/true"], {}, policy)
        assert "--unshare-net" not in plan.argv

    def test_plan_before_probe_is_refused(self, layout):
        with pytest.raises(RuntimeError, match="probe"):
            BwrapBackend().plan(["/usr/bin/true"], {}, _policy(layout))


@pytest.mark.unit
class TestSocketFilterWrapper:
    """bwrap and firejail start the scanner through the seccomp socket filter.

    Their mounts hide most socket paths but not one in a directory they mount, and
    with a network they share the host's abstract Unix sockets, so the same filter
    Landlock uses has to run inside them. Measured on bwrap before this: the Nix
    daemon's socket under /nix answered, offline and online.
    """

    # firejail's plan reads os.getuid(), which Windows lacks; neither backend runs there.
    @pytest.mark.skipif(sys.platform == "win32", reason="no backend runs on Windows")
    @pytest.mark.parametrize("backend_class", [BwrapBackend, FirejailBackend])
    @pytest.mark.parametrize("network", [False, True])
    def test_the_scanner_runs_under_the_filter(self, layout, backend_class, network):
        backend = backend_class()
        backend._executable = "/usr/bin/sandbox"
        policy = _policy(layout, SandboxRequirements(network=network))
        argv = backend.plan(["/usr/bin/true", "--flag"], {}, policy).argv
        # The backend's own options end at its first "--"; the rest is what runs.
        inside = argv[argv.index("--") + 1 :]
        assert inside == [
            sys.executable,
            "-I",
            str(LANDLOCK_EXEC),
            "--socket-filter",
            "unix",
            "--",
            "/usr/bin/true",
            "--flag",
        ]


@pytest.mark.skipif(sys.platform == "win32", reason="no backend runs on Windows")
@pytest.mark.unit
class TestHostCachesAreNotWrittenInPlace:
    """A host cache is writable only where the write is thrown away.

    bwrap's overlay discards what a scanner writes to a cache. firejail, Landlock,
    sandbox-exec, and bwrap without overlay support would write in place, changing
    what later runs read: uv hard-links its cache into the tool environments a
    later unsandboxed `uv tool install` builds. So they mount every cache
    read-only, and point UV_CACHE_DIR, and each variable a scanner names in
    cache_env, at a private directory under the results directory that is
    removed after the spawn.
    """

    @pytest.fixture
    def cache(self, layout, monkeypatch):
        cache = layout.home.parent / "uv-cache"
        cache.mkdir()
        monkeypatch.setenv("UV_CACHE_DIR", str(cache))
        return cache

    def _plan(self, name, layout, requirements=SandboxRequirements(), overlay=False):
        backend = BACKENDS[name]()
        if hasattr(backend, "_executable"):
            backend._executable = f"/usr/bin/{name}"
        if name == "bwrap":
            backend._overlay = overlay
        return backend.plan(
            ["/usr/bin/true"], {"PATH": "/usr/bin"}, _policy(layout, requirements)
        )

    def _assert_private(self, plan, layout, variable):
        private = Path(plan.env[variable])
        assert private.is_dir()
        assert private.parent.name.startswith(".sandbox-cache-")
        assert _resolved([private.parent.parent]) == _resolved([layout.results])
        plan.run_cleanup()
        assert not private.parent.exists()

    def test_bwrap_keeps_its_throwaway_overlay(self, layout, cache, monkeypatch):
        # The plan probes the cache's filesystem with the real bwrap once per
        # filesystem (_overlay_over); on a host without bwrap that probe reads as a
        # refusal and the cache is mounted read-only, which is not what this test
        # measures. The probe is answered here, so the test reads the plan's shape.
        monkeypatch.setattr(backends_module, "_probe_run", lambda argv, env=None: None)
        plan = self._plan("bwrap", layout, overlay=True)
        real = _as_argv(cache)
        i = plan.argv.index("--overlay-src")
        assert plan.argv[i : i + 4] == ["--overlay-src", real, "--tmp-overlay", real]
        # Through the overlay the host cache itself is used, read and written.
        assert "UV_CACHE_DIR" not in plan.env
        plan.run_cleanup()

    def test_bwrap_without_an_overlay_mounts_caches_read_only(self, layout, cache):
        plan = self._plan("bwrap", layout, overlay=False)
        real = _as_argv(cache)
        binds = [
            plan.argv[i]
            for i in range(len(plan.argv) - 1)
            if plan.argv[i + 1] == real and plan.argv[i].startswith("--")
        ]
        assert binds == ["--ro-bind"], binds
        self._assert_private(plan, layout, "UV_CACHE_DIR")

    def test_firejail_mounts_caches_read_only(self, layout, cache):
        plan = self._plan("firejail", layout)
        real = _as_argv(cache)
        assert f"--read-only={real}" in plan.argv
        assert f"--read-write={real}" not in plan.argv
        self._assert_private(plan, layout, "UV_CACHE_DIR")

    def test_landlock_grants_caches_read_only(self, layout, cache):
        import json

        plan = self._plan("landlock", layout)
        document = json.loads(plan.argv[plan.argv.index("--policy") + 1])
        assert _as_argv(cache) in document["read_only"]
        assert _as_argv(cache) not in document["writable"]
        self._assert_private(plan, layout, "UV_CACHE_DIR")

    def test_sandbox_exec_grants_caches_read_only(self, layout, cache, tmp_path):
        backend = BACKENDS["sandbox-exec"]()
        profile = backend.profile(_policy(layout), tmp_path)
        writable = [line for line in profile.splitlines() if "file-write*" in line]
        assert not any(_as_argv(cache) in line for line in writable), writable
        assert any(
            _as_argv(cache) in line and "file-write*" not in line
            for line in profile.splitlines()
        )
        plan = self._plan("sandbox-exec", layout)
        self._assert_private(plan, layout, "UV_CACHE_DIR")

    @pytest.mark.parametrize("name", ["firejail", "landlock", "sandbox-exec"])
    def test_a_declared_cache_variable_gets_a_private_directory(
        self, layout, cache, name, tmp_path
    ):
        npm_cache = tmp_path / "npm-cache"
        npm_cache.mkdir()
        requirements = SandboxRequirements(
            cache_paths=(str(npm_cache),), cache_env=("npm_config_cache",)
        )
        plan = self._plan(name, layout, requirements)
        assert (
            Path(plan.env["npm_config_cache"]).parent
            == Path(plan.env["UV_CACHE_DIR"]).parent
        )
        self._assert_private(plan, layout, "npm_config_cache")

    def test_a_redirect_replaces_a_differently_cased_copy(self, layout, cache):
        # npm reads npm_config_* whatever the case, so a NPM_CONFIG_CACHE from the
        # parent would compete with the private npm_config_cache.
        backend = BACKENDS["landlock"]()
        requirements = SandboxRequirements(
            env_prefixes=("NPM_CONFIG_",), cache_env=("npm_config_cache",)
        )
        plan = backend.plan(
            ["/usr/bin/true"],
            {"PATH": "/usr/bin", "NPM_CONFIG_CACHE": "/host/npm"},
            _policy(layout, requirements),
        )
        assert "NPM_CONFIG_CACHE" not in plan.env
        self._assert_private(plan, layout, "npm_config_cache")

    def test_bundled_scanners_that_write_a_cache_declare_where(self):
        """Measured under Landlock with the caches read-only: these failed or lost
        findings until redirected (semgrep and opengrep cannot open their log under
        ~/.semgrep or ~/.opengrep; npm-audit lost the advisory ranges it reads
        from registry metadata it caches). grype's and trivy's databases are only
        read, so they are not redirected."""
        declared = {
            getattr(cls, "__name__"): getattr(cls, "sandbox_requirements").cache_env
            for cls in _bundled_scanner_classes()
            if isinstance(
                getattr(cls, "sandbox_requirements", None), SandboxRequirements
            )
        }
        assert declared["SemgrepScanner"] == ("XDG_CONFIG_HOME",)
        assert declared["OpengrepScanner"] == ("XDG_CONFIG_HOME",)
        assert declared["NpmAuditScanner"] == ("npm_config_cache",)
        assert declared["GrypeScanner"] == ()
        assert declared["TrivyRepoScanner"] == ()


#: Variables that name a local IPC endpoint: the SSH agent, the session bus, the
#: Docker and Podman sockets, and the per-user runtime directory holding them.
IPC_ENDPOINT_VARIABLES = {
    "SSH_AUTH_SOCK": "/run/user/1000/ssh-agent.socket",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
    "DOCKER_HOST": "unix:///run/docker.sock",
    "CONTAINER_HOST": "unix:///run/podman/podman.sock",
    "XDG_RUNTIME_DIR": "/run/user/1000",
}


def _bundled_scanner_classes():
    import importlib

    for module in (
        "ash_builtin",
        "ash_snyk_plugins",
        "ash_trivy_plugins",
        "ash_ferret_plugins",
    ):
        package = importlib.import_module(
            f"automated_security_helper.plugin_modules.{module}"
        )
        yield from package.ASH_SCANNERS


def _every_declared_requirement():
    """The sandbox requirements every bundled scanner declares on its class."""
    found = []
    for scanner in _bundled_scanner_classes():
        declared = getattr(scanner, "sandbox_requirements", None)
        # detect-secrets computes its own per instance; it declares no
        # environment, only a network.
        if isinstance(declared, SandboxRequirements):
            found.append(declared)
    return found


@pytest.mark.unit
class TestIpcEndpointVariables:
    """None of IPC_ENDPOINT_VARIABLES reaches a scanner, on any backend.

    The sockets themselves are out of reach (the escape suite asserts that under a
    real scan); dropping the variables keeps a scanner from learning where they
    are and from passing the address to a tool that would use it.
    """

    @pytest.mark.parametrize("network", [False, True])
    def test_no_declared_prefix_lets_one_through(self, layout, network):
        declared = _every_declared_requirement()
        assert len(declared) >= 10, "too few scanners found to mean anything"
        everything = SandboxRequirements(
            network=network,
            env_prefixes=tuple(p for r in declared for p in r.env_prefixes),
            env_names=tuple(n for r in declared for n in r.env_names),
        )
        env = _policy(layout, everything).filter_env(
            {"PATH": "/usr/bin", **IPC_ENDPOINT_VARIABLES}
        )
        assert env["PATH"] == "/usr/bin"
        assert not set(IPC_ENDPOINT_VARIABLES) & set(env)

    @pytest.mark.skipif(sys.platform == "win32", reason="no backend runs on Windows")
    @pytest.mark.parametrize("name", sorted(BACKENDS))
    @pytest.mark.parametrize("network", [False, True])
    def test_no_backend_hands_one_to_the_scanner(self, layout, name, network):
        backend = BACKENDS[name]()
        if hasattr(backend, "_executable"):
            # Planning needs only the path; nothing is started.
            backend._executable = f"/usr/bin/{name}"
        policy = _policy(layout, SandboxRequirements(network=network))
        plan = backend.plan(
            ["/usr/bin/true"], {"PATH": "/usr/bin", **IPC_ENDPOINT_VARIABLES}, policy
        )
        try:
            assert plan.env["PATH"] == "/usr/bin"
            assert not set(IPC_ENDPOINT_VARIABLES) & set(plan.env), name
        finally:
            plan.run_cleanup()


def _context(tmp_path, mode="bwrap"):
    config = AshConfig(sandbox=SandboxConfig(mode=mode))
    return SimpleNamespace(
        config=config, source_dir=tmp_path, output_dir=tmp_path / "out"
    )


def _plugin(requirements=SandboxRequirements(), name="grype"):
    return SimpleNamespace(
        config=SimpleNamespace(name=name),
        sandbox_requirements=requirements,
        results_dir=None,
    )


@pytest.mark.unit
class TestScope:
    def test_mode_off_gives_no_scope(self, tmp_path):
        assert (
            scanner_sandbox_scope(_plugin(), _context(tmp_path, "off"), tmp_path)
            is None
        )

    def test_a_context_without_a_real_config_gives_no_scope(self, tmp_path):
        context = SimpleNamespace(
            config=object(), source_dir=tmp_path, output_dir=tmp_path
        )
        assert scanner_sandbox_scope(_plugin(), context, tmp_path) is None

    def test_an_unavailable_backend_raises_with_its_reason(self, tmp_path, monkeypatch):
        clear_backend_cache()
        monkeypatch.setattr(
            scope_module.BACKENDS["bwrap"], "probe", lambda self: "no bwrap here"
        )
        try:
            with pytest.raises(SandboxUnavailable, match="no bwrap here"):
                scanner_sandbox_scope(_plugin(), _context(tmp_path), tmp_path)
        finally:
            clear_backend_cache()

    def test_auto_reports_every_backend_it_tried(self, tmp_path, monkeypatch):
        clear_backend_cache()
        for backend in scope_module.BACKENDS.values():
            monkeypatch.setattr(backend, "probe", lambda self: "absent")
        monkeypatch.setattr(scope_module.platform, "system", lambda: "Linux")
        try:
            with pytest.raises(SandboxUnavailable) as raised:
                scanner_sandbox_scope(_plugin(), _context(tmp_path, "auto"), tmp_path)
            for name in ("bwrap", "firejail", "landlock"):
                assert name in str(raised.value)
        finally:
            clear_backend_cache()

    def test_windows_auto_names_the_alternatives(self, tmp_path, monkeypatch):
        clear_backend_cache()
        monkeypatch.setattr(scope_module.platform, "system", lambda: "Windows")
        try:
            with pytest.raises(SandboxUnavailable, match="WSL2"):
                scanner_sandbox_scope(_plugin(), _context(tmp_path, "auto"), tmp_path)
        finally:
            clear_backend_cache()

    def test_prepare_spawn_is_a_no_op_outside_a_scope(self):
        assert prepare_spawn(["/usr/bin/true"], None, None) is None

    def test_prepare_spawn_wraps_inside_a_scope_and_not_after(self, tmp_path):
        class Recorder:
            name = "recorder"

            def plan(self, argv, env, policy):
                return SpawnPlan(argv=["wrapped", *argv], env=dict(env))

        scope = scope_module.SandboxScope(
            backend=Recorder(),  # type: ignore[arg-type]
            scanner_name="grype",
            requirements=SandboxRequirements(),
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            results_dir=tmp_path / "out" / "scanners" / "grype",
            scan_target=tmp_path,
            offline=True,
        )
        with sandbox_scope(scope):
            plan = prepare_spawn(["/usr/bin/true"], {"PATH": "/usr/bin"}, None)
        assert plan is not None and plan.argv[0] == "wrapped"
        assert prepare_spawn(["/usr/bin/true"], None, None) is None

    def test_a_shell_command_inside_a_scope_is_refused(self, tmp_path):
        from automated_security_helper.utils.subprocess_utils import (
            SPAWN_FAILURE_RETURNCODE,
            run_command,
        )

        scope = scope_module.SandboxScope(
            backend=object(),  # type: ignore[arg-type]
            scanner_name="grype",
            requirements=SandboxRequirements(),
            source_dir=tmp_path,
            output_dir=tmp_path,
            results_dir=tmp_path / "r",
            scan_target=None,
            offline=True,
        )
        with sandbox_scope(scope):
            result = run_command(["echo hi"], shell=True)  # nosec B604 - asserts the sandbox refuses a shell command
        # Reported as a command that could not start (SandboxUnavailable is an
        # OSError), never run unwrapped.
        assert result.returncode == SPAWN_FAILURE_RETURNCODE
        assert "shell" in result.stderr

    def test_a_backend_that_fails_while_planning_starts_nothing(
        self, tmp_path, monkeypatch
    ):
        """plan() raising RecursionError (a deep or looping directory layout) is
        reported as a command that could not start, or raised, by every spawn
        helper: no process starts, sandboxed or not."""
        import subprocess

        from automated_security_helper.utils import subprocess_utils

        class Exploding:
            name = "exploding"

            def plan(self, argv, env, policy):
                raise RecursionError("maximum recursion depth exceeded")

        started = []

        def record(*args, **kwargs):
            started.append(args)
            raise AssertionError("a process was started")

        monkeypatch.setattr(subprocess, "run", record)
        monkeypatch.setattr(subprocess, "Popen", record)
        scope = scope_module.SandboxScope(
            backend=Exploding(),  # type: ignore[arg-type]
            scanner_name="grype",
            requirements=SandboxRequirements(),
            source_dir=tmp_path,
            output_dir=tmp_path,
            results_dir=tmp_path / "r",
            scan_target=None,
            offline=True,
        )
        true = "/usr/bin/true"
        with sandbox_scope(scope):
            result = subprocess_utils.run_command([true])
            streamed = subprocess_utils.run_command_stream_output([true])
            with pytest.raises(RecursionError):
                subprocess_utils.spawn_run([true])
            with pytest.raises(RecursionError):
                subprocess_utils.create_process_with_pipes([true])

        assert result.returncode == subprocess_utils.SPAWN_FAILURE_RETURNCODE
        assert streamed == subprocess_utils.SPAWN_FAILURE_RETURNCODE
        assert started == []


@pytest.mark.unit
class TestPolicyEdges:
    """Symlinked results directories, tool prefixes under home, and the env filter."""

    def test_a_symlinked_results_directory_is_refused(self, layout, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (layout.output / "scanners").mkdir(parents=True)
        layout.results.symlink_to(elsewhere, target_is_directory=True)
        with pytest.raises(SandboxUnavailable, match="symlink"):
            _policy(layout)

    def test_a_symlink_above_the_results_directory_is_refused(self, layout, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "grype").mkdir(parents=True)
        (layout.output / "scanners").symlink_to(elsewhere, target_is_directory=True)
        with pytest.raises(SandboxUnavailable, match="symlink"):
            _policy(layout)

    def test_a_tool_prefix_directly_under_home_is_not_mounted(self, layout):
        cargo_bin = layout.home / ".cargo" / "bin"
        cargo_bin.mkdir(parents=True)
        (layout.home / ".cargo" / "credentials.toml").write_text("token = 'x'\n")
        tool = cargo_bin / "tool"
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)
        exposed = _resolved(_policy(layout, argv0=str(tool)).read_only)
        assert Path(os.path.realpath(layout.home / ".cargo")) not in exposed
        assert Path(os.path.realpath(cargo_bin)) in exposed

    def test_a_deep_tool_prefix_under_home_is_mounted(self, layout):
        node_bin = layout.home / ".nvm" / "versions" / "node" / "v22" / "bin"
        node_bin.mkdir(parents=True)
        tool = node_bin / "node"
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)
        exposed = _resolved(_policy(layout, argv0=str(tool)).read_only)
        assert Path(os.path.realpath(node_bin.parent)) in exposed

    def test_a_non_bin_path_entry_inside_home_is_not_mounted(self, layout, monkeypatch):
        config_dir = layout.home / ".config" / "tool"
        config_dir.mkdir(parents=True)
        monkeypatch.setenv("PATH", str(config_dir))
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(config_dir)) not in exposed

    def test_credential_shaped_names_under_allowed_prefixes_are_dropped(self, layout):
        env = _policy(
            layout
        ).filter_env(
            {
                "UV_PUBLISH_TOKEN": "s",
                "UV_INDEX_PRIVATE_PASSWORD": "s",
                # A fake credential in URL form: the filter must drop it.
                "UV_INDEX_URL": "https://user:tok@example.invalid/simple",  # pragma: allowlist secret
                "UV_CACHE_DIR": "/cache",
                "ASH_API_KEY": "s",
            }
        )
        assert env.get("UV_CACHE_DIR") == "/cache"
        for dropped in (
            "UV_PUBLISH_TOKEN",
            "UV_INDEX_PRIVATE_PASSWORD",
            "UV_INDEX_URL",
            "ASH_API_KEY",
        ):
            assert dropped not in env, dropped

    def test_a_scanner_can_name_the_credential_it_needs(self, layout):
        policy = _policy(
            layout,
            SandboxRequirements(env_prefixes=("SNYK_",), env_names=("SNYK_TOKEN",)),
        )
        env = policy.filter_env({"SNYK_TOKEN": "t", "SNYK_OTHER_TOKEN": "x"})
        assert env["SNYK_TOKEN"] == "t"
        assert "SNYK_OTHER_TOKEN" not in env

    def test_a_refusing_scope_fails_every_spawn(self):
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            _ACTIVE,
        )
        from automated_security_helper.utils.subprocess_utils import spawn_run

        scope_reset = _ACTIVE.set(RefusingScope("grype", "no bwrap here"))
        try:
            with pytest.raises(SandboxUnavailable, match="no bwrap here"):
                # An anchored program: on Windows "/usr/bin/true" has no drive, and
                # spawn_run refuses that before it asks the scope.
                spawn_run([os.path.abspath("/usr/bin/true")])
        finally:
            _ACTIVE.reset(scope_reset)


@pytest.mark.unit
class TestSymlinkedOutputDirectory:
    """The scanned repository cannot choose where the output directory really is.

    The output directory is mounted into every sandbox and written by ASH, so a
    link the repository commits on the way to it (``build -> /host/dir`` with
    ``--output-dir build/ash``) would hand the repository a host directory.
    """

    @pytest.fixture
    def tree(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        target = tmp_path / "elsewhere"
        (target / "deep").mkdir(parents=True)
        return SimpleNamespace(source=source, target=target, root=tmp_path)

    def test_a_link_on_the_way_down_is_refused(self, tree):
        (tree.source / "build").symlink_to(tree.target, target_is_directory=True)
        with pytest.raises(SandboxUnavailable, match="build is a symlink"):
            refuse_symlinked_output_dir(tree.source, tree.source / "build" / "ash")

    def test_the_default_location_as_a_link_is_refused(self, tree):
        (tree.source / ".ash").mkdir()
        (tree.source / ".ash" / "ash_output").symlink_to(
            tree.target, target_is_directory=True
        )
        with pytest.raises(SandboxUnavailable, match="ash_output is a symlink"):
            refuse_symlinked_output_dir(
                tree.source, tree.source / ".ash" / "ash_output"
            )

    def test_a_dotdot_after_a_link_is_refused(self, tree):
        # Reads as <source>/out; the kernel resolves it under the link's target.
        (tree.source / "build").symlink_to(
            tree.target / "deep", target_is_directory=True
        )
        with pytest.raises(SandboxUnavailable, match="build is a symlink"):
            refuse_symlinked_output_dir(
                tree.source, tree.source / "build" / ".." / "out"
            )

    def test_an_output_directory_that_is_a_link_is_refused_outside_the_tree(self, tree):
        link = tree.root / "out-link"
        link.symlink_to(tree.target, target_is_directory=True)
        with pytest.raises(SandboxUnavailable, match="out-link is a symlink"):
            refuse_symlinked_output_dir(tree.source, link)

    def test_ordinary_output_directories_are_accepted(self, tree):
        refuse_symlinked_output_dir(tree.source, tree.root / "out")
        refuse_symlinked_output_dir(tree.source, tree.source / ".ash" / "ash_output")
        (tree.source / ".ash" / "ash_output").mkdir(parents=True)
        refuse_symlinked_output_dir(tree.source, tree.source / ".ash" / "ash_output")

    def test_a_link_at_or_above_the_source_directory_is_the_operators(self, tree):
        # A home directory that links elsewhere, or macOS's /var -> /private/var.
        real = tree.root / "real"
        (real / "src").mkdir(parents=True)
        link = tree.root / "home-link"
        link.symlink_to(real, target_is_directory=True)
        source = link / "src"
        refuse_symlinked_output_dir(source, source / ".ash" / "ash_output")
        refuse_symlinked_output_dir(source, link / "out")

    @pytest.mark.parametrize("mode", ["off", "landlock"])
    def test_a_scan_stops_before_writing_through_it_in_every_mode(self, tree, mode):
        # The orchestrator checks before ensure_directories, which would create
        # and clear subdirectories under the link's target.
        from automated_security_helper.core.exceptions import ASHValidationError
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        (tree.source / "build").symlink_to(tree.target, target_is_directory=True)
        orchestrator = ASHScanOrchestrator(
            source_dir=tree.source, output_dir=tree.source / "build" / "ash"
        )
        orchestrator.config = AshConfig(sandbox=SandboxConfig(mode=mode))
        # Whatever the mode: the check is not the sandbox's alone.
        with pytest.raises(ASHValidationError, match="build is a symlink"):
            orchestrator._refuse_linked_output_dir()
        assert sorted(p.name for p in tree.target.iterdir()) == ["deep"]

    def test_every_spawn_policy_refuses_it(self, layout, tmp_path):
        target = tmp_path / "elsewhere"
        target.mkdir()
        (layout.source / "build").symlink_to(target, target_is_directory=True)
        with pytest.raises(SandboxUnavailable, match="build is a symlink"):
            _policy(
                layout,
                output_dir=layout.source / "build" / "ash",
                results_dir=layout.source / "build" / "ash" / "scanners" / "grype",
            )


_BUILTIN = "automated_security_helper.plugin_modules.ash_builtin"


@pytest.mark.unit
class TestProbeScope:
    def test_off_mode_leaves_probes_alone(self, tmp_path):
        from automated_security_helper.utils.sandbox.scope import (
            active_scope,
            plugin_probe_scope,
        )

        with plugin_probe_scope(_plugin(), _context(tmp_path, "off")):
            assert active_scope() is None

    def test_an_unavailable_sandbox_makes_probes_refuse(self, tmp_path, monkeypatch):
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            active_scope,
            plugin_probe_scope,
        )

        clear_backend_cache()
        monkeypatch.setattr(
            scope_module.BACKENDS["bwrap"], "probe", lambda self: "no bwrap here"
        )
        try:
            with plugin_probe_scope(_plugin(), _context(tmp_path)):
                active = active_scope()
                assert isinstance(active, RefusingScope)
                assert "no bwrap here" in active.reason
            assert active_scope() is None
        finally:
            clear_backend_cache()

    @pytest.mark.parametrize(
        "plugin_path, own_name",
        [
            (f"{_BUILTIN}.scanners.bandit_scanner.BanditScanner", "bandit"),
            (f"{_BUILTIN}.converters.jupyter_converter.JupyterConverter", "jupyter"),
        ],
        ids=["scanner", "converter"],
    )
    def test_a_plugin_class_gets_a_sandbox_for_its_construction_probes(
        self, tmp_path, monkeypatch, plugin_path, own_name
    ):
        """Before an instance exists, the probes run under the plugin's own name.

        The class is what the scan and convert phases pass while constructing a
        plugin, whose model_post_init runs ``uv tool run <tool> --version``. It has
        no config instance, so it must not be judged a plugin a config file renamed.
        """
        import importlib

        from automated_security_helper.utils.sandbox.scope import (
            SandboxScope,
            active_scope,
            plugin_probe_scope,
        )

        module_name, _, attribute = plugin_path.rpartition(".")
        plugin_class = getattr(importlib.import_module(module_name), attribute)

        class Recorder:
            name = "recorder"

            def probe(self):
                return None

        clear_backend_cache()
        monkeypatch.setitem(scope_module.BACKENDS, "bwrap", Recorder)
        try:
            with plugin_probe_scope(plugin_class, _context(tmp_path)):
                active = active_scope()
                assert isinstance(active, SandboxScope), (
                    f"the construction probes of {own_name} were refused: "
                    f"{getattr(active, 'reason', active)!r}"
                )
                assert active.scanner_name == own_name
        finally:
            clear_backend_cache()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="no backend runs on Windows: firejail is Linux-only and its plan reads "
    "os.getuid()",
)
@pytest.mark.unit
class TestFirejailHidesBothHomes:
    """firejail hides the passwd entry's home; HOME's directory needs its own blacklist.

    firejail is setuid and takes the home it makes private, and the one a whitelist
    inside $HOME applies to, from getpwuid() (init_cfg in firejail's main.c), never
    from HOME. The plan decided ``--private`` and its whitelists against HOME's
    directory, so with HOME elsewhere it hid the passwd home by luck (``--private``)
    or not at all (a whitelist under HOME), and HOME's own directory, where the
    scanner is told its home is, stayed readable unless it was under /tmp.
    """

    @pytest.fixture(autouse=True)
    def _a_user_id_where_the_platform_has_none(self, monkeypatch):
        """firejail's plan names /run/user/<uid> (backends.py), and Windows has no getuid.

        The plan is only computed here, never run, so a fixed id gives the assertions
        below the same argv they read on Linux.
        """
        if not hasattr(os, "getuid"):
            monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)

    @pytest.fixture
    def fake_tmp(self, tmp_path, monkeypatch):
        """Stand in for /tmp, so no test writes to the real one."""
        root = tmp_path / "fake-tmp"
        root.mkdir()
        monkeypatch.setattr(backends_module, "_TMP_ROOT", root, raising=False)
        return root

    def _argv(self, layout):
        backend = FirejailBackend()
        backend._executable = "/fj"
        return backend.plan(["/usr/bin/true"], {}, _policy(layout)).argv

    def test_home_is_the_passwd_home(self, layout, fake_tmp):
        """Unchanged: --private hides the one home, and nothing is blacklisted."""
        argv = self._argv(layout)
        assert "--private" in argv
        assert not [a for a in argv if a.startswith("--blacklist=") and "home" in a]

    def test_home_elsewhere_with_nothing_in_the_passwd_home(
        self, layout, fake_tmp, tmp_path, monkeypatch
    ):
        passwd_home = tmp_path / "passwd-home"
        passwd_home.mkdir()
        _fake_passwd_home(monkeypatch, passwd_home)
        argv = self._argv(layout)
        assert "--private" in argv
        assert f"--blacklist={_as_argv(layout.home)}" in argv

    def test_home_elsewhere_with_a_tool_in_the_passwd_home(
        self, layout, fake_tmp, tmp_path, monkeypatch
    ):
        """The whitelist applies to the passwd home, so it is decided against that."""
        passwd_home = tmp_path / "passwd-home"
        venv_bin = passwd_home / "work" / "venv" / "bin"
        venv_bin.mkdir(parents=True)
        _fake_passwd_home(monkeypatch, passwd_home)
        monkeypatch.setenv("PATH", str(venv_bin))
        argv = self._argv(layout)
        assert f"--whitelist={_as_argv(venv_bin)}" in argv
        assert "--private" not in argv
        assert f"--blacklist={_as_argv(layout.home)}" in argv

    def test_home_elsewhere_under_tmp_needs_no_blacklist(
        self, layout, fake_tmp, tmp_path, monkeypatch
    ):
        """/tmp is already hidden by --private-tmp or by its own whitelists."""
        home = fake_tmp / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        passwd_home = tmp_path / "passwd-home"
        passwd_home.mkdir()
        _fake_passwd_home(monkeypatch, passwd_home)
        argv = self._argv(layout)
        assert not [a for a in argv if a.startswith("--blacklist=") and "home" in a]
        assert "--private" in argv


@pytest.mark.unit
class TestTheBackendsHideADirectoryAHomeLinksTo:
    """~/.local -> /persist/me/.local: the backends hide the target like a home.

    sandbox-exec reads from "/" and takes back the homes, and firejail shows all
    that is outside the home, so a directory a link at the top of a home names
    stayed readable whatever the policy granted. sandbox-exec now denies reading it
    with the homes, before the policy's allows, and firejail blacklists it, or,
    where the policy grants a path inside it, every entry beside the way to that
    path. A link to a system directory is not hidden.
    """

    @pytest.fixture
    def fake_tmp(self, tmp_path, monkeypatch):
        """Stand in for /tmp: firejail skips a link target under the real one by
        design (its private tmp hides it already), and tmp_path is under /tmp on
        Linux."""
        root = tmp_path / "fake-tmp"
        root.mkdir()
        monkeypatch.setattr(backends_module, "_TMP_ROOT", root, raising=False)
        return root

    @pytest.fixture(params=["HOME", "passwd home"])
    def linked(self, request, layout, tmp_path, monkeypatch, fake_tmp):
        if request.param == "HOME":
            home = layout.home
            # The layout's own ~/.local makes way for the link.
            shutil.rmtree(home / ".local")
        else:
            home = tmp_path / "passwd-home"
            (home / ".ssh").mkdir(parents=True)
            _fake_passwd_home(monkeypatch, home)
        elsewhere = tmp_path / "persist" / "me" / ".local"
        (elsewhere / "share" / "keyrings").mkdir(parents=True)
        (elsewhere / "share" / "keyrings" / "login.keyring").write_text("x")
        tool = elsewhere / "bin" / "tool"
        tool.parent.mkdir()
        tool.write_bytes(b"\x7fELF")
        tool.chmod(0o755)
        (home / ".local").symlink_to(elsewhere)
        return SimpleNamespace(
            home=home, elsewhere=elsewhere, tool=home / ".local/bin/tool"
        )

    @staticmethod
    def _sbpl_after_deny(policy, tmp_path, target):
        lines = SandboxExecBackend().profile(policy, tmp_path / "ptmp").splitlines()
        deny = f'(deny file-read* (subpath "{_as_argv(target)}"))'
        assert deny in lines, deny
        at = lines.index(deny)
        allows = [
            line for line in lines[at + 1 :] if line.startswith("(allow file-read")
        ]
        return at, lines, set().union(*(_subpaths(line) for line in allows))

    @staticmethod
    def _firejail(policy, argv0="/usr/bin/true"):
        backend = FirejailBackend()
        backend._executable = "/fj"
        return backend.plan([str(argv0)], {}, policy).argv

    def test_sandbox_exec_denies_it_before_the_policys_allows(
        self, layout, linked, tmp_path
    ):
        at, lines, allowed = self._sbpl_after_deny(
            _policy(layout, argv0="/usr/bin/true"), tmp_path, linked.elsewhere
        )
        read_everywhere = lines.index('(allow file-read* (subpath "/"))')
        assert read_everywhere < at
        keyring = linked.elsewhere / "share" / "keyrings" / "login.keyring"
        for kept in (linked.elsewhere, linked.elsewhere / "share", keyring):
            real = Path(_as_argv(kept))
            covering = [
                p for p in allowed if Path(p) == real or Path(p) in real.parents
            ]
            assert not covering, (kept, covering)

    def test_sandbox_exec_gives_a_tools_own_bin_back(self, layout, linked, tmp_path):
        policy = _policy(layout, argv0=str(linked.tool))
        _at, _lines, allowed = self._sbpl_after_deny(policy, tmp_path, linked.elsewhere)
        assert _as_argv(linked.elsewhere / "bin") in allowed
        assert _as_argv(linked.elsewhere / "share") not in allowed
        assert _as_argv(linked.elsewhere) not in allowed

    def test_firejail_blacklists_it(self, layout, linked):
        argv = self._firejail(_policy(layout, argv0="/usr/bin/true"))
        assert f"--blacklist={_as_argv(linked.elsewhere)}" in argv

    def test_firejail_hides_all_but_a_tools_own_bin(self, layout, linked):
        policy = _policy(layout, argv0=str(linked.tool))
        argv = self._firejail(policy, linked.tool)
        assert f"--blacklist={_as_argv(linked.elsewhere / 'share')}" in argv
        assert f"--blacklist={_as_argv(linked.elsewhere / 'bin')}" not in argv
        assert f"--blacklist={_as_argv(linked.elsewhere)}" not in argv

    def test_firejail_hides_a_directory_a_link_inside_it_names(
        self, layout, linked, tmp_path
    ):
        """~/.local/extra -> /persist/other: a link beside the way to the tool's
        bin names a directory of the user's too, and firejail shows it."""
        other = tmp_path / "persist" / "other"
        (other / "keyrings").mkdir(parents=True)
        (linked.elsewhere / "extra").symlink_to(other)

        argv = self._firejail(_policy(layout, argv0=str(linked.tool)), linked.tool)

        assert f"--blacklist={_as_argv(other)}" in argv
        assert f"--blacklist={_as_argv(linked.elsewhere / 'bin')}" not in argv
        assert f"--blacklist={_as_argv(linked.elsewhere)}" not in argv

    def test_firejail_ends_for_links_that_lead_back(self, layout, linked, tmp_path):
        other = tmp_path / "persist" / "other"
        other.mkdir(parents=True)
        (linked.elsewhere / "extra").symlink_to(other)
        (other / "back").symlink_to(linked.elsewhere)

        argv = self._firejail(_policy(layout, argv0=str(linked.tool)), linked.tool)

        assert f"--blacklist={_as_argv(other)}" in argv

    def test_firejail_leaves_a_link_to_a_system_directory_inside_it(
        self, layout, linked
    ):
        (linked.elsewhere / "system").symlink_to("/usr")

        argv = self._firejail(_policy(layout, argv0=str(linked.tool)), linked.tool)

        assert f"--blacklist={_as_argv('/usr')}" not in argv
        assert f"--blacklist={_as_argv(linked.elsewhere / 'share')}" in argv

    def test_firejail_hides_a_directory_a_link_inside_a_hidden_entry_names(
        self, layout, linked, tmp_path
    ):
        """~/.local/share/extra -> /persist/other: share is blacklisted whole, and
        what a link inside it names is a directory of the user's too."""
        other = tmp_path / "persist" / "other"
        (other / "keyrings").mkdir(parents=True)
        (linked.elsewhere / "share" / "extra").symlink_to(other)

        argv = self._firejail(_policy(layout, argv0=str(linked.tool)), linked.tool)

        assert f"--blacklist={_as_argv(linked.elsewhere / 'share')}" in argv
        assert f"--blacklist={_as_argv(other)}" in argv

    def test_firejail_hides_a_directory_a_link_inside_an_ungranted_target_names(
        self, layout, linked, tmp_path
    ):
        """The policy grants nothing inside ~/.local's target, so the target is
        blacklisted whole; a link at its top still names another directory."""
        other = tmp_path / "persist" / "other"
        (other / "keyrings").mkdir(parents=True)
        (linked.elsewhere / "extra").symlink_to(other)

        argv = self._firejail(_policy(layout, argv0="/usr/bin/true"))

        assert f"--blacklist={_as_argv(linked.elsewhere)}" in argv
        assert f"--blacklist={_as_argv(other)}" in argv

    def test_firejail_follows_a_link_below_the_first_directory_level(
        self, layout, linked, tmp_path
    ):
        """The tool sits at ~/.local/a/b/bin; the link is in ~/.local/a, beside
        the way to it and one level down."""
        other = tmp_path / "persist" / "other"
        (other / "keyrings").mkdir(parents=True)
        tool = linked.elsewhere / "a" / "b" / "bin" / "tool"
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b"\x7fELF")
        tool.chmod(0o755)
        (linked.elsewhere / "a" / "extra").symlink_to(other)

        argv = self._firejail(
            _policy(layout, argv0=str(linked.home / ".local/a/b/bin/tool")),
            linked.home / ".local/a/b/bin/tool",
        )

        assert f"--blacklist={_as_argv(other)}" in argv
        assert f"--blacklist={_as_argv(linked.elsewhere / 'a' / 'b')}" not in argv

    def test_firejail_hides_the_other_entries_of_a_directory_above_the_target(
        self, layout, linked, tmp_path
    ):
        """~/.local/up -> /persist (which holds me/.local): the rest of /persist is
        the user's, and the way to the tool's bin stays."""
        persist = tmp_path / "persist"
        (persist / "other" / "keyrings").mkdir(parents=True)
        (linked.elsewhere / "up").symlink_to(persist)

        argv = self._firejail(_policy(layout, argv0=str(linked.tool)), linked.tool)

        assert f"--blacklist={_as_argv(persist / 'other')}" in argv
        assert f"--blacklist={_as_argv(persist)}" not in argv
        assert f"--blacklist={_as_argv(persist / 'me')}" not in argv
        assert f"--blacklist={_as_argv(linked.elsewhere / 'bin')}" not in argv

    def test_firejail_ends_for_two_linked_directories_that_both_hold_grants(
        self, layout, linked, tmp_path
    ):
        """Each links to the other and the policy grants a path in each."""
        other = tmp_path / "persist" / "other"
        (other / "data").mkdir(parents=True)
        (other / "junk").mkdir()
        (linked.elsewhere / "extra").symlink_to(other)
        (other / "back").symlink_to(linked.elsewhere)

        argv = self._firejail(
            _policy(
                layout, argv0=str(linked.tool), extra_read_paths=[str(other / "data")]
            ),
            linked.tool,
        )

        assert f"--blacklist={_as_argv(other / 'junk')}" in argv
        assert f"--blacklist={_as_argv(other / 'data')}" not in argv
        assert f"--blacklist={_as_argv(other)}" not in argv
        assert f"--blacklist={_as_argv(linked.elsewhere / 'share')}" in argv

    def test_firejail_leaves_a_link_to_a_home_directory_inside_it_to_the_home(
        self, layout, linked
    ):
        """~/.local/mine -> ~/.ssh: a home is handled as a home, and is not hidden
        a second time as the directory a link names."""
        (linked.elsewhere / "mine").symlink_to(linked.home / ".ssh")

        argv = self._firejail(_policy(layout, argv0=str(linked.tool)), linked.tool)

        assert f"--blacklist={_as_argv(linked.home / '.ssh')}" not in argv
        assert f"--blacklist={_as_argv(linked.elsewhere / 'share')}" in argv

    def test_firejail_hides_a_file_a_link_at_the_top_of_a_home_names(
        self, layout, linked, tmp_path
    ):
        """~/.netrc -> /persist/me/netrc: a file of the user's outside the home."""
        netrc = tmp_path / "persist" / "me" / "netrc"
        netrc.write_text("machine example login me password x\n")
        (linked.home / ".netrc").symlink_to(netrc)

        argv = self._firejail(_policy(layout, argv0=str(linked.tool)), linked.tool)

        assert f"--blacklist={_as_argv(netrc)}" in argv

    def test_sandbox_exec_denies_a_file_a_link_at_the_top_of_a_home_names(
        self, layout, linked, tmp_path
    ):
        netrc = tmp_path / "persist" / "me" / "netrc"
        netrc.write_text("machine example login me password x\n")
        (linked.home / ".netrc").symlink_to(netrc)

        at, lines, allowed = self._sbpl_after_deny(
            _policy(layout, argv0="/usr/bin/true"), tmp_path, netrc
        )

        read_everywhere = lines.index('(allow file-read* (subpath "/"))')
        assert read_everywhere < at
        # No allow after the deny covers the file or a directory above it.
        real = Path(_as_argv(netrc))
        covering = [p for p in allowed if Path(p) == real or Path(p) in real.parents]
        assert not covering, covering

    def test_firejail_keeps_a_scanned_tree_kept_in_a_linked_directory(
        self, layout, tmp_path, fake_tmp
    ):
        """~/code -> /data/code with the scanned repository in it: the repository is
        the policy's own path there, so only what is beside it is blacklisted."""
        code = tmp_path / "data" / "code"
        repo = code / "repo"
        output = repo / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (code / "other" / "notes").mkdir(parents=True)
        (layout.home / "code").symlink_to(code)

        policy = _policy(
            layout,
            argv0="/usr/bin/true",
            source_dir=repo,
            output_dir=output,
            results_dir=output / "scanners" / "grype",
            scan_target=repo,
            cwd=repo,
        )
        argv = self._firejail(policy)

        blacklisted = [a.split("=", 1)[1] for a in argv if a.startswith("--blacklist=")]
        assert _as_argv(code / "other") in blacklisted
        for shown in (code, repo, output):
            assert _as_argv(shown) not in blacklisted, shown

    def test_firejail_leaves_a_file_a_link_names_inside_the_scanned_tree(
        self, layout, stand_in_tmp, tmp_path
    ):
        """~/.gitconfig -> /persist/dotfiles/gitconfig, with /persist/dotfiles the
        tree being scanned: the policy grants that tree, and the file in it is
        read like the rest of it, not blacklisted."""
        repo = tmp_path / "persist" / "dotfiles"
        output = repo / ".ash" / "ash_output"
        output.mkdir(parents=True)
        config = repo / "gitconfig"
        config.write_text("[user]\n\tname = me\n")
        (layout.home / ".gitconfig").symlink_to(config)

        policy = _policy(
            layout,
            argv0="/usr/bin/true",
            source_dir=repo,
            output_dir=output,
            results_dir=output / "scanners" / "grype",
            scan_target=repo,
            cwd=repo,
        )
        blacklisted = self._blacklisted(self._firejail(policy))

        inside = [
            b
            for b in blacklisted
            if b == _as_argv(repo) or b.startswith(_as_argv(repo) + "/")
        ]
        assert not inside, inside

    def test_firejail_still_hides_a_file_a_link_names_beside_the_scanned_tree(
        self, layout, stand_in_tmp, tmp_path
    ):
        """The control: a file outside the granted tree is hidden as before."""
        repo = tmp_path / "persist" / "dotfiles"
        output = repo / ".ash" / "ash_output"
        output.mkdir(parents=True)
        netrc = tmp_path / "persist" / "netrc"
        netrc.write_text("machine example login me password x\n")
        (layout.home / ".netrc").symlink_to(netrc)

        policy = _policy(
            layout,
            argv0="/usr/bin/true",
            source_dir=repo,
            output_dir=output,
            results_dir=output / "scanners" / "grype",
            scan_target=repo,
            cwd=repo,
        )
        blacklisted = self._blacklisted(self._firejail(policy))

        assert _as_argv(netrc) in blacklisted

    def test_a_link_to_a_system_directory_is_not_hidden(self, layout, tmp_path):
        (layout.home / "u").symlink_to("/usr")
        policy = _policy(layout, argv0="/usr/bin/true")
        lines = SandboxExecBackend().profile(policy, tmp_path / "ptmp").splitlines()
        assert not [
            line
            for line in lines
            if line.startswith("(deny file-read*") and _as_argv("/usr") in line
        ]
        argv = self._firejail(policy)
        assert f"--blacklist={_as_argv('/usr')}" not in argv

    @pytest.fixture
    def stand_in_tmp(self, tmp_path, monkeypatch):
        """Stand in for /tmp, so the tests neither depend on nor write the real one."""
        root = tmp_path / "stand-in-tmp"
        root.mkdir()
        monkeypatch.setattr(backends_module, "_TMP_ROOT", root, raising=False)
        return root

    @pytest.fixture
    def stand_in_pseudo_fs(self, tmp_path, monkeypatch):
        """Stand in for /dev/shm and /run: a few entries, not the real ones."""
        shm = tmp_path / "stand-in-shm"
        run = tmp_path / "stand-in-run"
        for root in (shm, run):
            root.mkdir()
            (root / "segment").write_text("x")
        monkeypatch.setattr(
            policy_module, "_PSEUDO_FS_ROOTS", (shm, run), raising=False
        )
        return SimpleNamespace(shm=shm, run=run)

    @staticmethod
    def _blacklisted(argv):
        return [a.split("=", 1)[1] for a in argv if a.startswith("--blacklist=")]

    def test_firejail_leaves_tmp_alone_for_a_link_inside_a_hidden_directory(
        self, layout, stand_in_tmp, tmp_path
    ):
        """~/data -> /persist/other, which holds a link into /tmp: /tmp is covered
        by --private-tmp, so what the link names there is not blacklisted, however
        few or many entries it has."""
        other = tmp_path / "persist" / "other"
        other.mkdir(parents=True)
        scratch = stand_in_tmp / "scratch"
        scratch.mkdir()
        for name in ("a", "b", "c"):
            (scratch / name).write_text("x")
        (other / "scratch").symlink_to(scratch)
        (layout.home / "data").symlink_to(other)

        blacklisted = self._blacklisted(self._firejail(_policy(layout)))

        assert _as_argv(other) in blacklisted
        under_tmp = [
            b
            for b in blacklisted
            if b == _as_argv(stand_in_tmp) or b.startswith(_as_argv(stand_in_tmp) + "/")
        ]
        assert not under_tmp, under_tmp

    def test_firejail_does_not_hide_shared_memory_a_home_link_names(
        self, layout, stand_in_tmp, stand_in_pseudo_fs
    ):
        (layout.home / ".shm").symlink_to(stand_in_pseudo_fs.shm)
        (layout.home / ".run").symlink_to(stand_in_pseudo_fs.run)

        blacklisted = self._blacklisted(self._firejail(_policy(layout)))

        for root in (stand_in_pseudo_fs.shm, stand_in_pseudo_fs.run):
            hidden = [
                b
                for b in blacklisted
                if b == _as_argv(root) or b.startswith(_as_argv(root) + "/")
            ]
            assert not hidden, (root, hidden)

    def test_firejail_keeps_shared_memory_a_nested_link_names(
        self, layout, stand_in_tmp, stand_in_pseudo_fs, tmp_path
    ):
        """The control sits beside it: the directory the link is in is still hidden."""
        other = tmp_path / "persist" / "other"
        other.mkdir(parents=True)
        (other / "shm").symlink_to(stand_in_pseudo_fs.shm)
        (layout.home / "data").symlink_to(other)

        blacklisted = self._blacklisted(self._firejail(_policy(layout)))

        assert _as_argv(other) in blacklisted
        assert _as_argv(stand_in_pseudo_fs.shm) not in blacklisted

    def test_sandbox_exec_does_not_deny_shared_memory_a_home_link_names(
        self, layout, stand_in_tmp, stand_in_pseudo_fs, tmp_path
    ):
        (layout.home / ".shm").symlink_to(stand_in_pseudo_fs.shm)

        profile = SandboxExecBackend().profile(_policy(layout), tmp_path / "ptmp")

        assert _as_argv(stand_in_pseudo_fs.shm) not in profile

    def test_the_breadth_rules_agree_on_a_link_into_shared_memory(
        self, layout, stand_in_pseudo_fs, tmp_path
    ):
        """The breadth checks read the same list of links as the backends: a link
        into shared memory or the runtime directory names no directory of the
        user's, so a path at it is not refused as holding part of the home. A link
        to a directory of the user's beside it still counts."""
        persist = tmp_path / "persist-data"
        persist.mkdir()
        (layout.home / ".shm").symlink_to(stand_in_pseudo_fs.shm)
        (layout.home / ".run").symlink_to(stand_in_pseudo_fs.run)
        (layout.home / ".data").symlink_to(persist)
        homes = [Path(os.path.realpath(layout.home))]

        targets = policy_module._home_link_targets(homes)

        assert targets == [Path(os.path.realpath(persist))]
        for root in (stand_in_pseudo_fs.shm, stand_in_pseudo_fs.run):
            assert not policy_module._broader_than_a_tool(root, homes)
        assert policy_module._broader_than_a_tool(persist, homes)


@pytest.mark.unit
class TestHomeElsewhereThanThePasswdEntry:
    """HOME and the passwd entry's home can be two directories; deny reading both.

    The policy's home is Path.home(), which reads HOME. sandbox-exec allows reading
    everything and then denied that one home, so with HOME set elsewhere the passwd
    entry's home (the real ~/.ssh, ~/.aws, ~/Library/Keychains) stayed readable.
    The policy's own paths under it are allowed again after the denies.
    """

    @pytest.fixture
    def passwd_home(self, tmp_path, monkeypatch):
        home = tmp_path / "passwd-home"
        (home / "Library" / "Keychains").mkdir(parents=True)
        _fake_passwd_home(monkeypatch, home)
        return home

    def test_sandbox_exec_denies_reading_both_homes(
        self, layout, passwd_home, tmp_path
    ):
        profile = SandboxExecBackend().profile(_policy(layout), tmp_path / "ptmp")
        for home in (layout.home, passwd_home):
            assert f'(deny file-read* (subpath "{_as_argv(home)}"))' in profile, home
            assert _as_argv(home / "Library" / "Keychains") in profile, home

    def test_a_policy_path_under_the_passwd_home_is_readable_again(
        self, layout, passwd_home, monkeypatch, tmp_path
    ):
        """ASH's own venv can live in the passwd home; its allow comes after the deny."""
        venv_bin = passwd_home / "work" / "venv" / "bin"
        venv_bin.mkdir(parents=True)
        monkeypatch.setenv("PATH", str(venv_bin))
        profile = SandboxExecBackend().profile(_policy(layout), tmp_path / "ptmp")
        lines = profile.splitlines()
        deny = lines.index(f'(deny file-read* (subpath "{_as_argv(passwd_home)}"))')
        allow = next(
            i
            for i, line in enumerate(lines)
            if line.startswith("(allow file-read*") and _as_argv(venv_bin) in line
        )
        assert allow > deny

    def test_the_passwd_home_itself_on_path_is_not_readable_again(
        self, layout, passwd_home, monkeypatch, tmp_path
    ):
        """The negative case: what the policy must not list stays behind the deny.

        A PATH entry naming the passwd home is no tool directory. No allow after
        that home's deny may name it, nor its .ssh, while the venv's bin beside it
        is allowed again.
        """
        venv_bin = passwd_home / "work" / "venv" / "bin"
        venv_bin.mkdir(parents=True)
        (passwd_home / ".ssh").mkdir()
        monkeypatch.setenv("PATH", os.pathsep.join([str(passwd_home), str(venv_bin)]))
        profile = SandboxExecBackend().profile(_policy(layout), tmp_path / "ptmp")
        lines = profile.splitlines()
        deny = lines.index(f'(deny file-read* (subpath "{_as_argv(passwd_home)}"))')
        after = [line for line in lines[deny + 1 :] if line.startswith("(allow")]

        assert any(_as_argv(venv_bin) in line for line in after)
        for hidden in (passwd_home, passwd_home / ".ssh"):
            assert not [
                line for line in after if f'(subpath "{_as_argv(hidden)}")' in line
            ], hidden

    def test_one_home_changes_nothing(self, layout, monkeypatch, tmp_path):
        """Positive control: HOME is the passwd home, as on most hosts."""
        _fake_passwd_home(monkeypatch, layout.home)
        profile = SandboxExecBackend().profile(_policy(layout), tmp_path / "ptmp")
        home_denials = [
            line
            for line in profile.splitlines()
            if line.startswith("(deny file-read* (subpath")
            and '"/private/tmp"' not in line
        ]
        assert home_denials == [
            f'(deny file-read* (subpath "{_as_argv(layout.home)}"))'
        ], home_denials

    @pytest.mark.parametrize(
        "pw_dir", ["/", "", "relative/home", "link-to-home"], ids=repr
    )
    def test_an_unusable_passwd_home_adds_no_deny(
        self, layout, monkeypatch, tmp_path, pw_dir
    ):
        """No entry to deny: "/" would take back every read the policy does not
        re-grant, a relative or empty pw_dir names no directory, and a link to
        HOME is the home already denied."""
        if pw_dir == "link-to-home":
            value = tmp_path / "home-link"
            value.symlink_to(layout.home, target_is_directory=True)
        else:
            value = Path(pw_dir)
        _fake_passwd_home(monkeypatch, value)
        profile = SandboxExecBackend().profile(_policy(layout), tmp_path / "ptmp")
        home_denials = [
            line
            for line in profile.splitlines()
            if line.startswith("(deny file-read* (subpath")
            and '"/private/tmp"' not in line
        ]
        assert home_denials == [
            f'(deny file-read* (subpath "{_as_argv(layout.home)}"))'
        ], home_denials


def _reopened_after_deny(profile, home, paths):
    """The rules after ``home``'s deny that allow reading one of ``paths`` again."""
    lines = profile.splitlines()
    deny = lines.index(f'(deny file-read* (subpath "{_as_argv(home)}"))')
    return [
        line
        for line in lines[deny + 1 :]
        if line.startswith("(allow")
        and any(f'(subpath "{_as_argv(p)}")' in line for p in paths)
    ]


@pytest.mark.unit
class TestPolicyPathsUnderThePasswdHome:
    """The breadth filters measure a path against both homes, not only HOME's.

    sandbox-exec denies reading the passwd entry's home and then allows the policy's
    read-only paths again, and bwrap, firejail and landlock mount the same set. With
    HOME elsewhere the filters screened only paths under HOME, so a PATH entry naming
    the passwd home or a configuration directory in it, a tool's prefix directly
    under it (~/.local for ~/.local/bin/uv, ~/.cargo for ~/.cargo/bin/x), a sys.path
    entry of the passwd home (``python -m`` run from it) and an import root equal to
    it each re-opened that home, or part of it.
    """

    @pytest.fixture
    def pw(self, tmp_path, monkeypatch):
        home = tmp_path / "passwd-home"
        for name in (
            ".ssh",
            ".config/t",
            ".local/bin",
            ".local/share",
            ".cargo/bin",
            "bin",
        ):
            (home / name).mkdir(parents=True)
        _fake_passwd_home(monkeypatch, home)
        return home

    @staticmethod
    def _tool(directory):
        """An executable that is not a script, so no interpreter is added."""
        program = directory / "tool"
        program.write_bytes(b"\x7fELF")
        program.chmod(0o755)
        return program

    def test_path_entries_and_a_tool_in_dot_local_bin(
        self, layout, pw, monkeypatch, tmp_path
    ):
        argv0 = self._tool(pw / ".local" / "bin")
        monkeypatch.setenv(
            "PATH",
            os.pathsep.join([str(pw), str(pw / ".config" / "t"), str(argv0.parent)]),
        )
        policy = _policy(layout, argv0=str(argv0))
        exposed = _resolved(policy.read_only)
        assert _resolved([pw / ".local" / "bin"]) <= exposed
        for hidden in (pw, pw / ".config" / "t", pw / ".local"):
            assert Path(os.path.realpath(hidden)) not in exposed, hidden
        profile = SandboxExecBackend().profile(policy, tmp_path / "ptmp")
        children = [pw, pw / ".config" / "t", *pw.iterdir()]
        assert _reopened_after_deny(profile, pw, children) == []

    @pytest.mark.parametrize("bin_dir", [".local/bin", ".cargo/bin", "bin"])
    def test_a_tools_prefix_directly_under_the_passwd_home(
        self, layout, pw, monkeypatch, bin_dir
    ):
        argv0 = self._tool(pw / bin_dir)
        monkeypatch.setenv("PATH", str(argv0.parent))
        exposed = _resolved(_policy(layout, argv0=str(argv0)).read_only)
        assert Path(os.path.realpath(argv0.parent)) in exposed
        assert Path(os.path.realpath(argv0.parent.parent)) not in exposed

    def test_a_deeper_prefix_under_the_passwd_home_stays_readable(
        self, layout, pw, monkeypatch
    ):
        """Positive control: one installation, such as ~/.nvm/versions/node/v22."""
        prefix = pw / ".nvm" / "versions" / "node" / "v22"
        (prefix / "bin").mkdir(parents=True)
        argv0 = self._tool(prefix / "bin")
        monkeypatch.setenv("PATH", str(argv0.parent))
        exposed = _resolved(_policy(layout, argv0=str(argv0)).read_only)
        assert Path(os.path.realpath(prefix)) in exposed

    @pytest.mark.parametrize("entry", ["", ".config/t"], ids=["home", "config-dir"])
    def test_a_sys_path_entry_under_the_passwd_home(
        self, layout, pw, monkeypatch, entry
    ):
        """``python -m ...`` run from the passwd home puts it first on sys.path."""
        path = pw / entry if entry else pw
        monkeypatch.setattr(sys, "path", [str(path), *sys.path])
        assert Path(os.path.realpath(path)) not in _resolved(_policy(layout).read_only)

    def test_an_import_root_that_is_the_passwd_home(self, layout, pw, monkeypatch):
        """ASH checked out directly in the passwd home: mount the package, not it."""
        module = pw / "automated_security_helper" / "utils" / "sandbox" / "policy.py"
        module.parent.mkdir(parents=True)
        module.touch()
        monkeypatch.setattr(policy_module, "__file__", str(module))
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(pw)) not in exposed
        assert Path(os.path.realpath(pw / "automated_security_helper")) in exposed


@pytest.mark.unit
class TestAshsInterpreterThroughAHome:
    """ASH's interpreter paths are mounted unfiltered, so a home among them is refused.

    _ash_paths adds sys.prefix, sys.base_prefix, sys.exec_prefix, the interpreter's
    real prefix and the directory of every link sys.executable passes through, so
    that exec of the interpreter by the path it was started with works inside the
    sandbox. None of them went through a breadth filter. A venv created by a python
    reached through a link in the home (``~/python3 -m venv ~/env``) has
    env/bin/python3 -> ~/python3, which made the home itself, ~/.ssh included, a
    read-only path of every scanner. Mounting less would break that exec, so the
    spawn is refused instead, measured against both homes.
    """

    @staticmethod
    def _interpreter_through(link, tmp_path, monkeypatch):
        """sys.executable is env/bin/python -> ``link`` -> a stand-in binary."""
        binary = tmp_path / "real-python" / "bin" / "python3.14"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"\x7fELF")
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(binary)
        venv_python = tmp_path / "env" / "bin" / "python"
        venv_python.parent.mkdir(parents=True)
        venv_python.symlink_to(link)
        monkeypatch.setattr(sys, "executable", str(venv_python))

    @pytest.mark.parametrize("where", ["python3", ".config/python3"])
    def test_a_link_in_the_home(self, layout, tmp_path, monkeypatch, where):
        self._interpreter_through(layout.home / where, tmp_path, monkeypatch)
        with pytest.raises(SandboxUnavailable, match="home directory"):
            _policy(layout)

    def test_a_link_in_the_passwd_home(self, layout, tmp_path, monkeypatch):
        passwd_home = tmp_path / "passwd-home"
        (passwd_home / ".ssh").mkdir(parents=True)
        _fake_passwd_home(monkeypatch, passwd_home)
        self._interpreter_through(passwd_home / "python3", tmp_path, monkeypatch)
        with pytest.raises(SandboxUnavailable, match="home directory"):
            _policy(layout)

    @pytest.mark.parametrize("prefix", ["sys.prefix", "sys.base_prefix"])
    def test_an_interpreter_prefix_that_is_the_home(self, layout, monkeypatch, prefix):
        """A python built with --prefix=$HOME: its prefix is the home itself."""
        monkeypatch.setattr(sys, prefix.split(".")[1], str(layout.home))
        with pytest.raises(SandboxUnavailable, match="home directory"):
            _policy(layout)

    @pytest.mark.parametrize("in_home", ["HOME", "passwd home"])
    def test_a_python_built_with_the_home_as_its_prefix(
        self, layout, tmp_path, monkeypatch, in_home
    ):
        """--prefix=<home>: a real <home>/bin/python3, every prefix the home itself.

        Refused whichever home it is, rather than mounting that home for every
        scanner; argv0 is a system tool, so only ASH's own paths are in play.
        """
        home = layout.home
        if in_home == "passwd home":
            home = tmp_path / "passwd-home"
            _fake_passwd_home(monkeypatch, home)
        python = home / "bin" / "python3"
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_bytes(b"\x7fELF")
        (home / "lib" / "python3.12").mkdir(parents=True)
        monkeypatch.setattr(sys, "executable", str(python))
        for name in ("prefix", "exec_prefix", "base_prefix"):
            monkeypatch.setattr(sys, name, str(home))
        with pytest.raises(SandboxUnavailable, match="home directory"):
            _policy(layout, argv0="/usr/bin/true")

    @pytest.mark.parametrize("where", ["bin/python3", ".local/opt/py/bin/python3"])
    def test_a_link_in_a_bin_directory_in_the_home(
        self, layout, tmp_path, monkeypatch, where
    ):
        """Positive control: ~/bin/python3, like a PATH entry named bin."""
        link = layout.home / where
        self._interpreter_through(link, tmp_path, monkeypatch)
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(link.parent)) in exposed
        assert Path(os.path.realpath(layout.home)) not in exposed

    def test_a_venv_directly_under_the_home(self, layout, monkeypatch):
        """Positive control: sys.prefix ~/env is one installation, mounted as is."""
        venv = layout.home / "env"
        venv.mkdir()
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        monkeypatch.setattr(sys, "prefix", str(venv))
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(venv)) in exposed
        assert Path(os.path.realpath(layout.home)) not in exposed

    @pytest.mark.parametrize("in_home", ["HOME", "passwd home"])
    def test_a_real_python_in_dot_local_bin(
        self, layout, tmp_path, monkeypatch, in_home
    ):
        """Its prefix is ~/.local, which holds ~/.local/share and its keyrings."""
        home = layout.home
        if in_home == "passwd home":
            home = tmp_path / "passwd-home"
            _fake_passwd_home(monkeypatch, home)
        python = home / ".local" / "bin" / "python3.12"
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_bytes(b"\x7fELF")
        (home / ".local" / "lib" / "python3.12").mkdir(parents=True)
        monkeypatch.setattr(sys, "executable", str(python))
        for name in ("prefix", "exec_prefix", "base_prefix"):
            monkeypatch.setattr(sys, name, str(home / ".local"))
        with pytest.raises(SandboxUnavailable, match="home directory"):
            _policy(layout)

    def test_the_refusal_names_the_path_escaped_and_the_way_out(
        self, layout, tmp_path, monkeypatch
    ):
        odd = layout.home / "odd\n::error::name"
        self._interpreter_through(odd / "python3", tmp_path, monkeypatch)
        with pytest.raises(SandboxUnavailable) as refused:
            _policy(layout)
        message = str(refused.value)
        assert repr(odd.as_posix()) in message
        assert "\n" not in message
        assert "outside the home directory" in message


@pytest.mark.unit
class TestAshBinPathUnderAHome:
    """ASH_BIN_PATH is mounted for every scanner, so it gets the same breadth rule."""

    @pytest.mark.parametrize("value", ["home", "holding-home", ".local"])
    def test_a_broad_bin_path_is_refused(self, layout, monkeypatch, value):
        named = {
            "home": layout.home,
            "holding-home": layout.home.parent,
            ".local": layout.home / ".local",
        }[value]
        monkeypatch.setenv("ASH_BIN_PATH", str(named))
        with pytest.raises(SandboxUnavailable, match="ASH_BIN_PATH"):
            _policy(layout)

    @pytest.mark.parametrize("where", ["bin", ".ash/bin"])
    def test_a_bin_directory_in_the_home_is_mounted(self, layout, monkeypatch, where):
        named = layout.home / where
        named.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("ASH_BIN_PATH", str(named))
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(named)) in exposed
        assert Path(os.path.realpath(layout.home)) not in exposed


@pytest.mark.unit
class TestNoBinDirectoryToMount:
    """A relative ASH_BIN_PATH, or none at all, leaves no bin directory to mount.

    A relative value names a directory under the working directory, usually the
    scanned repository, so the policy leaves it out of the mounts (the tool lookup
    does not search it either). With no bin directory, the check that refuses a
    home among ASH's own paths has nothing to measure. It used to hand the missing
    directory to os.path.isdir, and every sandboxed spawn raised TypeError instead
    of being planned.
    """

    @pytest.mark.parametrize(
        ("value", "exists"),
        [("bin", True), ("./bin", True), ("tools/bin", True), ("no-such-dir", False)],
    )
    def test_a_relative_ash_bin_path_still_plans_the_spawn(
        self, layout, monkeypatch, value, exists
    ):
        named = layout.source / value
        if exists:
            named.mkdir(parents=True)
        monkeypatch.chdir(layout.source)
        monkeypatch.setenv("ASH_BIN_PATH", value)
        # The input this test is about: a value that names no location by itself.
        assert not subprocess_utils._is_anchored(str(subprocess_utils._bin_path()))
        policy = _policy(layout)
        mounted = _resolved([*policy.read_only, *policy.executable])
        assert Path(os.path.realpath(named)) not in mounted

    def test_a_relative_ash_bin_path_that_reaches_a_home_mounts_nothing(
        self, layout, monkeypatch
    ):
        """Positive control for the drop: ``..`` from the source tree holds the home.

        It is left out of the mounts, so neither it nor the home inside it is
        exposed, and nothing is measured against where the working directory would
        put it.
        """
        monkeypatch.chdir(layout.source)
        monkeypatch.setenv("ASH_BIN_PATH", "..")
        assert not subprocess_utils._is_anchored(str(subprocess_utils._bin_path()))
        policy = _policy(layout)
        mounted = _resolved([*policy.read_only, *policy.executable])
        assert Path(os.path.realpath(layout.source.parent)) not in mounted
        assert Path(os.path.realpath(layout.home)) not in mounted

    def test_no_ash_bin_path_and_no_default_still_plans_the_spawn(
        self, layout, monkeypatch
    ):
        """ASH_BIN_PATH unset, and no default bin directory to fall back to."""
        monkeypatch.delenv("ASH_BIN_PATH", raising=False)
        monkeypatch.setattr(subprocess_utils, "ASH_BIN_PATH", None)
        assert subprocess_utils._bin_path() is None
        policy = _policy(layout)
        python_dir = Path(os.path.realpath(sys.executable)).parent
        assert python_dir in _resolved(policy.executable)

    def test_the_home_check_has_nothing_to_measure_for_no_bin_directory(self, layout):
        home = Path(os.path.realpath(layout.home))
        assert policy_module._refuse_a_home_among([], [], None, [home], []) is None

    def test_the_home_check_still_refuses_a_home_given_as_the_bin_directory(
        self, layout
    ):
        """Positive control: the same call, with a home where None was."""
        home = Path(os.path.realpath(layout.home))
        with pytest.raises(SandboxUnavailable, match="ASH_BIN_PATH"):
            policy_module._refuse_a_home_among([], [], layout.home, [home], [])

    def test_an_absolute_ash_bin_path_is_still_mounted(
        self, layout, monkeypatch, tmp_path
    ):
        """Control: an anchored bin directory outside the home is read-only and exec."""
        bin_dir = tmp_path / "ash-bin"
        bin_dir.mkdir()
        monkeypatch.chdir(layout.source)
        monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
        assert subprocess_utils._is_anchored(str(subprocess_utils._bin_path()))
        policy = _policy(layout)
        real = Path(os.path.realpath(bin_dir))
        assert real in _resolved(policy.read_only)
        assert real in _resolved(policy.executable)

    def test_a_relative_ash_bin_path_does_not_excuse_an_interpreter_in_a_home(
        self, layout, monkeypatch
    ):
        """Control: the other measurements still run when the bin directory is left out."""
        python = layout.home / ".local" / "bin" / "python3.12"
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_bytes(b"\x7fELF")
        (layout.home / ".local" / "lib" / "python3.12").mkdir(parents=True)
        monkeypatch.setattr(sys, "executable", str(python))
        for name in ("prefix", "exec_prefix", "base_prefix"):
            monkeypatch.setattr(sys, name, str(layout.home / ".local"))
        monkeypatch.chdir(layout.source)
        monkeypatch.setenv("ASH_BIN_PATH", "bin")
        with pytest.raises(SandboxUnavailable, match="home directory"):
            _policy(layout)


@pytest.mark.unit
class TestCommonInterpreterLayoutsStayAllowed:
    """The refusal above does not refuse the usual places a Python lives in a home.

    Each layout is built in HOME, and again in the passwd home with HOME elsewhere,
    and is mounted without the home itself.
    """

    @staticmethod
    def _binary(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")
        return path

    @classmethod
    def _pyenv(cls, home):
        prefix = home / ".pyenv" / "versions" / "3.12.1"
        cls._binary(prefix / "bin" / "python3.12")
        (prefix / "bin" / "python3").symlink_to("python3.12")
        (prefix / "lib" / "python3.12").mkdir(parents=True)
        return prefix / "bin" / "python3", prefix, prefix

    @classmethod
    def _uv(cls, home):
        prefix = home / ".local/share/uv/python/cpython-3.14.6-linux-x86_64-gnu"
        cls._binary(prefix / "bin" / "python3.14")
        (prefix / "bin" / "python3").symlink_to("python3.14")
        (prefix / "lib" / "python3.14").mkdir(parents=True)
        return prefix / "bin" / "python3", prefix, prefix

    @classmethod
    def _venv_at(cls, home, venv):
        _executable, base, _ = cls._uv(home)
        (venv / "bin").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text(f"home = {base / 'bin'}\n")
        (venv / "bin" / "python").symlink_to(base / "bin" / "python3.14")
        (venv / "bin" / "python3").symlink_to("python")
        return venv / "bin" / "python3", venv, base

    @classmethod
    def _venv(cls, home):
        """An in-tree .venv, as uv sync makes it."""
        return cls._venv_at(home, home / "work" / "project" / ".venv")

    @classmethod
    def _dot_venv(cls, home):
        """A venv directly under the home."""
        return cls._venv_at(home, home / ".venv")

    @classmethod
    def _conda(cls, home):
        prefix = home / "miniconda3"
        cls._binary(prefix / "bin" / "python3.12")
        (prefix / "bin" / "python3").symlink_to("python3.12")
        (prefix / "lib" / "python3.12").mkdir(parents=True)
        (prefix / "conda-meta").mkdir()
        return prefix / "bin" / "python3", prefix, prefix

    @pytest.mark.parametrize("which", ["pyenv", "uv", "venv", "dot_venv", "conda"])
    @pytest.mark.parametrize("in_home", ["HOME", "passwd home"])
    def test_it_is_mounted_and_the_home_is_not(
        self, layout, tmp_path, monkeypatch, which, in_home
    ):
        home = layout.home
        if in_home == "passwd home":
            home = tmp_path / "passwd-home"
            home.mkdir()
            _fake_passwd_home(monkeypatch, home)
        executable, prefix, base_prefix = getattr(self, f"_{which}")(home)
        monkeypatch.setattr(sys, "executable", str(executable))
        monkeypatch.setattr(sys, "prefix", str(prefix))
        monkeypatch.setattr(sys, "exec_prefix", str(prefix))
        monkeypatch.setattr(sys, "base_prefix", str(base_prefix))
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(prefix)) in exposed
        assert Path(os.path.realpath(base_prefix)) in exposed
        assert Path(os.path.realpath(home)) not in exposed


@pytest.mark.parametrize(
    "pw_dir", [None, "/", "", "relative/home", "HOME", "link to HOME"], ids=repr
)
@pytest.mark.unit
def test_no_second_home(tmp_path, pw_dir):
    """A passwd home that is not a second directory to measure against or deny."""
    home = tmp_path / "home"
    home.mkdir()
    link = tmp_path / "link"
    link.symlink_to(home, target_is_directory=True)
    special = {"HOME": home, "link to HOME": link}
    value = special.get(pw_dir) or (None if pw_dir is None else Path(pw_dir))
    assert policy_module._distinct_home(home, value) is None


@pytest.mark.unit
def test_a_home_of_root_is_not_a_home(tmp_path, monkeypatch):
    """A HOME of "/", as in some containers, names no home: every path is inside it."""
    monkeypatch.setenv("HOME", "/")
    monkeypatch.setenv("USERPROFILE", "/")
    other = tmp_path / "passwd-home"
    other.mkdir()
    _fake_passwd_home(monkeypatch, other)
    assert policy_module._homes() == [Path(os.path.realpath(other))]


@pytest.mark.unit
def test_a_second_home(tmp_path):
    home = tmp_path / "home"
    other = tmp_path / "other"
    home.mkdir()
    other.mkdir()
    assert policy_module._distinct_home(home, other) == Path(os.path.realpath(other))


@pytest.mark.skipif(sys.platform == "win32", reason="no backend runs on Windows")
@pytest.mark.unit
class TestBwrapAndLandlockGrantNothingInThePasswdHome:
    """With HOME elsewhere, no bwrap or Landlock grant opens the passwd entry's home.

    The plan-level stand-in for the escape suite's planted passwd-home files, which
    are written only in a throwaway CI job. Both backends show only the paths the
    policy lists. The passwd home here holds what a user's often does: a tool in
    ~/bin and one in ~/.local/bin, with PATH naming the home itself and a
    configuration directory in it, ~/.config/tool. No grant may be the passwd home
    or hold it, and inside it only a bin directory may be granted: the home, its
    ~/.local (keyrings in ~/.local/share) and ~/.config/tool must stay out. The
    tool's own bin directory is granted, which shows the check reads the plan.
    """

    @pytest.fixture
    def pw(self, tmp_path, monkeypatch):
        home = tmp_path / "passwd-home"
        for name in (".ssh", ".config/tool", ".local/bin", ".local/share/keyrings"):
            (home / name).mkdir(parents=True)
        (home / "bin").mkdir()
        _fake_passwd_home(monkeypatch, home)
        return home

    @staticmethod
    def _tool(directory):
        """An executable that is not a script, so no interpreter is added."""
        program = directory / "tool"
        program.write_bytes(b"\x7fELF")
        program.chmod(0o755)
        return program

    @staticmethod
    def _granted(backend_class, layout, argv0):
        backend = backend_class()
        backend._executable = "/usr/bin/bwrap"
        policy = _policy(layout, argv0=str(argv0))
        plan = backend.plan([str(argv0)], {"PATH": "/usr/bin"}, policy)
        try:
            if backend_class is LandlockBackend:
                document = json.loads(plan.argv[plan.argv.index("--policy") + 1])
                paths = document["read_only"] + document["writable"]
            else:
                # bwrap's own options end at its first "--"; what follows is the
                # command it runs, not a mount.
                options = plan.argv[1 : plan.argv.index("--")]
                # A --tmpfs or --tmp-overlay target is a fresh empty mount over the
                # host path and hides it; only bind and overlay sources are grants.
                hiding = ("--tmpfs", "--tmp-overlay")
                paths = [
                    a
                    for before, a in zip([""] + options, options)
                    if a.startswith("/") and before not in hiding
                ]
        finally:
            plan.run_cleanup()
        return {Path(p) for p in paths}

    @pytest.mark.parametrize("tool_dir", ["bin", ".local/bin"])
    @pytest.mark.parametrize("backend_class", [BwrapBackend, LandlockBackend])
    def test_no_grant_opens_the_passwd_home(
        self, layout, pw, monkeypatch, backend_class, tool_dir
    ):
        argv0 = self._tool(pw / tool_dir)
        monkeypatch.setenv(
            "PATH",
            os.pathsep.join(
                [str(pw), str(pw / ".config" / "tool"), str(argv0.parent), "/usr/bin"]
            ),
        )
        granted = self._granted(backend_class, layout, argv0)
        hidden = Path(_as_argv(pw))

        assert Path(_as_argv(argv0.parent)) in granted
        opening = sorted(
            str(p)
            for p in granted
            if p == hidden
            or p in hidden.parents
            or (hidden in p.parents and p.name not in ("bin", "sbin", "Scripts"))
        )
        assert opening == [], opening


@pytest.mark.unit
class TestSandboxExecLeavesTheRealCacheUnwritten:
    """filter_env drops XDG_CACHE_HOME, so tools fall back to $HOME/.cache.

    Under sandbox-exec HOME is the real path. The profile denies by default and
    allows writing only the results directory, the private TMPDIR, an unpack
    directory and uv's lock files, so a write to the real $HOME/.cache is refused
    rather than landing there.
    """

    def test_no_write_rule_reaches_home(self, layout, tmp_path):
        profile = SandboxExecBackend().profile(_policy(layout), tmp_path / "ptmp")
        writes = [line for line in profile.splitlines() if "file-write*" in line]
        assert writes
        home = _as_argv(layout.home)
        for line in writes:
            if line.startswith("(deny"):
                continue
            assert f'"{home}"' not in line and f'"{home}/' not in line, line


class TestBackendProbesKeepHome:
    """A probe child gets HOME, so it never falls back to the passwd home.

    The probes ran with only PATH. Without HOME, Path.home() and anything that
    expands ``~`` in the child resolve the passwd entry's home, whatever HOME the
    operator set: measured, `env -i python3 -c 'print(Path.home())'` printed the
    real home.
    """

    @pytest.mark.integration
    def test_a_probe_child_resolves_the_operators_home(self, tmp_path, monkeypatch):
        home = tmp_path / "operator-home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        result = backends_module._probe_process(
            [sys.executable, "-I", "-c", "from pathlib import Path; print(Path.home())"]
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == str(home)

    @pytest.mark.unit
    def test_the_landlock_probe_passes_home(self, tmp_path, monkeypatch):
        home = tmp_path / "operator-home"
        monkeypatch.setenv("HOME", str(home))
        envs = []

        def run(argv, **kwargs):
            envs.append(kwargs.get("env"))
            return backends_module.subprocess.CompletedProcess(argv, 0, "1\n", "")

        monkeypatch.setattr(backends_module.subprocess, "run", run)
        backends_module.LandlockBackend()._probe()
        assert envs, "the probe started nothing"
        assert all(env is not None and env.get("HOME") == str(home) for env in envs)


@pytest.mark.unit
class TestWritableWinsOverReadOnly:
    """A read-only bind inside the writable results directory must not cover it.

    bwrap applies mounts in order, so a read-only bind of a cwd under the results
    directory, emitted after the writable bind, made the results directory's subtree
    read-only. The cdk-nag worker hit it by running from its work directory.
    """

    def test_bwrap_mounts_nothing_read_only_under_the_results_directory(self, layout):
        work = layout.results / "work"
        work.mkdir(parents=True)
        backend = BwrapBackend()
        backend._executable = "/usr/bin/bwrap"
        plan = backend.plan(["/usr/bin/true"], {}, _policy(layout, cwd=work))
        results = _as_argv(layout.results)
        argv = plan.argv
        read_only_under_results = [
            argv[i + 2]
            for i, flag in enumerate(argv)
            if flag == "--ro-bind"
            and (argv[i + 2] == results or argv[i + 2].startswith(results + "/"))
        ]
        assert not read_only_under_results, read_only_under_results
        assert ["--bind", results, results] == argv[
            argv.index(results) - 1 : argv.index(results) + 2
        ]
        assert argv[argv.index("--chdir") + 1] == _as_argv(work)


@pytest.mark.unit
def test_every_import_path_directory_is_readable(layout, monkeypatch, tmp_path):
    """An editable install's .pth adds sys.path entries outside site-packages.

    The detect-secrets and cdk-nag workers run with this interpreter and import from
    the same entries; Landlock denies any entry it was not given.
    """
    editable_root = tmp_path / "checkout"
    editable_root.mkdir()
    monkeypatch.setattr(sys, "path", [*sys.path, str(editable_root)])
    exposed = _resolved(_policy(layout).read_only)
    for entry in sys.path:
        if entry and os.path.isabs(entry) and os.path.isdir(entry):
            if Path(os.path.realpath(entry)) in (
                Path("/"),
                Path(os.path.realpath(layout.home)),
            ):
                continue
            assert Path(os.path.realpath(entry)) in exposed, entry


@pytest.mark.unit
def test_an_import_path_entry_elsewhere_in_home_is_not_mounted(layout, monkeypatch):
    """PYTHONPATH=~/anything must not make that directory readable to scanners."""
    stray = layout.home / "notes"
    stray.mkdir()
    monkeypatch.setattr(sys, "path", [*sys.path, str(stray)])
    exposed = _resolved(_policy(layout).read_only)
    assert Path(os.path.realpath(stray)) not in exposed


@pytest.mark.unit
class TestPluginDeclarations:
    """Third-party and community plugin scanners get exactly what they declare.

    A scanner that declares no sandbox_requirements gets the strictest default: no
    network, read-only source, its own results directory as the only writable
    place, and the environment allowlist alone. The escape suite runs such a
    plugin (tests/test_data/sandbox_escape declares nothing) through a real scan.
    """

    class _Recorder:
        name = "recorder"

        def __init__(self):
            self.policies = []

        def plan(self, argv, env, policy):
            self.policies.append((policy, policy.filter_env(env)))
            return SpawnPlan(argv=list(argv), env=dict(env))

    def _policy_for(self, plugin, tmp_path, monkeypatch):
        recorder = self._Recorder()
        monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: recorder)
        monkeypatch.setattr(
            "automated_security_helper.core.constants.is_offline_mode", lambda: False
        )
        context = _context(tmp_path)
        scope = scanner_sandbox_scope(plugin, context, tmp_path)
        assert scope is not None
        env = {
            "PATH": os.environ.get("PATH", ""),
            "THIRDPARTY_LEVEL": "debug",
            "THIRDPARTY_TOKEN": "secret",
        }
        with sandbox_scope(scope):
            prepare_spawn([sys.executable, "--version"], env, None)
        return recorder.policies[-1]

    def test_an_undeclared_plugin_gets_the_strict_default(self, tmp_path, monkeypatch):
        plugin = SimpleNamespace(
            config=SimpleNamespace(name="thirdparty"), results_dir=None
        )
        policy, env = self._policy_for(plugin, tmp_path, monkeypatch)
        assert policy.network is False
        assert _resolved(policy.writable) == _resolved(
            [tmp_path / "out" / "scanners" / "thirdparty"]
        )
        assert "THIRDPARTY_LEVEL" not in env
        assert "THIRDPARTY_TOKEN" not in env

    def test_a_declared_plugin_gets_exactly_what_it_declared(
        self, tmp_path, monkeypatch
    ):
        extra = tmp_path / "rules"
        extra.mkdir()
        plugin = SimpleNamespace(
            config=SimpleNamespace(name="thirdparty"),
            results_dir=None,
            sandbox_requirements=SandboxRequirements(
                network=True,
                read_paths=(str(extra),),
                env_prefixes=("THIRDPARTY_",),
                env_names=("THIRDPARTY_TOKEN",),
            ),
        )
        policy, env = self._policy_for(plugin, tmp_path, monkeypatch)
        assert policy.network is True
        assert Path(os.path.realpath(extra)) in _resolved(policy.read_only)
        assert env["THIRDPARTY_LEVEL"] == "debug"
        assert env["THIRDPARTY_TOKEN"] == "secret"
        # Declaring more does not widen what is writable.
        assert _resolved(policy.writable) == _resolved(
            [tmp_path / "out" / "scanners" / "thirdparty"]
        )

    def test_a_declaration_that_is_not_a_requirements_object_is_ignored(
        self, tmp_path, monkeypatch
    ):
        plugin = SimpleNamespace(
            config=SimpleNamespace(name="thirdparty"),
            results_dir=None,
            sandbox_requirements={"network": True},
        )
        policy, _ = self._policy_for(plugin, tmp_path, monkeypatch)
        assert policy.network is False


@pytest.mark.unit
def test_a_uv_tool_interpreter_installed_elsewhere_is_readable(
    layout, tmp_path, monkeypatch
):
    """A uv tool environment runs on the interpreter it was created with.

    With UV_PYTHON_INSTALL_DIR set elsewhere at install time, that interpreter
    lives outside uv's default python directory; the sandbox has to show it or
    every uv tool fails to start. Measured: bandit and checkov failed to exec
    under both bwrap and landlock until this was added.
    """
    pythons = tmp_path / "elsewhere" / "cpython-3.13" / "bin"
    pythons.mkdir(parents=True)
    (pythons.parent / "lib" / "python3.13").mkdir(parents=True)
    interpreter = pythons / "python3.13"
    interpreter.write_text("")
    tool_bin = layout.home / ".local" / "share" / "uv" / "tools" / "bandit" / "bin"
    tool_bin.mkdir(parents=True)
    (tool_bin / "python").symlink_to(interpreter)
    exposed = _resolved(_policy(layout).read_only)
    assert Path(os.path.realpath(pythons.parent)) in exposed


@pytest.mark.unit
class TestNothingBroaderThanATool:
    """Paths taken from the environment never mount $HOME or anything above it."""

    def test_a_tool_link_into_the_parent_of_home_is_not_mounted(self, layout):
        tool_bin = layout.home / ".local" / "share" / "uv" / "tools" / "x" / "bin"
        tool_bin.mkdir(parents=True)
        (tool_bin / "python").symlink_to(layout.home.parent / "bin" / "python")
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(layout.home.parent)) not in exposed

    def test_a_tool_link_to_a_prefix_without_a_python_library_is_not_mounted(
        self, layout, tmp_path
    ):
        bare = tmp_path / "bare" / "bin"
        bare.mkdir(parents=True)
        (bare / "python").write_text("")
        tool_bin = layout.home / ".local" / "share" / "uv" / "tools" / "x" / "bin"
        tool_bin.mkdir(parents=True)
        (tool_bin / "python").symlink_to(bare / "python")
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(bare.parent)) not in exposed

    def test_an_import_path_entry_above_home_is_not_mounted(self, layout, monkeypatch):
        monkeypatch.setattr(sys, "path", [*sys.path, str(layout.home.parent)])
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(layout.home.parent)) not in exposed

    def test_a_path_entry_above_home_is_not_mounted(self, layout, monkeypatch):
        monkeypatch.setenv("PATH", str(layout.home.parent))
        exposed = _resolved(_policy(layout).read_only)
        assert Path(os.path.realpath(layout.home.parent)) not in exposed


def _sbpl(layout, tmp_path, **overrides):
    """The sandbox-exec profile for one policy, one rule per line."""
    policy = _policy(layout, **overrides)
    return SandboxExecBackend().profile(policy, tmp_path / "private-tmp").splitlines()


def _subpaths(rule):
    return set(re.findall(r'\(subpath "([^"]*)"\)', rule))


def _indexed(lines, prefix):
    return [(i, line) for i, line in enumerate(lines) if line.startswith(prefix)]


@pytest.mark.unit
class TestSandboxExecProfile:
    """The macOS profile names the Mach services and the exec paths it allows.

    Profile text only, so these run on every platform. The profile itself is run on
    macOS by tests/integration/sandbox/test_sandbox_exec_services.py and by the
    scanner parity job.
    """

    NETWORK = SandboxRequirements(network=True)

    def test_no_rule_allows_every_mach_lookup(self, layout, tmp_path):
        for requirements in (SandboxRequirements(), self.NETWORK):
            lines = _sbpl(layout, tmp_path, requirements=requirements)
            assert "(allow default)" not in lines
            allows = _indexed(lines, "(allow mach-lookup")
            assert allows, "no Mach service is allowed at all"
            for _, rule in allows:
                # Exact names only: no unfiltered rule, no prefix, no regex.
                assert rule.startswith("(allow mach-lookup (global-name "), rule
                assert set(re.findall(r"\((global-name\S*) ", rule)) == {
                    "global-name"
                }, rule

    def test_launch_services_and_the_pasteboard_are_denied_after_every_allow(
        self, layout, tmp_path
    ):
        for requirements in (SandboxRequirements(), self.NETWORK):
            lines = _sbpl(layout, tmp_path, requirements=requirements)
            denies = _indexed(lines, "(deny mach-lookup")
            assert len(denies) == 1, denies
            where, rule = denies[0]
            for denied in (
                '(global-name "com.apple.coreservices.launchservicesd")',
                '(global-name "com.apple.CoreServices.coreservicesd")',
                '(global-name-prefix "com.apple.lsd.")',
                '(global-name-prefix "com.apple.pasteboard.")',
                '(global-name "com.apple.SecurityServer")',
            ):
                assert denied in rule
            # In SBPL the last matching rule wins, so the deny has to come last.
            assert where > max(i for i, _ in _indexed(lines, "(allow mach-lookup"))

    def test_resolver_services_are_allowed_only_with_a_network(self, layout, tmp_path):
        offline = "\n".join(_sbpl(layout, tmp_path))
        online = "\n".join(_sbpl(layout, tmp_path, requirements=self.NETWORK))
        assert backends_module.MACH_SERVICES_WITH_NETWORK
        for name in backends_module.MACH_SERVICES_WITH_NETWORK:
            assert f'"{name}"' not in offline, name
            assert f'"{name}"' in online, name
        for name in backends_module.MACH_SERVICES:
            assert f'"{name}"' in offline, name
            assert f'"{name}"' in online, name

    def test_the_allowlists_name_no_denied_service_and_no_duplicate(self):
        always = list(backends_module.MACH_SERVICES)
        network = list(backends_module.MACH_SERVICES_WITH_NETWORK)
        assert len(set(always + network)) == len(always) + len(network)
        for name in always + network:
            assert name not in (
                "com.apple.coreservices.launchservicesd",
                "com.apple.CoreServices.coreservicesd",
                "com.apple.SecurityServer",
            ), name
            assert not name.startswith(("com.apple.lsd.", "com.apple.pasteboard.")), (
                name
            )

    def test_exec_is_allowed_only_from_tool_and_system_paths(self, layout, tmp_path):
        lines = _sbpl(layout, tmp_path)
        assert "(allow process-exec)" not in lines
        allows = _indexed(lines, "(allow process-exec ")
        assert len(allows) == 1, allows
        allowed = _subpaths(allows[0][1])
        interpreter = Path(os.path.realpath(sys.executable)).as_posix()
        assert any(
            interpreter.startswith(path.rstrip("/") + "/") for path in allowed
        ), (
            interpreter,
            allowed,
        )
        for never in (
            layout.results,
            tmp_path / "private-tmp",
            layout.source,
            layout.output,
            layout.home,
        ):
            assert _as_argv(never) not in allowed, never
        ((_, deny),) = _indexed(lines, "(deny process-exec ")
        for denied in (layout.results, tmp_path / "private-tmp", layout.source):
            assert _as_argv(denied) in _subpaths(deny), denied

    def test_the_spawns_private_uv_cache_is_executable_and_nothing_else_written(
        self, layout, monkeypatch, tmp_path
    ):
        uv_cache = tmp_path / "uv-cache"
        other_cache = tmp_path / "npm-cache"
        uv_cache.mkdir()
        other_cache.mkdir()
        monkeypatch.setenv("UV_CACHE_DIR", str(uv_cache))
        requirements = SandboxRequirements(
            cache_paths=(str(other_cache),), cache_env=("npm_config_cache",)
        )
        plan = SandboxExecBackend().plan(
            ["/usr/bin/true"], {}, _policy(layout, requirements)
        )
        try:
            private_uv = _as_argv(plan.env["UV_CACHE_DIR"])
            private_npm = _as_argv(plan.env["npm_config_cache"])
            profile = plan.argv[plan.argv.index("-p") + 1].splitlines()
            allowed = set().union(
                *(
                    _subpaths(rule)
                    for _, rule in _indexed(profile, "(allow process-exec ")
                )
            )
            ((deny_at, deny),) = _indexed(profile, "(deny process-exec ")
            # `uv tool run` builds an uninstalled tool's environment in its cache
            # and runs it from there; the private cache is this spawn's alone.
            assert private_uv in allowed
            last_allow = max(i for i, _ in _indexed(profile, "(allow process-exec "))
            assert last_allow > deny_at
            for never in (private_npm, _as_argv(uv_cache), _as_argv(other_cache)):
                assert never not in allowed, never
            assert {_as_argv(uv_cache), _as_argv(other_cache)} <= _subpaths(deny)
        finally:
            plan.run_cleanup()

    def test_a_root_cwd_is_not_scan_data_and_the_tree_stays_exec_denied(
        self, layout, tmp_path
    ):
        # checkov and ferret-scan run from the filesystem root so that they read no
        # config file from the scanned tree. The root is not the scan's data: the
        # read list already leaves it out, and the exec deny must too, or it holds
        # every tool path only because each one is given back after it.
        root = Path(os.path.abspath(os.sep))
        lines = _sbpl(layout, tmp_path, cwd=root)
        ((_, deny),) = _indexed(lines, "(deny process-exec ")
        assert _as_argv(root) not in _subpaths(deny), deny
        for still_denied in (layout.source, layout.output, layout.results):
            assert _as_argv(still_denied) in _subpaths(deny), still_denied
        policy = _policy(layout, cwd=root)
        assert Path(os.path.realpath(root)) not in _resolved(policy.scan_data)
        for data in (layout.source, layout.output):
            assert Path(os.path.realpath(data)) in _resolved(policy.scan_data)

    def test_the_scan_data_is_not_executable_inside_a_tool_path(self, layout, tmp_path):
        # A tool path that holds the scanned tree, as /opt holds a repository
        # checked out under it.
        lines = _sbpl(layout, tmp_path, extra_read_paths=[str(tmp_path)])
        ((allow_at, allow),) = _indexed(lines, "(allow process-exec ")
        ((deny_at, deny),) = _indexed(lines, "(deny process-exec ")
        assert _as_argv(tmp_path) in _subpaths(allow)
        assert {_as_argv(layout.source), _as_argv(layout.output)} <= _subpaths(deny)
        assert deny_at > allow_at

    def test_a_tool_path_inside_the_scan_data_stays_executable(self, layout, tmp_path):
        # A virtualenv inside the scanned project that ASH itself runs from.
        venv_bin = layout.source / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        lines = _sbpl(layout, tmp_path, extra_read_paths=[str(venv_bin)])
        allows = _indexed(lines, "(allow process-exec ")
        ((deny_at, _),) = _indexed(lines, "(deny process-exec ")
        assert len(allows) == 2, allows
        assert allows[1][0] > deny_at
        assert _subpaths(allows[1][1]) == {_as_argv(venv_bin)}

    def test_a_path_entry_inside_the_scanned_tree_is_no_exec_grant(
        self, layout, monkeypatch, tmp_path
    ):
        """A PATH entry in the repository or the output is the scan's data.

        The tree's exec deny would otherwise be given back for it after the deny,
        so the repository's programs ran under sandbox-exec. A tool directory on
        PATH outside the tree is still granted, which shows PATH was read.
        """
        inside = [layout.source / ".venv" / "bin", layout.output / "bin"]
        outside = tmp_path / "tools" / "bin"
        for directory in [*inside, outside]:
            directory.mkdir(parents=True)
        monkeypatch.setenv(
            "PATH", os.pathsep.join(str(p) for p in [*inside, outside, "/usr/bin"])
        )
        policy = _policy(layout, argv0="/usr/bin/true")
        lines = SandboxExecBackend().profile(policy, tmp_path / "private-tmp")
        allowed = set().union(
            *(
                _subpaths(rule)
                for _, rule in _indexed(lines.splitlines(), "(allow process-exec ")
            )
        )
        landlock = LandlockBackend()
        plan = landlock.plan(["/usr/bin/true"], {"PATH": "/usr/bin"}, policy)
        try:
            document = json.loads(plan.argv[plan.argv.index("--policy") + 1])
        finally:
            plan.run_cleanup()

        assert Path(os.path.realpath(outside)) in _resolved(policy.executable)
        assert _as_argv(outside) in allowed
        for directory in inside:
            assert Path(os.path.realpath(directory)) not in _resolved(
                policy.executable
            ), directory
            assert _as_argv(directory) not in allowed, directory
            assert _as_argv(directory) not in document["read_only"], directory

    def test_an_import_entry_inside_the_scanned_tree_is_readable_and_not_executable(
        self, layout, monkeypatch, tmp_path
    ):
        """PYTHONPATH=src: ASH's sys.path names a directory of the repository.

        Workers started with ASH's interpreter import from it, so it stays readable,
        but it is the scan's data: no exec grant gives it back after sandbox-exec
        denies running anything from the tree. An import entry outside the tree
        stays executable, which shows the entry was read.
        """
        in_tree = layout.source / "src"
        outside = tmp_path / "site" / "packages"
        for directory in (in_tree, outside):
            directory.mkdir(parents=True)
        monkeypatch.setattr(sys, "path", [str(in_tree), str(outside), *sys.path])

        policy = _policy(layout, argv0="/usr/bin/true")
        lines = SandboxExecBackend().profile(policy, tmp_path / "private-tmp")
        allowed = set().union(
            *(
                _subpaths(rule)
                for _, rule in _indexed(lines.splitlines(), "(allow process-exec ")
            )
        )

        real = Path(os.path.realpath(in_tree))
        assert real in _resolved(policy.read_only)
        assert real not in _resolved(policy.executable)
        assert _as_argv(in_tree) not in allowed
        assert Path(os.path.realpath(outside)) in _resolved(policy.executable)

    def test_a_path_entry_in_an_output_directory_outside_the_source_is_no_exec_grant(
        self, layout, monkeypatch, tmp_path
    ):
        """--output-dir outside the scanned tree: a PATH entry in it is still the
        scan's data, not a tool directory, though the source does not hold it."""
        output = tmp_path / "elsewhere" / "ash_output"
        in_output = output / "bin"
        in_output.mkdir(parents=True)
        monkeypatch.setenv("PATH", os.pathsep.join([str(in_output), "/usr/bin"]))

        policy = _policy(
            layout,
            argv0="/usr/bin/true",
            output_dir=output,
            results_dir=output / "scanners" / "grype",
        )
        lines = SandboxExecBackend().profile(policy, tmp_path / "private-tmp")
        allowed = set().union(
            *(
                _subpaths(rule)
                for _, rule in _indexed(lines.splitlines(), "(allow process-exec ")
            )
        )

        assert Path(os.path.realpath(in_output)) not in _resolved(policy.executable)
        assert _as_argv(in_output) not in allowed

    def test_a_path_entry_outside_the_scanned_tree_is_still_a_tool_directory(
        self, layout, monkeypatch, tmp_path
    ):
        """The positive counterpart: skipping in-tree entries keeps every other one.

        A tool directory on PATH outside the scanned tree and the output directory,
        named by nothing else in the policy, is readable, executable and allowed to
        run under sandbox-exec. A PATH filter that dropped every entry fails here.
        """
        tools = tmp_path / "opt-tools" / "bin"
        tools.mkdir(parents=True)
        monkeypatch.setenv("PATH", os.pathsep.join([str(tools), "/usr/bin"]))

        policy = _policy(layout, argv0="/usr/bin/true")
        lines = SandboxExecBackend().profile(policy, tmp_path / "private-tmp")
        allowed = set().union(
            *(
                _subpaths(rule)
                for _, rule in _indexed(lines.splitlines(), "(allow process-exec ")
            )
        )

        real = Path(os.path.realpath(tools))
        assert real in _resolved(policy.read_only)
        assert real in _resolved(policy.executable)
        assert _as_argv(tools) in allowed

    def test_the_keychain_files_are_denied_after_every_file_allow(
        self, layout, tmp_path
    ):
        keychains = Path(os.path.realpath(layout.home)) / "Library" / "Keychains"
        for requirements in (SandboxRequirements(), self.NETWORK):
            lines = _sbpl(layout, tmp_path, requirements=requirements)
            ((where, rule),) = _indexed(lines, "(deny file-read* file-write* ")
            assert _subpaths(rule) == {"/Library/Keychains", keychains.as_posix()}
            # Last of the file rules, so no path the policy grants can reopen them.
            assert where > max(i for i, _ in _indexed(lines, "(allow file-"))


@pytest.mark.unit
class TestSystemTrustRoots:
    """semgrep-core reads root certificates from a file instead of the keychain."""

    # Shaped enough for the export to accept it, and not a certificate.
    PEM = "-----BEGIN CERTIFICATE-----\nplaceholder, not a certificate\n"

    def _plan(self, layout, monkeypatch, env=None, declared=True, pem=PEM):
        monkeypatch.setattr(backends_module, "_system_trust_roots", lambda: pem)
        policy = _policy(layout, SandboxRequirements(system_trust_roots=declared))
        return SandboxExecBackend().plan(["/usr/bin/true"], env or {}, policy)

    @staticmethod
    def _profile(plan):
        return plan.argv[plan.argv.index("-p") + 1].splitlines()

    def test_semgrep_declares_it(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            semgrep_scanner,
        )

        requirements = semgrep_scanner.SemgrepScanner.sandbox_requirements
        assert requirements.system_trust_roots is True

    def test_the_roots_are_a_read_only_file_named_by_ssl_cert_file(
        self, layout, monkeypatch
    ):
        plan = self._plan(layout, monkeypatch)
        try:
            roots = Path(plan.env["SSL_CERT_FILE"])
            assert roots.read_text() == self.PEM
            profile = self._profile(plan)
            assert f'(allow file-read* (literal "{_as_argv(roots)}"))' in profile
            writable = set().union(
                *(
                    _subpaths(line)
                    for line in profile
                    if line.startswith("(allow") and "file-write*" in line
                )
            )
            assert not any(
                _as_argv(roots).startswith(path.rstrip("/") + "/") for path in writable
            ), writable
        finally:
            plan.run_cleanup()
        assert not roots.exists()

    def test_an_operator_ssl_cert_file_wins(self, layout, monkeypatch):
        plan = self._plan(layout, monkeypatch, env={"SSL_CERT_FILE": "/etc/corp.pem"})
        try:
            assert plan.env["SSL_CERT_FILE"] == "/etc/corp.pem"
        finally:
            plan.run_cleanup()

    def test_nothing_is_set_unless_declared_and_exported(self, layout, monkeypatch):
        for declared, pem in ((False, self.PEM), (True, None)):
            plan = self._plan(layout, monkeypatch, declared=declared, pem=pem)
            try:
                assert "SSL_CERT_FILE" not in plan.env
                assert not any(
                    line.startswith("(allow file-read* (literal ")
                    for line in self._profile(plan)
                )
            finally:
                plan.run_cleanup()

    def test_the_export_runs_security_once_per_process(self, monkeypatch, tmp_path):
        keychains = [tmp_path / "roots.keychain", tmp_path / "system.keychain"]
        for keychain in keychains:
            keychain.write_text("")
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            ok = argv[-1] == str(keychains[0])
            return SimpleNamespace(
                returncode=0 if ok else 44, stdout=self.PEM if ok else "", stderr=""
            )

        monkeypatch.setattr(
            backends_module, "_TRUST_ROOT_KEYCHAINS", tuple(map(str, keychains))
        )
        monkeypatch.setattr(backends_module, "_trust_roots_cache", [])
        monkeypatch.setattr(backends_module.subprocess, "run", fake_run)
        assert backends_module._system_trust_roots() == self.PEM
        assert backends_module._system_trust_roots() == self.PEM
        # One call per keychain, and none the second time.
        assert [argv[:4] for argv in calls] == [
            ["/usr/bin/security", "find-certificate", "-a", "-p"]
        ] * 2


def _scanner_requirements():
    """Every scanner plugin ASH ships, by class name: each plugin module's
    ASH_SCANNERS, so trivy-repo, snyk-code and ferret-scan are held to the same
    guards as the builtin scanners, and a new plugin module is too."""
    import importlib
    import pkgutil

    import automated_security_helper.plugin_modules as plugin_modules

    found = {}
    for module in pkgutil.iter_modules(plugin_modules.__path__):
        package = importlib.import_module(f"{plugin_modules.__name__}.{module.name}")
        for scanner in getattr(package, "ASH_SCANNERS", []):
            requirements = getattr(scanner, "sandbox_requirements", None)
            if isinstance(requirements, SandboxRequirements):
                found[scanner.__name__] = requirements
    return found


@pytest.mark.unit
def test_the_guards_see_every_shipped_scanner_plugin():
    found = set(_scanner_requirements())
    assert {
        "GrypeScanner",
        "OpengrepScanner",
        "TrivyRepoScanner",
        "SnykCodeScanner",
        "FerretScanScanner",
    } <= found


def _content_db_scanners():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
    )

    return {"grype": GrypeScanner, "trivy": TrivyRepoScanner}


@pytest.mark.unit
class TestMacosScannerDeclarations:
    """What each shipped scanner is granted for macOS, and how narrowly."""

    @pytest.mark.parametrize("tool", ["grype", "trivy"])
    def test_the_macos_database_is_a_cache_not_a_read_path(self, tool):
        """sandbox-exec runs programs from read paths, and never from a cache, which
        it mounts read-only like every backend but bwrap's throwaway overlay."""
        requirements = _content_db_scanners()[tool].sandbox_requirements
        assert f"~/Library/Caches/{tool}" in requirements.cache_paths
        assert f"~/Library/Caches/{tool}" not in requirements.read_paths
        # Not updated inside the sandbox: content_db_refresh updates the database
        # outside it before an online scan.
        assert dict(requirements.sandbox_exec_env) == {}

    @pytest.mark.parametrize("tool", ["grype", "trivy"])
    def test_sandbox_exec_runs_nothing_from_the_database_directory(self, layout, tool):
        database = layout.home / "Library" / "Caches" / tool
        database.mkdir(parents=True)
        requirements = _content_db_scanners()[tool].sandbox_requirements
        policy = _policy(layout, requirements)
        assert _resolved([database]) <= _resolved(policy.cache)
        assert not _resolved([database]) & _resolved(policy.executable)
        plan = SandboxExecBackend().plan(["/usr/bin/true"], {}, policy)
        try:
            profile = plan.argv[plan.argv.index("-p") + 1].splitlines()
            allowed = set().union(
                *(
                    _subpaths(rule)
                    for _, rule in _indexed(profile, "(allow process-exec ")
                )
            )
            assert _as_argv(database) not in allowed
        finally:
            plan.run_cleanup()

    def test_cdk_nag_does_not_use_the_shared_jsii_cache(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            cdk_nag_scanner,
        )

        requirements = cdk_nag_scanner.CdkNagScanner.sandbox_requirements
        assert dict(requirements.sandbox_exec_env) == {
            "JSII_RUNTIME_PACKAGE_CACHE": "disabled"
        }
        assert not any("jsii" in p for p in requirements.cache_paths)

    def test_only_opengrep_unpacks_itself(self):
        declared = {
            name: requirements.unpack_dir_env
            for name, requirements in _scanner_requirements().items()
            if requirements.unpack_dir_env
        }
        assert declared == {"OpengrepScanner": "XDG_CACHE_HOME"}

    def test_no_grant_covers_the_whole_library_caches_directory(self):
        for name, requirements in _scanner_requirements().items():
            for path in requirements.read_paths + requirements.cache_paths:
                parts = Path(path).parts
                assert parts[-2:] != ("Library", "Caches"), (name, path)
                assert parts[-1:] != ("Library",), (name, path)


@pytest.mark.unit
class TestSandboxExecEnv:
    def test_the_declared_values_win_over_the_scanner_environment(self, layout):
        requirements = SandboxRequirements(
            env_prefixes=("GRYPE_",),
            sandbox_exec_env=(("GRYPE_DB_AUTO_UPDATE", "false"),),
        )
        plan = SandboxExecBackend().plan(
            ["/usr/bin/true"],
            {"GRYPE_DB_AUTO_UPDATE": "true"},
            _policy(layout, requirements),
        )
        try:
            assert plan.env["GRYPE_DB_AUTO_UPDATE"] == "false"
        finally:
            plan.run_cleanup()

    def test_other_backends_ignore_them(self, layout):
        backend = BwrapBackend()
        backend._executable = "/usr/bin/bwrap"
        requirements = SandboxRequirements(sandbox_exec_env=(("JSII_X", "1"),))
        plan = backend.plan(["/usr/bin/true"], {}, _policy(layout, requirements))
        assert "JSII_X" not in plan.env


@pytest.mark.unit
class TestUnpackDir:
    """A self-unpacking tool gets a private directory it may write and run from."""

    REQUIREMENTS = SandboxRequirements(unpack_dir_env="XDG_CACHE_HOME")

    def test_the_variable_names_a_private_writable_executable_directory(self, layout):
        plan = SandboxExecBackend().plan(
            ["/usr/bin/true"], {}, _policy(layout, self.REQUIREMENTS)
        )
        try:
            unpack = Path(plan.env["XDG_CACHE_HOME"])
            assert unpack.is_dir()
            profile = plan.argv[plan.argv.index("-p") + 1].splitlines()
            allowed = set().union(
                *(
                    _subpaths(rule)
                    for _, rule in _indexed(profile, "(allow process-exec ")
                )
            )
            ((_, deny),) = _indexed(profile, "(deny process-exec ")
            assert _as_argv(unpack) in allowed
            assert _as_argv(unpack) not in _subpaths(deny)
            writable = set().union(
                *(
                    _subpaths(line)
                    for line in profile
                    if line.startswith("(allow file-read* file-write* ")
                )
            )
            assert _as_argv(unpack) in writable
        finally:
            plan.run_cleanup()
        assert not unpack.exists(), "the unpack directory outlived its spawn"

    def test_each_spawn_gets_its_own(self, layout):
        policy = _policy(layout, self.REQUIREMENTS)
        first = SandboxExecBackend().plan(["/usr/bin/true"], {}, policy)
        second = SandboxExecBackend().plan(["/usr/bin/true"], {}, policy)
        try:
            assert first.env["XDG_CACHE_HOME"] != second.env["XDG_CACHE_HOME"]
        finally:
            first.run_cleanup()
            second.run_cleanup()

    def test_without_the_field_nothing_is_set_or_executable(self, layout):
        plan = SandboxExecBackend().plan(["/usr/bin/true"], {}, _policy(layout))
        try:
            assert "XDG_CACHE_HOME" not in plan.env
            assert "ash-sandbox-unpack-" not in plan.argv[plan.argv.index("-p") + 1]
        finally:
            plan.run_cleanup()


@pytest.mark.unit
class TestUvToolLock:
    """uv tool run opens its tools-directory lock read-write; nothing else there."""

    def test_the_lock_file_is_writable_and_the_tools_directory_is_not(
        self, layout, monkeypatch, tmp_path
    ):
        tools = tmp_path / "uv-tools"
        tools.mkdir()
        (tools / ".lock").write_text("")
        monkeypatch.setenv("UV_TOOL_DIR", str(tools))
        policy = _policy(layout)
        assert [Path(p) for p in policy.uv_tool_locks] == [(tools / ".lock").absolute()]
        lines = _sbpl(layout, tmp_path)
        writable = [
            line for line in lines if line.startswith("(allow file-read* file-write* ")
        ]
        assert any(
            f'(literal "{_as_argv(tools / ".lock")}")' in line for line in writable
        )
        assert not any(_as_argv(tools) in _subpaths(line) for line in writable)

    def test_no_lock_file_no_grant(self, layout, monkeypatch, tmp_path):
        tools = tmp_path / "uv-tools"
        tools.mkdir()
        monkeypatch.setenv("UV_TOOL_DIR", str(tools))
        assert _policy(layout).uv_tool_locks == ()

    def test_a_lock_that_is_a_symlink_is_not_granted(
        self, layout, monkeypatch, tmp_path
    ):
        tools = tmp_path / "uv-tools"
        tools.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_text("")
        (tools / ".lock").symlink_to(elsewhere)
        monkeypatch.setenv("UV_TOOL_DIR", str(tools))
        assert _policy(layout).uv_tool_locks == ()


@pytest.mark.unit
class TestScriptInterpreter:
    """A script's interpreter prefix is readable, as cfn_nag_scan's Ruby must be."""

    def _install(self, tmp_path, shebang):
        prefix = tmp_path / "toolcache" / "Ruby" / "3.3.12"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "lib").mkdir()
        ruby = prefix / "bin" / "ruby"
        ruby.write_text("")
        ruby.chmod(0o755)
        script_dir = tmp_path / "ash-bin"
        script_dir.mkdir()
        script = script_dir / "cfn_nag_scan"
        script.write_text(shebang.format(ruby=ruby) + "\nputs 1\n")
        script.chmod(0o755)
        return prefix, script

    def test_an_absolute_shebang(self, layout, tmp_path):
        prefix, script = self._install(tmp_path, "#!{ruby}")
        policy = _policy(layout, argv0=str(script))
        assert Path(os.path.realpath(prefix)) in _resolved(policy.read_only)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="PATH lookup on Windows needs an extension, and #! is a POSIX launch",
    )
    def test_an_env_shebang_is_resolved_through_path(
        self, layout, monkeypatch, tmp_path
    ):
        prefix, script = self._install(tmp_path, "#!/usr/bin/env ruby")
        monkeypatch.setenv("PATH", str(prefix / "bin"))
        policy = _policy(layout, argv0=str(script))
        assert Path(os.path.realpath(prefix)) in _resolved(policy.read_only)

    def test_a_binary_is_not_read_as_a_script(self, layout, tmp_path):
        binary = tmp_path / "tool"
        binary.write_bytes(b"\xcf\xfa\xed\xfe#!/opt/unlisted-prefix/bin/x")
        policy = _policy(layout, argv0=str(binary))
        assert not any(
            "unlisted-prefix" in p.as_posix() for p in _resolved(policy.read_only)
        )


@pytest.mark.unit
class TestSandboxExecWorkingDirectory:
    """A spawn without a cwd of its own starts in the private TMPDIR, not in ASH's."""

    def _chdir_arg(self, plan):
        return plan.argv[plan.argv.index(backends_module._SETSID_EXEC) + 1]

    def test_a_probe_without_a_cwd_starts_in_its_private_tmpdir(self, layout):
        plan = SandboxExecBackend().plan(
            ["/usr/bin/true"], {}, _policy(layout, cwd=None)
        )
        try:
            assert self._chdir_arg(plan) == plan.env["TMPDIR"]
        finally:
            plan.run_cleanup()

    def test_a_spawn_with_a_cwd_keeps_it(self, layout):
        plan = SandboxExecBackend().plan(["/usr/bin/true"], {}, _policy(layout))
        try:
            assert self._chdir_arg(plan) == ""
        finally:
            plan.run_cleanup()


@pytest.mark.unit
class TestAToolGivenAStagedCopy:
    """A tool handed a staged copy of its input reads that copy, not the scan's tree.

    nbconvert converts one notebook ASH copied to a private directory, so the source
    and output directories are left out of what it may read
    (``SandboxRequirements.staged_input_only``). The policy names them, and the
    backends that can hide a directory inside one they show do: bwrap mounts an
    empty directory over each, and sandbox-exec denies reading them after the reads
    it allows. Both give back what the policy lists inside them, the results
    directory first. A scanner, the control, still reads both.
    """

    STAGED = SandboxRequirements(staged_input_only=True)

    @pytest.fixture
    def staging(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()
        (staging / "analysis.ipynb").write_text("{}")
        return staging

    @pytest.fixture
    def under_a_tool_path(self, tmp_path, monkeypatch):
        """A tree checked out inside a directory every tool reads, as under /opt."""
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        opt = tmp_path / "opt"
        source = opt / "repo"
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (opt / "tool").mkdir()
        return SimpleNamespace(
            home=home,
            opt=opt,
            source=source,
            output=output,
            results=output / "converted" / "jupyter",
        )

    def _staged(self, layout, staging, **overrides):
        kwargs = {"scan_target": staging, "cwd": staging, **overrides}
        return _policy(layout, self.STAGED, **kwargs)

    @staticmethod
    def _reaches(paths, target) -> bool:
        real = Path(os.path.realpath(target))
        return any(p == real or p in real.parents or real in p.parents for p in paths)

    def test_the_source_and_output_directories_are_not_readable(self, layout, staging):
        policy = self._staged(layout, staging)

        readable = _resolved([*policy.read_only, *policy.cache])
        for withheld in (layout.source, layout.output):
            assert not self._reaches(readable, withheld), (
                f"a tool given a staged copy may read {withheld}: {sorted(readable)}"
            )

    def test_the_staged_copy_is_readable_and_the_results_directory_writable(
        self, layout, staging
    ):
        policy = self._staged(layout, staging)

        assert Path(os.path.realpath(staging)) in _resolved(policy.read_only)
        assert _resolved(policy.writable) == _resolved([layout.results])

    def test_the_policy_names_the_withheld_directories(self, layout, staging):
        assert _resolved(self._staged(layout, staging).unread) == _resolved(
            [layout.source, layout.output]
        )

    def test_a_scanner_still_reads_the_source_and_output_directories(
        self, layout, staging
    ):
        policy = _policy(layout, scan_target=staging, cwd=staging)

        readable = _resolved(policy.read_only)
        for scanned in (layout.source, layout.output):
            assert Path(os.path.realpath(scanned)) in readable
        assert policy.unread == ()

    def test_bwrap_hides_a_withheld_directory_inside_a_mounted_one(
        self, under_a_tool_path, staging
    ):
        layout = under_a_tool_path
        policy = self._staged(layout, staging, extra_read_paths=[str(layout.opt)])
        backend = BwrapBackend()
        backend._executable = "/usr/bin/bwrap"

        argv = backend.plan(["/usr/bin/true"], {}, policy).argv

        def mount(flag, path):
            spelled = _as_argv(path)
            found = [
                i for i, a in enumerate(argv) if a == flag and argv[i + 1] == spelled
            ]
            assert found, f"no {flag} {spelled} in {argv}"
            return found[0]

        opt = mount("--ro-bind", layout.opt)
        hidden = mount("--tmpfs", layout.source)
        results = mount("--bind", layout.results)
        assert opt < hidden < results, (
            "the empty directory has to cover the tree after the mount that shows "
            "it, and before the results directory inside it is mounted"
        )

    def test_bwrap_mounts_no_empty_directory_for_a_scanner(self, under_a_tool_path):
        layout = under_a_tool_path
        policy = _policy(layout, extra_read_paths=[str(layout.opt)])
        backend = BwrapBackend()
        backend._executable = "/usr/bin/bwrap"

        argv = backend.plan(["/usr/bin/true"], {}, policy).argv

        tmpfs = {argv[i + 1] for i, a in enumerate(argv) if a == "--tmpfs"}
        assert _as_argv(layout.source) not in tmpfs
        assert _as_argv(layout.output) not in tmpfs

    def test_sandbox_exec_denies_the_withheld_directories_after_its_reads(
        self, under_a_tool_path, staging, tmp_path
    ):
        layout = under_a_tool_path
        tool_inside = layout.source / ".venv"
        tool_inside.mkdir()
        policy = self._staged(
            layout, staging, extra_read_paths=[str(layout.opt), str(tool_inside)]
        )

        lines = SandboxExecBackend().profile(policy, tmp_path / "private-tmp")
        lines = lines.splitlines()

        def last(prefix, path):
            spelled = _as_argv(path)
            found = [
                i for i, line in _indexed(lines, prefix) if spelled in _subpaths(line)
            ]
            assert found, f"no {prefix} rule names {spelled}"
            return found[-1]

        shown = last("(allow file-read* (subpath", layout.opt)
        denied = last("(deny file-read*", layout.source)
        assert last("(deny file-read*", layout.output) == denied
        given_back = last("(allow file-read* (subpath", tool_inside)
        written = last("(allow file-read* file-write*", layout.results)
        assert shown < denied < given_back, (
            "the tree has to be denied after the read that shows it, and a tool "
            "path inside it given back after that"
        )
        assert denied < written

    def test_sandbox_exec_denies_nothing_more_for_a_scanner(self, layout, tmp_path):
        lines = _sbpl(layout, tmp_path)

        denied = set()
        for _, line in _indexed(lines, "(deny file-read*"):
            denied |= _subpaths(line)
        assert _as_argv(layout.source) not in denied
        assert _as_argv(layout.output) not in denied


def _uv_plugin(pin="1.8"):
    """A uv-run scanner double: its pinned spec reveals a short env-read pin
    the plain value layer cannot match (below the whole-word band)."""
    return SimpleNamespace(
        config=SimpleNamespace(name="uvscanner"),
        results_dir=None,
        use_uv_tool=True,
        _uv_run_inputs=lambda: (f"bandit=={pin}", "sarif-tools"),
        _values_to_redact=lambda: (pin,),
    )


@pytest.mark.unit
def test_the_scope_factory_carries_a_uv_plugins_run_inputs(tmp_path, monkeypatch):
    """The scope's plugin inputs come from the FACTORY reading the plugin, so
    every record made under the scope hides a spec that holds an env-read
    value. A non-uv plugin contributes none, even with the method present."""
    monkeypatch.setattr(
        scope_module, "resolve_backend", lambda mode: SimpleNamespace(name="fake")
    )
    scope = scanner_sandbox_scope(_uv_plugin(), _context(tmp_path), tmp_path)
    assert scope is not None
    assert scope.plugin_inputs == ("bandit==1.8", "sarif-tools")
    assert scope.environment_values == ("1.8",)

    plugin = _uv_plugin()
    plugin.use_uv_tool = False
    scope = scanner_sandbox_scope(plugin, _context(tmp_path), tmp_path)
    assert scope is not None
    assert scope.plugin_inputs == ()


@pytest.mark.unit
def test_the_scope_factory_carries_the_plugins_public_command(tmp_path, monkeypatch):
    """The scope's record tool name is the plugin's COMMAND, read by the
    factory -- the same public anchor the report lines and the install
    records pass -- not its config name. A scanner whose config name differs
    from its command otherwise had the command replaced in the scope's
    records and kept on the report lines, numbering the placeholders apart:
    under the scope, a record quoting the command keeps it visible while the
    pinned spec is hidden."""
    monkeypatch.setattr(
        scope_module, "resolve_backend", lambda mode: SimpleNamespace(name="fake")
    )
    plugin = _uv_plugin()
    plugin.command = "bandit-cmd"
    plugin._uv_run_inputs = lambda: ("bandit-cmd==1.8", "sarif-tools")
    scope = scanner_sandbox_scope(plugin, _context(tmp_path), tmp_path)
    assert scope is not None
    assert scope.command == "bandit-cmd"

    with sandbox_scope(scope):
        shown = scope_module.scope_shown_text(
            "Running command: uv tool run --from bandit-cmd==1.8 bandit-cmd -r src"
        )

    assert "bandit-cmd==1.8" not in shown, shown
    assert "1.8" not in shown, shown
    assert "bandit-cmd -r src" in shown, shown


@pytest.mark.unit
def test_the_record_context_hides_a_short_pin_with_the_sandbox_off():
    """Under the default sandbox mode "off" no scope exists, so the process
    runner's own records fell back to the plain value layer and a short pin
    ("1.8", below the whole-word band) printed in ash.log while every report
    line hid it. The dispatch's record-only context carries the run's input
    set to those records whatever the sandbox mode; outside both, the plain
    layer still applies."""
    assert scope_module.active_scope() is None

    line = "Running command: uv tool run --from stub-tool==1.8 stub-tool -r src"
    with scope_module.uv_record_inputs(("1.8",), ("stub-tool==1.8",), "stub-tool"):
        shown = scope_module.scope_shown_text(line)
    assert "stub-tool==1.8" not in shown, shown
    assert "1.8" not in shown, shown
    assert "stub-tool -r src" in shown, shown

    # Outside the context (and any scope) the plain value layer applies:
    # the short pin is below its whole-word band, so the line is unchanged.
    assert scope_module.scope_shown_text(line) == line


@pytest.mark.unit
def test_the_uv_dispatch_sets_the_record_context_around_the_run(tmp_path):
    """_try_uv_tool_execution wraps run_tool in the record-only context, so
    every record the runner makes while the child runs -- with the sandbox
    off -- hides the run's plugin-built inputs. The fake runner stands where
    the real one calls scope_shown_text for its own log lines."""
    from unittest.mock import patch as mock_patch

    from automated_security_helper.base.uv_tool_mixin import UVToolMixin

    seen: list = []

    class _Runner:
        def uv_availability(self):
            return True, None

        def run_tool(self, **kwargs):
            seen.append(
                scope_module.scope_shown_text(
                    "Running command: uv tool run --from stub-tool==1.8 "
                    "stub-tool -r src"
                )
            )
            return {"returncode": 0, "stdout": "", "stderr": ""}

    class _Plugin(UVToolMixin):
        """Overrides only what a plugin supplies; the dispatch's own helpers (the
        stderr log identity, the interpreter request, the after-the-start
        response, the --with dependencies and the redacted error text) are the
        mixin's, so a change to one of their signatures reaches this test."""

        command = "stub-tool"
        use_uv_tool = True
        # The package that provides the command (None: the command's own name).
        uv_tool_package_name = None

        def _is_offline_mode(self):
            return False

        def _values_to_redact(self):
            return ("1.8",)

        def _uv_run_inputs_for_records(self):
            return ("stub-tool==1.8",)

        def _get_tool_package_extras(self):
            return None

        def _get_tool_version_constraint(self):
            return "==1.8"

        def _plugin_log(self, *args, **kwargs):
            return None

        def _uv_response(self, result, results_dir, **kwargs):
            return result

    with mock_patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        return_value=_Runner(),
    ):
        result = _Plugin()._try_uv_tool_execution(["stub-tool", "-r", "src"], tmp_path)

    assert result is not None and result.get("returncode") == 0, result
    assert seen, "the fake runner never logged"
    assert "stub-tool==1.8" not in seen[0], seen[0]
    assert "1.8" not in seen[0], seen[0]
    # The context is scoped to the run: after the dispatch it is gone.
    assert scope_module.scope_shown_text("stub-tool==1.8") == "stub-tool==1.8"


@pytest.mark.unit
def test_the_sandbox_debug_line_hides_a_spec_that_pins_an_env_read_value(
    tmp_path, monkeypatch, caplog
):
    """prepare_spawn's record quotes the planned argv; for a uv run it gets
    the run's own inputs, so a spec pinning a short env-read value is hidden
    by origin while an input holding no value stays shown."""
    import logging

    class _Planner:
        name = "fake"

        def plan(self, argv, env, policy):
            return SpawnPlan(argv=list(argv), env=dict(env))

    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: _Planner())
    scope = scanner_sandbox_scope(_uv_plugin(), _context(tmp_path), tmp_path)
    assert scope is not None

    with caplog.at_level(logging.DEBUG, logger="ash"):
        with sandbox_scope(scope):
            prepare_spawn(
                ["uv", "tool", "run", "--with", "sarif-tools", "bandit==1.8"],
                {"PATH": os.environ.get("PATH", "")},
                None,
            )

    lines = [
        record.getMessage()
        for record in caplog.records
        if "Scanner sandbox" in record.getMessage()
    ]
    assert lines, [record.getMessage() for record in caplog.records]
    assert not any("bandit==1.8" in line for line in lines), lines
    assert any("sarif-tools" in line for line in lines), lines


@pytest.mark.unit
def test_the_runners_own_records_hide_a_pinning_spec_inside_a_uv_scope(
    tmp_path, monkeypatch
):
    """subprocess_utils' own command records route through the uv layer when
    the active scope carries a uv run's inputs: a spec pinning a short
    env-read value is hidden there too, and an input holding no value stays
    shown. The plain value layer alone cannot match the short pin, which is
    what made the routing load-bearing."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(
        scope_module, "resolve_backend", lambda mode: SimpleNamespace(name="fake")
    )
    scope = scanner_sandbox_scope(_uv_plugin(), _context(tmp_path), tmp_path)
    assert scope is not None
    text = "Running command: uv tool run --with sarif-tools bandit==1.8"

    with sandbox_scope(scope):
        inside = subprocess_utils._logged_without(text, ("1.8",))

    assert "bandit==1.8" not in inside, inside
    assert "sarif-tools" in inside, inside


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a POSIX special file")
@pytest.mark.unit
def test_a_sweep_failure_warning_hides_an_env_read_value(tmp_path, monkeypatch, caplog):
    """The could-not-remove warning names the entry, the root and the OS
    error, and any of them can hold an env-read value (a tool names files
    after options it was given). The record is redacted with the sweep's
    values before it is logged, and the refusal the sweep raises at its end
    for the entry it could not remove repeats the logged line, nothing more."""
    import logging

    from automated_security_helper.utils.sandbox import fs_guard

    value = "SWEEPSECRET-7731"
    root = tmp_path / "results"
    root.mkdir()
    os.mkfifo(root / f"fifo-{value}")

    def _refuse(*args, **kwargs):
        raise OSError(f"refused: fifo-{value}")

    monkeypatch.setattr(fs_guard.os, "unlink", _refuse)

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(OSError) as refused:
            fs_guard.sweep_writable([root], (value,))

    lines = [
        record.getMessage()
        for record in caplog.records
        if "Could not remove" in record.getMessage()
    ]
    assert lines, [record.getMessage() for record in caplog.records]
    assert not any(value in line for line in lines), lines
    assert value not in str(refused.value), str(refused.value)
    # The refusal is chained to nothing: a traceback or a logged exception of it
    # prints its cause and its context too, and either would quote the OS error.
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None


def _sweep_notes_after_a_spawn(tmp_path, monkeypatch, caplog, hook):
    """Build a scope for a plugin whose values hook is ``hook``, plan a spawn
    inside it, and run the plan's sweep over a results directory that holds a
    special file named after the value, whose removal fails. Returns the
    sweep's could-not-remove notes, the refusal it raised at its end among
    them, and the results directory.

    The sweep runs from the plan's cleanup, so the scope's values are its
    only redaction source. A removal that fails is a refusal the sweep raises
    once it has finished (the plan's run_cleanup records it, best effort); the
    step is called directly here, so the raise reaches the test."""
    import logging

    from automated_security_helper.utils.sandbox import fs_guard

    class _Planner:
        name = "fake"

        def plan(self, argv, env, policy):
            return SpawnPlan(argv=list(argv), env=dict(env))

    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: _Planner())
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="sweeper"),
        results_dir=None,
        _values_to_redact=hook,
    )
    scope = scanner_sandbox_scope(plugin, _context(tmp_path), tmp_path)
    assert scope is not None
    results = scope.results_dir
    results.mkdir(parents=True)
    os.mkfifo(results / f"fifo-{_SWEEP_VALUE}")

    def _refuse(*args, **kwargs):
        raise OSError(f"refused: fifo-{_SWEEP_VALUE}")

    monkeypatch.setattr(fs_guard.os, "unlink", _refuse)

    with sandbox_scope(scope):
        plan = prepare_spawn(["/usr/bin/true"], {"PATH": "/usr/bin"}, None)
    assert plan is not None
    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(OSError) as refused:
            plan.cleanup[0]()

    notes = [
        record.getMessage()
        for record in caplog.records
        if "Could not remove" in record.getMessage()
    ]
    assert notes, [record.getMessage() for record in caplog.records]
    notes.append(str(refused.value))
    # What a traceback or a logged exception of the refusal would print besides
    # its own text: its cause and its context, which are none.
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None
    return notes, results


_SWEEP_VALUE = "tool-qz4b9secret"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a POSIX special file")
@pytest.mark.unit
def test_a_bare_string_values_answer_is_hidden_whole_from_the_sweep_note(
    tmp_path, monkeypatch, caplog
):
    """The scope reads the plugin's values hook when it is built. A bare
    string the hook answers is ONE value, not its characters: split, each
    character is below every redaction band, and the sweep, whose only
    redaction is the scope's values, quoted the entry whole."""
    notes, _ = _sweep_notes_after_a_spawn(
        tmp_path, monkeypatch, caplog, lambda: _SWEEP_VALUE
    )

    assert not any(_SWEEP_VALUE in note for note in notes), notes


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a POSIX special file")
@pytest.mark.unit
def test_a_raising_values_hook_makes_the_sweep_note_value_free(
    tmp_path, monkeypatch, caplog
):
    """A hook that raised when the scope was built leaves no values to hide
    with. That is not "no values": the sweep names no entry, root or OS error,
    rather than quoting them with an empty value set."""

    def raising():
        raise RuntimeError(f"the hook broke on {_SWEEP_VALUE}")

    notes, results = _sweep_notes_after_a_spawn(tmp_path, monkeypatch, caplog, raising)

    assert not any(_SWEEP_VALUE in note for note in notes), notes
    assert not any("fifo-" in note or str(results) in note for note in notes), notes


@pytest.mark.unit
def test_a_cleanup_failure_record_hides_the_scopes_env_values(
    tmp_path, monkeypatch, caplog
):
    """run_cleanup's best-effort record quotes the exception, which can name
    a path an option chose. Inside a scanner's scope the record is redacted
    with the scope's env-read values."""
    import logging

    value = "CLEANSECRET-9917"

    def _fails():
        raise OSError(f"could not remove /work/{value}/x")

    monkeypatch.setattr(
        scope_module, "resolve_backend", lambda mode: SimpleNamespace(name="fake")
    )
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="cleaner"),
        results_dir=None,
        _values_to_redact=lambda: (value,),
    )
    scope = scanner_sandbox_scope(plugin, _context(tmp_path), tmp_path)
    assert scope is not None
    plan = SpawnPlan(argv=[], env={}, cleanup=[_fails])

    with caplog.at_level(logging.DEBUG, logger="ash"):
        with sandbox_scope(scope):
            plan.run_cleanup()

    lines = [
        record.getMessage()
        for record in caplog.records
        if "Sandbox cleanup failed" in record.getMessage()
    ]
    assert lines, [record.getMessage() for record in caplog.records]
    assert not any(value in line for line in lines), lines


@pytest.mark.unit
def test_scope_records_keep_the_plugins_public_command_visible(tmp_path):
    """scope_shown_text passed the scope's scanner_name as the public tool
    name while every report line passes the plugin's command: a plugin whose
    config name differs from its command had the command replaced in sandbox
    records ("<argument 2 not shown>") and kept on report lines, numbering
    the placeholders differently. The scope carries the command next to its
    inputs, so one name is public on both."""
    from automated_security_helper.utils.sandbox import scope as scope_module
    from automated_security_helper.utils.sandbox.policy import SandboxRequirements

    scope = scope_module.SandboxScope(
        backend=object(),  # type: ignore[arg-type] -- unused by the record path
        scanner_name="nice-name",
        requirements=SandboxRequirements(),
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        results_dir=tmp_path / "out" / "scanners" / "nice-name",
        scan_target=None,
        offline=True,
        environment_values=("9.9",),
        plugin_inputs=("bandit==9.9",),
        command="bandit",
    )
    token = scope_module._ACTIVE.set(scope)
    try:
        shown = scope_module.scope_shown_text("bandit exited 1 running bandit==9.9")
    finally:
        scope_module._ACTIVE.reset(token)

    assert "bandit exited 1" in shown, shown
    assert "bandit==9.9" not in shown, shown
    assert "9.9" not in shown, shown


def _scope_with(tmp_path, **overrides):
    from automated_security_helper.utils.sandbox import scope as scope_module
    from automated_security_helper.utils.sandbox.policy import SandboxRequirements

    fields = {
        "backend": object(),  # unused by the record path
        "scanner_name": "nice-name",
        "requirements": SandboxRequirements(),
        "source_dir": tmp_path,
        "output_dir": tmp_path / "out",
        "results_dir": tmp_path / "out" / "scanners" / "nice-name",
        "scan_target": None,
        "offline": True,
        "environment_values": (),
        "plugin_inputs": (),
        "command": "",
    }
    fields.update(overrides)
    return scope_module.SandboxScope(**fields)


@pytest.mark.unit
def test_the_scopes_and_the_records_hidden_sets_are_unioned(tmp_path):
    """A scope that carries its own inputs made the record context invisible:
    the dispatch-time values and inputs of the run the record is FROM were
    dropped whenever the active scope had any inputs of its own, so a glued
    value in the record's set printed. The two sources union -- hiding
    another run's set hides more, never less."""
    from automated_security_helper.utils.sandbox import scope as scope_module

    scope = _scope_with(
        tmp_path,
        environment_values=("9.9",),
        plugin_inputs=("bandit==9.9",),
        command="bandit",
    )
    token = scope_module._ACTIVE.set(scope)
    try:
        with scope_module.uv_record_inputs(
            ("1.77rc9",), ("sarif-tools[extraqz4b]==1.77rc9",), "bandit"
        ):
            shown = scope_module.scope_shown_text(
                "bandit exited 1: bandit==9.9 could not use "
                "sarif-tools[extraqz4b] at 1.77rc9"
            )
    finally:
        scope_module._ACTIVE.reset(token)

    assert "bandit exited 1" in shown, shown
    assert "bandit==9.9" not in shown, shown
    assert "9.9" not in shown, shown
    assert "extraqz4b" not in shown, shown
    assert "1.77rc9" not in shown, shown


@pytest.mark.unit
def test_a_records_command_outranks_the_scopes_config_name(tmp_path):
    """The record context carries the plugin's public command; a scope built
    before construction carries only the config name. Preferring the config
    name over the record's command put the command among the hidden input's
    name tokens, so the tool's own name was replaced in its records while
    every report line kept it."""
    from automated_security_helper.utils.sandbox import scope as scope_module

    scope = _scope_with(tmp_path)
    token = scope_module._ACTIVE.set(scope)
    try:
        with scope_module.uv_record_inputs(
            ("1.77rc9",), ("stub-tool==1.77rc9",), "stub-tool"
        ):
            shown = scope_module.scope_shown_text(
                "stub-tool exited 1 installing stub-tool==1.77rc9"
            )
    finally:
        scope_module._ACTIVE.reset(token)

    assert shown.startswith("stub-tool exited 1"), shown
    assert "1.77rc9" not in shown, shown


@pytest.mark.unit
def test_a_raising_redaction_returns_a_value_free_note(monkeypatch):
    """scope_shown_text never raises: its callers record from inside except
    blocks, where a raise becomes the frame's own failure. The note carries
    no text from the record."""
    from automated_security_helper.utils.sandbox import scope as scope_module

    def raising():
        raise RuntimeError("the redactor broke")

    monkeypatch.setattr(scope_module, "active_scope", raising)

    shown = scope_module.scope_shown_text("saw EDGESECRET-9912", ("EDGESECRET-9912",))

    assert shown == "(this text could not be shown)"
    assert "EDGESECRET-9912" not in shown


@pytest.mark.unit
def test_a_raising_redaction_does_not_stop_the_symlink_sweep(tmp_path, monkeypatch):
    """fs_guard's sweep records a removal failure from inside its except
    block. A raise from the redaction there stopped the os.fwalk sweep
    partway: symlinks after that point stayed, and the redactor's error
    escaped sweep_writable into the executor's post-scan sweep.

    The sweep still refuses the entry it could not remove, once, after it has
    walked everything else: the raise read here is that refusal (an OSError),
    never the redactor's RuntimeError, and the link after the failed one is
    gone before it is raised. Whichever link the walk reaches first is the one
    whose removal fails, so the check does not depend on the order the
    directory lists its entries in: a sweep that stopped at the failure would
    leave both links, whichever came first."""
    from automated_security_helper.utils.sandbox import fs_guard
    from automated_security_helper.utils.sandbox import scope as scope_module

    root = tmp_path / "writable"
    root.mkdir()
    (root / "aaa-link").symlink_to(tmp_path)
    (root / "zzz-link").symlink_to(tmp_path)

    real_unlink = os.unlink
    failed: list = []

    def failing_unlink(name, *args, **kwargs):
        if not failed and "-link" in str(name):
            failed.append(Path(str(name)).name)
            raise OSError("the first removal fails")
        return real_unlink(name, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", failing_unlink)

    def raising():
        raise RuntimeError("the redactor broke")

    monkeypatch.setattr(scope_module, "active_scope", raising)

    with pytest.raises(OSError):
        fs_guard.sweep_writable([root], ("EDGESECRET-9912",))

    # os.path.lexists, not Path.exists(follow_symlinks=False): the keyword
    # arrived in Python 3.12 and CI's 3.10 leg raises TypeError on it.
    assert len(failed) == 1, failed
    remaining = [
        name for name in ("aaa-link", "zzz-link") if os.path.lexists(root / name)
    ]
    assert remaining == failed, (
        "the entry whose removal failed is what the refusal is about, and the "
        "other link must still be removed"
    )


@pytest.mark.unit
def test_a_raising_redaction_does_not_skip_the_remaining_cleanup(monkeypatch):
    """A sandbox plan's cleanup records a failed step from inside its except
    block. A raise from the redaction there skipped every remaining step,
    the private-dir removal included."""
    from automated_security_helper.utils.sandbox import backends
    from automated_security_helper.utils.sandbox import scope as scope_module

    def raising():
        raise RuntimeError("the redactor broke")

    monkeypatch.setattr(scope_module, "active_scope", raising)

    ran: list = []

    def broken_step():
        raise OSError("the first cleanup step fails")

    plan = backends.SpawnPlan(
        argv=[], env={}, cleanup=[broken_step, lambda: ran.append("second")]
    )
    plan.run_cleanup()

    assert ran == ["second"], "the remaining cleanup steps must still run"
