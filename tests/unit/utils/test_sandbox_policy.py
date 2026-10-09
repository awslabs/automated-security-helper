# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The backend-neutral sandbox policy and the scope that decides when it applies."""

import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.utils.sandbox import (
    SandboxRequirements,
    SandboxUnavailable,
    clear_backend_cache,
    prepare_spawn,
    sandbox_scope,
    scanner_sandbox_scope,
)
from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import (
    BACKENDS,
    LANDLOCK_EXEC,
    BwrapBackend,
    FirejailBackend,
    SandboxExecBackend,
    SpawnPlan,
)
from automated_security_helper.utils.sandbox.policy import (
    build_scanner_policy,
    refuse_symlinked_output_dir,
)


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

    def test_proxy_settings_pass_only_with_a_network(self, layout):
        online = _policy(layout, SandboxRequirements(network=True))
        assert online.filter_env({"HTTPS_PROXY": "p"})["HTTPS_PROXY"] == "p"


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

    def test_bwrap_keeps_its_throwaway_overlay(self, layout, cache):
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
        ~/.semgrep or ~/.opengrep; npm-audit lost the vulnerable ranges it reads
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


class TestReviewFindings:
    """Regressions for the gaps the policy review found."""

    def test_a_symlinked_results_directory_is_refused(self, layout, tmp_path):
        victim = tmp_path / "victim"
        victim.mkdir()
        (layout.output / "scanners").mkdir(parents=True)
        layout.results.symlink_to(victim, target_is_directory=True)
        with pytest.raises(SandboxUnavailable, match="symlink"):
            _policy(layout)

    def test_a_symlink_above_the_results_directory_is_refused(self, layout, tmp_path):
        victim = tmp_path / "victim"
        (victim / "grype").mkdir(parents=True)
        (layout.output / "scanners").symlink_to(victim, target_is_directory=True)
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
                spawn_run(["/usr/bin/true"])
        finally:
            _ACTIVE.reset(scope_reset)


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
    def test_a_sandboxed_scan_stops_before_writing_through_it(self, tree, mode):
        # The orchestrator checks before ensure_directories, which would create
        # and clear subdirectories under the link's target.
        from automated_security_helper.core.exceptions import ASHValidationError
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        (tree.source / "build").symlink_to(tree.target, target_is_directory=True)
        orchestrator = ASHScanOrchestrator(
            source_dir=tree.source, output_dir=tree.source / "build" / "ash"
        )
        orchestrator.config = AshConfig(sandbox=SandboxConfig(mode=mode))
        if mode == "off":
            orchestrator._refuse_symlinked_output_dir()
        else:
            with pytest.raises(ASHValidationError, match="build is a symlink"):
                orchestrator._refuse_symlinked_output_dir()
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


def test_an_import_path_entry_elsewhere_in_home_is_not_mounted(layout, monkeypatch):
    """PYTHONPATH=~/anything must not make that directory readable to scanners."""
    stray = layout.home / "notes"
    stray.mkdir()
    monkeypatch.setattr(sys, "path", [*sys.path, str(stray)])
    exposed = _resolved(_policy(layout).read_only)
    assert Path(os.path.realpath(stray)) not in exposed


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


def _builtin_requirements():
    from automated_security_helper.plugin_modules.ash_builtin import ASH_SCANNERS

    found = {}
    for scanner in ASH_SCANNERS:
        requirements = getattr(scanner, "sandbox_requirements", None)
        if isinstance(requirements, SandboxRequirements):
            found[scanner.__name__] = requirements
    return found


class TestMacosScannerDeclarations:
    """What each builtin scanner is granted for macOS, and how narrowly."""

    def test_grype_reads_its_macos_database_and_never_updates_it_there(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            grype_scanner,
        )

        requirements = grype_scanner.GrypeScanner.sandbox_requirements
        assert "~/Library/Caches/grype" in requirements.read_paths
        assert "~/Library/Caches/grype" not in requirements.cache_paths
        assert dict(requirements.sandbox_exec_env) == {"GRYPE_DB_AUTO_UPDATE": "false"}

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
            for name, requirements in _builtin_requirements().items()
            if requirements.unpack_dir_env
        }
        assert declared == {"OpengrepScanner": "XDG_CACHE_HOME"}

    def test_no_grant_covers_the_whole_library_caches_directory(self):
        for name, requirements in _builtin_requirements().items():
            for path in requirements.read_paths + requirements.cache_paths:
                parts = Path(path).parts
                assert parts[-2:] != ("Library", "Caches"), (name, path)
                assert parts[-1:] != ("Library",), (name, path)


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
        victim = tmp_path / "victim"
        victim.write_text("")
        (tools / ".lock").symlink_to(victim)
        monkeypatch.setenv("UV_TOOL_DIR", str(tools))
        assert _policy(layout).uv_tool_locks == ()


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
        binary.write_bytes(b"\xcf\xfa\xed\xfe#!/opt/evil/bin/x")
        policy = _policy(layout, argv0=str(binary))
        assert not any("evil" in p.as_posix() for p in _resolved(policy.read_only))


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
