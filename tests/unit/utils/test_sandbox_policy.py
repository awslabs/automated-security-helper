# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The backend-neutral sandbox policy and the scope that decides when it applies."""

import os
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
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import (
    BwrapBackend,
    SpawnPlan,
)
from automated_security_helper.utils.sandbox.policy import build_scanner_policy


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".local" / "share" / "keyrings").mkdir(parents=True)
    (home / ".local" / "bin").mkdir(parents=True)
    (home / ".ssh").mkdir()
    monkeypatch.setenv("HOME", str(home))
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
        assert env["HOME"] == str(layout.home)
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
        home = os.path.realpath(layout.home)
        results = os.path.realpath(layout.results)
        source = os.path.realpath(layout.source)
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
            result = run_command(["echo hi"], shell=True)
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
        env = _policy(layout).filter_env(
            {
                "UV_PUBLISH_TOKEN": "s",
                "UV_INDEX_PRIVATE_PASSWORD": "s",
                "UV_INDEX_URL": "https://user:tok@example.invalid/simple",
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

        token = _ACTIVE.set(RefusingScope("grype", "no bwrap here"))
        try:
            with pytest.raises(SandboxUnavailable, match="no bwrap here"):
                spawn_run(["/usr/bin/true"])
        finally:
            _ACTIVE.reset(token)


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
        results = os.path.realpath(layout.results)
        argv = plan.argv
        read_only_under_results = [
            argv[i + 2]
            for i, flag in enumerate(argv)
            if flag == "--ro-bind"
            and (argv[i + 2] == results or argv[i + 2].startswith(results + os.sep))
        ]
        assert not read_only_under_results, read_only_under_results
        assert ["--bind", results, results] == argv[
            argv.index(results) - 1 : argv.index(results) + 2
        ]
        assert argv[argv.index("--chdir") + 1] == os.path.realpath(work)

    def test_a_writable_cwd_under_the_results_directory_can_be_written(
        self, layout, tmp_path
    ):
        import shutil
        import subprocess

        if not shutil.which("bwrap"):
            pytest.skip("bwrap is not installed")
        backend = BwrapBackend()
        if backend.probe():
            pytest.skip("bwrap cannot start a sandbox here")
        work = layout.results / "work"
        work.mkdir(parents=True)
        plan = backend.plan(
            ["/bin/sh", "-c", "echo ok > written && cat written"],
            {"PATH": "/usr/bin:/bin"},
            _policy(layout, argv0="/bin/sh", cwd=work),
        )
        result = subprocess.run(plan.argv, env=plan.env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert (work / "written").read_text() == "ok\n"


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
