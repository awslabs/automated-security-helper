"""Tests for the buildx GitHub Actions layer-cache gate.

Every guard in ``_gha_layer_cache_args`` exists because getting it wrong is either
silent or destructive: emitting ``type=gha`` flags outside Actions makes the build
fail on a cache backend that cannot authenticate, emitting them for podman or finch
fails on an unsupported backend, and emitting them alongside ``--no-cache``
contradicts the caller. The default is therefore "return nothing", and these tests
pin both that default and the one combination that opts in.
"""

import logging
import subprocess

import pytest

from automated_security_helper.interactions import run_ash_container
from automated_security_helper.interactions.run_ash_container import (
    _gha_layer_cache_args,
    _runner_supports_buildx,
)

# The credentials buildx needs. Actions does not expose these to `run:` steps by
# default, so a workflow has to export them; the gate treats their absence as
# "caching unavailable".
_ACTIONS_ENV = {
    "ACTIONS_RUNTIME_TOKEN": "token",
    "ACTIONS_CACHE_URL": "https://example.invalid/cache/",
}


@pytest.fixture(autouse=True)
def buildx_present(monkeypatch):
    """Assume the resolved runner really does provide buildx.

    The capability check shells out, so leaving it live would make every test in
    this file depend on whether the machine running them happens to have docker
    and buildx installed. ``TestBuildxCapabilityProbe`` exercises the real
    function; everything else states the assumption and moves on.
    """
    monkeypatch.setattr(
        run_ash_container, "_runner_supports_buildx", lambda runner: True
    )


@pytest.fixture(autouse=True)
def pinned_arch(monkeypatch):
    """Pin the architecture so scope strings are deterministic off arm hardware."""
    monkeypatch.setattr(run_ash_container.platform, "machine", lambda: "x86_64")


@pytest.fixture
def in_actions(monkeypatch):
    """Simulate a GitHub Actions run that has exported the cache credentials."""
    for key, value in _ACTIONS_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("ACTIONS_RESULTS_URL", raising=False)
    monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)


class TestCacheEnabled:
    def test_docker_in_actions_emits_both_directions(self, in_actions):
        args = _gha_layer_cache_args("docker", "ci", force=False, offline=False)
        assert args == [
            "--cache-from",
            "type=gha,scope=ash-ci-x86_64-online",
            "--cache-to",
            "type=gha,mode=min,ignore-error=true,scope=ash-ci-x86_64-online",
        ]

    def test_scope_is_per_build_target(self, in_actions):
        """Targets must not share a scope; buildx lets one overwrite the other.

        Worth knowing while reading this: ``build_target`` cannot actually differ
        on any path that reaches the cache. run_ash_container forces it to "ci"
        whenever CI is set, and the cache needs ACTIONS_RUNTIME_TOKEN, which only
        exists inside Actions -- where CI is always set. So "non-root" here is a
        value the live path cannot produce, and it is asserted only because
        build_target remains a parameter that a future caller could vary. The
        discriminators that matter today are architecture and offline, covered by
        ``TestScopeSeparatesWhatCannotBeShared``.
        """
        ci = _gha_layer_cache_args("docker", "ci", force=False, offline=False)
        non_root = _gha_layer_cache_args(
            "docker", "non-root", force=False, offline=False
        )
        assert "scope=ash-ci-x86_64-online" in ci[1]
        assert "scope=ash-non-root-x86_64-online" in non_root[1]
        assert ci != non_root

    def test_results_url_alone_is_sufficient(self, monkeypatch):
        """Cache protocol v2 supplies ACTIONS_RESULTS_URL instead of ACTIONS_CACHE_URL."""
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.delenv("ACTIONS_CACHE_URL", raising=False)
        monkeypatch.setenv("ACTIONS_RESULTS_URL", "https://example.invalid/results/")
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)
        assert _gha_layer_cache_args("docker", "ci", force=False, offline=False) != []


class TestCacheDeclined:
    @pytest.mark.parametrize("runner", ["podman", "finch", "nerdctl", ""])
    def test_non_docker_runners_decline(self, in_actions, runner):
        """type=gha is a buildx backend; the others only cache via a registry."""
        assert _gha_layer_cache_args(runner, "ci", force=False, offline=False) == []

    def test_force_declines(self, in_actions):
        """force means --no-cache, so reading a cache would contradict the caller."""
        assert _gha_layer_cache_args("docker", "ci", force=True, offline=False) == []

    def test_opt_out_env_declines(self, in_actions, monkeypatch):
        monkeypatch.setenv("ASH_DISABLE_GHA_BUILD_CACHE", "1")
        assert _gha_layer_cache_args("docker", "ci", force=False, offline=False) == []

    def test_blank_opt_out_is_not_an_opt_out(self, in_actions, monkeypatch):
        """An empty or whitespace value must not silently disable caching."""
        monkeypatch.setenv("ASH_DISABLE_GHA_BUILD_CACHE", "   ")
        assert _gha_layer_cache_args("docker", "ci", force=False, offline=False) != []

    def test_missing_token_declines(self, monkeypatch):
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)
        monkeypatch.setenv("ACTIONS_CACHE_URL", "https://example.invalid/cache/")
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)
        assert _gha_layer_cache_args("docker", "ci", force=False, offline=False) == []

    def test_missing_endpoint_declines(self, monkeypatch):
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.delenv("ACTIONS_CACHE_URL", raising=False)
        monkeypatch.delenv("ACTIONS_RESULTS_URL", raising=False)
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)
        assert _gha_layer_cache_args("docker", "ci", force=False, offline=False) == []

    def test_outside_actions_declines(self, monkeypatch):
        """The common case: a developer building locally must be unaffected."""
        for key in (
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_CACHE_URL",
            "ACTIONS_RESULTS_URL",
            "ASH_DISABLE_GHA_BUILD_CACHE",
        ):
            monkeypatch.delenv(key, raising=False)
        assert _gha_layer_cache_args("docker", "ci", force=False, offline=False) == []

    def test_runner_without_buildx_declines(self, in_actions, monkeypatch):
        """A binary named docker that has no buildx must not be offered type=gha.

        This is the podman-docker case: that package installs a /usr/bin/docker
        shim which execs podman, and runner discovery reaches docker before
        podman, so every other guard here passes for a runner that cannot honor a
        buildx cache backend.
        """
        monkeypatch.setattr(
            run_ash_container, "_runner_supports_buildx", lambda runner: False
        )
        assert (
            _gha_layer_cache_args("/usr/bin/docker", "ci", force=False, offline=False)
            == []
        )


class TestExportIsFailSoftAndBounded:
    """The two properties that keep a live cache from breaking unrelated things.

    Both were established by a real CI run rather than reasoned about: a transient
    400 from the cache service failed three scan cells, and the Actions cache is
    capped per repository and evicts across workflows.
    """

    def test_only_cache_to_ignores_errors(self, in_actions):
        """cache-to must be fail-soft; cache-from must not be.

        buildkit already degrades a failed import into a cache miss and carries on
        -- the observed run continued building for over two minutes after one --
        so wrapping the read direction would hide real problems for no gain. The
        export failure is what aborted the build.
        """
        args = _gha_layer_cache_args("docker", "ci", force=False, offline=False)
        cache_from = args[args.index("--cache-from") + 1]
        cache_to = args[args.index("--cache-to") + 1]
        assert "ignore-error=true" in cache_to
        assert "ignore-error" not in cache_from

    def test_export_is_mode_min(self, in_actions):
        """mode=max would export every intermediate stage of a multi-GB image.

        Against a 10 GB per-repository cap that evicts by least-recent access
        across all workflows, that risks evicting caches other jobs depend on.
        """
        args = _gha_layer_cache_args("docker", "ci", force=False, offline=False)
        cache_to = args[args.index("--cache-to") + 1]
        assert "mode=min" in cache_to
        assert "mode=max" not in cache_to


class TestScopeSeparatesWhatCannotBeShared:
    """Architecture and OFFLINE change the layers, so they must change the key.

    Under a single scope the cache-enabled cells demonstrably could not share
    entries -- they requested different manifests -- and buildkit keeps only
    whichever build finished last, so the cache never survives to be reused.
    """

    def test_architecture_is_in_the_scope(self, in_actions, monkeypatch):
        monkeypatch.setattr(run_ash_container.platform, "machine", lambda: "x86_64")
        amd64 = _gha_layer_cache_args("docker", "ci", force=False, offline=False)
        monkeypatch.setattr(run_ash_container.platform, "machine", lambda: "aarch64")
        arm64 = _gha_layer_cache_args("docker", "ci", force=False, offline=False)
        assert "scope=ash-ci-x86_64-online" in amd64[1]
        assert "scope=ash-ci-aarch64-online" in arm64[1]
        assert amd64 != arm64

    def test_offline_is_in_the_scope(self, in_actions):
        online = _gha_layer_cache_args("docker", "ci", force=False, offline=False)
        offline = _gha_layer_cache_args("docker", "ci", force=False, offline=True)
        assert "scope=ash-ci-x86_64-online" in online[1]
        assert "scope=ash-ci-x86_64-offline" in offline[1]
        assert online != offline

    def test_both_directions_use_the_same_scope(self, in_actions):
        """Reading one key and writing another would never produce a hit."""
        args = _gha_layer_cache_args("docker", "ci", force=False, offline=True)
        cache_from = args[args.index("--cache-from") + 1]
        cache_to = args[args.index("--cache-to") + 1]
        assert "scope=ash-ci-x86_64-offline" in cache_from
        assert "scope=ash-ci-x86_64-offline" in cache_to


class TestBuildxCapabilityProbe:
    """The real ``_runner_supports_buildx``, with only the subprocess faked.

    The autouse fixture above replaces the module attribute, but the name imported
    at the top of this file still refers to the original function, so these
    exercise it rather than the stand-in.
    """

    @pytest.fixture(autouse=True)
    def clear_probe_cache(self):
        """The probe memoizes by path, so the cache must not leak between tests."""
        run_ash_container._BUILDX_SUPPORT_CACHE.clear()
        yield
        run_ash_container._BUILDX_SUPPORT_CACHE.clear()

    def test_exit_zero_means_supported(self, monkeypatch):
        monkeypatch.setattr(
            run_ash_container.subprocess_utils,
            "run_command",
            lambda *a, **k: subprocess.CompletedProcess(args=[], returncode=0),
        )
        assert _runner_supports_buildx("/usr/bin/docker") is True

    def test_non_zero_exit_means_unsupported(self, monkeypatch):
        """What the podman-docker shim does: `podman buildx version` is not a command."""
        monkeypatch.setattr(
            run_ash_container.subprocess_utils,
            "run_command",
            lambda *a, **k: subprocess.CompletedProcess(args=[], returncode=125),
        )
        assert _runner_supports_buildx("/usr/bin/docker") is False

    def test_a_raising_probe_is_treated_as_unsupported(self, monkeypatch):
        """A timeout or a missing binary must decline the cache, not crash the build."""

        def boom(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="docker buildx version", timeout=30)

        monkeypatch.setattr(run_ash_container.subprocess_utils, "run_command", boom)
        assert _runner_supports_buildx("/usr/bin/docker") is False

    def test_the_probe_runs_once_per_runner(self, monkeypatch):
        """It sits on the build path, so it must not shell out repeatedly."""
        calls = []

        def record(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args=args, returncode=0)

        monkeypatch.setattr(run_ash_container.subprocess_utils, "run_command", record)
        assert _runner_supports_buildx("/usr/bin/docker") is True
        assert _runner_supports_buildx("/usr/bin/docker") is True
        assert len(calls) == 1
        assert calls[0] == ["/usr/bin/docker", "buildx", "version"]

    def test_the_probe_does_not_log_at_info(self, monkeypatch):
        """Probing is bookkeeping; it should not narrate itself into scan output."""
        seen = {}

        def record(args, **kwargs):
            seen.update(kwargs)
            return subprocess.CompletedProcess(args=args, returncode=0)

        monkeypatch.setattr(run_ash_container.subprocess_utils, "run_command", record)
        _runner_supports_buildx("/usr/bin/docker")
        assert seen["log_level"] == logging.DEBUG
        assert seen["timeout"] == 30


class TestRunnerArrivesResolved:
    """The runner reaches this gate already resolved to a path, never as a name.

    ``_resolve_oci_runner`` returns whatever ``find_executable`` produced, and that
    is a full path -- ``/usr/bin/docker``, plus a ``.exe`` suffix on Windows. Every
    test above passes the bare string ``docker``, which no caller supplies, so the
    suite could pass while the gate rejected the only value it is ever handed.
    These pin the resolved shape instead.
    """

    @pytest.mark.parametrize(
        "runner",
        [
            "/usr/bin/docker",
            "/usr/local/bin/docker",
            "/opt/homebrew/bin/docker",
            # Forward slashes parse the same under either pathlib flavor, so this
            # case says nothing about Windows on its own -- the shape Windows
            # actually produces is backslash-separated, and is covered by
            # test_windows_backslash_path_is_accepted below.
            "C:/Program Files/Docker/docker.exe",
            # Still accepted: a bare name remains valid input.
            "docker",
        ],
    )
    def test_resolved_docker_paths_enable_the_cache(self, in_actions, runner):
        assert _gha_layer_cache_args(runner, "ci", force=False, offline=False) == [
            "--cache-from",
            "type=gha,scope=ash-ci-x86_64-online",
            "--cache-to",
            "type=gha,mode=min,ignore-error=true,scope=ash-ci-x86_64-online",
        ]

    def test_windows_backslash_path_is_accepted(self, in_actions, monkeypatch):
        """The shape find_executable actually returns on Windows.

        ``Path`` resolves to ``WindowsPath`` there, which reads a backslash as a
        separator; a POSIX interpreter does not, and would take the whole string
        as one component. Dispatching the module's ``Path`` to the Windows flavor
        is what makes this assertion mean anything off Windows -- and it has to be
        asserted here, because no Windows cell in CI can reach this gate: the
        credentials are gated on ubuntu, and windows-latest appears in the scan
        matrix only as python-local.
        """
        from pathlib import PureWindowsPath

        monkeypatch.setattr(run_ash_container, "Path", PureWindowsPath)
        assert (
            _gha_layer_cache_args(
                r"C:\Program Files\Docker\docker.exe",
                "ci",
                force=False,
                offline=False,
            )
            != []
        )

    @pytest.mark.parametrize(
        "runner",
        [
            "/usr/bin/podman",
            "/usr/local/bin/finch",
            "/usr/bin/nerdctl",
        ],
    )
    def test_resolved_non_docker_paths_still_decline(self, in_actions, runner):
        assert _gha_layer_cache_args(runner, "ci", force=False, offline=False) == []

    @pytest.mark.parametrize(
        "runner",
        [
            "/usr/bin/docker-compose",
            "/usr/bin/docker-credential-ecr-login",
            "/usr/bin/not-docker",
        ],
    )
    def test_neighbors_of_docker_on_path_decline(self, in_actions, runner):
        """Matching must be on the whole final component, not a substring of it.

        ``docker`` is a prefix of several unrelated binaries that sit in the same
        directory, so a substring test would enable a buildx-only cache for a
        runner that cannot honor it.
        """
        assert _gha_layer_cache_args(runner, "ci", force=False, offline=False) == []
