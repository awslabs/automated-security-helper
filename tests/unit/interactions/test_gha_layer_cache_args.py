"""Tests for the buildx GitHub Actions layer-cache gate.

Every guard in ``_gha_layer_cache_args`` exists because getting it wrong is either
silent or destructive: emitting ``type=gha`` flags outside Actions makes the build
fail on a cache backend that cannot authenticate, emitting them for podman or finch
fails on an unsupported backend, and emitting them alongside ``--no-cache``
contradicts the caller. The default is therefore "return nothing", and these tests
pin both that default and the one combination that opts in.
"""

import pytest

from automated_security_helper.interactions.run_ash_container import (
    _gha_layer_cache_args,
)

# The credentials buildx needs. Actions does not expose these to `run:` steps by
# default, so a workflow has to export them; the gate treats their absence as
# "caching unavailable".
_ACTIONS_ENV = {
    "ACTIONS_RUNTIME_TOKEN": "token",
    "ACTIONS_CACHE_URL": "https://example.invalid/cache/",
}


@pytest.fixture
def in_actions(monkeypatch):
    """Simulate a GitHub Actions run that has exported the cache credentials."""
    for key, value in _ACTIONS_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("ACTIONS_RESULTS_URL", raising=False)
    monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)


class TestCacheEnabled:
    def test_docker_in_actions_emits_both_directions(self, in_actions):
        args = _gha_layer_cache_args("docker", "ci", force=False)
        assert args == [
            "--cache-from",
            "type=gha,scope=ash-ci",
            "--cache-to",
            "type=gha,mode=max,scope=ash-ci",
        ]

    def test_scope_is_per_build_target(self, in_actions):
        """Targets must not share a scope; buildx lets one overwrite the other."""
        ci = _gha_layer_cache_args("docker", "ci", force=False)
        non_root = _gha_layer_cache_args("docker", "non-root", force=False)
        assert "scope=ash-ci" in ci[1]
        assert "scope=ash-non-root" in non_root[1]
        assert ci != non_root

    def test_results_url_alone_is_sufficient(self, monkeypatch):
        """Cache protocol v2 supplies ACTIONS_RESULTS_URL instead of ACTIONS_CACHE_URL."""
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.delenv("ACTIONS_CACHE_URL", raising=False)
        monkeypatch.setenv("ACTIONS_RESULTS_URL", "https://example.invalid/results/")
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)
        assert _gha_layer_cache_args("docker", "ci", force=False) != []


class TestCacheDeclined:
    @pytest.mark.parametrize("runner", ["podman", "finch", "nerdctl", ""])
    def test_non_docker_runners_decline(self, in_actions, runner):
        """type=gha is a buildx backend; the others only cache via a registry."""
        assert _gha_layer_cache_args(runner, "ci", force=False) == []

    def test_force_declines(self, in_actions):
        """force means --no-cache, so reading a cache would contradict the caller."""
        assert _gha_layer_cache_args("docker", "ci", force=True) == []

    def test_opt_out_env_declines(self, in_actions, monkeypatch):
        monkeypatch.setenv("ASH_DISABLE_GHA_BUILD_CACHE", "1")
        assert _gha_layer_cache_args("docker", "ci", force=False) == []

    def test_blank_opt_out_is_not_an_opt_out(self, in_actions, monkeypatch):
        """An empty or whitespace value must not silently disable caching."""
        monkeypatch.setenv("ASH_DISABLE_GHA_BUILD_CACHE", "   ")
        assert _gha_layer_cache_args("docker", "ci", force=False) != []

    def test_missing_token_declines(self, monkeypatch):
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)
        monkeypatch.setenv("ACTIONS_CACHE_URL", "https://example.invalid/cache/")
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)
        assert _gha_layer_cache_args("docker", "ci", force=False) == []

    def test_missing_endpoint_declines(self, monkeypatch):
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.delenv("ACTIONS_CACHE_URL", raising=False)
        monkeypatch.delenv("ACTIONS_RESULTS_URL", raising=False)
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)
        assert _gha_layer_cache_args("docker", "ci", force=False) == []

    def test_outside_actions_declines(self, monkeypatch):
        """The common case: a developer building locally must be unaffected."""
        for key in (
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_CACHE_URL",
            "ACTIONS_RESULTS_URL",
            "ASH_DISABLE_GHA_BUILD_CACHE",
        ):
            monkeypatch.delenv(key, raising=False)
        assert _gha_layer_cache_args("docker", "ci", force=False) == []
