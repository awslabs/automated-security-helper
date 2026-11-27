# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The opengrep child may read git's view of the one directory it scans.

opengrep 2.0.0 runs ``git ls-files`` itself and exits 2 ("Could not get files from
git ls-files") when git refuses the directory as owned by another user, which is the
case for the mount the container scans read. 1.33.1 tolerated that. The scanner
therefore hands its child a ``safe.directory`` entry through ``GIT_CONFIG_*``: only
for the directory the scan was pointed at, only in that child's environment, and
never the ``*`` that would trust every directory.
"""

import os
import sys

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxUnavailable,
    build_scanner_policy,
)
from tests.utils.env_assertions import environ_names
from tests.utils.tool_guard import stub_tool_probes

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    stub_tool_probes(monkeypatch)


@pytest.fixture(autouse=True)
def _no_checkout_above_the_test_directory(monkeypatch, tmp_path):
    """A ``.git`` counts only where the test made it.

    The scanner walks up from its target, and the temporary directory may sit inside
    a checkout (a CI workspace, a developer's ``/tmp`` under a repository); every
    exact-count assertion below would then read that checkout's top as well. The
    walk asks ``os.path.lexists``, so the answer is fixed there: the real one inside
    ``tmp_path``, no ``.git`` anywhere else.
    """
    root = os.path.realpath(tmp_path)
    real = os.path.lexists

    def lexists(path):
        text = os.fspath(path)
        if os.path.basename(text) == ".git" and not text.startswith(root + os.sep):
            return False
        return real(path)

    monkeypatch.setattr(os.path, "lexists", lexists)


def _scanner(test_plugin_context):
    config = OpengrepScannerConfig(options=OpengrepScannerConfigOptions())
    scanner = OpengrepScanner(context=test_plugin_context, config=config)
    scanner.dependencies_satisfied = True
    return scanner


def _child_env(scanner, target):
    _args, _results, env = scanner._execute_scan(
        target=target, target_type="source", global_ignore_paths=[]
    )
    return env


def test_the_child_env_names_the_real_path_of_the_scanned_directory(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:  # pragma: no cover - no symlinks on this platform
        link = real

    env = _child_env(_scanner(test_plugin_context), link)

    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "safe.directory"
    assert env["GIT_CONFIG_VALUE_0"] == os.path.realpath(real)


def test_the_child_env_never_trusts_every_directory(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)

    env = _child_env(_scanner(test_plugin_context), tmp_path)

    values = [v for k, v in env.items() if k.startswith("GIT_CONFIG_VALUE_")]
    assert values and "*" not in values


def test_an_entry_the_caller_already_set_keeps_its_place(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.pager")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "cat")

    env = _child_env(_scanner(test_plugin_context), tmp_path)

    assert env["GIT_CONFIG_COUNT"] == "2"
    assert env["GIT_CONFIG_KEY_1"] == "safe.directory"
    assert env["GIT_CONFIG_VALUE_1"] == os.path.realpath(tmp_path)
    assert env["GIT_CONFIG_KEY_0"] == "core.pager"
    assert env["GIT_CONFIG_VALUE_0"] == "cat"


def test_the_parent_process_environment_is_not_changed(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)

    _child_env(_scanner(test_plugin_context), tmp_path)

    assert "GIT_CONFIG_COUNT" not in environ_names()


# ---------------------------------------------------------------------------
# What the sandbox hands the child. The tests above read the environment the scanner
# returns, which is read BEFORE the sandbox's allowlist; a sandboxed spawn only gets
# what ``SandboxPolicy.filter_env`` keeps of it.
# ---------------------------------------------------------------------------


def _production_policy(tmp_path, scan_target, environment=None):
    """The policy the sandbox builds for opengrep, through the production builder."""
    source = tmp_path / "source"
    results = tmp_path / "results"
    source.mkdir(exist_ok=True)
    results.mkdir(exist_ok=True)
    return build_scanner_policy(
        "OpengrepScanner",
        OpengrepScanner.sandbox_requirements,
        argv0=sys.executable,
        source_dir=source,
        output_dir=tmp_path,
        results_dir=results,
        scan_target=scan_target,
        cwd=None,
        offline=False,
        network_scanners=None,
        environment=environment,
    )


def _sandboxed_env(scanner, policy, target):
    """What the sandbox passes the child: the scanner's env, through the filter."""
    return policy.filter_env(_child_env(scanner, target))


def _git_entries(env):
    count = int(env.get("GIT_CONFIG_COUNT", "0"))
    return [
        (env.get(f"GIT_CONFIG_KEY_{i}"), env.get(f"GIT_CONFIG_VALUE_{i}"))
        for i in range(count)
    ]


def _assert_coherent(env):
    """Every index below the count has its key and its value; git exits on a gap."""
    entries = _git_entries(env)
    assert entries, "no GIT_CONFIG block reached the child"
    for index, (key, value) in enumerate(entries):
        assert key and value is not None, (index, entries)


def test_the_sandbox_filter_keeps_the_injected_entries(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    target = tmp_path / "source"
    target.mkdir()
    policy = _production_policy(tmp_path, target)

    env = _sandboxed_env(_scanner(test_plugin_context), policy, target)

    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "safe.directory"
    assert env["GIT_CONFIG_VALUE_0"] == os.path.realpath(target)


def test_the_sandbox_never_passes_the_operators_own_git_config(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "safe.directory")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "*")
    target = tmp_path / "source"
    target.mkdir()
    policy = _production_policy(tmp_path, target)

    env = _sandboxed_env(_scanner(test_plugin_context), policy, target)

    assert [v for _k, v in _git_entries(env)] == [os.path.realpath(target)]
    assert "*" not in env.values()


def test_an_operator_block_leaves_the_sandboxed_count_coherent(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.pager")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "cat")
    target = tmp_path / "source"
    target.mkdir()
    scanner = _scanner(test_plugin_context)

    direct = _child_env(scanner, target)
    sandboxed = _sandboxed_env(scanner, _production_policy(tmp_path, target), target)

    assert direct["GIT_CONFIG_COUNT"] == "2"
    _assert_coherent(direct)
    _assert_coherent(sandboxed)
    assert os.path.realpath(target) in [v for _k, v in _git_entries(sandboxed)]


def test_a_listed_block_is_refused_rather_than_merged_or_dropped(monkeypatch, tmp_path):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    target = tmp_path / "source"
    target.mkdir()

    # The scanner's own block is written from the directories the policy names; an
    # operator's entry, valued or not, would be passed unchanged or dropped, so the
    # list is refused with the entry named.
    with pytest.raises(SandboxUnavailable, match="GIT_CONFIG_COUNT"):
        _production_policy(
            tmp_path,
            target,
            environment=[
                "GIT_CONFIG_COUNT=2",
                "GIT_CONFIG_KEY_0=core.pager",
                "GIT_CONFIG_VALUE_0=cat",
            ],
        )


def test_the_sandbox_does_not_leak_the_private_hand_over_name(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    target = tmp_path / "source"
    target.mkdir()
    policy = _production_policy(tmp_path, target)

    env = _sandboxed_env(_scanner(test_plugin_context), policy, target)

    assert not [name for name in env if "SAFE_DIRECTOR" in name]


def test_only_opengrep_asks_for_the_git_safe_directory():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
    )

    assert getattr(OpengrepScanner.sandbox_requirements, "git_safe_directory", False)
    assert not getattr(SemgrepScanner.sandbox_requirements, "git_safe_directory", False)


@pytest.mark.skipif(
    not hasattr(os, "geteuid"),
    reason=(
        "no user ids here: the checkout's top is not named (pinned by the "
        "without_user_ids tests in test_opengrep_safe_directory_scope.py)"
    ),
)
def test_a_subdirectory_of_a_checkout_also_names_the_checkout(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    sub = repo / "pkg" / "inner"
    sub.mkdir(parents=True)
    scanner = _scanner(test_plugin_context)

    direct = _child_env(scanner, sub)
    sandboxed = _sandboxed_env(scanner, _production_policy(tmp_path, sub), sub)

    for env in (direct, sandboxed):
        _assert_coherent(env)
        values = [v for _k, v in _git_entries(env)]
        assert os.path.realpath(sub) in values
        assert os.path.realpath(repo) in values
        assert "*" not in values


def test_outside_a_checkout_only_the_scanned_directory_is_named(
    test_plugin_context, monkeypatch, tmp_path
):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    target = tmp_path / "plain"
    target.mkdir()

    env = _child_env(_scanner(test_plugin_context), target)

    assert [v for _k, v in _git_entries(env)] == [os.path.realpath(target)]


def test_the_facets_describe_the_single_run_and_not_a_local_rerun():
    """opengrep runs once; a failed ruleset download (exit 2) and invalid downloaded
    rules (exit 7) end the scan as a scanner error, with no second run on local
    configs."""
    facets = OpengrepScanner.operational_facets
    text = f"{facets.network.offline_reason} {facets.exit_codes.semantics}".lower()

    assert "rerun" not in text
    assert "local configs only" not in text
    assert "exit 2" in text or "exits 2" in text
    assert "7" in facets.exit_codes.semantics
    assert "fatal" in facets.exit_codes.semantics.lower()
