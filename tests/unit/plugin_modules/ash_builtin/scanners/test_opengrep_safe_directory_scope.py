# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which directories opengrep's child is told git may trust, and who decides.

The scanned directory is always named. A parent is named only when it is the top of the
checkout the directory sits in, its ``.git`` entry belongs to the same user as the
scanned directory, and it is a directory a ``safe.directory`` entry may name (never a
filesystem root). One list, computed from the scan target, reaches the unsandboxed
child and the sandboxed one; no environment variable carries it, so an inherited value
cannot choose entries. A ``GIT_CONFIG_*`` entry in the operator's environment list is
refused for this scanner, which writes that block itself.
"""

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxUnavailable,
    build_scanner_policy,
)
from tests.utils.tool_guard import stub_tool_probes

pytestmark = pytest.mark.unit

_REAL_LEXISTS = os.path.lexists
_REAL_LSTAT = os.lstat


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    stub_tool_probes(monkeypatch)
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)


@pytest.fixture
def only_staged_checkouts(monkeypatch, tmp_path):
    """A ``.git`` counts only where this test made it.

    The walk reads the real filesystem above the temporary directory, which may sit
    inside a checkout; a ``.git`` there is not what these tests are about.
    """
    root = os.path.realpath(tmp_path)

    def lexists(path):
        text = os.fspath(path)
        if os.path.basename(text) == ".git" and not text.startswith(root + os.sep):
            return False
        return _REAL_LEXISTS(path)

    monkeypatch.setattr(os.path, "lexists", lexists)
    return tmp_path


def _scanner(test_plugin_context):
    config = OpengrepScannerConfig(options=OpengrepScannerConfigOptions())
    scanner = OpengrepScanner(context=test_plugin_context, config=config)
    scanner.dependencies_satisfied = True
    return scanner


def _direct_env(scanner, target):
    _args, _results, env = scanner._execute_scan(
        target=target, target_type="source", global_ignore_paths=[]
    )
    return env or {}


def _policy(tmp_path, scan_target, environment=None, requirements=None):
    source = tmp_path / "policy_source"
    results = tmp_path / "policy_results"
    source.mkdir(exist_ok=True)
    results.mkdir(exist_ok=True)
    return build_scanner_policy(
        "OpengrepScanner",
        requirements or OpengrepScanner.sandbox_requirements,
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


def _named(env):
    count = int(env.get("GIT_CONFIG_COUNT", "0"))
    return [
        env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(count)
        if env.get(f"GIT_CONFIG_KEY_{i}") == "safe.directory"
    ]


def _both_spawn_paths(scanner, policy, target):
    """The environment each spawn path hands the child, for the same scan."""
    direct = _direct_env(scanner, target)
    sandboxed = policy.filter_env(direct)
    return {"direct": direct, "sandboxed": sandboxed}


def _owned_by_someone_else(monkeypatch, path):
    """``os.lstat(path)`` reports another user as the owner; nothing else changes."""
    other = os.fspath(path)

    def lstat(candidate, *args, **kwargs):
        real = _REAL_LSTAT(candidate, *args, **kwargs)
        if os.fspath(candidate) != other:
            return real
        fields = list(real)[:10]
        fields[4] = real.st_uid + 1
        return os.stat_result(tuple(fields))

    monkeypatch.setattr(os, "lstat", lstat)


def _checkout(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    sub = repo / "pkg" / "inner"
    sub.mkdir(parents=True)
    return repo, sub


def test_a_parent_whose_git_entry_belongs_to_another_user_is_not_named(
    test_plugin_context, monkeypatch, only_staged_checkouts
):
    repo, sub = _checkout(only_staged_checkouts)
    _owned_by_someone_else(monkeypatch, repo / ".git")
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, sub), sub)

    for name, env in envs.items():
        assert _named(env) == [os.path.realpath(sub)], name


def test_a_parent_whose_git_entry_belongs_to_the_scan_targets_owner_is_named(
    test_plugin_context, only_staged_checkouts
):
    repo, sub = _checkout(only_staged_checkouts)
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, sub), sub)

    for name, env in envs.items():
        assert _named(env) == [os.path.realpath(sub), os.path.realpath(repo)], name


def test_a_parent_git_entry_owned_by_the_effective_uid_is_named_for_a_foreign_target(
    test_plugin_context, monkeypatch, only_staged_checkouts
):
    """git trusts a top whose ``.git`` the effective uid owns, so the walk names it.

    The scanned directory belongs to another user (a container mount, a build
    directory a different uid created) while the checkout's ``.git`` belongs to
    the user running ASH. Before the widened acceptance the walk compared the
    ``.git`` owner with the target's owner only, dropped the top, and git then
    refused the checkout.
    """
    repo, sub = _checkout(only_staged_checkouts)
    _owned_by_someone_else(monkeypatch, os.path.realpath(sub))
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, sub), sub)

    for name, env in envs.items():
        assert _named(env) == [os.path.realpath(sub), os.path.realpath(repo)], name


def test_the_walk_logs_the_git_entry_it_refuses_to_trust(
    test_plugin_context, monkeypatch, only_staged_checkouts
):
    """The early stop names the ``.git`` it refused, so a missing top is diagnosable."""
    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    messages = []

    class _Capture(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = _Capture(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        repo, sub = _checkout(only_staged_checkouts)
        _owned_by_someone_else(monkeypatch, repo / ".git")
        scanner = _scanner(test_plugin_context)
        _both_spawn_paths(scanner, _policy(only_staged_checkouts, sub), sub)
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)

    refusals = [m for m in messages if "safe_directories_for: not naming" in m]
    assert refusals, messages
    assert any(".git" in m for m in refusals)


def test_a_filesystem_root_parent_is_refused_on_both_spawn_paths(
    test_plugin_context, monkeypatch, only_staged_checkouts
):
    target = only_staged_checkouts / "plain"
    target.mkdir()
    root_git = os.path.join(os.sep, ".git")
    real_lexists = os.path.lexists
    real_lstat = os.lstat

    # Every ancestor of the target lacks a ``.git`` but the filesystem root, whose
    # entry is made to belong to the target's own owner, so only the root check
    # stands between the walk and a ``safe.directory`` entry for ``/``.
    monkeypatch.setattr(
        os.path,
        "lexists",
        lambda p: True if os.fspath(p) == root_git else real_lexists(p),
    )

    def lstat(candidate, *args, **kwargs):
        if os.fspath(candidate) == root_git:
            return real_lstat(target)
        return real_lstat(candidate, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, target), target)

    for name, env in envs.items():
        assert _named(env) == [os.path.realpath(target)], name
        assert os.sep not in _named(env), name


def test_scanning_a_filesystem_root_names_nothing_on_both_spawn_paths(
    test_plugin_context, only_staged_checkouts
):
    from automated_security_helper.utils.sandbox import policy as policy_module

    scanner = _scanner(test_plugin_context)
    # The hook the unsandboxed spawn reads, called directly: a scan of ``/`` itself
    # would list the whole filesystem.
    scanner._scan_target_path = Path(os.sep)

    direct = scanner.extra_subprocess_env() or {}

    assert os.sep not in _named(direct)
    # The list both spawn paths read, from the function that computes it.
    assert policy_module.safe_directories_for(Path(os.sep)) == []


def test_the_list_does_not_travel_through_the_environment(
    test_plugin_context, only_staged_checkouts
):
    target = only_staged_checkouts / "plain"
    target.mkdir()
    scanner = _scanner(test_plugin_context)
    policy = _policy(only_staged_checkouts, target)

    envs = _both_spawn_paths(scanner, policy, target)

    for name, env in envs.items():
        assert not [key for key in env if "SAFE_DIRECTOR" in key], name


def test_an_inherited_value_does_not_choose_what_the_sandbox_names(
    only_staged_checkouts,
):
    target = only_staged_checkouts / "plain"
    target.mkdir()
    policy = _policy(only_staged_checkouts, target)

    env = policy.filter_env(
        {"ASH_GIT_SAFE_DIRECTORIES": '["/etc", "/var"]', "PATH": "/usr/bin"}
    )

    # The ASH_-prefixed name may pass as an inert variable; its value names nothing.
    assert _named(env) == [os.path.realpath(target)]
    assert "/etc" not in env.values()


def test_the_policy_carries_the_validated_list(only_staged_checkouts):
    repo, sub = _checkout(only_staged_checkouts)

    policy = _policy(only_staged_checkouts, sub)

    assert policy.safe_directories == (
        os.path.realpath(sub),
        os.path.realpath(repo),
    )


def test_a_scanner_without_the_declaration_gets_no_list(only_staged_checkouts):
    target = only_staged_checkouts / "plain"
    target.mkdir()

    policy = _policy(
        only_staged_checkouts, target, requirements=SemgrepScanner.sandbox_requirements
    )

    assert policy.safe_directories == ()
    assert _named(policy.filter_env({"PATH": "/usr/bin"})) == []


@pytest.mark.parametrize(
    "entries",
    [
        ["GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory"],
        ["GIT_CONFIG_VALUE_0=*"],
        ["GIT_CONFIG_KEY_0"],
        ["GIT_CONFIG_COUNT"],
    ],
)
def test_a_listed_git_config_entry_is_refused_naming_it(only_staged_checkouts, entries):
    target = only_staged_checkouts / "plain"
    target.mkdir()

    with pytest.raises(SandboxUnavailable) as refused:
        _policy(only_staged_checkouts, target, environment=entries)

    first = entries[0].partition("=")[0]
    assert first in str(refused.value)
    assert "=" not in str(refused.value), "the message shows a name, never a value"


def test_a_listed_git_config_entry_is_still_allowed_for_other_scanners(
    only_staged_checkouts,
):
    target = only_staged_checkouts / "plain"
    target.mkdir()

    policy = _policy(
        only_staged_checkouts,
        target,
        environment=["GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.pager"],
        requirements=SemgrepScanner.sandbox_requirements,
    )

    assert "GIT_CONFIG_COUNT" in policy.environment[0]
