# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which directories opengrep's child is told git may trust, and who decides.

The scanned directory is always named. A parent is named only when it is the top of the
checkout the directory sits in, the top and its ``.git`` entry each belong to the user
who owns the scanned directory or to the effective uid, and it is a directory a
``safe.directory`` entry may name (never a filesystem root). git's own ownership check
reads the same two entries, so a top that a third user owns, who could replace its
``.git``, is never named. One list, computed from the scan target, reaches the
unsandboxed child and the sandboxed one; no environment variable carries it, so an
inherited value cannot choose entries.

Of git's configuration variables the sandboxed child gets the
``GIT_CONFIG_COUNT``/``KEY_<n>``/``VALUE_<n>`` block ASH writes, and only what can take
configuration away besides: ``GIT_CONFIG_NOSYSTEM``, and ``GIT_CONFIG_GLOBAL`` or
``GIT_CONFIG_SYSTEM`` set to the null device. An entry in the operator's environment
list that could add configuration is refused for this scanner, in words that say what
the entry would do.

Where the platform has no user ids (Windows: no ``os.geteuid``, and ``os.lstat``
reports uid 0 for every file), no ``.git`` can be shown to belong to either user, so
no parent is named and git's own ownership check decides about the checkout's top.
The tests that pin the owner rule need user ids; the ``without_user_ids`` tests pin
the other reading on every platform by taking ``os.geteuid`` away.
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
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    SandboxUnavailable,
    build_scanner_policy,
)
from tests.utils.tool_guard import stub_tool_probes

pytestmark = pytest.mark.unit

_REAL_LEXISTS = os.path.lexists
_REAL_LSTAT = os.lstat

#: The owner rule compares uids, so the tests that pin it need a platform that has
#: them. Without user ids the walk names no parent; the ``without_user_ids`` tests
#: below pin that reading on every platform.
needs_user_ids = pytest.mark.skipif(
    not hasattr(os, "geteuid"),
    reason="no user ids here: the walk names no parent (the without_user_ids tests)",
)


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


def _owned_by(monkeypatch, owners):
    """``os.lstat`` reports, for each path in ``owners``, the uid given for it; every
    other path keeps its real owner, and nothing but the owner changes."""
    wanted = {os.path.realpath(path): uid for path, uid in owners.items()}

    def lstat(candidate, *args, **kwargs):
        real = _REAL_LSTAT(candidate, *args, **kwargs)
        uid = wanted.get(os.fspath(candidate))
        if uid is None:
            return real
        fields = list(real)[:10]
        fields[4] = uid
        return os.stat_result(tuple(fields))

    monkeypatch.setattr(os, "lstat", lstat)


def _checkout(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    sub = repo / "pkg" / "inner"
    sub.mkdir(parents=True)
    return repo, sub


def _checkout_top(repo):
    """The entry a staged checkout's top adds after the target's: one where the
    platform has user ids and the ``.git`` is the test user's, none without them."""
    return [os.path.realpath(repo)] if hasattr(os, "geteuid") else []


def _without_user_ids(monkeypatch):
    """The platform as Windows presents it to the walk: no ``os.geteuid``."""
    monkeypatch.delattr(os, "geteuid", raising=False)


@pytest.fixture
def walk_messages():
    """The debug lines ASH's logger prints while a test runs."""
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
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def test_a_parent_whose_git_entry_belongs_to_another_user_is_not_named(
    test_plugin_context, monkeypatch, only_staged_checkouts
):
    repo, sub = _checkout(only_staged_checkouts)
    _owned_by_someone_else(monkeypatch, repo / ".git")
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, sub), sub)

    for name, env in envs.items():
        assert _named(env) == [os.path.realpath(sub)], name


@needs_user_ids
def test_a_parent_whose_git_entry_belongs_to_the_scan_targets_owner_is_named(
    test_plugin_context, only_staged_checkouts
):
    repo, sub = _checkout(only_staged_checkouts)
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, sub), sub)

    for name, env in envs.items():
        assert _named(env) == [os.path.realpath(sub), os.path.realpath(repo)], name


@needs_user_ids
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


#: The owners of the scan target, the checkout's top and its ``.git`` entry, as
#: offsets from the effective uid (0 is the effective uid, 1 another user, who owns
#: the scan target in most rows, 2 a third user), and whether the walk names the top.
#: git trusts a work tree only when its top and its ``.git`` both belong to the user
#: running it, and the walk names the top in git's place only when each of the two
#: belongs to the scan target's owner or to the effective uid: a third user who owns
#: the top could replace its ``.git``, whoever owns the ``.git`` today.
_TOP_OWNERS = [
    pytest.param(1, 0, 0, True, id="top-and-git-the-effective-uids"),
    pytest.param(1, 1, 1, True, id="top-and-git-the-target-owners"),
    pytest.param(1, 1, 0, True, id="top-the-target-owners-git-the-effective-uids"),
    pytest.param(1, 0, 1, True, id="top-the-effective-uids-git-the-target-owners"),
    pytest.param(1, 2, 0, False, id="top-a-third-users-git-the-effective-uids"),
    pytest.param(0, 2, 0, False, id="own-target-top-a-third-users"),
    pytest.param(1, 2, 1, False, id="top-a-third-users-git-the-target-owners"),
    pytest.param(1, 1, 2, False, id="git-a-third-users"),
]


@needs_user_ids
@pytest.mark.parametrize("target_uid, top_uid, git_uid, top_named", _TOP_OWNERS)
def test_the_top_is_named_only_when_it_and_its_git_entry_belong_to_a_trusted_user(
    test_plugin_context,
    monkeypatch,
    only_staged_checkouts,
    walk_messages,
    target_uid,
    top_uid,
    git_uid,
    top_named,
):
    repo, sub = _checkout(only_staged_checkouts)
    effective = os.geteuid()
    _owned_by(
        monkeypatch,
        {
            sub: effective + target_uid,
            repo: effective + top_uid,
            repo / ".git": effective + git_uid,
        },
    )
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, sub), sub)

    top = os.path.realpath(repo)
    expected = [os.path.realpath(sub), *([top] if top_named else [])]
    for name, env in envs.items():
        assert _named(env) == expected, name
    refusals = [
        m for m in walk_messages if f"safe_directories_for: not naming {top}:" in m
    ]
    if top_named:
        assert not refusals, refusals
    else:
        assert refusals, walk_messages
        assert all("is owned by uid" in m for m in refusals), refusals


@needs_user_ids
def test_an_owner_the_walk_cannot_read_is_logged_as_unreadable(
    monkeypatch, only_staged_checkouts, walk_messages
):
    """A ``.git`` whose owner cannot be read stops the walk, and the log says so in
    those words instead of reporting an owner of ``None``."""
    repo, sub = _checkout(only_staged_checkouts)
    git_entry = os.path.join(os.path.realpath(repo), ".git")
    staged_lexists = os.path.lexists

    def lexists(path):
        return True if os.fspath(path) == git_entry else staged_lexists(path)

    def lstat(candidate, *args, **kwargs):
        if os.fspath(candidate) == git_entry:
            raise PermissionError(13, "Permission denied", git_entry)
        return _REAL_LSTAT(candidate, *args, **kwargs)

    monkeypatch.setattr(os.path, "lexists", lexists)
    monkeypatch.setattr(os, "lstat", lstat)

    assert policy_module.safe_directories_for(sub) == [os.path.realpath(sub)]
    refusals = [m for m in walk_messages if "safe_directories_for: not naming" in m]
    assert refusals, walk_messages
    assert all(f"the owner of {git_entry} cannot be read" in m for m in refusals), (
        refusals
    )
    assert not [m for m in refusals if "uid None" in m], refusals


@needs_user_ids
def test_a_filesystem_root_top_is_logged_in_its_own_words(
    monkeypatch, only_staged_checkouts, walk_messages
):
    """A ``.git`` at the filesystem root whose owners pass stops the walk on the root
    test alone, and the log names that reason rather than an owner."""
    target = only_staged_checkouts / "plain"
    target.mkdir()
    root_git = os.path.join(os.sep, ".git")
    staged_lexists = os.path.lexists

    monkeypatch.setattr(
        os.path,
        "lexists",
        lambda p: True if os.fspath(p) == root_git else staged_lexists(p),
    )

    def lstat(candidate, *args, **kwargs):
        if os.fspath(candidate) in (root_git, os.sep):
            return _REAL_LSTAT(target)
        return _REAL_LSTAT(candidate, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)

    assert policy_module.safe_directories_for(target) == [os.path.realpath(target)]
    refusals = [m for m in walk_messages if "safe_directories_for: not naming" in m]
    assert refusals, walk_messages
    assert all("filesystem root" in m for m in refusals), refusals
    assert not [m for m in refusals if "is owned by uid" in m], refusals


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

    # Every ancestor of the target lacks a ``.git`` but the filesystem root, which
    # and whose entry are made to belong to the target's own owner, so only the root
    # check stands between the walk and a ``safe.directory`` entry for ``/``.
    monkeypatch.setattr(
        os.path,
        "lexists",
        lambda p: True if os.fspath(p) == root_git else real_lexists(p),
    )

    def lstat(candidate, *args, **kwargs):
        if os.fspath(candidate) in (root_git, os.sep):
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
        *_checkout_top(repo),
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
        ["GIT_CONFIG_PARAMETERS='safe.directory'='*'"],
        ["GIT_CONFIG_GLOBAL=/elsewhere/gitconfig"],
        ["GIT_CONFIG_SYSTEM=/elsewhere/gitconfig"],
        ["GIT_CONFIG_GLOBAL"],
        ["GIT_CONFIG_SYSTEM"],
        ["GIT_CONFIG_GLOBAL="],
        ["GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_GLOBAL"],
        ["GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_SYSTEM=/elsewhere/gitconfig"],
        ["GIT_CONFIG=/elsewhere/gitconfig"],
        ["GIT_CONFIG"],
        ["GIT_CONFIG_UNKNOWN=1"],
        pytest.param(
            ["GIT_CONFIG_GLOBAL=NUL"],
            marks=pytest.mark.skipif(
                os.name == "nt", reason="NUL is the null device on Windows"
            ),
            id="nul-names-a-file-off-windows",
        ),
    ],
)
def test_a_listed_git_config_entry_is_refused_naming_it(only_staged_checkouts, entries):
    target = only_staged_checkouts / "plain"
    target.mkdir()

    with pytest.raises(SandboxUnavailable) as refused:
        _policy(only_staged_checkouts, target, environment=entries)

    first = entries[0].partition("=")[0]
    message = str(refused.value)
    assert first in message
    assert "=" not in message, "the message shows a name, never a value"
    assert "/elsewhere" not in message, "the message never shows a value"


@pytest.mark.parametrize(
    "entry, says, never_says",
    [
        pytest.param("GIT_CONFIG_COUNT=1", "ASH writes", None, id="count"),
        pytest.param("GIT_CONFIG_KEY_0=safe.directory", "ASH writes", None, id="key"),
        pytest.param("GIT_CONFIG_VALUE_0=*", "ASH writes", None, id="value"),
        pytest.param(
            "GIT_CONFIG_PARAMETERS='safe.directory'='*'",
            "git -c",
            "ASH writes",
            id="parameters",
        ),
        pytest.param(
            "GIT_CONFIG_GLOBAL=/elsewhere/gitconfig",
            "null device",
            "ASH writes",
            id="global-file",
        ),
        pytest.param(
            "GIT_CONFIG_SYSTEM=/elsewhere/gitconfig",
            "null device",
            "ASH writes",
            id="system-file",
        ),
        pytest.param(
            "GIT_CONFIG_GLOBAL", "the caller's value", "ASH writes", id="global-passed"
        ),
        pytest.param(
            "GIT_CONFIG=/elsewhere/gitconfig",
            "git config command",
            "ASH writes",
            id="bare",
        ),
        pytest.param(
            "GIT_CONFIG_UNKNOWN=1", "GIT_CONFIG_NOSYSTEM", "ASH writes", id="unknown"
        ),
    ],
)
def test_each_refused_git_config_entry_is_refused_in_its_own_words(
    only_staged_checkouts, entry, says, never_says
):
    """The refusal says what the named entry would do. ASH writes the
    ``GIT_CONFIG_COUNT``/``KEY_<n>``/``VALUE_<n>`` block, but no global or system
    file, which an entry may point only at the null device."""
    target = only_staged_checkouts / "plain"
    target.mkdir()

    with pytest.raises(SandboxUnavailable) as refused:
        _policy(only_staged_checkouts, target, environment=[entry])

    message = str(refused.value)
    assert says in message, message
    if never_says is not None:
        assert never_says not in message, message


@pytest.mark.parametrize(
    "entries, passed",
    [
        pytest.param(
            ["GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"],
            {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
            id="the-hardening-pair",
        ),
        pytest.param(
            ["GIT_CONFIG_SYSTEM=/dev/null"],
            {"GIT_CONFIG_SYSTEM": "/dev/null"},
            id="no-system-file",
        ),
        pytest.param(
            [f"GIT_CONFIG_GLOBAL={os.devnull}", f"GIT_CONFIG_SYSTEM={os.devnull}"],
            {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
            id="this-platforms-null-device",
        ),
    ],
)
def test_a_listed_entry_that_only_takes_configuration_away_is_passed(
    only_staged_checkouts, entries, passed
):
    """The common hardening pair keeps opengrep running: an entry that can only stop
    git reading a configuration file is taken, and it reaches the sandboxed child
    beside the block ASH writes."""
    repo, sub = _checkout(only_staged_checkouts)

    policy = _policy(only_staged_checkouts, sub, environment=entries)
    child = policy.filter_env({"PATH": "/usr/bin"})

    for name, value in passed.items():
        assert child.get(name) == value, name
    assert _named(child) == [os.path.realpath(sub), *_checkout_top(repo)]


def test_a_listed_git_config_nosystem_passes_the_callers_value(only_staged_checkouts):
    """``GIT_CONFIG_NOSYSTEM`` can only stop git reading the system file, whatever
    its value, so a listed name passes the caller's value."""
    target = only_staged_checkouts / "plain"
    target.mkdir()

    policy = _policy(only_staged_checkouts, target, environment=["GIT_CONFIG_NOSYSTEM"])
    child = policy.filter_env({"PATH": "/usr/bin", "GIT_CONFIG_NOSYSTEM": "true"})

    assert child["GIT_CONFIG_NOSYSTEM"] == "true"
    assert _named(child) == [os.path.realpath(target)]


@pytest.mark.parametrize(
    "value, windows, admitted",
    [
        ("/dev/null", False, True),
        ("/dev/null", True, True),
        ("NUL", True, True),
        ("nul", True, True),
        ("Nul", True, True),
        ("NUL", False, False),
        ("nul", False, False),
        ("", False, False),
        ("", True, False),
        ("/dev/null/", False, False),
        ("/dev//null", False, False),
        ("/elsewhere/gitconfig", False, False),
        ("C:\\Users\\someone\\.gitconfig", True, False),
        ("NUL.txt", True, False),
    ],
)
def test_the_null_device_is_read_as_each_platform_spells_it(value, windows, admitted):
    """``/dev/null`` on every platform, as git's documentation spells it, and ``NUL``
    in any case on Windows only: elsewhere ``NUL`` names a file in the scanner's
    working directory, the scanned tree."""
    assert policy_module._names_null_device(value, windows=windows) is admitted


def test_this_platforms_null_device_is_the_null_device():
    assert policy_module._names_null_device(os.devnull) is True


def test_an_inherited_entry_that_only_takes_configuration_away_is_screened_like_any_other(
    only_staged_checkouts,
):
    """A scanner whose declared prefix covers them passes an inherited
    ``GIT_CONFIG_NOSYSTEM`` and a ``GIT_CONFIG_GLOBAL`` naming the null device, as it
    would any other variable, and drops a ``GIT_CONFIG_SYSTEM`` that names a file."""
    target = only_staged_checkouts / "plain"
    target.mkdir()
    requirements = SandboxRequirements(git_safe_directory=True, env_prefixes=("GIT_",))
    policy = _policy(only_staged_checkouts, target, requirements=requirements)

    child = policy.filter_env(
        {
            "PATH": "/usr/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/elsewhere/gitconfig",
        }
    )

    assert child["GIT_CONFIG_NOSYSTEM"] == "1"
    assert child["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert "GIT_CONFIG_SYSTEM" not in child


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


def test_an_ambient_git_config_variable_never_reaches_the_sandboxed_child(
    only_staged_checkouts,
):
    """The child's ``GIT_CONFIG_*`` block is the one ASH writes; git's other
    config channels in the caller's environment are dropped, so no inherited
    ``safe.directory`` or config file can reach the child beside it.

    The scanner here declares a ``GIT_`` prefix, which would pass all of them: a
    ``GIT_`` variable that is not a configuration channel reaches the child, so
    what keeps the channels out is the policy's own screen, not the allowlist."""
    repo, sub = _checkout(only_staged_checkouts)
    requirements = SandboxRequirements(git_safe_directory=True, env_prefixes=("GIT_",))
    policy = _policy(only_staged_checkouts, sub, requirements=requirements)

    child = policy.filter_env(
        {
            "PATH": "/usr/bin",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_PARAMETERS": "'safe.directory'='*'",
            "GIT_CONFIG_GLOBAL": "/elsewhere/gitconfig",
            "GIT_CONFIG_SYSTEM": "/elsewhere/gitconfig",
            "GIT_CONFIG": "/elsewhere/gitconfig",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": "*",
        }
    )

    assert child["GIT_TERMINAL_PROMPT"] == "0", "the prefix passes a plain GIT_ name"
    assert "GIT_CONFIG_PARAMETERS" not in child
    assert "GIT_CONFIG_GLOBAL" not in child
    assert "GIT_CONFIG_SYSTEM" not in child
    assert "GIT_CONFIG" not in child
    assert _named(child) == [os.path.realpath(sub), *_checkout_top(repo)]
    assert "*" not in child.values()


def test_without_user_ids_the_checkout_top_is_left_to_gits_own_check(
    test_plugin_context, monkeypatch, only_staged_checkouts, walk_messages
):
    """No ``os.geteuid`` (Windows): the ``.git`` above the target cannot be shown to
    belong to either user, so neither spawn path names the top, and the walk logs
    the entry it stopped at. Before, the walk called ``os.geteuid`` there and the
    scan raised ``AttributeError``."""
    repo, sub = _checkout(only_staged_checkouts)
    _without_user_ids(monkeypatch)
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, sub), sub)

    for name, env in envs.items():
        assert _named(env) == [os.path.realpath(sub)], name
    refusals = [m for m in walk_messages if "safe_directories_for: not naming" in m]
    assert refusals, walk_messages
    assert all("cannot be read on this platform" in m for m in refusals), refusals
    git_entry = os.path.join(os.path.realpath(repo), ".git")
    assert any(git_entry in m for m in refusals), refusals


def test_without_user_ids_a_scan_of_the_checkout_top_still_names_it(
    test_plugin_context, monkeypatch, only_staged_checkouts, walk_messages
):
    """The scanned directory is named on every platform: a scan pointed at the
    checkout's top names it on both spawn paths without user ids, and the walk
    logs no refusal for the directory it named."""
    repo, _sub = _checkout(only_staged_checkouts)
    _without_user_ids(monkeypatch)
    scanner = _scanner(test_plugin_context)

    envs = _both_spawn_paths(scanner, _policy(only_staged_checkouts, repo), repo)

    for name, env in envs.items():
        assert _named(env) == [os.path.realpath(repo)], name
    refusals = [m for m in walk_messages if "safe_directories_for: not naming" in m]
    assert not refusals, refusals
