#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform CodeCommit gate must not approve code it did not scan.

Why this file exists
--------------------
Review finding, and until now nothing tested this file at all -- no Python test targeted
``ash_pr_gate.py``, which is why both defects below could sit in a control that can APPROVE a pull
request.

**Exit 0 did not mean "scanned and clean".** ASH exits 0 when no scanner completed, because no
scanner produced a finding to fail on. The gate mapped exit 0 to outcome "pass", and "pass" is the
only outcome that calls ``update_pull_request_approval_state`` with APPROVE. So arming
``ASH_MANAGE_APPROVAL_STATE`` on a Lambda where the scanners cannot run produced auto-approval of
unscanned code. Not hypothetical: Lambda's root filesystem is read-only, ASH's scanners write caches
at scan time, and a measured run on that image reported three scanners MISSING, one ERROR, and grype
PASSED with zero findings. ``--fail-on-incomplete-scanners`` is what makes exit 0 mean what the gate
reads it as meaning.

**A stale approval outlived the code it was granted for.** The gate approved on a clean commit and
then, when a later commit introduced findings, left that approval in place -- declining to withdraw
the very approval it had granted, on code it had just judged unclean. The CDK gate revokes. These
two have to agree, because choosing an infrastructure flavour is not choosing a security posture.

The gate is loaded by path rather than imported: it lives under ``deploy/terraform/modules/`` and is
packaged into a Lambda, so it is not on any import path. Loading it by path is also what lets this
test exist at all, which is the point the review made.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from types import ModuleType, SimpleNamespace
from typing import Any, Dict, List

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
GATE_PATH = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "codecommit-gate"
    / "files"
    / "ash_pr_gate.py"
)
CDK_SCRIPTS = REPO_ROOT / "deploy" / "cdk" / "lib" / "ash-container-scripts.ts"


def _load_gate() -> ModuleType:
    """Load the gate by path, since it is packaged into a Lambda rather than importable."""
    assert GATE_PATH.is_file(), f"gate not found at {GATE_PATH}"
    spec = importlib.util.spec_from_file_location("_ash_pr_gate_under_test", GATE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def gate() -> ModuleType:
    return _load_gate()


# ---------------------------------------------------------------------------
# 1. Exit 0 has to mean "every requested scanner ran"
# ---------------------------------------------------------------------------


def test_the_scan_argv_forces_incomplete_scanners_to_fail(gate, monkeypatch, tmp_path):
    """Without this flag, a run where nothing ran exits 0 and the gate calls that a pass."""
    captured: List[List[str]] = []

    def _fake_run(argv, cwd=None):
        captured.append(list(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gate, "_run", _fake_run)
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")

    gate.run_scan(tmp_path / "src", "low", True)

    assert captured, "run_scan did not invoke the scanner"
    argv = captured[0]
    assert "--fail-on-incomplete-scanners" in argv, (
        "a gate that can APPROVE must treat ERROR/MISSING scanners as a failure; without "
        f"this flag exit 0 is indistinguishable from a clean scan. argv={argv}"
    )


def _resolve_scan_params(argv: list[str]) -> dict[str, Any]:
    """Resolve an ``ash scan`` argv through the real CLI and return the parameter values.

    Membership in argv is not the property that matters. ``click`` resolves a repeated option
    to its LAST occurrence, so a flag can sit in argv and still resolve to the opposite value --
    which is how the fail-closed flag came to be switchable. Extra args were appended after it,
    and appending the negation resolved ``fail_on_incomplete_scanners`` to ``False`` while
    leaving the affirmative token in argv for an ``in argv`` assertion to find. Building the
    real command and reading ``ctx.params`` is the only way to assert what ASH will do.

    Imported inside the function because this module otherwise loads the gate by path and needs
    nothing from the package; the import exists to get the genuine option definitions rather
    than a restatement of them here that could drift from the CLI.
    """
    import typer.main

    from automated_security_helper.cli.main import app

    assert argv[:2] == ["ash", "scan"], f"unexpected argv prefix: {argv[:2]}"
    scan_command = typer.main.get_command(app).commands["scan"]
    return scan_command.make_context("scan", argv[2:], resilient_parsing=False).params


def _capture_argv(gate, monkeypatch, tmp_path) -> list[list[str]]:
    """Point the gate's subprocess runner at a list, and return that list."""
    captured: list[list[str]] = []
    monkeypatch.setattr(
        gate,
        "_run",
        lambda argv, cwd=None: (
            captured.append(list(argv))
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    return captured


def test_the_flag_is_not_switchable_by_configuration(gate, monkeypatch, tmp_path):
    """The fail-closed behaviour must not depend on how the gate was deployed.

    An environment variable that can disable it is a control whose safety varies by deployment,
    and the failure is silent when it is set wrong. ASH_SCAN_EXTRA_ARGS is the one knob that could
    plausibly be used to smuggle in the negation, so both halves of the property are asserted: a
    benign extra arg leaves the flag RESOLVING to True, and the negation is not honored.

    The second half is what this test was missing. It asserted the affirmative token was ``in
    argv``, which the appended negation does not disturb, so it could not fail for the condition
    it is named after.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", "--offline")

    gate.run_scan(tmp_path / "src", "low", True)

    argv = captured[0]
    assert "--fail-on-incomplete-scanners" in argv

    params = _resolve_scan_params(argv)
    assert params["fail_on_incomplete_scanners"] is True, (
        "the flag is in argv but resolves to "
        f"{params['fail_on_incomplete_scanners']!r}; argv={argv}"
    )

    # Positive control on the instrument above. An assertion that a value resolves True is
    # worthless if the resolver cannot produce False, and this is the exact argv shape the gate
    # used to build: extra args appended after the gate's own flags.
    negated = _resolve_scan_params([*argv, "--no-fail-on-incomplete-scanners"])
    assert negated["fail_on_incomplete_scanners"] is False, (
        "appending the negation did not resolve to False, so this test's resolver cannot "
        "distinguish the switched-off case and the assertion above proves nothing"
    )

    # The negation itself: refused, so there is no argv for it to resolve in.
    captured.clear()
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", "--no-fail-on-incomplete-scanners")
    with pytest.raises(RuntimeError):
        gate.run_scan(tmp_path / "src", "low", True)
    assert not captured, (
        "the negation was carried into the scan; whatever argv ordering says today, the gate's "
        f"verdict is now switchable from the environment. argv={captured}"
    )


def test_a_refusal_names_the_offending_token(gate, monkeypatch, tmp_path):
    """Refusal over silent dropping, and the error has to be actionable.

    An operator whose intent was discarded has no signal to correct it, and the gate keeps
    running in a configuration nobody chose. The refusal reaches the pull request as outcome
    "error", which says the code has not been assessed and revokes any standing approval -- so
    this message is the only place the operator learns which token was rejected.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    monkeypatch.setenv(
        "ASH_SCAN_EXTRA_ARGS", "--offline --no-fail-on-incomplete-scanners"
    )

    with pytest.raises(RuntimeError) as excinfo:
        gate.run_scan(tmp_path / "src", "low", True)

    message = str(excinfo.value)
    assert "--no-fail-on-incomplete-scanners" in message, (
        "the error must name the offending token, or an operator cannot tell which of their "
        f"extra args was rejected: {message}"
    )
    assert "ASH_SCAN_EXTRA_ARGS" in message, (
        f"the error must name the variable: {message}"
    )
    assert not captured, (
        "the scan ran anyway; a refusal that still invokes the scanner leaves the resolved "
        f"flag to argv ordering. argv={captured}"
    )


@pytest.mark.parametrize(
    "extra, why",
    [
        (
            "--no-fail-on-incomplete-scanners",
            "the completeness gate is the whole point",
        ),
        ("--no-fail-on-findings", "would make a pull request with findings pass"),
        (
            "--fail-on-incomplete-scanners",
            "a redundant affirmative today is one edit away from the negation",
        ),
        ("--fail-on-findings", "the same, in the other direction"),
        (
            "--min-severity critical",
            "would raise the floor so medium findings stop failing",
        ),
        (
            "--min-severity=critical",
            "the same override in the other form click accepts",
        ),
        ("--source-dir /elsewhere", "would scan a tree that is not the pull request"),
        (
            "--output-dir /elsewhere",
            "would hide the results file the comment is built from",
        ),
    ],
)
def test_no_gate_owned_option_can_be_set_from_extra_args(
    gate, monkeypatch, tmp_path, extra, why
):
    """Every option the gate sets is refused in extra args, not only the flag that was reported.

    The reported defect named one flag. The mechanism -- extra args resolving last -- applies to
    every option the gate passes, so guarding only the reported one leaves the same hole open
    under a different name.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", extra)

    with pytest.raises(RuntimeError):
        gate.run_scan(tmp_path / "src", "low", True)

    assert not captured, f"{extra} was honored: {why}"


#: Options that take a value and narrow, or redirect, what the gate's verdict is computed
#: from. The gate passes none of them, so the argv ordering below is no defence and the
#: refusal is the only one; and none of them is covered by --fail-on-incomplete-scanners,
#: because a scanner that was never selected is recorded SKIPPED rather than MISSING and
#: SKIPPED is on the completeness allowlist.
#:
#: The value in each pair is one that would do damage, not a placeholder, and
#: ``test_a_reserved_option_would_really_have_narrowed_the_scan`` resolves these same values
#: through the real CLI. Without that, a typo in the frozenset would leave this table green
#: while the hole stayed open: the refusal would fire on a spelling ASH does not accept, and
#: the spelling ASH does accept would sail past.
_NARROWING_OPTIONS_WITH_VALUES = [
    ("--scanners", "bandit", "scans one scanner and reports the other nine as SKIPPED"),
    (
        "--exclude-scanners",
        "semgrep",
        "drops a scanner the completeness gate would otherwise have covered",
    ),
    (
        "--mode",
        "precommit",
        "the precommit preset replaces the selection with a fixed list of fast scanners",
    ),
    (
        "--phases",
        "convert",
        "drops the scan phase, so there are no scanner statuses left to be incomplete",
    ),
    (
        "--config",
        "/tmp/none.yaml",  # a test argument, never opened
        "a config that disables every scanner is --scanners with no names",
    ),
    (
        "--config-overrides",
        "scanners.bandit.enabled=false",
        "reaches the same settings a replacement config would, one key at a time",
    ),
    ("--shard-index", "0", "one shard runs a disjoint subset and nothing here recombines"),
    ("--shard-count", "4", "the same, from the other half of the pair"),
    (
        "--base-ref",
        "HEAD~1",
        "filters findings to one commit's diff before the exit code is computed",
    ),
]

#: The same class, spelled as flags that take no value. ``--full`` and its aliases are ASH's
#: own default, so they change nothing today; they are refused for the reason this file
#: already refuses a redundant ``--fail-on-incomplete-scanners``, which is that accepting the
#: harmless polarity establishes this variable as the place the setting gets chosen, and the
#: next edit to it is the harmful one.
_NARROWING_FLAGS = [
    ("--python-only", "narrows to Python-only plugins; the rest are recorded SKIPPED"),
    ("--python-based-scanners-only", "an alias of the same option"),
    ("--python-based-plugins-only", "another alias of the same option"),
    ("--full", "the safe polarity, refused so the pair is decided in one place"),
    ("--all-enabled-scanners", "an alias of that polarity"),
    ("--all-enabled-plugins", "another alias of that polarity"),
    ("--use-existing", "answers from a prior results file instead of scanning"),
    ("--no-use-existing", "the other polarity of the same option"),
    ("--changed-files-only", "drops findings outside a git diff from the verdict"),
]


@pytest.mark.parametrize(
    "option, value, why",
    _NARROWING_OPTIONS_WITH_VALUES,
    ids=[option for option, _, _ in _NARROWING_OPTIONS_WITH_VALUES],
)
@pytest.mark.parametrize("form", ["space", "equals"])
def test_no_reserved_option_with_a_value_can_be_set_from_extra_args(
    gate, monkeypatch, tmp_path, option, value, why, form
):
    """Narrowing the selection switches the gate off by a route the ordering cannot close.

    ``--fail-on-incomplete-scanners`` gates only the scanners that were selected, so every
    option here is a more thorough way to reach the outcome that flag exists to prevent: a
    pull request with critical findings scanned by nothing that would see them, exiting 0,
    commented as a pass, and APPROVEd wherever the deployment arms approval management.

    Both forms are asserted because ``click`` accepts both for an option that takes a value,
    and the guard splits on the first ``=`` in order to see the second one.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    extra = f"{option} {value}" if form == "space" else f"{option}={value}"
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", extra)

    with pytest.raises(RuntimeError) as excinfo:
        gate.run_scan(tmp_path / "src", "low", True)

    assert option in str(excinfo.value), (
        f"the refusal does not name {option}, so an operator cannot tell which of their extra "
        f"args was rejected: {excinfo.value}"
    )
    assert not captured, f"{extra} was honored: {why}"


@pytest.mark.parametrize(
    "flag, why", _NARROWING_FLAGS, ids=[flag for flag, _ in _NARROWING_FLAGS]
)
def test_no_reserved_flag_can_be_set_from_extra_args(gate, monkeypatch, tmp_path, flag, why):
    """The same class of option, in the spellings that take no value.

    Only the bare token is exercised. ``click`` would reject ``--python-only=true`` as a usage
    error, so asserting that the guard refuses that shape would be asserting about a token
    which could never have reached the CLI in the first place.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", flag)

    with pytest.raises(RuntimeError):
        gate.run_scan(tmp_path / "src", "low", True)

    assert not captured, f"{flag} was honored: {why}"


@pytest.mark.parametrize(
    "extra",
    ["-c /tmp/none.yaml", "-c=/tmp/none.yaml", "-c/tmp/none.yaml"],
)
def test_the_short_alias_of_a_reserved_option_is_refused(gate, monkeypatch, tmp_path, extra):
    """``--config`` has a short alias, and an exact match on the long spelling cannot see it.

    ``click`` lets a short option's value be attached with no separator, so
    ``-c/tmp/none.yaml`` resolves ``config`` to ``/tmp/none.yaml`` while splitting that token
    on ``=`` leaves it whole -- an exact-equality entry for ``-c`` would miss it. Measured
    against the real CLI in ``test_a_reserved_option_would_really_have_narrowed_the_scan``,
    which resolves the attached form and asserts what it produces.

    This is the one short alias that matters: no other reserved option has one.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", extra)

    with pytest.raises(RuntimeError):
        gate.run_scan(tmp_path / "src", "low", True)

    assert not captured, f"{extra} reached the scan, setting --config from the environment"


@pytest.mark.parametrize(
    "extra",
    [
        "--min-severity-foo bar",
        "--output-directory /elsewhere",
        "--source-dir-extra /elsewhere",
        "--scanners-list bandit",
        "--config-file /tmp/other.yaml",
        "--modes container",
        "--container-uid 1000",
    ],
)
def test_an_option_that_merely_shares_a_prefix_is_not_refused(
    gate, monkeypatch, tmp_path, extra
):
    """Refusal is by spelling and not by prefix, for the long options.

    A guard that refused anything starting with a reserved spelling would reject
    ``--container-uid`` on account of ``-c``, and a plugin's own option on account of sharing
    a stem with ``--scanners``. The gate would then refuse to scan for a reason the operator
    cannot deduce from the message, which is the same fail-closed behaviour aimed at the wrong
    input.

    ``--container-uid`` is the case that survives even a greedy prefix rule, because it begins
    with two dashes: ``"--container-uid".startswith("-c")`` is False. It is here so that the
    reason the other six are safe is not confused with the reason this one is.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", extra)

    gate.run_scan(tmp_path / "src", "low", True)

    assert captured, f"{extra} was refused, but it sets no option the gate reserves"
    for token in extra.split():
        assert token in captured[0], f"{token} was dropped from argv: {captured[0]}"


def test_every_reserved_spelling_is_one_the_cli_actually_accepts():
    """A reserved spelling ASH does not accept is a hole that reads as a closed one.

    This is the failure mode the refusal tests cannot catch on their own. A typo --
    ``--exclude-scanner`` for ``--exclude-scanners``, or a spelling ASH renames later --
    leaves every one of them green, because the guard refuses the token the test feeds it and
    the test never asks whether that token is the one ASH resolves. The real spellings are
    read off the real click command for that reason, rather than restated here where they
    could drift from it.

    Note what this does NOT check: that the set is non-empty. An empty set is trivially a
    subset, so this test is a guard on the contents of a populated set and not on the set
    being populated. The refusal tests above are what hold that.
    """
    import typer.main

    from automated_security_helper.cli.main import app

    scan_command = typer.main.get_command(app).commands["scan"]
    declared = {
        spelling
        for param in scan_command.params
        for spelling in (*param.opts, *param.secondary_opts)
    }
    gate_module = _load_gate()
    reserved = gate_module.GATE_OWNED_SCAN_OPTIONS | gate_module.GATE_OWNED_SHORT_OPTIONS

    assert reserved <= declared, (
        "these reserved spellings are not options ASH declares, so refusing them protects "
        f"nothing: {sorted(reserved - declared)}"
    )


@pytest.mark.parametrize(
    "argv_tail, parameter, expected",
    [
        (["--scanners", "bandit"], "scanners", ("bandit",)),
        (["--exclude-scanners", "semgrep"], "exclude_scanners", ("semgrep",)),
        (["--python-only"], "python_based_plugins_only", True),
        (["--changed-files-only"], "changed_files_only", True),
        (["--base-ref", "HEAD~1"], "base_ref", "HEAD~1"),
        (["--shard-index", "0"], "shard_index", 0),
        (["--shard-count", "4"], "shard_count", 4),
        (["--use-existing"], "use_existing", True),
        (["--config", "/tmp/none.yaml"], "config", "/tmp/none.yaml"),
        (["-c", "/tmp/none.yaml"], "config", "/tmp/none.yaml"),
        (["-c/tmp/none.yaml"], "config", "/tmp/none.yaml"),
    ],
)
def test_a_reserved_option_would_really_have_narrowed_the_scan(
    argv_tail, parameter, expected
):
    """The positive control behind every refusal above.

    A refusal is only worth its cost to an operator if the token it refuses would have changed
    what ASH does. Each case here is resolved through the real CLI, so the assertion is on the
    value ASH would have used rather than on a token being present in a list. ``ash scan`` sets
    ignore_unknown_options, so a spelling ASH does not declare leaves the parameter at its
    default and these assertions fail -- which is what makes this a control and not a
    restatement.

    The last two cases are why ``-c`` is matched by prefix rather than by equality: ``click``
    resolves ``-c/tmp/none.yaml`` to the same value as ``-c /tmp/none.yaml``, and no amount of
    splitting on ``=`` recovers the ``-c`` from the attached form.
    """
    params = _resolve_scan_params(["ash", "scan", *argv_tail])

    assert params[parameter] == expected, (
        f"{argv_tail} resolves {parameter} to {params[parameter]!r}, not {expected!r}; if this "
        "option does not do what the refusal says it does, the refusal is costing an operator "
        "an extra arg for nothing"
    )


def test_a_benign_extra_arg_is_still_passed_through(gate, monkeypatch, tmp_path):
    """The guard rejects the options the gate reserves, not extra args in general.

    The extras here were chosen for being unable to narrow the verdict, which
    ``--scanners bandit`` -- what this test used to offer as its example of a benign arg -- is
    not. ``--offline`` does not drop the npm/pnpm/yarn audit scanners; it passes ``--offline``
    through to the tool and keeps going, so each of them still runs and still reports a status
    that ``--fail-on-incomplete-scanners`` covers. ``--output-formats`` decides which report
    files get written and is read by nothing that computes the exit code.

    An operator whose Lambda has no egress needs ``--offline``, so a guard that refused it
    would fail closed on a correct deployment.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", "--offline --output-formats html")

    gate.run_scan(tmp_path / "src", "low", True)

    argv = captured[0]
    assert "--offline" in argv and "--output-formats" in argv and "html" in argv, argv


def test_the_gates_own_options_are_resolved_last(gate, monkeypatch, tmp_path):
    """Ordering is the second line of defence, behind the refusal.

    The refusal knows the spellings ASH accepts today. If a future spelling slips past it,
    last-occurrence-wins still has to land on the gate's value rather than the operator's, so
    every option the gate owns is emitted after the operator's extras.

    Note what this defence does NOT cover, which is why it is the second line and not the
    first: it helps only for options the gate itself passes. An unrecognized spelling of
    ``--scanners`` would resolve to the operator's value whatever the ordering, because the
    gate passes no ``--scanners`` of its own for the ordering to favour.
    """
    captured = _capture_argv(gate, monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", "--offline --output-formats html")

    gate.run_scan(tmp_path / "src", "medium", False)

    argv = captured[0]
    last_extra = max(argv.index("--offline"), argv.index("html"))
    for owned in (
        "--source-dir",
        "--output-dir",
        "--min-severity",
        "--no-fail-on-findings",
        "--fail-on-incomplete-scanners",
    ):
        assert argv.index(owned) > last_extra, (
            f"{owned} is emitted before the operator's extra args, so a repeat of it in "
            f"ASH_SCAN_EXTRA_ARGS would resolve last and win. argv={argv}"
        )

    # And the values ASH resolves are the gate's, with the operator's tokens interspersed.
    params = _resolve_scan_params(argv)
    assert params["fail_on_incomplete_scanners"] is True
    assert params["fail_on_findings"] is False
    assert params["min_severity"] == "medium"


# ---------------------------------------------------------------------------
# 2. Approval state: APPROVE only on pass, REVOKE otherwise, matching CDK
# ---------------------------------------------------------------------------


class _FakeCodeCommit:
    """Records approval-state calls. Nothing else about the client is exercised."""

    def __init__(self) -> None:
        self.approval_calls: List[Dict[str, Any]] = []
        self.comments: List[Dict[str, Any]] = []

    def post_comment_for_pull_request(self, **kwargs):
        self.comments.append(kwargs)
        return {}

    def update_pull_request_approval_state(self, **kwargs):
        self.approval_calls.append(kwargs)
        return {}


def _drive_handler(gate, monkeypatch, tmp_path, scan_exit: int) -> _FakeCodeCommit:
    """Run the handler end to end with the scan's exit code forced.

    ``boto3.client`` is patched rather than a module attribute, because the handler builds its own
    client inline. Patching an attribute that does not exist with ``raising=False`` looked like it
    worked and let the real factory run -- botocore then found the developer's own
    ``~/.aws/credentials`` and failed on a missing region, which is a unit test one environment
    variable away from calling a live AWS API.
    """
    client = _FakeCodeCommit()
    monkeypatch.setattr(
        gate.boto3,
        "client",
        lambda service, *a, **k: client
        if service == "codecommit"
        else pytest.fail(f"unexpected boto3 client requested: {service}"),
    )
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    monkeypatch.setattr(gate, "clone_source", lambda *a, **k: tmp_path / "src")
    monkeypatch.setattr(
        gate, "run_scan", lambda *a, **k: (scan_exit, tmp_path / "out", "log tail")
    )
    monkeypatch.setattr(gate, "read_severity_counts", lambda *a, **k: None)
    monkeypatch.setenv("ASH_MANAGE_APPROVAL_STATE", "true")
    # The handler reads os.environ["AWS_REGION"] directly (ash_pr_gate.py:330) -- a KeyError, not
    # a .get with a default -- because Lambda always sets it. Set explicitly rather than inherited:
    # the first version of this file passed locally only because this developer's shell had
    # AWS_REGION exported, and failed on all 18 CI legs where it is absent. A test whose verdict
    # depends on what happens to be in the environment is not testing the code, and local green
    # was not evidence of anything.
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    event = {
        "detail": {
            "pullRequestId": "7",
            "repositoryNames": ["repo"],
            "sourceCommit": "a" * 40,
            "destinationCommit": "b" * 40,
            "sourceReference": "refs/heads/feature",
            "revisionId": "rev-1",
        }
    }
    gate.handler(event, object())
    return client


def test_a_refused_extra_arg_reaches_the_pull_request_as_error_and_revokes(
    gate, monkeypatch, tmp_path
):
    """The refusal has to be fail-closed end to end, not only a raise inside run_scan.

    This is the reason refusing beats dropping the token, so it is asserted rather than reasoned
    about: the real ``handler`` runs with the negation set, and the outcome has to be "error",
    which comments that the pull request was not assessed and REVOKEs an approval standing from
    an earlier commit. ``run_scan`` is NOT stubbed here; only the clone and the subprocess are.

    ``pytest.fail`` in the subprocess stub is load-bearing: ``handler`` wraps the scan in a bare
    ``except Exception``, and ``Failed`` derives from ``BaseException``, so a scan that ran
    anyway fails this test rather than being absorbed into the error outcome it is asserting.
    """
    client = _FakeCodeCommit()
    monkeypatch.setattr(
        gate.boto3,
        "client",
        lambda service, *a, **k: (
            client
            if service == "codecommit"
            else pytest.fail(f"unexpected boto3 client requested: {service}")
        ),
    )
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    monkeypatch.setattr(gate, "clone_source", lambda *a, **k: tmp_path / "src")
    monkeypatch.setattr(
        gate,
        "_run",
        lambda argv, cwd=None: pytest.fail(
            f"the scan ran despite a refused extra arg: {argv}"
        ),
    )
    monkeypatch.setenv("ASH_MANAGE_APPROVAL_STATE", "true")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("ASH_SCAN_EXTRA_ARGS", "--no-fail-on-incomplete-scanners")

    result = gate.handler(
        {
            "detail": {
                "pullRequestId": "7",
                "repositoryNames": ["repo"],
                "sourceCommit": "a" * 40,
                "destinationCommit": "b" * 40,
                "sourceReference": "refs/heads/feature",
                "revisionId": "rev-1",
            }
        },
        object(),
    )

    assert result["outcome"] == "error", (
        "a gate that cannot run must not report a verdict; anything but 'error' here means the "
        f"refusal was folded into a real outcome: {result}"
    )
    assert [call["approvalState"] for call in client.approval_calls] == ["REVOKE"], (
        "an approval granted on an earlier commit survives a gate that refused to run: "
        f"{client.approval_calls}"
    )
    assert client.comments, "the refusal left no comment on the pull request"


@pytest.mark.parametrize(
    "scan_exit, expected_state, why",
    [
        (0, "APPROVE", "a clean scan is the one outcome that may approve"),
        (2, "REVOKE", "findings must withdraw an approval granted on earlier, cleaner code"),
        (
            1,
            "REVOKE",
            "exit 1 is the incomplete-scanner failure: nothing was scanned, so nothing "
            "supports an approval",
        ),
        (70, "REVOKE", "an unrecognised failure is not evidence of cleanliness"),
    ],
)
def test_approval_state_follows_the_outcome(
    gate, monkeypatch, tmp_path, scan_exit, expected_state, why
):
    client = _drive_handler(gate, monkeypatch, tmp_path, scan_exit)

    assert len(client.approval_calls) == 1, (
        f"exit {scan_exit}: expected exactly one approval-state call, got "
        f"{client.approval_calls}"
    )
    assert client.approval_calls[0]["approvalState"] == expected_state, why


def test_a_non_pass_outcome_never_leaves_the_state_untouched(gate, monkeypatch, tmp_path):
    """The specific regression: silence on a non-pass leaves a stale APPROVE standing.

    Asserted separately from the parametrized table because "no call was made" and "the wrong
    call was made" are different failures, and only this one describes the defect that was found.
    """
    client = _drive_handler(gate, monkeypatch, tmp_path, 2)

    assert client.approval_calls, (
        "findings left the approval state untouched; an approval granted on an earlier clean "
        "commit therefore survives on code the gate has just judged unclean"
    )


# ---------------------------------------------------------------------------
# 3. CDK and Terraform must not disagree about what revokes
# ---------------------------------------------------------------------------


def test_cdk_and_terraform_gates_both_revoke_on_a_non_pass():
    """Parity between the two infrastructure flavours.

    A behavioural parity test would need both runtimes -- the CDK gate's handler is a Python
    string inside a TypeScript template literal, executed only inside a Lambda image. What is
    checkable here is that neither file carries the shape this review flagged: an approval path
    that revokes in one flavour and declines to act in the other. Stated as the structural check
    it is, because a text assertion cannot prove behaviour, only that the branch exists.
    """
    assert CDK_SCRIPTS.is_file(), f"CDK scripts not found at {CDK_SCRIPTS}"
    cdk = CDK_SCRIPTS.read_text(encoding="utf-8")
    terraform = GATE_PATH.read_text(encoding="utf-8")

    assert "REVOKE" in cdk, "the CDK gate no longer revokes; parity has moved"
    assert "REVOKE" in terraform, (
        "the Terraform gate has no REVOKE path, so a stale approval survives a failing scan "
        "while the CDK gate withdraws it"
    )
    assert "leaving approval state unchanged" not in terraform, (
        "the leave-untouched branch is back; that is the defect this test exists for"
    )
