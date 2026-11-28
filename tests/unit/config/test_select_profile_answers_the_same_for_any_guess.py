# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""select_profile answers a patch the same for a right and a wrong guess of a
value the profile read from the environment.

The cells hold for any mechanism: each sends the same ops twice, once with the
value the variable holds and once with another, and compares the two whole
responses with the guess written as ``GUESS``. A ``test`` op is aimed at the
setting that holds the value, at what holds that setting, and inside its text;
a ``copy`` or ``move`` takes the setting somewhere a ``test`` op then reads.
Where a comparison can take place, the same op at a setting the profile writes
as text is the control. Measured, the operation answers a right and a wrong
guess byte for byte alike at every setting, a literal-written one included, so
the control pins the same uniformity there: the answer carries no information
about the guess wherever the op lands.

The last cell aims a ``test`` op at a setting no policy entry denies, bandit's
``config_file``, which a profile reads from the environment as a relative path
the load anchors at the profile's directory and folds a ``..`` out of. Its control
is the profile that writes the same path as text: there a right guess binds the
profile and a wrong one is refused, as it is for any setting nothing denies, so
the uniform answer for the path read from the environment is the reading of the
reference and not a refusal made before the op is read.

The same setting is the target where a base that a variable chose writes the path
itself: the load anchors it at the base's directory, which holds what the
variable gave, and a ``test`` op reads that directory as ``<value>``, so a right
and a wrong guess of the absolute path are answered alike. The control is a base
the profile's own text names, where a right guess binds the profile.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import pytest

pytestmark = pytest.mark.unit

PROJECT = "ash-canary-7f3e-0123456789"
PATH_VALUE = "ash-canary-7f3e-path-0123456789"
LITERAL = "literal-control-0123456789"
OTHER = "ash-canary-0000-9876543210"

PROFILE = (
    "project_name: ${ASH_PROBE_PROJECT}\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    "    - path: ${ASH_PROBE_PATH}\n"
    "      reason: vendored\n"
    f"    - path: {LITERAL}\n"
    "      reason: kept\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
    "        - /project_name/**\n"
    "        - /global_settings/ignore_paths\n"
    "        - /global_settings/ignore_paths/**\n"
    "      denied_paths: []\n"
)


@pytest.fixture
def select(tmp_path, monkeypatch):
    """Call select_profile with fresh session state, as a client does."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_PROBE_PROJECT", PROJECT)
    monkeypatch.setenv("ASH_PROBE_PATH", PATH_VALUE)
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(PROFILE, encoding="utf-8")

    def _select(ops: List[Dict[str, Any]]) -> Dict[str, Any]:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()
        profile_registry.set_profile_registry(
            profile_registry.register_profiles([f"op={profile}"])
        )
        try:
            return mcp_select_profile("op", patch_ops=ops, session_id="session-a")
        finally:
            profile_registry.clear_profile_registry()
            profile_registry.clear_all_session_state()

    return _select


def _neutral(result: Dict[str, Any], guess: str) -> str:
    """The response with the guess written as GUESS. A short guess (one
    character) is replaced only where it stands quoted, as an op's value."""
    text = json.dumps(result, sort_keys=True)
    if len(guess) >= 8:
        return text.replace(guess, "GUESS")
    for quoted, neutral in (
        (f'\\"{guess}\\"', '\\"GUESS\\"'),
        (json.dumps(guess), '"GUESS"'),
        (f"'{guess}'", "'GUESS'"),
    ):
        text = text.replace(quoted, neutral)
    return text


def _answers_the_same(select, ops_for, right: str, wrong: str) -> bool:
    return _neutral(select(ops_for(right)), right) == _neutral(
        select(ops_for(wrong)), wrong
    )


def _is_a_patch_answer(result: Dict[str, Any]) -> bool:
    """Whether *result* is select_profile's own answer to a patch: a structured,
    non-empty response whose success flag is a boolean, that is either the bound
    profile (``mode`` inherit_and_patch and a ``config_path``) or the patch's
    refusal (``patch denied: ...`` with no ``error_type``). A registry that does
    not hold the profile, a busy session workspace or a failed write answers in
    other shapes, so a pipeline that never reached the patch is not one. Read
    from mcp_tools._select_profile; a boolean, so a failure prints no value."""
    if not isinstance(result, dict) or not result:
        return False
    success = result.get("success")
    if success is True:
        path = result.get("config_path")
        return (
            result.get("mode") == "inherit_and_patch"
            and isinstance(path, str)
            and bool(path)
        )
    if success is False:
        error = result.get("error")
        return (
            isinstance(error, str)
            and error.startswith("patch denied: ")
            and "error_type" not in result
        )
    return False


def test_select_profile_answers_a_patch_both_ways(select):
    """The uniform answers below mean something only if the pipeline can answer
    both ways: a patch that applies binds the profile, a test op whose value the
    profile does not hold is refused with the patch's own error. Both aim at
    /project_name, which the profile allows and the always-denied paths do not
    cover (ignore_paths is always denied, so a write there is refused whatever
    the profile allows)."""
    bound = select([{"op": "replace", "path": "/project_name", "value": "x"}])
    assert _is_a_patch_answer(bound), "a patch that applies is not bound"
    assert bound["success"] is True

    refused = select([{"op": "test", "path": "/project_name", "value": "x"}])
    assert _is_a_patch_answer(refused), "a refused patch is not answered as one"
    assert refused["success"] is False
    assert "patch apply failed" in refused["error"]


def _entry(path: str, reason: str) -> Dict[str, Any]:
    """An ignore_paths entry as the configuration's dump holds it, every field.

    ``expires`` is the canonical spelling (``expiration`` is a deprecated alias,
    removed in v4), and the model adds ``client_supplied`` to every entry
    (models/core.py), so a test op's value equals the as-written dump only in
    this shape.
    """
    return {
        "path": path,
        "reason": reason,
        "expires": None,
        "client_supplied": False,
    }


# Each case: the ops for a guess at the setting read from the environment, the
# value it holds, and the same ops at the setting written as text with its text
# (None where no comparison can take place in the text, as inside it).
CASES = [
    pytest.param(
        lambda g: [{"op": "test", "path": "/project_name", "value": g}],
        PROJECT,
        None,
        None,
        id="test-at-a-setting",
    ),
    pytest.param(
        lambda g: [
            {"op": "test", "path": "/global_settings/ignore_paths/0/path", "value": g}
        ],
        PATH_VALUE,
        lambda g: [
            {"op": "test", "path": "/global_settings/ignore_paths/1/path", "value": g}
        ],
        LITERAL,
        id="test-at-a-list-entry-s-setting",
    ),
    pytest.param(
        lambda g: [
            {
                "op": "test",
                "path": "/global_settings/ignore_paths/0",
                "value": _entry(g, "vendored"),
            }
        ],
        PATH_VALUE,
        lambda g: [
            {
                "op": "test",
                "path": "/global_settings/ignore_paths/1",
                "value": _entry(g, "kept"),
            }
        ],
        LITERAL,
        id="test-above-at-the-entry",
    ),
    pytest.param(
        lambda g: [
            {
                "op": "test",
                "path": "/global_settings/ignore_paths",
                "value": [_entry(g, "vendored"), _entry(LITERAL, "kept")],
            }
        ],
        PATH_VALUE,
        None,
        None,
        id="test-above-at-the-list",
    ),
    pytest.param(
        lambda g: [{"op": "test", "path": "/project_name/0", "value": g}],
        PROJECT[0],
        None,
        None,
        id="test-inside-a-setting",
    ),
    pytest.param(
        lambda g: [
            {
                "op": "test",
                "path": "/global_settings/ignore_paths/0/path/0",
                "value": g,
            }
        ],
        PATH_VALUE[0],
        None,
        None,
        id="test-inside-a-list-entry-s-setting",
    ),
]


@pytest.mark.parametrize(("ops_for", "right", "twin_ops_for", "text"), CASES)
def test_a_right_guess_is_answered_as_a_wrong_one(
    select, ops_for, right, twin_ops_for, text
):
    wrong = "#" if len(right) == 1 else OTHER
    # A boolean, so a failure does not print the value.
    same = _answers_the_same(select, ops_for, right, wrong)
    assert same, "the response tells a right guess from a wrong one"
    if twin_ops_for is not None:
        # The control: at a setting the profile writes as text, the answer is
        # uniform as well. Measured: the operation answers a right and a wrong
        # guess byte for byte alike everywhere, so the control pins that
        # uniformity at the literal-written entry too.
        uniform = _answers_the_same(select, twin_ops_for, text, OTHER)
        assert uniform, "the control: the response tells a right guess from a wrong one"
        # And the uniform answer is the pipeline's own: both responses are
        # structured patch answers, so a blanket refusal or a load failure that
        # answers alike does not pass for it.
        assert _is_a_patch_answer(select(twin_ops_for(text))), (
            "the control: the right guess got no patch answer"
        )
        assert _is_a_patch_answer(select(twin_ops_for(OTHER))), (
            "the control: the wrong guess got no patch answer"
        )


TO = "/global_settings/ignore_paths/1/reason"

MOVES = [
    pytest.param(
        lambda op, g: [
            {"op": op, "from": "/project_name", "path": TO},
            {"op": "test", "path": TO, "value": g},
        ],
        PROJECT,
        id="from-a-setting",
    ),
    pytest.param(
        lambda op, g: [
            {"op": op, "from": "/global_settings/ignore_paths/0/path", "path": TO},
            {"op": "test", "path": TO, "value": g},
        ],
        PATH_VALUE,
        id="from-a-list-entry-s-setting",
    ),
    pytest.param(
        lambda op, g: [
            {
                "op": op,
                "from": "/global_settings/ignore_paths/0",
                "path": "/global_settings/ignore_paths/-",
            },
            # A copy lands after both entries, a move after the one left.
            {
                "op": "test",
                "path": f"/global_settings/ignore_paths/{2 if op == 'copy' else 1}",
                "value": _entry(g, "vendored"),
            },
        ],
        PATH_VALUE,
        id="from-the-entry",
    ),
]


@pytest.mark.parametrize("op", ["copy", "move"])
@pytest.mark.parametrize(("ops_for", "right"), MOVES)
def test_a_value_copied_or_moved_is_answered_as_a_wrong_guess(
    select, op, ops_for, right
):
    same = _answers_the_same(select, lambda g: ops_for(op, g), right, OTHER)
    assert same, "the response tells a right guess from a wrong one"
    # The control: the test op that follows, aimed at the text the profile
    # writes where the value would land, is answered uniformly too. Measured:
    # the operation answers a right and a wrong guess byte for byte alike
    # everywhere, so the uniform answer is the contract at this entry as well.
    literal_ops = lambda g: [{"op": "test", "path": TO, "value": g}]  # noqa: E731
    uniform = _answers_the_same(select, literal_ops, "kept", OTHER)
    assert uniform, "the control: the response tells a right guess from a wrong one"
    # The uniform answer is the pipeline's own patch answer, not a blanket
    # refusal or a load failure that answers alike.
    assert _is_a_patch_answer(select(literal_ops("kept"))), (
        "the control: the right guess got no patch answer"
    )
    assert _is_a_patch_answer(select(literal_ops(OTHER))), (
        "the control: the wrong guess got no patch answer"
    )


CONFIG_FILE = "/scanners/bandit/options/config_file"
FOLDED = "../shared-6d0a/x-6d0a.yaml"


def _scanner_profile(config_file: str) -> str:
    """A profile that sets bandit's ``config_file`` and lets a client aim ops at
    it. ``replace_default_denied_paths`` lifts the shipped denial of a scanner's own
    config file, which would refuse every op there before the op is read."""
    return (
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        f"      config_file: {config_file}\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        f"        - {CONFIG_FILE}\n"
        "      denied_paths: []\n"
        "      replace_default_denied_paths: true\n"
    )


@pytest.fixture
def select_for(tmp_path, monkeypatch):
    """``select``, for a profile the cell writes itself: called with the profile's
    text, it returns the function that sends ops to that profile."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    def _for(text: str):
        profile = tmp_path / "scanner.ash.yaml"
        profile.write_text(text, encoding="utf-8")

        def _select(ops: List[Dict[str, Any]]) -> Dict[str, Any]:
            profile_registry.clear_profile_registry()
            profile_registry.clear_all_session_state()
            profile_registry.set_profile_registry(
                profile_registry.register_profiles([f"op={profile}"])
            )
            try:
                return mcp_select_profile("op", patch_ops=ops, session_id="session-a")
            finally:
                profile_registry.clear_profile_registry()
                profile_registry.clear_all_session_state()

        return _select

    return _for


@pytest.mark.parametrize(
    "from_the_environment",
    [
        pytest.param(True, id="folded-path-read-from-the-environment"),
        pytest.param(False, id="literal-path-control"),
    ],
)
def test_a_test_op_at_a_folded_operator_path_answers_the_same_for_any_guess(
    select_for, tmp_path, monkeypatch, from_the_environment
):
    """A profile reads bandit's ``config_file`` from a variable that holds
    ``../shared-6d0a/x-6d0a.yaml``. The load anchors it at the profile's directory
    and folds the ``..`` out, so the configuration holds an absolute path that
    contains neither the variable's text nor its reference. A ``test`` op reads the
    configuration as its file wrote it, which is that directory and the reference,
    so the op names the setting the same way for the path the configuration holds
    (the right guess) and for another of its length (the wrong one), and the two
    answers are alike. The control is the profile that writes the same path as
    text: a right guess binds it and a wrong one is refused, so the answers at
    this setting can tell the guesses apart, where nothing hides the value."""
    monkeypatch.setenv("ASH_PROBE_FOLDED", FOLDED)
    right = os.path.normpath(os.path.join(os.path.realpath(tmp_path), FOLDED))
    wrong = right.replace("6d0a", "0000")
    select = select_for(
        _scanner_profile("${ASH_PROBE_FOLDED}" if from_the_environment else right)
    )

    def ops_for(guess: str) -> List[Dict[str, Any]]:
        return [{"op": "test", "path": CONFIG_FILE, "value": guess}]

    # A boolean, so a failure does not print the value.
    same = _answers_the_same(select, ops_for, right, wrong)
    if from_the_environment:
        assert same, "the response tells a right guess from a wrong one"
        # The uniform answer is the pipeline's own: the patch's refusal, for
        # both, and not a refusal made before the op is read.
        assert _is_a_patch_answer(select(ops_for(right))), (
            "the right guess got no patch answer"
        )
        assert _is_a_patch_answer(select(ops_for(wrong))), (
            "the wrong guess got no patch answer"
        )
        assert select(ops_for(right))["success"] is False
    else:
        assert not same, "the control: the answer does not depend on the guess"
        assert select(ops_for(right))["success"] is True, (
            "the control: the right guess did not bind the profile"
        )
        assert select(ops_for(wrong))["success"] is False, (
            "the control: the wrong guess was not refused"
        )


def _runtime_overrides_block(*allowed: str) -> str:
    """The ``global_settings`` block of a profile that lets a client aim ops at the
    ``allowed`` paths and denies none of them: ``replace_default_denied_paths``
    lifts the shipped denials, which would refuse an op at a scanner's config file
    before the op is read."""
    return (
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        + "".join(f"        - {path}\n" for path in allowed)
        + "      denied_paths: []\n"
        "      replace_default_denied_paths: true\n"
    )


@pytest.mark.parametrize(
    "from_the_environment",
    [
        pytest.param(True, id="chosen-base"),
        pytest.param(False, id="named-base-control"),
    ],
)
def test_a_test_op_at_a_relative_path_a_chosen_base_writes_answers_the_same_for_any_guess(
    select_for, tmp_path, monkeypatch, from_the_environment
):
    """A profile extends a base, and the base writes bandit's ``config_file``
    itself as a relative path. Where a variable names the base (``chosen-base``),
    the load takes the path from a directory that holds what the variable gave, so
    the configuration holds an absolute path with that text in it. A ``test`` op
    reads the configuration as its files wrote it, which is ``<value>`` and the
    path as the base wrote it, so the op names the setting the same way for the
    path the configuration holds (the right guess) and for another of its length
    (the wrong one), and the two answers are alike. The control is the profile
    whose own text names the base: nothing there is a value, so a right guess binds
    the profile and a wrong one is refused."""
    monkeypatch.setenv("ASH_PROBE_TEAM_BASE", "teams-4c7e/base.yaml")
    base = tmp_path / "teams-4c7e" / "base.yaml"
    base.parent.mkdir()
    base.write_text(
        "scanners:\n  bandit:\n    options:\n      config_file: lit-2a9f/bandit.yaml\n",
        encoding="utf-8",
    )
    right = os.path.normpath(
        os.path.join(
            os.path.realpath(tmp_path), "teams-4c7e", "lit-2a9f", "bandit.yaml"
        )
    )
    wrong = right.replace("2a9f", "0000")
    extends = (
        "${ASH_PROBE_TEAM_BASE}" if from_the_environment else "teams-4c7e/base.yaml"
    )
    select = select_for(f"extends: {extends}\n" + _runtime_overrides_block(CONFIG_FILE))

    def ops_for(guess: str) -> List[Dict[str, Any]]:
        return [{"op": "test", "path": CONFIG_FILE, "value": guess}]

    # A boolean, so a failure does not print the value.
    same = _answers_the_same(select, ops_for, right, wrong)
    if from_the_environment:
        assert same, "the response tells a right guess from a wrong one"
        # The uniform answer is the pipeline's own: the patch's refusal, for
        # both, and not a refusal made before the op is read.
        assert _is_a_patch_answer(select(ops_for(right))), (
            "the right guess got no patch answer"
        )
        assert _is_a_patch_answer(select(ops_for(wrong))), (
            "the wrong guess got no patch answer"
        )
        assert select(ops_for(right))["success"] is False
    else:
        assert not same, "the control: the answer does not depend on the guess"
        assert select(ops_for(right))["success"] is True, (
            "the control: the right guess did not bind the profile"
        )
        assert select(ops_for(wrong))["success"] is False, (
            "the control: the wrong guess was not refused"
        )


@pytest.mark.parametrize(
    "path, as_op_value, right, wrong",
    [
        pytest.param(
            "/output_formats",
            lambda guess: guess.split(","),
            "sarif,html",
            "sarif,xml",
            id="list",
        ),
        pytest.param(
            "/output_formats/0",
            lambda guess: guess,
            "sarif",
            "html",
            id="entry",
        ),
    ],
)
@pytest.mark.parametrize(
    "written, from_the_environment",
    [
        pytest.param("${ASH_PROBE_FMT}", True, id="from-the-environment"),
        pytest.param("[sarif, html]", False, id="literal-control"),
    ],
)
def test_a_test_op_at_a_list_made_of_one_reference_answers_the_same_for_any_guess(
    select_for,
    monkeypatch,
    written,
    from_the_environment,
    path,
    as_op_value,
    right,
    wrong,
):
    """A profile reads ``output_formats`` from a variable that holds ``sarif,html``,
    which the field makes a list of two names. A ``test`` op reads the
    configuration as its file wrote it, which is the reference where the field made
    its entries of the variable's text, so an op at the list (``list``) or at its
    first entry (``entry``) names the setting the same way for the names the list
    holds (the right guess) and for others (the wrong one), and the two answers are
    alike. The control is the profile that writes the list itself: a right guess
    binds it and a wrong one is refused."""
    monkeypatch.setenv("ASH_PROBE_FMT", "sarif,html")
    select = select_for(
        f"output_formats: {written}\n"
        + _runtime_overrides_block("/output_formats", "/output_formats/**")
    )

    def ops_for(guess: str) -> List[Dict[str, Any]]:
        return [{"op": "test", "path": path, "value": as_op_value(guess)}]

    # A boolean, so a failure does not print the value.
    same = _answers_the_same(select, ops_for, right, wrong)
    if from_the_environment:
        assert same, "the response tells a right guess from a wrong one"
        # The uniform answer is the pipeline's own: the patch's refusal, for
        # both, and not a refusal made before the op is read.
        assert _is_a_patch_answer(select(ops_for(right))), (
            "the right guess got no patch answer"
        )
        assert _is_a_patch_answer(select(ops_for(wrong))), (
            "the wrong guess got no patch answer"
        )
        assert select(ops_for(right))["success"] is False
    else:
        assert not same, "the control: the answer does not depend on the guess"
        assert select(ops_for(right))["success"] is True, (
            "the control: the right guess did not bind the profile"
        )
        assert select(ops_for(wrong))["success"] is False, (
            "the control: the wrong guess was not refused"
        )
