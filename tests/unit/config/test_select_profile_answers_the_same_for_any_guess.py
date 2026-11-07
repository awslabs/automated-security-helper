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
"""

from __future__ import annotations

import json
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
