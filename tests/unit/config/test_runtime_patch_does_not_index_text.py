# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A patch op's path names a setting, never a character of one.

jsonpointer indexes a string like a list, so a ``test`` op whose path goes on
past a string setting (``.../path/0``) would compare one character and a
``remove`` there would raise a TypeError. Every op whose path passes
through a string, or ends inside one, is refused, with one refusal whatever
the op's value. And a refusal carries nothing of jsonpatch's: no text in its
message, no error as its context, nothing logged.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_patch,
)
from automated_security_helper.models.core import IgnorePathWithReason

CANARY = "ash-canary-7f3e-0123456789"
ALLOWLIST = RuntimeOverridesConfig(
    enabled=True, allowed_paths=["/global_settings/**"], denied_paths=[]
)


def _base() -> AshConfig:
    base = AshConfig(project_name="demo")
    base.global_settings.ignore_paths = [
        IgnorePathWithReason(path=f"{CANARY}/**", reason="vendored")
    ]
    return base


def _refusal(op: dict) -> RuntimePatchDeniedError:
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(_base(), [op], allowlist=ALLOWLIST)
    return refused.value


INTO_TEXT = "/global_settings/ignore_paths/0/path/0"


def test_a_test_op_into_text_answers_the_same_for_any_character():
    right = _refusal({"op": "test", "path": INTO_TEXT, "value": CANARY[0]})
    wrong = _refusal({"op": "test", "path": INTO_TEXT, "value": "#"})
    same = right.rule == wrong.rule
    assert same, "the refusal tells the right character from a wrong one"


@pytest.mark.parametrize(
    "op",
    [
        pytest.param({"op": "remove", "path": INTO_TEXT}, id="remove"),
        pytest.param({"op": "replace", "path": INTO_TEXT, "value": "x"}, id="replace"),
        pytest.param({"op": "add", "path": INTO_TEXT, "value": "x"}, id="add"),
        pytest.param(
            {
                "op": "test",
                "path": "/global_settings/ignore_paths/0/path/0/x",
                "value": 1,
            },
            id="past-the-text",
        ),
    ],
)
def test_any_op_into_text_is_refused(op):
    """Not a TypeError from jsonpatch (remove), and not an applied op."""
    refusal = _refusal(op)
    named = refusal.op == op
    assert named, "the refusal does not name its op"


def test_a_list_index_is_ascii_digits(tmp_path, monkeypatch):
    """'²' is a digit to str.isdigit, and int() refuses it: refused, not raised.
    The base reads a list entry from the environment, so its references are
    followed through the op."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_IP", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: ${ASH_IP}\n"
        "      reason: vendored\n",
        encoding="utf-8",
    )
    _, base = load_config_file_for_run(path)
    followed = bool(base._written_references)
    assert followed, "the control: the base has a reference to follow"
    op = {
        "op": "add",
        "path": "/global_settings/ignore_paths/²",
        "value": {"path": "x"},
    }
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(base, [op], allowlist=ALLOWLIST)
    named = refused.value.op == op
    assert named, "the refusal does not name its op"


@pytest.mark.parametrize(
    "op",
    [
        pytest.param(
            {"op": "test", "path": INTO_TEXT, "value": CANARY[0]}, id="into-text"
        ),
        pytest.param(
            {
                "op": "test",
                "path": "/global_settings/ignore_paths/0/path",
                "value": "x",
            },
            id="wrong-guess",
        ),
        pytest.param(
            {"op": "test", "path": "/global_settings/no_such_key", "value": 1},
            id="missing-member",
        ),
    ],
)
def test_a_refusal_carries_and_logs_nothing_of_jsonpatch(op, caplog):
    with caplog.at_level(logging.DEBUG):
        refusal = _refusal(op)
    # Booleans, so a failure does not print the value.
    logged = CANARY in caplog.text
    assert not logged, "a log line holds the value"
    unchained = refusal.__cause__ is None and refusal.__context__ is None
    assert unchained, "the refusal carries an error with it"


def test_a_test_op_compares_with_the_reference_not_the_value(tmp_path, monkeypatch):
    """A test op at a setting the profile read from the environment compares
    with the reference the file wrote: a correct guess of the value does not
    pass, the reference does."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_PN", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text("project_name: ${ASH_PN}\n", encoding="utf-8")
    _, base = load_config_file_for_run(path)
    allowlist = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/project_name"], denied_paths=[]
    )
    guessed = {"op": "test", "path": "/project_name", "value": CANARY}
    with pytest.raises(RuntimePatchDeniedError):
        apply_runtime_patch(base, [guessed], allowlist=allowlist)
    referenced = {"op": "test", "path": "/project_name", "value": "${ASH_PN}"}
    patched = apply_runtime_patch(base, [referenced], allowlist=allowlist)
    # The control: a test op changes nothing.
    unchanged = patched.project_name == CANARY
    assert unchanged, "the test op changed the setting"


@pytest.mark.parametrize("guess", [CANARY, "ash-canary-0000-9876543210"])
def test_a_test_op_after_the_client_s_own_write_compares_with_that_text(
    tmp_path, monkeypatch, guess
):
    """A replace writes the client's guess over the setting, and its reference
    with it: a test op after it compares with what the client wrote, so a test
    for the reference is refused for a right guess as for a wrong one."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_PN", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text("project_name: ${ASH_PN}\n", encoding="utf-8")
    _, base = load_config_file_for_run(path)
    allowlist = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/project_name"], denied_paths=[]
    )
    ops = [
        {"op": "replace", "path": "/project_name", "value": guess},
        {"op": "test", "path": "/project_name", "value": "${ASH_PN}"},
    ]
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(base, ops, allowlist=allowlist)
    named = refused.value.op == ops[1]
    assert named, "the refusal does not name the test op"
    # The control: a test for the text the client wrote passes.
    ops[1] = {"op": "test", "path": "/project_name", "value": guess}
    patched = apply_runtime_patch(base, ops, allowlist=allowlist)
    kept = patched.project_name == guess
    assert kept, "the control: the client's text is not the setting"
