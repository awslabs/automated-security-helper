# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each of the two rules that guard one position in a patch holds on its own.

At a setting the profile read from the environment, two rules stand between a
patch op and the value, and either one is enough:

- a copy or a move is refused by the op rule (check_runtime_ops), and the value
  it would take somewhere else is refused by the reference check
  (_ReferencesThroughPatch.settle);
- a test op inside the setting's text is refused by the into-text rule, and it
  would compare with the reference the file wrote, not the value
  (_as_written);
- a remove inside a text is refused by the into-text rule, and jsonpatch's
  TypeError there is a refusal too.

The select_profile cells (test_select_profile_answers_the_same_for_any_guess.py)
pass while either rule of a pair stands, so they cannot tell when one of them is
gone. Each cell here turns one rule of a pair off, as the follow cell in
test_as_written_checks_only_moved_values.py turns off follow, and checks that the
other rule still answers.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import runtime_patch
from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.runtime_patch import (
    INTO_TEXT_REFUSAL,
    MOVED_WITHOUT_ITS_REFERENCE,
    RuntimePatchDeniedError,
    apply_runtime_patch,
)

pytestmark = pytest.mark.unit

CANARY = "ash-canary-5c1d-9876543210"
ALLOWLIST = RuntimeOverridesConfig(
    enabled=True,
    allowed_paths=["/project_name/**", "/global_settings/**"],
    denied_paths=[],
)
#: A setting the profile writes as text, where a copy or a move would put the
#: value.
ELSEWHERE = "/global_settings/ignore_paths/0/reason"


@pytest.fixture
def base(tmp_path, monkeypatch):
    """A configuration whose project_name the file wrote as ``${ASH_PN}``."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_PN", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(
        "project_name: ${ASH_PN}\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: vendored/**\n"
        "      reason: vendored\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(path)
    assert config.project_name == CANARY
    return config


def _outcome(base, op):
    """The refusal's rule, or None when the op applied."""
    try:
        apply_runtime_patch(base, [op], allowlist=ALLOWLIST)
    except RuntimePatchDeniedError as refused:
        return refused.rule
    return None


@pytest.mark.parametrize("name", ["copy", "move"])
def test_a_copy_or_move_is_refused_by_the_op_rule_alone(base, monkeypatch, name):
    """With the reference check off, the op rule still refuses the op."""
    monkeypatch.setattr(
        runtime_patch._ReferencesThroughPatch, "settle", lambda self: None
    )
    op = {"op": name, "from": "/project_name", "path": ELSEWHERE}
    rule = _outcome(base, op)
    assert rule is not None, f"the {name} applied"
    assert "forbidden (move/copy)" in rule, rule


@pytest.mark.parametrize("name", ["copy", "move"])
def test_a_copy_or_move_is_refused_by_the_reference_check_alone(
    base, monkeypatch, name
):
    """With the op rule off, the value the op takes away from its reference is
    refused."""
    monkeypatch.setattr(runtime_patch, "_FORBIDDEN_OPS", frozenset())
    op = {"op": name, "from": "/project_name", "path": ELSEWHERE}
    assert _outcome(base, op) == MOVED_WITHOUT_ITS_REFERENCE


def test_a_test_op_inside_the_text_is_refused_by_the_into_text_rule_alone(
    base, monkeypatch
):
    """With the as-written comparison off, a test op inside the text is still
    refused, for the right first character as for any other."""
    monkeypatch.setattr(
        runtime_patch, "_as_written", lambda base, rewrites, document: document
    )
    right = _outcome(
        base, {"op": "test", "path": "/project_name/0", "value": CANARY[0]}
    )
    assert right == INTO_TEXT_REFUSAL, right


def test_a_test_op_inside_the_text_compares_with_the_reference_alone(base, monkeypatch):
    """With the into-text rule off, a test op inside the text compares with the
    reference's characters: the value's first character fails as any other
    does."""
    monkeypatch.setattr(runtime_patch, "_goes_into_text", lambda path, document: False)

    def first(character):
        return _outcome(
            base, {"op": "test", "path": "/project_name/0", "value": character}
        )

    right, wrong = first(CANARY[0]), first("#")
    assert right == wrong, (right, wrong)
    # The control: a comparison is reached, and the reference's own first
    # character passes it.
    assert first("$") is None, "no comparison took place"


def test_the_typeerror_catch_holds_if_the_into_text_rule_is_bypassed(base, monkeypatch):
    """The TypeError catch is defense in depth: no patch reaches it through the API
    today. jsonpatch raises TypeError only for an item deleted from a string or
    another immutable sequence, a configuration's dump holds no such sequence but
    strings, and the into-text rule refuses every path into a string first. With
    that rule bypassed, the TypeError a remove inside a string raises is a refusal
    too, not an error."""
    monkeypatch.setattr(runtime_patch, "_goes_into_text", lambda path, document: False)
    rule = _outcome(base, {"op": "remove", "path": "/project_name/0"})
    assert rule == "patch apply failed: TypeError", rule
