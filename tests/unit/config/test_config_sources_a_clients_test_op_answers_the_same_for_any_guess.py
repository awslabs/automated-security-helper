# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``test`` op in a config file an MCP client chose answers the same for any
guess.

A ``patch`` test op compares a place of the configuration with the value it
gives, and the file loads only when they are equal. A client's file that
extends the operator's config could so learn whether a value it may not read
was the one it guessed: a wrong guess was refused as a failed test, naming the
place, and a right one loaded. Every test op of a file the chain's rule refuses
for itself (``refuse_env``, the rule that keeps a client's file from the
environment) is now refused before any operation applies, in one text.

Red at the base: the right guess loaded, so the two answers differed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import resolve_config_document
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit

OPERATOR_VALUE = "operator-only-name"


def _clients_file(path: Path) -> bool:
    """The rule a caller passes: only the client's own file is refused."""
    return Path(path).name == "client.yaml"


def _chain(tmp_path: Path, guess: str) -> Path:
    (tmp_path / "operator.yaml").write_text(
        f"project_name: {OPERATOR_VALUE}\n", encoding="utf-8"
    )
    client = tmp_path / "client.yaml"
    client.write_text(
        "extends: operator.yaml\n"
        "patch:\n"
        "  - op: test\n"
        "    path: /project_name\n"
        f"    value: {guess}\n",
        encoding="utf-8",
    )
    return client


def _refusal(path: Path, refuse_env=_clients_file) -> str:
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(path, refuse_env=refuse_env)
    return str(refused.value)


def test_a_right_and_a_wrong_guess_get_the_same_refusal(tmp_path: Path) -> None:
    # The same files, rewritten with the other guess, so the two refusals
    # name the same paths.
    right = _refusal(_chain(tmp_path, OPERATOR_VALUE))
    wrong = _refusal(_chain(tmp_path, "a-wrong-guess"))

    assert right == wrong, (right, wrong)
    assert "is a test op" in right, right
    assert "does not equal" not in wrong, wrong


def test_the_operators_own_test_op_still_applies(tmp_path: Path) -> None:
    """The control for the scope: a base the client's file extends is refused
    with it for the environment, but its own test op is the operator's, and it
    still applies."""
    (tmp_path / "operator.yaml").write_text(
        f"project_name: {OPERATOR_VALUE}\n"
        "patch:\n"
        "  - op: test\n"
        "    path: /project_name\n"
        f"    value: {OPERATOR_VALUE}\n",
        encoding="utf-8",
    )
    client = tmp_path / "client.yaml"
    client.write_text("extends: operator.yaml\nscan_label: client\n", encoding="utf-8")

    document = resolve_config_document(client, refuse_env=_clients_file)

    assert document.data["project_name"] == OPERATOR_VALUE


def test_a_file_no_rule_refuses_keeps_its_test_op(tmp_path: Path) -> None:
    """The control for the premise: outside the rule the test op compares,
    so a right guess loads and a wrong one is refused as a failed test."""
    loaded = resolve_config_document(
        _chain(tmp_path, OPERATOR_VALUE), refuse_env=lambda path: False
    )
    assert loaded.data["project_name"] == OPERATOR_VALUE

    wrong = _refusal(_chain(tmp_path, "a-wrong-guess"), refuse_env=lambda path: False)
    assert "does not equal" in wrong, wrong
