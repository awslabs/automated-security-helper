# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The tree pre-check reads the ASH_CONFIG file as the load reads it.

``default_config_document_for_tree`` says it reads the file ``get_default_config``
loads. The load takes a relative path the operator's file names (a scanner's
``config_file``) from that file's own directory. The document read left it
relative, so the pre-check judged a path the scan never uses.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config import default_config

pytestmark = pytest.mark.unit


def _operator_file(tmp_path: Path) -> Path:
    operator = tmp_path / "ops" / "ash.yaml"
    operator.parent.mkdir(parents=True)
    operator.write_text(
        yaml.safe_dump(
            {"scanners": {"bandit": {"options": {"config_file": "bandit.yaml"}}}}
        ),
        encoding="utf-8",
    )
    (operator.parent / "bandit.yaml").write_text("# placeholder\n", encoding="utf-8")
    return operator


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo


def test_a_relative_operator_path_is_taken_from_the_files_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    operator = _operator_file(tmp_path)
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    document = default_config.default_config_document_for_tree(_repo(tmp_path))

    assert document is not None
    written = document.data["scanners"]["bandit"]["options"]["config_file"]
    absolute = Path(written).is_absolute()
    assert absolute, "the document keeps the path relative to nothing"
    same = Path(written).resolve() == (operator.parent / "bandit.yaml").resolve()
    assert same, "the path is not taken from the operator file's directory"


def test_the_file_itself_still_holds_what_it_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the document's own copy of the file is the file's text."""
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    operator = _operator_file(tmp_path)
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    document = default_config.default_config_document_for_tree(_repo(tmp_path))

    assert document is not None
    held = [
        file_document["scanners"]["bandit"]["options"]["config_file"]
        for file_document in document.documents.values()
    ]
    assert held == ["bandit.yaml"]
