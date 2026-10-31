# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A named operator config whose text does not parse is refused naming itself.

``_load_operator_config`` reads the trusted base through the chain walk, which
reads the root file raw: a YAML parse error came out as the parser raised it,
with no refusal naming the file. A caller that frames load failures with the
one path it holds (the MCP tools hold the client's delivered file) then blamed
that file for the operator's copy that would not parse. The refusal is now an
``ASHConfigUnparsedError`` in ``unparsed_config_reason``'s words: it names the
trusted file, says what failed and where, and quotes nothing of the text.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import _load_operator_config
from automated_security_helper.core.exceptions import ASHConfigUnparsedError

pytestmark = pytest.mark.unit

UNPARSED = "project_name: [unclosed\n"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo


def _named(tmp_path: Path, text: str) -> Path:
    operator_dir = tmp_path / "ops"
    operator_dir.mkdir(parents=True)
    named = operator_dir / "ash.yaml"
    named.write_text(text, encoding="utf-8")
    return named


def test_an_unparsed_operator_config_is_refused_naming_itself(
    tmp_path: Path,
) -> None:
    named = _named(tmp_path, UNPARSED)

    with pytest.raises(ASHConfigUnparsedError) as raised:
        _load_operator_config(named, source_dir=_repo(tmp_path), permit_base=None)

    text = str(raised.value)
    assert text.startswith(named.as_posix()), text
    assert "could not be parsed (ParserError at line" in text, text
    # Nothing of the file's text, and no parser error as the refusal's context.
    assert "unclosed" not in text
    assert raised.value.__context__ is None


def test_control_a_parsed_operator_config_still_loads(tmp_path: Path) -> None:
    named = _named(tmp_path, "project_name: operator\n")

    operator = _load_operator_config(
        named, source_dir=_repo(tmp_path), permit_base=None
    )

    assert operator is not None
    assert operator.config.project_name == "operator"
    assert operator.named[0] == named
