# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A document whose anchors multiply past the expansion bound is refused.

A file a few hundred bytes long can demand a number of containers exponential
in its depth: each level of a stack of anchored mappings multiplies the copies
of the level below. ASH's config loader refuses every YAML alias while it
composes the document (``_NoAliasSafeLoader``, ``load_config_yaml``), so the
refusal comes at the first alias, before anything is expanded and before an
expansion budget (``refuse_past_expansion_bound``) is charged. The file is
refused as a source error that gives the error's type and where the parser
stopped, and quotes nothing of the file, so the cost of a hostile file is the
read, never its product.

The budgets are still charged by the readers that answer a document as written
(``get_config(raw=True)``); ``tests/unit/cli/mcp/
test_get_config_raw_expansion_bound.py`` pins them there. The other side, that
every alias is refused wherever the config chain reads YAML, is pinned by
``test_yaml_aliases_are_refused.py`` and
``test_a_yaml_alias_never_makes_a_config_unloadable.py``.
"""

import sys
from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import _unaliased
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigUnparsedError,
)
from tests.utils.helpers import mark_git_checkout


def _bomb_text() -> str:
    """A small document that expands to well over the bound: nine aliases
    of the level below at each of six levels on top of a leaf mapping."""
    lines = ["project_name: bounded", "a0: &a0 {leaf: 1}"]
    for level in range(1, 7):
        refs = ", ".join(f"k{j}: *a{level - 1}" for j in range(9))
        lines.append(f"a{level}: &a{level} {{{refs}}}")
    return "\n".join(lines) + "\n"


def test_a_document_past_the_expansion_bound_is_refused(tmp_path, monkeypatch):
    src = tmp_path / "src"
    mark_git_checkout(src)
    config = tmp_path / "ash.yaml"
    config.write_text(_bomb_text(), encoding="utf-8")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(src)

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(config_path=config, source_dir=src, trusted_config_path=config)

    said = str(refused.value)
    # The parser's refusal at the first alias, in the shared words: its type
    # and place, with no text of the file (not an anchor's name, not a value).
    assert "could not be parsed (ComposerError at line " in said, said
    assert "*a" not in said and "leaf" not in said, said


def _nested_lists(depth: int) -> list:
    """A list nested ``depth`` levels deep, built without recursion."""
    document: list = []
    innermost = document
    for _ in range(depth):
        deeper: list = []
        innermost.append(deeper)
        innermost = deeper
    return document


def test_a_parsed_document_nested_past_the_recursion_limit_is_refused():
    """The rebuild of a parsed document runs out of recursion on a deep one.

    Whether a parser itself recurses out on a deep file depends on the
    interpreter and its parser, so the rebuild that follows a successful parse
    is pinned directly, with a document built in memory: it is refused as an
    unparsed config in the shared words, never raised as a RecursionError.
    """
    depth = sys.getrecursionlimit() + 100
    # Under the expansion bound, so the refusal can only be the recursion's.
    assert depth < 100_000

    with pytest.raises(ASHConfigUnparsedError) as refused:
        _unaliased(_nested_lists(depth), Path("planted/deep.yaml"))

    said = str(refused.value)
    assert said == "planted/deep.yaml could not be parsed (RecursionError)", said


def test_a_shallow_parsed_document_is_rebuilt_unchanged():
    document = {"project_name": "shallow", "items": [1, [2, {"k": "v"}]]}

    rebuilt = _unaliased(document, Path("planted/shallow.yaml"))

    assert rebuilt == document
    assert rebuilt is not document
    assert rebuilt["items"] is not document["items"]
