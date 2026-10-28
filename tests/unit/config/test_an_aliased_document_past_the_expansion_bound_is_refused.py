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

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigSourceError
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
