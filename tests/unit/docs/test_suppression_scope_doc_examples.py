# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scope examples in the suppressions concept page parse as written.

Docs that show YAML a reader will paste must validate against the models that
read it; a drifted example teaches a refused config.
"""

from pathlib import Path

import pytest
import yaml

from automated_security_helper.models.core import AshSuppression

pytestmark = pytest.mark.unit

DOC = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "content"
    / "concepts"
    / "suppressions.md"
)


def _yaml_fences(text: str):
    fences = []
    inside = False
    lines: list = []
    for line in text.splitlines():
        if line.strip() == "```yaml":
            inside = True
            lines = []
        elif line.strip() == "```" and inside:
            inside = False
            fences.append("\n".join(lines))
        elif inside:
            lines.append(line)
    return fences


def test_the_scope_examples_validate():
    text = DOC.read_text(encoding="utf-8")
    fences = [f for f in _yaml_fences(text) if "scope:" in f]
    assert fences, "the scope section lost its YAML examples"
    # The first fence is a complete config fragment; the engines fence is an
    # indented continuation of a suppression entry, completed here.
    full = yaml.safe_load(fences[0])
    entry = full["global_settings"]["suppressions"][0]
    suppression = AshSuppression.model_validate(entry)
    assert suppression.scope is not None
    assert suppression.scope.resource_id
    for fence in fences[1:]:
        fragment = yaml.safe_load("rule_id: R\npath: a\nreason: r\n" + fence)
        AshSuppression.model_validate(fragment)
