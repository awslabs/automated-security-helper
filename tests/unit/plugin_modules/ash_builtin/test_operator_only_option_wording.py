# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The new scanners' operator-only options state the repository-written rule.

A config is limited when any file it was built from is inside any git checkout or
inside the scanned directory, or an MCP client delivered it
(``utils/config_trust.repository_written``). "A config file outside the scanned
tree" says less: a config kept in an ops checkout outside the scanned tree is
limited too, so an operator told that would set a value there and see it ignored.
The option descriptions (in the schema and ``ash config``'s help) and the warnings
the scanners log say "outside every git checkout and the scanned directory".

A path an option names is still judged against the scanned tree, so "a file outside
the scanned tree" is not what this looks for.
"""

from __future__ import annotations

import ast
import inspect
import re
from types import ModuleType
from typing import List

import pytest
from pydantic import BaseModel

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base,
    actionlint_scanner,
    cfn_guard_scanner,
    cfn_lint_scanner,
    gitleaks_scanner,
    trivy_scanner,
    zizmor_scanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins import (
    trivy_repo_scanner,
)
from automated_security_helper.utils import config_trust

pytestmark = pytest.mark.unit

#: The narrower rule, as a config's place.
NARROWER = re.compile(r"config files? outside the (scanned )?tree")

MODELS = [
    actionlint_scanner.ActionlintScannerConfigOptions,
    cfn_guard_scanner.CfnGuardScannerConfigOptions,
    cfn_lint_scanner.CfnLintScannerConfigOptions,
    gitleaks_scanner.GitleaksScannerConfigOptions,
    trivy_scanner.TrivyScannerConfigOptions,
    trivy_repo_scanner.TrivyRepoScannerConfigOptions,
    zizmor_scanner.ZizmorScannerConfigOptions,
]

MODULES = [
    _trivy_scanner_base,
    actionlint_scanner,
    cfn_guard_scanner,
    cfn_lint_scanner,
    gitleaks_scanner,
    trivy_scanner,
    trivy_repo_scanner,
    zizmor_scanner,
    config_trust,
]


def _strings(module: ModuleType) -> List[str]:
    """Every string literal in the module, adjacent literals joined, spaces collapsed.

    The parser joins implicitly concatenated literals into one constant, so a
    sentence split over several source lines is read whole; an f-string's
    literal parts are read one by one.
    """
    found = []
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append(" ".join(node.value.split()))
    return found


def test_control_the_check_finds_the_narrower_rule():
    assert NARROWER.search(
        "set by --config-overrides or a config file outside the tree"
    )
    assert NARROWER.search("a config file outside the scanned tree; otherwise")
    assert not NARROWER.search(
        "a config file outside every git checkout and the scanned directory"
    )
    assert not NARROWER.search("for a file outside the scanned tree")


@pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
def test_no_option_description_states_the_narrower_rule(model: type[BaseModel]):
    stale = sorted(
        name
        for name, field in model.model_fields.items()
        if NARROWER.search(" ".join((field.description or "").split()))
    )
    assert stale == [], f"{model.__name__}: {stale}"


@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.__name__)
def test_no_warning_or_docstring_states_the_narrower_rule(module: ModuleType):
    stale = [text for text in _strings(module) if NARROWER.search(text)]
    assert stale == [], stale
