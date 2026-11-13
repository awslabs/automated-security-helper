# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``utils.error_text`` imports no other module's private name.

Every timeout message prints its limit through ``error_text``
(``timeout_limit_token``), which asks the config validator whether an
environment value's text types to the limit. A private name is its module's
to change without notice, so what ``error_text`` imports from another module
is that module's public name.
"""

import ast
from pathlib import Path

import pytest

import automated_security_helper.utils.error_text as error_text

pytestmark = pytest.mark.unit


def test_error_text_imports_no_private_name_from_another_module():
    tree = ast.parse(Path(error_text.__file__).read_text(encoding="utf-8"))
    imports = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    # The control: the walk reaches the import made inside a function body.
    assert "automated_security_helper.config.config_validator" in [
        node.module for node in imports
    ], [node.module for node in imports]
    private = [
        f"{node.module}.{alias.name}"
        for node in imports
        for alias in node.names
        if alias.name.startswith("_") and not alias.name.startswith("__")
    ]
    assert private == [], private
