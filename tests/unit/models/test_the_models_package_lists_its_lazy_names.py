# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The lazily loaded names of ``automated_security_helper.models`` are discoverable.

The package loads its four public names on first use through a PEP 562
``__getattr__``. Without a ``__dir__`` they are missing from ``dir(models)``
(tab completion, ``inspect``, ``__all__`` consumers), and without ``TYPE_CHECKING``
re-imports a type checker reads each package-level import as ``Any``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import automated_security_helper.models as models

pytestmark = pytest.mark.unit


def test_dir_lists_every_name_in_all():
    assert set(models.__all__) <= set(dir(models))
    assert dir(models) == sorted(dir(models))


def test_the_type_checking_block_reimports_every_lazy_name():
    tree = ast.parse(Path(models.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in tree.body:
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "TYPE_CHECKING"
        ):
            for stmt in node.body:
                if isinstance(stmt, ast.ImportFrom):
                    imported.update(alias.name for alias in stmt.names)
    assert imported == set(models.__all__)
