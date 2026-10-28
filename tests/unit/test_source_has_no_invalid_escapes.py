# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No module of the package compiles with an invalid escape sequence.

``"``.\\``"`` in a non-raw docstring is a SyntaxWarning on Python 3.12 and later
(a DeprecationWarning before), printed by every import, and the language has
said it will become a SyntaxError. Ruff's W605 is not in the repository's
selected rules, so nothing else reports it. One slipped into
``utils/workspace_paths.py``'s module docstring.
"""

import warnings
from pathlib import Path

import automated_security_helper

PACKAGE = Path(automated_security_helper.__file__).resolve().parent


def test_every_module_compiles_without_a_warning():
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except (SyntaxError, SyntaxWarning, DeprecationWarning) as error:
                offenders.append(f"{path.relative_to(PACKAGE)}: {error}")
    assert not offenders, "\n".join(offenders)
