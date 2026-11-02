# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for the unit tests of the repository's verification scripts.

The scripts under ``scripts/`` are not a package, so a test loads one by path,
the way ``tests/integration/docs/docs_runner.py`` loads ``docs_checks.py``. Each
script is loaded once per session and registered under a private module name,
so two tests of one script share the module and a script that imports another
by name is not shadowed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = REPO_ROOT / "scripts"


def load_script(name: str) -> ModuleType:
    """Load ``scripts/<name>.py`` as a module, once per session."""
    module_name = f"_ash_script_{name}"
    cached = sys.modules.get(module_name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(
        module_name, SCRIPTS_DIR / f"{name}.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        # A script that fails to load (a missing optional dependency, a
        # SyntaxError mid-edit) must not stay cached half-built: every later
        # test of it would get the broken module back and fail with a
        # misleading AttributeError instead of the real error.
        sys.modules.pop(module_name, None)
        raise
    return module


@pytest.fixture(scope="session")
def script_loader() -> Callable[[str], ModuleType]:
    return load_script
