"""Load scripts/_ci_matrix.py by path, for the tests that read a workflow's matrices.

scripts/ is not a package, so a test loads the reader by its path. A module that raises
while it loads must not stay in sys.modules: the next test to ask for it would be handed
the half-initialized module and fail on a name it lacks, and that failure would hide the
error that broke the load.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Where the reader lives, and the one name the test modules load it under, so that they
#: share one module.
CI_MATRIX_PATH = REPO_ROOT / "scripts" / "_ci_matrix.py"
CI_MATRIX_NAME = "_ash_ci_matrix"


def load_by_path(name: str, path: Path) -> ModuleType:
    """The module at ``path``, registered in sys.modules as ``name`` and loaded once.

    It is registered before it runs, so the dataclasses it defines can resolve their
    annotations, and removed again if it raises, so a failed load is not remembered.
    """
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    return module


def load_ci_matrix() -> ModuleType:
    """scripts/_ci_matrix.py, the one reader of the workflow matrices."""
    return load_by_path(CI_MATRIX_NAME, CI_MATRIX_PATH)
