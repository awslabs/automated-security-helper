# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""PluginContext works in a process that has not imported config.ash_config.

Why this file exists
--------------------
``PluginContext.config`` is annotated with the string "AshConfig", so the model is
incomplete until something resolves that reference against the real class. Were
only the last lines of ``config/ash_config.py`` to do that
(``PluginContext.model_rebuild()``), the model would work only in a process that
had imported that module. Importing ``models.asharp_model`` does not import it as
a side effect (such an import loads every built-in plugin group from inside a
half-imported module), so a process that imported the models and then built a
context would fail: ``PluginContext(...)`` would raise PydanticUserError
("`PluginContext` is not fully defined; you should define `AshConfig`"), the
failure test_model_cleanup.py's work_dir tests would hit when they run first in
a worker.

PluginContext resolves the reference on first use, the way
AshAggregatedResults does: construction, ``model_validate``,
``model_validate_json``, ``model_rebuild`` and ``model_json_schema``.

What the test does
------------------
Each use is tried in a fresh interpreter that imported one module first, because
the defect depends on what the process imported. The interpreter checks the
premise, that ``config.ash_config`` was not imported, so the test cannot pass
because something else resolved the reference.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - a fresh interpreter is the property under test
import sys

import pytest

from tests.utils.helpers import importing_this_checkout

DRIVER = """
import importlib, json, sys, tempfile
from pathlib import Path

importlib.import_module(sys.argv[1])
from automated_security_helper.base.plugin_context import PluginContext

outcome = {"premise": "automated_security_helper.config.ash_config" not in sys.modules}
work = Path(tempfile.mkdtemp())
data = {
    "source_dir": str(work),
    "output_dir": str(work / "out"),
    "config": {"project_name": "first-use"},
}
uses = {
    "construct": lambda: PluginContext(**data),
    "model_validate": lambda: PluginContext.model_validate(data),
    "model_validate_json": lambda: PluginContext.model_validate_json(json.dumps(data)),
    "model_json_schema": lambda: PluginContext.model_json_schema(),
    "model_rebuild": lambda: PluginContext.model_rebuild(),
}
try:
    result = uses[sys.argv[2]]()
    if isinstance(result, PluginContext):
        assert type(result.config).__name__ == "AshConfig", type(result.config)
    outcome["result"] = "ok"
except Exception as exc:
    outcome["result"] = f"{type(exc).__name__}: {exc}"[:400]
print(json.dumps(outcome))
"""

FIRST_IMPORTS = [
    "automated_security_helper.models.asharp_model",
    "automated_security_helper.base.plugin_context",
]
USES = [
    "construct",
    "model_validate",
    "model_validate_json",
    "model_json_schema",
    "model_rebuild",
]


@pytest.mark.parametrize("use", USES)
@pytest.mark.parametrize("first", FIRST_IMPORTS)
def test_the_context_works_before_config_is_imported(first, use, tmp_path):
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [sys.executable, "-I", "-c", importing_this_checkout(DRIVER), first, use],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr[-3000:]
    outcome = json.loads(completed.stdout.strip().splitlines()[-1])

    assert outcome["premise"], (
        f"importing {first} imported config.ash_config, so this test cannot tell "
        "whether PluginContext resolves the reference itself"
    )
    assert outcome["result"] == "ok", outcome["result"]
