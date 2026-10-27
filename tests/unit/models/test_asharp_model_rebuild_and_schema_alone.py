# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""AshAggregatedResults.model_rebuild() and model_json_schema() work on first use.

The defect
----------
``models.asharp_model`` stopped importing ``config.ash_config`` while it is being
imported (the import pulled in every built-in plugin group while the importing
module was still half-initialized). The model's ``ash_config`` field is annotated
with the string "AshConfig", so the model is incomplete until something resolves
that reference. ``__init__``, ``model_validate`` and ``model_validate_json`` resolve
it first; ``model_rebuild`` and ``model_json_schema`` did not. In a process that had
imported only the model, ``model_json_schema()`` raised PydanticUserError and
``model_rebuild()`` raised PydanticUndefinedAnnotation for AshConfig, where the base
did both. test_github_ghas_reporter.py calls ``model_rebuild()`` at import, so run
on its own it failed to collect.

What the test does
------------------
Each method is called in a fresh interpreter that has imported only the model,
because the defect depends on what the process imported first. The interpreter
checks the premise, that importing the model did not import ``config.ash_config``,
so the test cannot pass because something else resolved the reference.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - a fresh interpreter is the property under test
import sys

import pytest

from tests.utils.helpers import importing_this_checkout

DRIVER = """
import json, sys
from automated_security_helper.models.asharp_model import AshAggregatedResults
outcome = {"premise": "automated_security_helper.config.ash_config" not in sys.modules}
try:
    getattr(AshAggregatedResults, sys.argv[1])()
    outcome["result"] = "ok"
except Exception as exc:
    outcome["result"] = f"{type(exc).__name__}: {exc}"[:400]
print(json.dumps(outcome))
"""


@pytest.mark.parametrize("method", ["model_json_schema", "model_rebuild"])
def test_the_method_works_when_only_the_model_was_imported(method):
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [sys.executable, "-I", "-c", importing_this_checkout(DRIVER), method],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-3000:]
    outcome = json.loads(completed.stdout.strip().splitlines()[-1])

    assert outcome["premise"], (
        "importing the model imported config.ash_config, so this test cannot tell "
        "whether the method resolves the reference itself"
    )
    assert outcome["result"] == "ok", outcome["result"]
