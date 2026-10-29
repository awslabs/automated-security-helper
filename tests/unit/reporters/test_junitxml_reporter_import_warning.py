# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Building the JUnit XML reporter emits no warning.

``JunitXmlReporter.model_post_init`` calls ``defusedxml.defuse_stdlib()``, whose
first call in a process imports ``defusedxml.cElementTree``, which issues a
DeprecationWarning. The reporter wrapped the call in ``warnings.catch_warnings()``,
which only saves and restores the filters, so the warning went out. Under pytest's
live logging, a warning emitted inside a ``CliRunner`` invocation suspends the
output capture and drops the runner's stream, so the first ``ash report`` in a
process failed with "I/O operation on closed file".

The reporter is built in a fresh interpreter, because only the first import of
``defusedxml.cElementTree`` in a process warns, and removing it from
``sys.modules`` in this one is not a fresh import: the package keeps the
submodule as an attribute, so ``defuse_stdlib`` finds the module without
importing it and then fails looking it up in ``sys.modules``.
"""

import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration

#: Imports everything first, so only what building the reporter does is recorded.
_BUILD_THE_REPORTER = r"""
import json, sys, warnings
from pathlib import Path
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
    JunitXmlReporter,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()
root = Path(sys.argv[1])
context = PluginContext(
    source_dir=root / "src",
    output_dir=root / "out",
    work_dir=root / "work",
    config=AshConfig(),
)
imported_before = "defusedxml.cElementTree" in sys.modules
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    JunitXmlReporter(context=context)
print(json.dumps({
    "imported_before": imported_before,
    "imported_after": "defusedxml.cElementTree" in sys.modules,
    "deprecations": [
        str(warning.message)
        for warning in caught
        if issubclass(warning.category, DeprecationWarning)
    ],
}))
"""


def test_building_the_reporter_issues_no_deprecation_warning(tmp_path):
    completed = subprocess.run(
        [sys.executable, "-c", _BUILD_THE_REPORTER, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=tmp_path,
    )

    assert completed.returncode == 0, completed.stderr
    outcome = json.loads(completed.stdout.strip().splitlines()[-1])
    # The build is what first imports the module, so the warning path was taken.
    assert outcome["imported_before"] is False
    assert outcome["imported_after"] is True
    assert outcome["deprecations"] == []
