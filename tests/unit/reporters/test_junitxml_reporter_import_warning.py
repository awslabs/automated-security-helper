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
"""

import sys
import warnings


def test_building_the_reporter_issues_no_deprecation_warning(monkeypatch, tmp_path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
        JunitXmlReporter,
    )

    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=AshConfig(),
    )
    # As in a fresh process: defuse_stdlib imports the module again.
    monkeypatch.delitem(sys.modules, "defusedxml.cElementTree", raising=False)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        JunitXmlReporter(context=context)

    assert [
        str(warning.message)
        for warning in caught
        if issubclass(warning.category, DeprecationWarning)
    ] == []
