# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""gitlab-cyclonedx writes only the license lists CycloneDX 1.6 allows.

A stored results file can hold a license entry that is neither a license object
nor an SPDX expression, such as a bare ``"MIT"``: the model keeps it as written
on load so one entry does not refuse the component that carries it. The
``cyclonedx`` reporter reduces every license list before it writes. This
reporter dumped the stored model as it was, so the artifact GitLab validates
against the CycloneDX schema repeated the entry and was refused.
"""

import json
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    GitLabCycloneDXReporter,
    GitLabCycloneDXReporterConfig,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()

LOGGER = "automated_security_helper.utils.log.ASH_LOGGER"


def _model_with_licenses(licenses: list) -> AshAggregatedResults:
    model = AshAggregatedResults()
    with patch(LOGGER):
        model.cyclonedx = CycloneDXReport.model_validate(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"timestamp": "2026-10-29T00:00:00Z"},
                "components": [
                    {
                        "type": "library",
                        "name": "lodash",
                        "version": "4.17.21",
                        "purl": "pkg:npm/lodash@4.17.21",
                        "licenses": licenses,
                    }
                ],
            }
        )
    return model


def _report(tmp_path, model: AshAggregatedResults) -> dict:
    ctx = PluginContext(source_dir=tmp_path, output_dir=tmp_path)
    reporter = GitLabCycloneDXReporter(
        context=ctx, config=GitLabCycloneDXReporterConfig()
    )
    return json.loads(reporter.report(model))


def test_a_bare_license_id_is_written_as_an_spdx_expression(tmp_path):
    model = _model_with_licenses(["MIT"])

    with patch(LOGGER):
        doc = _report(tmp_path, model)

    assert doc["components"][0]["licenses"] == [{"expression": "MIT"}]


def test_an_entry_that_is_neither_form_is_left_out_and_one_warning_counts_both(
    tmp_path,
):
    entries = [
        "MIT",
        {"license": {"id": "Apache-2.0"}},
        7,
        {"license": {}},
    ]
    model = _model_with_licenses(entries)

    with patch(LOGGER) as logger:
        doc = _report(tmp_path, model)

    assert doc["components"][0]["licenses"] == [
        {"expression": "MIT"},
        {"license": {"id": "Apache-2.0"}},
    ]
    assert logger.warning.call_count == 1
    message = logger.warning.call_args.args[0]
    assert "1 bare license id(s) were written as SPDX expressions" in message
    assert "2 other entry(ies) were left out" in message


def test_the_stored_bom_is_left_as_it_was(tmp_path):
    model = _model_with_licenses(["MIT", {"license": {}}])

    with patch(LOGGER):
        _report(tmp_path, model)

    stored = model.cyclonedx.components[0].licenses.root
    assert stored[0] == "MIT" and stored[1] == {"license": {}}


def test_control_a_conforming_license_list_is_written_as_stored_without_a_warning(
    tmp_path,
):
    entries = [
        {"license": {"id": "MIT"}},
        {"expression": "MIT OR Apache-2.0", "bom-ref": "lic-1"},
    ]
    model = _model_with_licenses(entries)

    with patch(LOGGER) as logger:
        doc = _report(tmp_path, model)

    assert doc["components"][0]["licenses"] == entries
    logger.warning.assert_not_called()
