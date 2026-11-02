# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An integer 1 and a float 1.0 stay different in the written CycloneDX text.

``Method.confidence`` and ``ComponentIdentityEvidence.confidence`` are a union
of a bounded int and a bounded float, so a BOM that wrote ``1`` is read as the
int and one that wrote ``1.0`` as the float. The model tests pin that at load
and dump; this file pins it through the two writers that turn a stored BOM into
a document, ``cyclonedx`` and ``gitlab-cyclonedx``, because a writer that
copied or rebuilt the BOM could turn one into the other on the way out.
"""

import json
import re

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
    serialize_bom,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    GitLabCycloneDXReporter,
    GitLabCycloneDXReporterConfig,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()

#: ``"confidence":`` followed by its number as written in the JSON text.
_WRITTEN = re.compile(r'"confidence":([0-9][0-9.]*)')


def _bom(value) -> CycloneDXReport:
    """One component whose identity evidence and one method both carry ``value``."""
    method = {"technique": "manifest-analysis", "confidence": value}
    return CycloneDXReport.model_validate(
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
                    "evidence": {
                        "identity": [
                            {
                                "field": "purl",
                                "confidence": value,
                                "methods": [method],
                            }
                        ]
                    },
                }
            ],
        }
    )


def _cyclonedx_text(value) -> str:
    return serialize_bom(_bom(value))


def _gitlab_text(tmp_path, value) -> str:
    model = AshAggregatedResults()
    model.cyclonedx = _bom(value)
    ctx = PluginContext(source_dir=tmp_path, output_dir=tmp_path)
    reporter = GitLabCycloneDXReporter(
        context=ctx, config=GitLabCycloneDXReporterConfig()
    )
    return reporter.report(model)


@pytest.mark.parametrize(
    "value, written",
    [(1, ["1", "1"]), (1.0, ["1.0", "1.0"]), (0.85, ["0.85", "0.85"])],
    ids=["int", "float", "fraction"],
)
def test_the_cyclonedx_reporter_writes_each_confidence_as_the_bom_wrote_it(
    value, written
):
    text = _cyclonedx_text(value)
    assert _WRITTEN.findall(text) == written, text


@pytest.mark.parametrize(
    "value, written",
    [(1, ["1", "1"]), (1.0, ["1.0", "1.0"]), (0.85, ["0.85", "0.85"])],
    ids=["int", "float", "fraction"],
)
def test_the_gitlab_reporter_writes_each_confidence_as_the_bom_wrote_it(
    tmp_path, value, written
):
    text = _gitlab_text(tmp_path, value)
    assert _WRITTEN.findall(text) == written, text


def test_control_the_two_writers_agree_with_each_other_on_the_written_text(tmp_path):
    """Both documents are valid JSON that carries the numbers at the same places;
    the int and the float differ only by the text of the number."""
    for value in (1, 1.0):
        cyclonedx = json.loads(_cyclonedx_text(value))
        gitlab = json.loads(_gitlab_text(tmp_path, value))
        for doc in (cyclonedx, gitlab):
            identity = doc["components"][0]["evidence"]["identity"][0]
            assert type(identity["confidence"]) is type(value)
            assert type(identity["methods"][0]["confidence"]) is type(value)
