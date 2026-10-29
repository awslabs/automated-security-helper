# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's reports name the project its configuration names.

Why this exists
---------------
``AshConfig.project_name`` names the results of a single-directory scan, so a
project configured as ``payments-api`` is "Project: payments-api" in the HTML,
Markdown and text reports, ``"project": "payments-api"`` in ``ash.flat.json``, the
``metadata.project_name`` of the aggregated results and the name of the SPDX
document's root package, as ``ash config get project_name`` says, and not the
results model's placeholder ``"ASH"``.

The engine names the results after the resolved configuration's
``project_name``: the config file's value, a ``--config-overrides`` value,
``ASH_PROJECT_NAME``, or the field's default (``ash-scan``) when nothing names
the project. A workspace project's display label replaces it.
``"ASH"`` remains only for results built without any configuration.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.orchestrator import ASHScanOrchestrator


def _orchestrator(tmp_path: Path, config_yaml=None, **kwargs) -> ASHScanOrchestrator:
    source = tmp_path / "src"
    source.mkdir(parents=True, exist_ok=True)
    if config_yaml is not None:
        config_path = tmp_path / "ash.yaml"
        config_path.write_text(config_yaml, encoding="utf-8")
        kwargs["config_path"] = config_path
    return ASHScanOrchestrator.create(
        source_dir=source, output_dir=tmp_path / "out", **kwargs
    )


def _project(orchestrator: ASHScanOrchestrator) -> str:
    return orchestrator.execution_engine._asharp_model.metadata.project_name


def test_the_config_files_project_name_names_the_results(tmp_path):
    orchestrator = _orchestrator(tmp_path, "project_name: payments-api\n")

    assert _project(orchestrator) == "payments-api"


def test_a_config_override_names_the_results(tmp_path):
    orchestrator = _orchestrator(
        tmp_path,
        "project_name: payments-api\n",
        config_overrides=["project_name=payments-api-canary"],
    )

    assert _project(orchestrator) == "payments-api-canary"


def test_with_no_project_name_the_results_carry_the_configs_default(tmp_path):
    orchestrator = _orchestrator(tmp_path, "fail_on_findings: true\n")

    assert _project(orchestrator) == AshConfig.model_fields["project_name"].default
    assert _project(orchestrator) == orchestrator.config.project_name


def test_a_workspace_label_wins(tmp_path):
    orchestrator = _orchestrator(
        tmp_path,
        "project_name: payments-api\n",
        metadata={"project_name": "Payments API"},
    )

    assert _project(orchestrator) == "Payments API"


def test_results_built_without_a_config_keep_the_placeholder():
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    assert AshAggregatedResults().metadata.project_name == "ASH"


@pytest.fixture
def named_model(tmp_path):
    model = _orchestrator(
        tmp_path, "project_name: payments-api\n"
    ).execution_engine._asharp_model
    return model


def _render(module: str, cls: str, tmp_path, model) -> str:
    import importlib

    reporter_module = importlib.import_module(
        f"automated_security_helper.plugin_modules.ash_builtin.reporters.{module}"
    )
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "rendered", config=model.ash_config
    )
    return getattr(reporter_module, cls)(context=context).report(model)


@pytest.mark.parametrize(
    "module, cls",
    [
        ("markdown_reporter", "MarkdownReporter"),
        ("text_reporter", "TextReporter"),
        ("html_reporter", "HtmlReporter"),
    ],
)
def test_the_human_readable_reports_print_it(named_model, tmp_path, module, cls):
    page = _render(module, cls, tmp_path, named_model)

    assert "payments-api" in page
    assert "Project:</strong> ASH<" not in page
    assert "Project: ASH\n" not in page


def test_flat_json_records_it(named_model, tmp_path):
    report = json.loads(
        _render("flatjson_reporter", "FlatJSONReporter", tmp_path, named_model)
    )

    assert report["metadata"]["project"] == "payments-api"


def test_the_aggregated_results_record_it(named_model):
    saved = json.loads(named_model.model_dump_json(by_alias=True))

    assert saved["metadata"]["project_name"] == "payments-api"


def test_the_spdx_root_package_is_named_after_it(named_model, tmp_path):
    document = json.loads(
        _render("spdx_reporter", "SpdxReporter", tmp_path, named_model)
    )

    assert document["name"] == "payments-api ASH SBOM"
    assert "payments-api" in {package["name"] for package in document["packages"]}
