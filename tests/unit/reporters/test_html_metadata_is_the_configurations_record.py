# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML metadata section prints the configuration's record of the metadata.

The results metadata names the project as ``config.project_name`` and lists the
expected scanners as the keys of ``config.scanners``. Where the configuration's
file read one of those from the environment, every other sink (the results
file, the flat export, the off-host payloads) records the written reference
through ``record_of_metadata``; the HTML report dumped the model raw and
printed the resolved value.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)

pytestmark = pytest.mark.unit

SCANNER_VAR = "ASH_U04_SCANNER_KEY_CANARY"
PROJECT_VAR = "ASH_U04_PROJECT_NAME_CANARY"


def _resolve(tmp_path, monkeypatch, body: str, **env: str):
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "recorded.yaml"
    path.write_text(body, encoding="utf-8")
    return resolve_config(config_path=str(path), fallback_to_default=False)


def _metadata_section(document: str) -> str:
    return document.split("metadata-section", 1)[1]


def test_an_env_read_scanner_key_prints_as_its_reference(
    tmp_path, monkeypatch, test_plugin_context
):
    config = _resolve(
        tmp_path,
        monkeypatch,
        "project_name: zz-recorded\nscanners:\n  ${" + SCANNER_VAR + "}:\n"
        "    enabled: false\n",
        **{SCANNER_VAR: "bandit"},
    )
    model = AshAggregatedResults(ash_config=config)
    model.metadata.expected_scanners = ["bandit"]

    section = _metadata_section(HtmlReporter(context=test_plugin_context).report(model))

    assert "${" + SCANNER_VAR + "}" in section, section[:2000]
    expected = section.split("expected_scanners", 1)[1].split("</div>", 1)[0]
    assert "bandit" not in expected, expected


def _env_named_project(tmp_path, monkeypatch) -> AshAggregatedResults:
    config = _resolve(
        tmp_path,
        monkeypatch,
        "project_name: ${" + PROJECT_VAR + "}\n",
        **{PROJECT_VAR: "zz-secret-project"},
    )
    model = AshAggregatedResults(ash_config=config)
    model.metadata.project_name = "zz-secret-project"
    return model


def test_an_env_read_project_name_prints_as_its_reference(
    tmp_path, monkeypatch, test_plugin_context
):
    """The whole document, not one section of it.

    A first fix recorded the metadata block alone, so the page read the
    reference there and the resolved value in its title and masthead (the
    ``report-title`` heading), which is the value the record exists to keep out
    of the report.
    """
    model = _env_named_project(tmp_path, monkeypatch)

    document = HtmlReporter(context=test_plugin_context).report(model)

    section = _metadata_section(document)
    project = section.split("project_name", 1)[1].split("</div>", 1)[0]
    assert "${" + PROJECT_VAR + "}" in project, project
    assert "zz-secret-project" not in document
    assert '<h1 id="report-title">${' + PROJECT_VAR + "}</h1>" in document


@pytest.mark.parametrize(
    "module, cls",
    [("markdown_reporter", "MarkdownReporter"), ("text_reporter", "TextReporter")],
)
def test_the_markdown_and_text_project_lines_print_the_reference(
    tmp_path, monkeypatch, test_plugin_context, module, cls
):
    """The three human reports read the name from one place; all three record it."""
    import importlib

    reporter_module = importlib.import_module(
        f"automated_security_helper.plugin_modules.ash_builtin.reporters.{module}"
    )
    model = _env_named_project(tmp_path, monkeypatch)

    document = getattr(reporter_module, cls)(context=test_plugin_context).report(model)

    assert "${" + PROJECT_VAR + "}" in document
    assert "zz-secret-project" not in document


def test_a_literal_scanner_key_prints_as_written(
    tmp_path, monkeypatch, test_plugin_context
):
    """The control: a key the file wrote literally is unchanged by the record."""
    config = _resolve(
        tmp_path,
        monkeypatch,
        "project_name: zz-literal\nscanners:\n  bandit:\n    enabled: false\n",
    )
    model = AshAggregatedResults(ash_config=config)
    model.metadata.expected_scanners = ["bandit"]

    section = _metadata_section(HtmlReporter(context=test_plugin_context).report(model))

    assert "bandit" in section.split("expected_scanners", 1)[1].split("</div>", 1)[0]
