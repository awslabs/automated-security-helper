# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The command a container's metadata records is copied into the report's scanner
details without any value the configuration read from the environment.

``ScanResultProcessor`` copies ``command_line`` and ``arguments`` from a results
container's metadata into the ``tool_invocation`` scanner details it attaches.
That copy is separate from what the scanner itself recorded, so it hides the
configuration's values on its own. Text that is not one of them is copied whole,
and so are the working directory, exit code and duration.
"""

from unittest.mock import MagicMock

from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.schemas.sarif_schema_model import SarifReport

FROM_ENVIRONMENT = "marker-secret-config-value"
WRITTEN_OUT = "marker-literal-flag-value"


def _scanner_report() -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "tool", "rules": [{"id": "tool-rule"}]}
                    },
                    "results": [
                        {
                            "ruleId": "tool-rule",
                            "level": "warning",
                            "message": {"text": "finding"},
                        }
                    ],
                }
            ],
        }
    )


def _tool_invocation(tmp_path, monkeypatch, marker):
    """The ``tool_invocation`` details the processor attaches for a container whose
    metadata records a command line and arguments holding ``marker``."""
    monkeypatch.setenv("ASH_TEST_PROJECT_NAME", FROM_ENVIRONMENT)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_file = tmp_path / "operator" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: !ENV ${ASH_TEST_PROJECT_NAME}\n", encoding="utf-8"
    )
    _, config = resolve_config_module.load_config_file_for_run(config_file)
    context = MagicMock()
    context.config = config
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.ignore_suppressions = True
    context.source_dir.mkdir()
    container = ScanResultsContainer(
        scanner_name="tool",
        report_type="sarif",
        target=context.source_dir,
        target_type="source",
        raw_results=_scanner_report(),
        metadata={
            "command_line": f"tool --flag {marker}",
            "arguments": ["--flag", marker],
            "working_directory": "work-dir-name",
        },
    )
    processor = ScanResultProcessor(
        plugin_context=context, validation_manager=MagicMock()
    )
    sarif = processor.process_container(container, AshAggregatedResults()).sarif
    return sarif.runs[0].results[0].properties.scanner_details["tool_invocation"]


def test_a_command_in_container_metadata_is_copied_without_env_read_values(
    tmp_path, monkeypatch
):
    details = _tool_invocation(tmp_path, monkeypatch, FROM_ENVIRONMENT)

    assert details["command_line"].startswith("tool --flag ")
    assert FROM_ENVIRONMENT not in details["command_line"]
    assert details["arguments"][0] == "--flag"
    assert FROM_ENVIRONMENT not in details["arguments"]
    assert FROM_ENVIRONMENT not in repr(details)
    assert details["working_directory"] == "work-dir-name"


def test_a_command_in_container_metadata_without_env_read_values_is_copied_whole(
    tmp_path, monkeypatch
):
    details = _tool_invocation(tmp_path, monkeypatch, WRITTEN_OUT)

    assert details["command_line"] == f"tool --flag {WRITTEN_OUT}"
    assert details["arguments"] == ["--flag", WRITTEN_OUT]
    assert details["working_directory"] == "work-dir-name"
