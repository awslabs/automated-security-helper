# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The record of a configuration keeps each environment reference as written.

A results file records the configuration its scan ran with
(``AshAggregatedResults.ash_config``). Where the file read a value or a key from
the environment, the record keeps the reference exactly as the file wrote it
and not the value, and only there:

- a variable that is not set, whose default was used, records the default: the
  default is the file's own text;
- a variable set to nothing records null, as the run had it;
- a string elsewhere that happens to equal the value is left as it is;
- in a string that only starts with a reference, only that part becomes the
  reference;
- a scanner section's key read from the environment is the reference in the
  scanner names the results carry too.

Each case goes through resolve_config and the results' own dump, as a scan
writes it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import resolve_env_references
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

CANARY = "ash-canary-7f3e-0123456789"
VALUE = "${ASH_PROBE_VALUE}"


@pytest.fixture(autouse=True)
def _canary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    monkeypatch.delenv("ASH_PROBE_UNSET", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    # The control for every test here: the canary's variable is one a
    # configuration reads.
    assert resolve_env_references(VALUE) == CANARY


def _record(tmp_path: Path, text: str) -> dict:
    """The results file a scan with this configuration writes, as a dict."""
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(text, encoding="utf-8")
    config = resolve_config(config_file)
    results = AshAggregatedResults(ash_config=config)
    results.metadata.project_name = config.project_name
    return json.loads(results.model_dump_json(by_alias=True))


def _options(record: dict) -> dict:
    return record["ash_config"]["reporters"]["gitlab-cyclonedx"]["options"]


def _reporter(options: str) -> str:
    return (
        f"project_name: demo\nreporters:\n  gitlab-cyclonedx:\n    options:\n{options}"
    )


def test_a_set_variable_records_the_reference(tmp_path):
    record = _record(tmp_path, _reporter(f"      language_override: {VALUE}\n"))
    assert _options(record)["language_override"] == VALUE, _options(record)
    assert CANARY not in json.dumps(record)


def test_an_unset_variable_records_the_default_it_used(tmp_path):
    """The default is the file's text; a fixed-choice field keeps a value the
    record can be read back with."""
    record = _record(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  severity_threshold: ${ASH_PROBE_UNSET:LOW}\n",
    )
    assert record["ash_config"]["global_settings"]["severity_threshold"] == "LOW"
    # Read back as merge and report read it, with no field it cannot hold.
    loaded = AshAggregatedResults.model_validate_json(json.dumps(record))
    assert loaded.ash_config.global_settings.severity_threshold == "LOW"


def test_a_variable_set_to_nothing_records_null(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_PROBE_EMPTY", "")
    record = _record(
        tmp_path, _reporter("      language_override: ${ASH_PROBE_EMPTY}\n")
    )
    assert _options(record)["language_override"] is None, _options(record)


def test_a_literal_equal_to_the_value_is_left_as_written(tmp_path):
    """Only the reference's own path: a string elsewhere equal to the value is
    the file's text, and replacing it would tell which strings equal it."""
    record = _record(
        tmp_path,
        _reporter(
            f"      language_override: {VALUE}\n"
            f"      package_manager_override: {CANARY}\n"
        ),
    )
    options = _options(record)
    assert options["language_override"] == VALUE, options
    assert options["package_manager_override"] == CANARY, options


def test_only_the_reference_in_a_longer_string_is_recorded_as_written(tmp_path):
    record = _record(
        tmp_path, _reporter(f"      input_file_path_override: {VALUE}/vendor\n")
    )
    assert _options(record)["input_file_path_override"] == f"{VALUE}/vendor"
    assert CANARY not in json.dumps(record)


def test_a_scanner_key_read_from_the_environment_is_its_reference(tmp_path):
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        f"project_name: demo\nscanners:\n  {VALUE}:\n    enabled: false\n",
        encoding="utf-8",
    )
    config = resolve_config(config_file)
    # The control: the run has the key as its value.
    assert CANARY in (config.scanners.model_extra or {}), config.scanners
    results = AshAggregatedResults(ash_config=config)
    results.metadata.expected_scanners = ["bandit", CANARY]
    record = json.loads(results.model_dump_json(by_alias=True))
    assert VALUE in record["ash_config"]["scanners"], record["ash_config"]["scanners"]
    assert record["metadata"]["expected_scanners"] == ["bandit", VALUE]
    assert CANARY not in json.dumps(record)


def test_the_project_name_the_results_carry_is_the_reference(tmp_path):
    record = _record(tmp_path, f"project_name: {VALUE}\n")
    assert record["ash_config"]["project_name"] == VALUE
    assert record["metadata"]["project_name"] == VALUE
    assert CANARY not in json.dumps(record)


def test_what_the_reporters_send_off_the_host_is_the_record(tmp_path):
    """to_simple_dict is what the CloudWatch Logs and S3 reporters send."""
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        _reporter(f"      language_override: {VALUE}\n").replace(
            "project_name: demo", f"project_name: {VALUE}"
        ),
        encoding="utf-8",
    )
    config = resolve_config(config_file)
    results = AshAggregatedResults(ash_config=config)
    results.metadata.project_name = config.project_name
    sent = json.dumps(results.to_simple_dict(), default=str)
    # The control: the reference is what is sent.
    assert VALUE in sent, sent
    assert CANARY not in sent, sent


@pytest.mark.parametrize(
    ("base_key", "child_key"),
    [("cloudwatch-logs", "cloudwatch_logs"), ("cloudwatch_logs", "cloudwatch-logs")],
)
def test_a_child_spelling_a_section_differently_records_the_reference(
    tmp_path, base_key, child_key
):
    """``extends`` folds a child's section into the base's under the base's
    spelling (``-`` or ``_``), so the record finds the child's value there."""
    (tmp_path / "base.yaml").write_text(
        f"project_name: demo\nreporters:\n  {base_key}:\n    enabled: false\n",
        encoding="utf-8",
    )
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "extends: base.yaml\n"
        f"reporters:\n  {child_key}:\n    options:\n"
        f"      log_stream_name: {VALUE}\n",
        encoding="utf-8",
    )
    config = resolve_config(config_file)
    results = AshAggregatedResults(ash_config=config)
    record = json.loads(results.model_dump_json(by_alias=True))
    sent = json.dumps(results.to_simple_dict(), default=str)

    reporters = record["ash_config"]["reporters"]
    section = reporters.get("cloudwatch-logs") or reporters.get("cloudwatch_logs")
    assert section["options"]["log_stream_name"] == VALUE, reporters
    assert CANARY not in json.dumps(record)
    assert VALUE in sent and CANARY not in sent, sent


def test_the_run_keeps_the_value(tmp_path):
    """The run's own configuration object is not changed: a scan reads the
    value, and its reports show what the configuration asks for."""
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(f"project_name: {VALUE}\n", encoding="utf-8")
    config = resolve_config(config_file)
    results = AshAggregatedResults(ash_config=config)
    results.model_dump_json()
    assert results.ash_config.project_name == CANARY
