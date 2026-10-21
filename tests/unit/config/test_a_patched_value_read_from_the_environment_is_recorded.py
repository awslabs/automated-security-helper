# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value a config file's ``patch`` operation reads from the environment is
recorded as the reference wherever ASH writes or sends the configuration.

The operation's ``value`` is written under ``patch``, but the value lands at the
operation's ``path``. Each place ASH writes the configuration out holds the
reference there, not the value: the ``ash_config`` of a results file, its
``metadata``, what the off-host reporters send (to_simple_dict), and the profile
file the MCP server writes for a session (``AshConfig.save(as_written=True)``),
which loads back to the value. A short value is recorded the same way, at its
place, and the session writer refuses to write one it finds left there as text,
whatever its length.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

CANARY = "ash-canary-patched-4d1e-0123456789"
VALUE = "${ASH_PROBE_PATCHED}"
SHORT = "Q"
SHORT_VALUE = "${ASH_PROBE_SHORT}"


@pytest.fixture(autouse=True)
def _canary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASH_PROBE_PATCHED", CANARY)
    monkeypatch.setenv("ASH_PROBE_SHORT", SHORT)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _patched(
    tmp_path: Path, path: str, value: str, head: str = "", op: str = "replace"
) -> Path:
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        f"project_name: demo\n{head}"
        f"patch:\n  - op: {op}\n    path: {path}\n    value: {value}\n",
        encoding="utf-8",
    )
    return config_file


def _results(config_file: Path) -> AshAggregatedResults:
    config = resolve_config(config_file)
    results = AshAggregatedResults(ash_config=config)
    results.metadata.project_name = config.project_name
    return results


def _record(config_file: Path) -> dict:
    return json.loads(_results(config_file).model_dump_json(by_alias=True))


def test_the_run_reads_the_patched_value(tmp_path):
    """The control: the scan runs with the value the operation read."""
    config = resolve_config(_patched(tmp_path, "/project_name", VALUE))
    assert config.project_name == CANARY


def test_a_results_files_config_records_the_patched_reference(tmp_path):
    record = _record(_patched(tmp_path, "/project_name", VALUE))
    assert record["ash_config"]["project_name"] == VALUE
    assert CANARY not in json.dumps(record["ash_config"])


def test_a_results_files_metadata_records_the_patched_reference(tmp_path):
    record = _record(_patched(tmp_path, "/project_name", VALUE))
    assert record["metadata"]["project_name"] == VALUE
    assert CANARY not in json.dumps(record["metadata"])


def test_what_the_reporters_send_off_the_host_holds_the_patched_reference(tmp_path):
    """to_simple_dict is what the CloudWatch Logs and S3 reporters send."""
    sent = json.dumps(
        _results(_patched(tmp_path, "/project_name", VALUE)).to_simple_dict(),
        default=str,
    )
    assert VALUE in sent, sent
    assert CANARY not in sent, sent


def test_a_patched_option_is_recorded_as_its_reference(tmp_path):
    """An operation that sets a plugin option, deeper than a top-level field."""
    config_file = _patched(
        tmp_path,
        "/reporters/gitlab-cyclonedx/options/language_override",
        VALUE,
        head="reporters:\n  gitlab-cyclonedx:\n    options:\n      language_override: en\n",
    )
    record = _record(config_file)
    options = record["ash_config"]["reporters"]["gitlab-cyclonedx"]["options"]
    assert options["language_override"] == VALUE
    assert CANARY not in json.dumps(record)


def test_the_session_profile_writes_the_patched_reference(tmp_path):
    """The profile the MCP server writes for a session holds the reference, and
    the scan that loads it reads the value again."""
    config = resolve_config(_patched(tmp_path, "/project_name", VALUE))
    target = tmp_path / "session" / "profile.yaml"
    target.parent.mkdir()

    config.save(target, as_written=True)

    text = target.read_text(encoding="utf-8")
    assert CANARY not in text, text
    assert yaml.safe_load(text)["project_name"] == VALUE
    assert resolve_config(target).project_name == CANARY


def test_the_materialized_session_config_holds_the_patched_reference(
    tmp_path, monkeypatch
):
    """materialize_session_config, the MCP server's own writer of a session's
    config."""
    from automated_security_helper.cli.mcp.profile_registry import (
        materialize_session_config,
    )

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
    config = resolve_config(_patched(tmp_path, "/project_name", VALUE))

    session = Path(materialize_session_config("session-a", config))

    text = session.read_text(encoding="utf-8")
    assert CANARY not in text, text
    assert yaml.safe_load(text)["project_name"] == VALUE


def test_a_value_an_operation_appends_is_recorded_at_its_entry(tmp_path):
    """An append (``-``): the reference is recorded at the entry the operation
    added, and the entry before it is left as written."""
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: demo\n"
        "global_settings:\n  ignore_paths:\n"
        "    - path: kept/**\n      reason: written\n"
        "patch:\n  - op: add\n    path: /global_settings/ignore_paths/-\n"
        f"    value:\n      path: {VALUE}\n      reason: patched\n",
        encoding="utf-8",
    )
    assert resolve_config(config_file).global_settings.ignore_paths[1].path == (CANARY)

    record = _record(config_file)

    entries = record["ash_config"]["global_settings"]["ignore_paths"]
    assert [entry["path"] for entry in entries] == ["kept/**", VALUE]
    assert CANARY not in json.dumps(record)


def test_a_short_patched_value_is_recorded_at_its_place(tmp_path):
    """One character long: recorded as the reference at the place the operation
    put it, in the results file and in the session profile."""
    config_file = _patched(tmp_path, "/project_name", SHORT_VALUE)
    record = _record(config_file)
    assert record["ash_config"]["project_name"] == SHORT_VALUE
    assert record["metadata"]["project_name"] == SHORT_VALUE

    config = resolve_config(config_file)
    target = tmp_path / "profile.yaml"
    config.save(target, as_written=True)
    assert yaml.safe_load(target.read_text(encoding="utf-8"))["project_name"] == (
        SHORT_VALUE
    )


def test_the_session_writer_refuses_a_short_patched_value_left_as_text(
    tmp_path, monkeypatch
):
    """The writer's own check, with the record made to leave the value as text:
    a value one character long at the place an operation put it is refused, and
    nothing is written."""
    from automated_security_helper.config import config_validator

    config = resolve_config(_patched(tmp_path, "/project_name", SHORT_VALUE))
    monkeypatch.setattr(
        config_validator, "record_of_config", lambda config, dumped, mark=None: dumped
    )
    target = tmp_path / "profile.yaml"

    with pytest.raises(RuntimeError, match="was not written"):
        config.save(target, as_written=True)
    assert not target.exists()
