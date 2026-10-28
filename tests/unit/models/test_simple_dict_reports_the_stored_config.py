# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``to_simple_dict`` reports the configuration the results record, and only that.

It is the payload the CloudWatch Logs and S3 reporters publish. Its ``ash_config``
is the configuration stored with the results, as the fields that were set. When
the results record none, the key is present and its value is None. ASH's
defaults, or the file ``ASH_CONFIG`` names in the process that renders the
payload, never stand in for it: they are not the configuration the scan ran with.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

MARKER = "configured-by-ash-config-variable"


@pytest.fixture(autouse=True)
def _ash_config_names_a_marker_file(tmp_path, monkeypatch):
    """A rendering process whose ASH_CONFIG names a file with a recognizable name.

    Anything taken from get_default_config() would carry MARKER into the payload.
    """
    path = tmp_path / "operator.yaml"
    path.write_text(f"project_name: {MARKER}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(path))


def _payload(results: AshAggregatedResults) -> dict:
    # As the reporters serialize it.
    return json.loads(json.dumps(results.to_simple_dict(), default=str))


def test_results_with_no_stored_config_report_none():
    payload = _payload(AshAggregatedResults())

    assert "ash_config" in payload
    assert payload["ash_config"] is None
    assert MARKER not in json.dumps(payload)


def test_results_read_from_a_file_with_a_null_config_report_none():
    results = AshAggregatedResults.model_validate_json('{"ash_config": null}')

    assert _payload(results)["ash_config"] is None


def test_a_stored_config_with_no_settings_is_not_replaced_by_the_defaults():
    payload = _payload(AshAggregatedResults(ash_config=AshConfig()))

    assert payload["ash_config"] == {}
    assert MARKER not in json.dumps(payload)


def test_a_stored_config_is_reported_as_stored():
    results = AshAggregatedResults(
        ash_config=AshConfig(project_name="stored-project", fail_on_findings=False)
    )

    payload = _payload(results)

    assert payload["ash_config"] == {
        "project_name": "stored-project",
        "fail_on_findings": False,
    }
    assert MARKER not in json.dumps(payload)
