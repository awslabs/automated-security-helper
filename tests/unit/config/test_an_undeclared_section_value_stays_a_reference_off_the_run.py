# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value an undeclared scanner section reads from the environment leaves the
configuration as its reference: in the dict sent off the host, and in a written
config.

The config model types only the scanner sections it declares; a section for a
plugin it does not declare is kept as a mapping in the scanners model's extras.
The record of what the files read from the environment names the place of each
reference, and the walk that follows a place into an extra is the one that can
miss it, leaving the value in the record as text. The end-to-end scan cell
(tests/unit/cli) reads the aggregated results and the run's files. These cells
drive the two other routes that dump the configuration, directly:

* ``AshAggregatedResults.to_simple_dict``, the dict the CloudWatch Logs and S3
  reporters send off the host;
* ``render_config_file_as_written``, which writes the session config a scan loads
  again, in YAML and in JSON.

Each cell reads the section's option back as the reference, not just the value's
absence, so a dump that dropped the section does not pass it.
"""

from __future__ import annotations

import json

import pytest
import yaml

from automated_security_helper.config.ash_config import _KeepsEnvReferences
from automated_security_helper.config.config_writer import (
    render_config_file_as_written,
)
from automated_security_helper.config.resolve_config import load_config_file_for_run
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

VARIABLE = "ASH_UNDECLARED_REFERENCE_CANARY"
REFERENCE = "${" + VARIABLE + "}"
CANARY = "ash-canary-4b2e-7713905"
SECTION = "community-demo-scanner"
OPTION = "ignore_unfixed"


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VARIABLE, CANARY)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: undeclared-reference\n"
        "scanners:\n"
        f"  {SECTION}:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      {OPTION}: {REFERENCE}\n",
        encoding="utf-8",
    )
    _, loaded = load_config_file_for_run(path)
    return loaded


def test_the_loaded_section_holds_the_value_the_variable_gave(config):
    """The premise: the section is an extra of the scanners model, and the
    configuration in memory holds the resolved value, so a record that shows
    the reference is the record at work."""
    extras = config.scanners.model_extra or {}
    assert SECTION in extras, sorted(extras)
    assert str(extras[SECTION]["options"][OPTION]) == CANARY


def test_the_dict_sent_off_the_host_holds_the_reference(config):
    sent = AshAggregatedResults(ash_config=config).to_simple_dict()

    option = sent["ash_config"]["scanners"][SECTION]["options"][OPTION]
    assert option == REFERENCE, option
    assert CANARY not in json.dumps(sent, default=str)


def test_the_written_yaml_holds_the_reference(config, tmp_path):
    text = render_config_file_as_written(tmp_path / "session.yaml", config, [])

    # The loader keeps an ``!ENV`` scalar as its text, so the file's own
    # reference is read back and nothing is read from the environment.
    written = yaml.load(text, Loader=_KeepsEnvReferences)  # nosec B506 - a SafeLoader
    option = written["scanners"][SECTION]["options"][OPTION]
    assert option == REFERENCE, option
    assert CANARY not in text


def test_the_written_yaml_reads_the_value_back_by_its_place(config, tmp_path):
    """The round trip: a scan loads the written session config again, so the
    written reference must resolve to the place's value on reload. The
    read-back above cannot tell a plain reference from a quoted literal (the
    reference-keeping loader reads both as the same text); the real loader
    resolves only the plain spelling, so this is the test a quoting writer
    fails."""
    path = tmp_path / "session.yaml"
    path.write_text(render_config_file_as_written(path, config, []), encoding="utf-8")

    _, loaded = load_config_file_for_run(path)

    extras = loaded.scanners.model_extra or {}
    assert SECTION in extras, sorted(extras)
    assert str(extras[SECTION]["options"][OPTION]) == CANARY


def test_the_written_json_holds_the_reference(config, tmp_path):
    text = render_config_file_as_written(tmp_path / "session.json", config, [])

    written = json.loads(text)["scanners"][SECTION]["options"][OPTION]
    assert written == REFERENCE, written
    assert CANARY not in text
