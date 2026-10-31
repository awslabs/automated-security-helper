# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A blank ASH_BEDROCK_* environment value is unset for the Bedrock reporter.

The region and profile defaults and the two numeric knobs already read a blank
value as unset (see
``test_a_blank_environment_value_is_unset_in_the_bedrock_reporter_defaults.py``).
Two reads still took a blank value as a value:

* the ``model_id`` default factory returned ``ASH_BEDROCK_MODEL_ID=""`` (or a
  space) as the model id, so every Converse call named a model of spaces;
* ``_read_ash_bedrock_defaults``, which collects the values the reporter
  redacts from its lines, kept a blank value as a needle, and a needle of
  spaces rewrites every run of spaces in a line the reporter prints.

Nothing here reaches AWS: the tests build the options model and read the
module's own helper.
"""

import sys
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
    _read_ash_bedrock_defaults,
)

pytestmark = pytest.mark.unit

BLANKS = ["", " ", "   ", "\t"]
BUILT_IN_MODEL_ID = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
DEFAULT_VARS = (
    "ASH_BEDROCK_MODEL_ID",
    "ASH_BEDROCK_TEMPERATURE",
    "ASH_BEDROCK_MAX_TOKENS",
)


@pytest.fixture(autouse=True)
def _no_bedrock_environment(monkeypatch):
    for name in DEFAULT_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_model_id_is_the_built_in_model_id(monkeypatch, blank):
    monkeypatch.setenv("ASH_BEDROCK_MODEL_ID", blank)

    assert BedrockSummaryReporterConfigOptions().model_id == BUILT_IN_MODEL_ID


def test_a_model_id_is_kept_without_the_whitespace_around_it(monkeypatch):
    monkeypatch.setenv("ASH_BEDROCK_MODEL_ID", "  eu.example.model-v1:0\t")

    assert BedrockSummaryReporterConfigOptions().model_id == "eu.example.model-v1:0"


@pytest.mark.parametrize("name", DEFAULT_VARS)
@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_value_is_no_redaction_needle(monkeypatch, name, blank):
    monkeypatch.setenv(name, blank)

    assert _read_ash_bedrock_defaults() == ()


def test_a_model_id_needle_is_the_value_the_option_holds(monkeypatch):
    monkeypatch.setenv("ASH_BEDROCK_MODEL_ID", "  eu.example.model-v1:0  ")

    assert _read_ash_bedrock_defaults() == ("eu.example.model-v1:0",)
    assert BedrockSummaryReporterConfigOptions().model_id == "eu.example.model-v1:0"


def test_a_numeric_knob_with_padding_is_still_no_needle(monkeypatch):
    """The control: the numeric-knob exclusion reads the stripped number."""
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", " 4000 ")
    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "\t0.5")

    assert _read_ash_bedrock_defaults() == ()


def test_with_nothing_set_the_model_id_is_built_in_and_nothing_is_redacted():
    assert BedrockSummaryReporterConfigOptions().model_id == BUILT_IN_MODEL_ID
    assert _read_ash_bedrock_defaults() == ()


def test_the_reference_pages_still_read_the_model_id_default(tmp_path):
    """The environment-variable page lists the default each read passes, and the
    configuration reference lists the variable a default is read from. The
    blank-safe factory keeps the read with the built-in id as its second
    argument, so neither generated page moves."""
    scripts = Path(__file__).resolve().parents[4] / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        import generate_config_reference
        import generate_env_var_reference
    finally:
        sys.path.remove(str(scripts))

    chains = generate_config_reference.env_defaults(BedrockSummaryReporterConfigOptions)
    assert chains["model_id"] == ["ASH_BEDROCK_MODEL_ID"], chains

    package = "automated_security_helper"
    relative = "plugin_modules/ash_aws_plugins/bedrock_summary_reporter.py"
    source = Path(__file__).resolve().parents[4] / package / relative
    planted = tmp_path / package / relative
    planted.parent.mkdir(parents=True)
    (tmp_path / package / "__init__.py").write_text("", encoding="utf-8")
    planted.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    scan = generate_env_var_reference.collect_env_reads(tmp_path)
    defaults = {}
    for read in scan.reads:
        if read.default is not None:
            defaults.setdefault(read.name, set()).add(read.default)

    assert defaults.get("ASH_BEDROCK_MODEL_ID") == {BUILT_IN_MODEL_ID}, defaults
