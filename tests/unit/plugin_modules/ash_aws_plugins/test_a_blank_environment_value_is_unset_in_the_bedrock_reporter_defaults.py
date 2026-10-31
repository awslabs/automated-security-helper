# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A blank AWS_REGION or AWS_PROFILE is unset for the Bedrock reporter too.

The other three AWS reporters treat a blank environment value as unset (see
``test_a_blank_environment_value_is_unset_in_the_aws_reporter_defaults.py``).
The Bedrock options read the variables with ``os.environ.get(name, default)``,
which returns a blank value as it is: ``AWS_REGION=""`` reached the region
pattern as an empty name and refused the whole configuration (exit 3), and a
blank ``AWS_PROFILE`` reached botocore as a profile named by spaces.

Nothing here reaches AWS: the tests build the options model.
"""

import sys
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
)

pytestmark = pytest.mark.unit

BLANKS = ["", " ", "   ", "\t"]


@pytest.fixture(autouse=True)
def _no_aws_environment(monkeypatch):
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_region_does_not_hide_the_default_region(monkeypatch, blank):
    monkeypatch.setenv("AWS_REGION", blank)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")

    assert BedrockSummaryReporterConfigOptions().aws_region == "eu-west-2"


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_region_with_no_default_falls_back_to_the_built_in_region(
    monkeypatch, blank
):
    monkeypatch.setenv("AWS_REGION", blank)
    monkeypatch.setenv("AWS_DEFAULT_REGION", blank)

    assert BedrockSummaryReporterConfigOptions().aws_region == "us-east-1"


@pytest.mark.parametrize("blank", BLANKS, ids=repr)
def test_a_blank_profile_is_no_profile(monkeypatch, blank):
    monkeypatch.setenv("AWS_PROFILE", blank)

    assert BedrockSummaryReporterConfigOptions().aws_profile is None


def test_values_with_text_in_them_are_kept(monkeypatch):
    """The control: the change does not touch a real region or profile."""
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_PROFILE", "reporting")

    options = BedrockSummaryReporterConfigOptions()

    assert options.aws_region == "ap-south-1"
    assert options.aws_profile == "reporting"


def test_with_nothing_set_the_region_is_the_built_in_one_and_no_profile():
    options = BedrockSummaryReporterConfigOptions()

    assert options.aws_region == "us-east-1"
    assert options.aws_profile is None


def test_the_reference_generator_still_reads_both_region_variables():
    """The configuration reference is generated from the factories' source: the
    first environment read and the fallback it names. The blank-safe factory
    keeps that shape, so the page still says AWS_REGION, else AWS_DEFAULT_REGION."""
    scripts = Path(__file__).resolve().parents[4] / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        import generate_config_reference
    finally:
        sys.path.remove(str(scripts))

    chains = generate_config_reference.env_defaults(BedrockSummaryReporterConfigOptions)

    assert chains["aws_region"] == ["AWS_REGION", "AWS_DEFAULT_REGION"], chains
    assert chains["aws_profile"] == ["AWS_PROFILE"], chains


def test_the_environment_page_keeps_the_region_defaults_it_lists(tmp_path):
    """The environment-variable page is generated from the same factory, and its
    Default column is the default each read passes: AWS_REGION's is the inner
    read as written, AWS_DEFAULT_REGION's is the built-in region. Dropping that
    second argument from the source makes the committed page stale, which the
    page's freshness check reports."""
    scripts = Path(__file__).resolve().parents[4] / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        import generate_env_var_reference
    finally:
        sys.path.remove(str(scripts))

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

    assert defaults.get("AWS_REGION") == {
        'os.environ.get("AWS_DEFAULT_REGION", "us-east-1")'
    }, defaults
    assert defaults.get("AWS_DEFAULT_REGION") == {"us-east-1"}, defaults
