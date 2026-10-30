# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ``config/operator_only_options.py`` reads sections and shows the ignored marker.

* A reporters key that is not a string (a YAML ``1:``) is no spelling of any
  reporter: the section lookup skips it instead of raising, so a discovered
  in-tree file with such a key is skipped as advisory and the scan goes on.
* The MCP get_config marker reads a scanners section as the model reads it
  (the declared section, or a spelling that folds to it), not with the
  reporter lookup, which also read an extra section the scanner never reads.
* The marker never shows a value the chain read from the environment: a list
  or mapping holding such a value shows the reference at that leaf, and a
  date or other non-JSON value a YAML file writes is shown as text, not raised.
* An option a file outside the tree set is written back by the confinement
  only, read through the options model: the settle list ``ash config validate``
  reads (``ignored_operator_only_options``) changes nothing, and a string the
  document holds for a numeric option is stored as the model's type.
"""

from __future__ import annotations

import datetime
from typing import Annotated

import pytest
from pydantic import BaseModel, Field, ValidationError, model_validator

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.environment_record import EnvironmentReference
from automated_security_helper.config.operator_only_options import (
    RepositorySettings,
    _confine_scanner_options,
    _sections_in,
    _set_scanner_option,
    ignored_operator_only_options,
    mark_operator_only_options,
)

pytestmark = pytest.mark.unit

SH = "aws-security-hub"


def _outside_tree_limit(value: object) -> RepositorySettings:
    """A chain whose file outside the tree wrote detect-secrets' limit as *value*."""
    repository = RepositorySettings(trees=[])
    repository.document = {
        "scanners": {"detect-secrets": {"options": {"max_worker_output_mib": value}}}
    }
    return repository


def test_the_settle_list_a_validation_reads_changes_nothing():
    """``ignored_operator_only_options`` serves ``ash config validate``, which
    judges a file without changing the configuration; the option a file
    outside the tree set is listed for the confinement to write back, not
    written back by the listing."""
    config = AshConfig.model_validate(
        {"scanners": {"detect-secrets": {"options": {"max_worker_output_mib": 2048}}}}
    )

    ignored = ignored_operator_only_options(
        config, AshConfig(), [], _outside_tree_limit(256)
    )

    assert ignored == []
    assert config.scanners.detect_secrets.options.max_worker_output_mib == 2048


def test_an_outside_files_string_value_is_stored_as_the_models_type():
    """The document holds a string where the model holds a number (an
    environment reference resolves to text); the write-back reads it through
    the options model, so the scanner gets the number, not the string."""
    config = AshConfig.model_validate(
        {"scanners": {"detect-secrets": {"options": {"max_worker_output_mib": 2048}}}}
    )

    _confine_scanner_options(config, AshConfig(), [], _outside_tree_limit("256"))

    limit = config.scanners.detect_secrets.options.max_worker_output_mib
    assert limit == 256
    assert isinstance(limit, int) and not isinstance(limit, bool)


def test_the_write_back_types_one_field_without_revalidating_the_whole_model():
    """An options model with a second required field, and a model validator
    that reads both fields: validating the one option as a whole model raised
    on the missing field before the value was ever typed. The write-back reads
    the one field, with its own constraints (the limit is held above zero), and
    leaves the rest of the model as it is."""

    class _TwoFields(BaseModel):
        limit: Annotated[int, Field(gt=0)] = 1
        ceiling: int

        @model_validator(mode="after")
        def _limit_within_ceiling(self) -> "_TwoFields":
            if self.limit > self.ceiling:
                raise ValueError("limit above ceiling")
            return self

    options = _TwoFields(limit=1, ceiling=512)

    _set_scanner_option(options, "limit", "256")

    assert options.limit == 256
    assert isinstance(options.limit, int)
    assert options.ceiling == 512
    with pytest.raises(ValidationError):
        _set_scanner_option(options, "limit", "0")


def test_an_option_a_file_outside_the_tree_set_holds_that_files_value():
    """The chain document holds the limit a file outside the tree wrote; the
    configuration holds another value by the time the settle runs. That other
    value is an MCP client's override: ``resolve_config`` applies a client's
    overrides to the model but hands the confinement the operator's
    ``--config-overrides`` only, and ``_set_by_override`` skips an option the
    operator overrode before this write-back runs, so an operator's own
    override is never written over (``test_an_override_of_the_limit_wins_whatever_the_trusted_base_says``
    in test_detect_secrets_output_limit_is_the_operators.py measures that at
    the resolve_config level, with an outside-tree file setting the same
    option). Skipping the option because a file outside the tree set it kept the
    client's value; the file's value is written back."""
    repository = RepositorySettings(trees=[])
    repository.document = {
        "scanners": {"detect-secrets": {"options": {"max_worker_output_mib": 256}}}
    }
    config = AshConfig.model_validate(
        {"scanners": {"detect-secrets": {"options": {"max_worker_output_mib": 2048}}}}
    )

    _confine_scanner_options(config, AshConfig(), [], repository)

    assert config.scanners.detect_secrets.options.max_worker_output_mib == 256


def test_a_non_string_reporters_key_is_skipped_not_raised():
    reporters = {1: {"options": {"findings_scope": "x"}}, SH: {"options": {}}}

    assert _sections_in(reporters, SH) == [(SH, {"options": {}})]


def test_an_extra_scanner_section_the_model_never_reads_is_not_marked():
    shown = mark_operator_only_options(
        {"scanners": {"detect.secrets": {"options": {"max_worker_output_mib": 7}}}}
    )

    assert shown["scanners"]["detect.secrets"]["options"]["max_worker_output_mib"] == 7


@pytest.mark.parametrize("spelling", ["detect-secrets", "detect_secrets"])
def test_a_scanner_section_the_model_reads_is_marked(spelling):
    """The control for the case above: the declared section, and a spelling
    that folds to it, are the scanner's, so the operator-only option a file
    wrote there is shown as ignored, with the file's value as JSON."""
    shown = mark_operator_only_options(
        {"scanners": {spelling: {"options": {"max_worker_output_mib": 7}}}}
    )

    assert shown["scanners"][spelling]["options"]["max_worker_output_mib"] == (
        "<operator only; ignored from this file: 7>"
    )


def test_a_list_holding_an_environment_read_value_shows_the_reference():
    reference = EnvironmentReference(
        path=("reporters", SH, "options", "findings_scope", 0),
        written="${ASH_PLANTED_SCOPE}",
        resolved="planted-scope-value",
        value="planted-scope-value",
    )
    shown = mark_operator_only_options(
        {
            "reporters": {
                SH: {"options": {"findings_scope": ["planted-scope-value", "all"]}}
            }
        },
        references=[reference],
    )

    marker = shown["reporters"][SH]["options"]["findings_scope"]
    assert "planted-scope-value" not in marker, marker
    assert "${ASH_PLANTED_SCOPE}" in marker and '"all"' in marker, marker


def test_a_date_a_yaml_file_wrote_is_shown_as_text():
    shown = mark_operator_only_options(
        {"reporters": {SH: {"options": {"findings_scope": datetime.date(2099, 1, 31)}}}}
    )

    marker = shown["reporters"][SH]["options"]["findings_scope"]
    assert marker.startswith("<operator only; ignored from this file: ")
    assert "2099-01-31" in marker, marker


def test_a_date_keyed_mapping_a_yaml_file_wrote_is_shown_as_text():
    """``json.dumps`` applies ``default=`` to values, not to mapping keys, so
    a date key (an unquoted ``2099-01-31:`` in YAML) raised out of the marking
    where a date value was shown as text; the key is shown as text too."""
    shown = mark_operator_only_options(
        {
            "reporters": {
                SH: {"options": {"findings_scope": {datetime.date(2099, 1, 31): "all"}}}
            }
        }
    )

    marker = shown["reporters"][SH]["options"]["findings_scope"]
    assert marker.startswith("<operator only; ignored from this file: ")
    assert "2099-01-31" in marker and '"all"' in marker, marker


def test_a_mapping_key_read_from_the_environment_shows_the_reference():
    """A key reference is recorded at its mapping's place; a key the file read
    from the environment is shown as the reference, as a read value is, never
    as the key's text."""
    reference = EnvironmentReference(
        path=("reporters", SH, "options", "findings_scope"),
        written="${ASH_PLANTED_KEY}",
        resolved="planted-key-text",
        value="planted-key-text",
        key=True,
    )
    shown = mark_operator_only_options(
        {
            "reporters": {
                SH: {"options": {"findings_scope": {"planted-key-text": "all"}}}
            }
        },
        references=[reference],
    )

    marker = shown["reporters"][SH]["options"]["findings_scope"]
    assert "planted-key-text" not in marker, marker
    assert "${ASH_PLANTED_KEY}" in marker and '"all"' in marker, marker
