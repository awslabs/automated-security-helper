# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results file recorded with an unreadable ``output_format`` still loads.

Why this file exists
--------------------
The reporter's ``output_format`` validator refuses any value but ``json``,
``markdown`` and ``both``, so a config file that says ``md`` is refused where it
once silently produced the JSON-only report. The config a results file recorded
is validated again by every reader of the file, and a scan by an earlier version
may have run with such a value: refusing it there lost the results of a scan
nobody is about to run again. Under the stored-config tolerance the value is
read as the earlier version read it, ``json``, with a note that does not name it.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporterConfigOptions,
)
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit


def test_a_stored_unreadable_format_is_read_as_json_with_a_note():
    """Red at the base: the validator raised under the tolerance as well."""
    notes = []

    options = UnusedSuppressionsReporterConfigOptions.model_validate(
        {"output_format": "md-from-an-earlier-version"},
        context={TOLERATE_STORED_CONFIG: notes},
    )

    assert options.output_format == "json"
    assert len(notes) == 1
    assert "output_format" in notes[0]
    assert "md-from-an-earlier-version" not in notes[0]


def test_a_config_file_is_still_refused_for_it():
    """The control: outside the tolerance the value is refused, as before."""
    with pytest.raises(ValidationError):
        UnusedSuppressionsReporterConfigOptions.model_validate({"output_format": "md"})


def test_a_readable_stored_format_records_no_note():
    notes = []

    options = UnusedSuppressionsReporterConfigOptions.model_validate(
        {"output_format": "Markdown"}, context={TOLERATE_STORED_CONFIG: notes}
    )

    assert options.output_format == "markdown"
    assert notes == []
