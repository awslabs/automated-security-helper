# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Bedrock summary reporter hands no shown text to a sink that shows it again.

The package-wide check (tests/unit/utils/test_no_text_is_shown_twice.py) reads
the data flow: a value bound from an expression that holds shown text is shown
text, and a function whose parameter reaches a log call shows that argument
again. The reporter's "written to" lines were built from the path
``write_report_file`` returned for a report whose text quotes shown values (the
scan outcome's project name, the model's answer), so the check read the path as
shown, the three log lines as sinks given shown text, and ``_write_files`` as a
function that shows its content arguments again, which made both of its callers
offenders too: four sites in one file. The lines now name the path the file
has, ``reports_dir / filename``, bound from nothing the report text touched.

This test asks the same check the same question for this one file, so the
reporter's part of the package-wide red is measured on its own: red while the
four sites stand, green once the lines are built from the file's name.
"""

import pytest

from tests.unit.utils.test_no_text_is_shown_twice import _Analysis, _package_sources

pytestmark = pytest.mark.unit

REPORTER = "automated_security_helper/plugin_modules/ash_aws_plugins/bedrock_summary_reporter.py"


def test_the_bedrock_reporter_hands_no_shown_text_to_a_sink():
    sources = _package_sources()
    # The control: the file is in the walk, so an empty answer is a reading.
    assert REPORTER in sources

    offenders = sorted(
        site for site in _Analysis(sources).offenders() if site[0] == REPORTER
    )

    assert offenders == [], "shown twice:\n" + "\n".join(map(repr, offenders))
