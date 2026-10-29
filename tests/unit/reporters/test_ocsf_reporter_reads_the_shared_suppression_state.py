# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The OCSF reporter reads suppression state through sarif_utils' one helper.

The reporter imports ``suppressions_in_effect`` at module level. ``sarif_utils``
imports the flat-finding model and the schema, never a reporter, so the two
modules import in either order; this test imports the reporter first, the order a
cycle would break, and checks the helper the reporter holds is sarif_utils' own.
"""

import pytest

pytestmark = pytest.mark.unit


def test_the_reporter_holds_the_helper_sarif_utils_defines():
    from automated_security_helper.plugin_modules.ash_builtin.reporters import (
        ocsf_reporter,
    )
    from automated_security_helper.utils import sarif_utils

    assert ocsf_reporter.suppressions_in_effect is sarif_utils.suppressions_in_effect


def test_the_reporter_and_the_model_agree_on_a_rejected_suppression(
    test_plugin_context,
):
    from automated_security_helper.models.flat_vulnerability import (
        FlatVulnerability,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
        OcsfReporter,
    )
    from automated_security_helper.schemas.sarif_schema_model import (
        Kind1,
        Message,
        Result,
        State,
        Suppression,
    )

    result = Result(
        ruleId="RULE-1",
        level="error",
        message=Message(text="finding"),
        suppressions=[Suppression(kind=Kind1.inSource, state=State.rejected)],
    )

    reporter = OcsfReporter(context=test_plugin_context)
    status, _, status_name = reporter._determine_status_from_suppressions(
        result.suppressions, "RULE-1"
    )
    flat = FlatVulnerability.from_sarif_result(result, "scripted", "SAST")

    assert status_name == "New"
    assert getattr(status, "value", status) == 1
    assert flat.is_suppressed is False
