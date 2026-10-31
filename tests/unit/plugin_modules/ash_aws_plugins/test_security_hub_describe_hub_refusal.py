# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused DescribeHub does not disable the Security Hub reporter.

The dependency check calls DescribeHub, a permission the import itself does not
need. Credentials granted only securityhub:BatchImportFindings (and GetFindings
to archive) import with `ash report`, which skips the check, but a scan dropped
the reporter on the refusal with no word of which permission was missing. The
check now leaves the reporter enabled on an access-denied refusal from
DescribeHub, in either spelling the reporter's ``_ACCESS_DENIED_ERRORS`` names
(AccessDeniedException, AccessDenied), and names the permission; any other
refusal is handled as before (the InvalidAccessException test beside this one in
the batch-import tests).

No test here calls AWS: the clients are botocore Stubbers over blocked sockets.
"""

import logging

import pytest

from tests.unit.plugin_modules.ash_aws_plugins.test_security_hub_batch_import import (
    _caller,
    _reporter,
    _stubbed_client,
    _validate_with,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("code", ["AccessDeniedException", "AccessDenied"])
def test_a_refused_describe_hub_leaves_the_reporter_enabled(tmp_path, caplog, code):
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_client_error(
        "describe_hub",
        service_error_code=code,
        service_message="not authorized to perform: securityhub:DescribeHub",
        http_status_code=403,
    )
    sts, sts_stub = _stubbed_client("sts")
    sts_stub.add_response("get_caller_identity", _caller("210987654321"))
    reporter = _reporter(tmp_path, account_id=None)

    with caplog.at_level(logging.WARNING):
        satisfied = _validate_with(reporter, {"securityhub": securityhub, "sts": sts})

    assert satisfied is True
    # The account lookup still ran: the check went on past the refusal.
    assert reporter.config.options.account_id == "210987654321"
    stub.assert_no_pending_responses()
    sts_stub.assert_no_pending_responses()
    assert "securityhub:DescribeHub" in caplog.text, caplog.text
    assert "securityhub:BatchImportFindings" in caplog.text, caplog.text
