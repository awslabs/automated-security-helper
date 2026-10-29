# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The error names the Security Hub reporter repeats a call for.

``security_hub_reporter._RETRYABLE_ERRORS`` is the shared list
(``aws_utils.RETRYABLE_EXCEPTIONS``) plus the API's own 500,
``InternalException``. A name added to the shared list for another service
(``InternalServerException`` was added for the Bedrock control plane) changes
what this reporter retries, so the names are written out here: such a change
has to be made on purpose.
"""

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins import (
    security_hub_reporter,
)

pytestmark = pytest.mark.unit

#: Written out, not read from the module: a name added to the list or dropped
#: from it must fail this test, not move it.
RETRIED_ERRORS = [
    "BandwidthLimitExceeded",
    "ConnectionError",
    "HTTPClientError",
    "InternalException",
    "InternalFailure",
    "InternalServerError",
    "InternalServerException",
    "LimitExceededException",
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "RequestThrottledException",
    "ServiceFailure",
    "ServiceUnavailable",
    "SlowDown",
    "ThrottledException",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "TransactionInProgressException",
]


def test_the_reporter_retries_exactly_these_errors():
    assert sorted(security_hub_reporter._RETRYABLE_ERRORS) == RETRIED_ERRORS
