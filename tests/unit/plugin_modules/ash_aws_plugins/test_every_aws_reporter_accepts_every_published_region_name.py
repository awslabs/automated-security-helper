# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""All three AWS reporters take the same region names and refuse the same others.

The reporters share one ``aws_region`` pattern, but each declares the field on
its own options model, so a model that left the pattern out would refuse a
published region as a configuration error while the other two accepted it.
Earlier tests covered a few new names on the S3 model and the trailing-newline
case on all three; this one runs one list over every model.

The commercial names are the Regions table of the AWS documentation page
https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html
(34 Regions when it was read). The China and GovCloud (US) names are the
Regions that page says those account types reach (Beijing, Ningxia, and
GovCloud East and West). The mx, eusc, us-isof and eu-isoe names are the
partitions the pattern's own comment lists.

Nothing here reaches AWS: the tests build option models.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3ReporterConfigOptions,
)

pytestmark = pytest.mark.unit

OPTION_MODELS = [
    pytest.param(BedrockSummaryReporterConfigOptions, {}, id="bedrock"),
    pytest.param(
        CloudWatchLogsReporterConfigOptions,
        {"log_group_name": "a-log-group"},
        id="cloudwatch",
    ),
    pytest.param(S3ReporterConfigOptions, {"bucket_name": "a-bucket"}, id="s3"),
]

COMMERCIAL_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-2",
    "ap-southeast-3",
    "ap-southeast-5",
    "ap-southeast-4",
    "ap-south-1",
    "ap-southeast-6",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-east-2",
    "ap-southeast-7",
    "ap-northeast-1",
    "ca-central-1",
    "ca-west-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-south-1",
    "eu-west-3",
    "eu-south-2",
    "eu-north-1",
    "eu-central-2",
    "il-central-1",
    "mx-central-1",
    "me-south-1",
    "me-central-1",
    "sa-east-1",
]
OTHER_PARTITION_REGIONS = [
    "cn-north-1",
    "cn-northwest-1",
    "us-gov-east-1",
    "us-gov-west-1",
    "us-iso-east-1",
    "us-isob-east-1",
    "us-isof-south-1",
    "eu-isoe-west-1",
    "eusc-de-east-1",
]
PUBLISHED_REGIONS = COMMERCIAL_REGIONS + OTHER_PARTITION_REGIONS

NOT_REGIONS = [
    "nowhere-1",
    "US-EAST-1",
    "us-east-1\n",
    " us-east-1",
    "us-east-1.example.test",
    "us-east-1/x",
    "us-east-1x",
    "us-east-100",
    "us-east",
    "east-1",
]


@pytest.mark.parametrize(("options_type", "required"), OPTION_MODELS)
@pytest.mark.parametrize("region", PUBLISHED_REGIONS)
def test_a_published_region_name_is_accepted(options_type, required, region):
    options = options_type(aws_region=region, **required)

    assert options.aws_region == region


@pytest.mark.parametrize(("options_type", "required"), OPTION_MODELS)
@pytest.mark.parametrize("region", NOT_REGIONS, ids=repr)
def test_a_value_that_is_no_region_name_is_refused_on_the_region_field(
    options_type, required, region
):
    with pytest.raises(ValidationError) as caught:
        options_type(aws_region=region, **required)

    locations = [error["loc"] for error in caught.value.errors()]
    assert ("aws_region",) in locations, locations


def test_the_list_holds_no_repeated_name():
    """A repeated name would make a parametrized count read higher than it is."""
    assert len(set(PUBLISHED_REGIONS)) == len(PUBLISHED_REGIONS)
