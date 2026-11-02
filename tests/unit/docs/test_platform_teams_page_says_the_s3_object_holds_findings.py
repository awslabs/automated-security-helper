# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The platform teams page says the S3 object holds the findings.

The AWS reporters page says the S3 reporter sends the findings as the SARIF report inside
its object, and that only the CloudWatch Logs reporter leaves them out. The platform teams
page once grouped the two and said both "send the scan summary and configuration, not
individual findings". An operator who sizes bucket access and retention from that page
would treat the S3 object as holding no findings, and it holds all of them.

The page has a template twin that the version tooling renders into the page, so each test
runs over both files. The code-side check reads the AWS reporters page, so the two pages
cannot drift apart again without this file saying so.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
PAGES_DIR = REPO_ROOT / "docs" / "content"
PLATFORM_PAGES = [
    PAGES_DIR / "getting-started" / "platform-teams.md",
    PAGES_DIR / "getting-started" / "platform-teams.md.template",
]
AWS_PAGE = PAGES_DIR / "plugins" / "aws.md"

#: The wording the page used while it grouped the S3 reporter with CloudWatch Logs.
STALE_CLAIM = (
    "The S3 and CloudWatch Logs reporters send the scan summary and configuration, "
    "not individual findings"
)


def _collapse(text: str) -> str:
    """Join wrapped lines, so a rewrapped paragraph does not hide a claim."""
    return re.sub(r"\s+", " ", text).strip()


def _page(path: Path) -> str:
    return _collapse(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", PLATFORM_PAGES, ids=lambda p: p.name)
def test_the_page_no_longer_groups_the_s3_reporter_with_the_no_findings_claim(
    path: Path,
) -> None:
    assert STALE_CLAIM not in _page(path), (
        f"{path.name} still says the S3 reporter sends no individual findings; its "
        "object holds the SARIF report with them"
    )


@pytest.mark.parametrize("path", PLATFORM_PAGES, ids=lambda p: p.name)
def test_the_page_says_the_s3_reporter_sends_the_findings_inside_its_object(
    path: Path,
) -> None:
    text = _page(path)
    assert "it sends the findings as the SARIF report inside its object" in text, (
        f"{path.name} does not say that the S3 object carries the findings"
    )


@pytest.mark.parametrize("path", PLATFORM_PAGES, ids=lambda p: p.name)
def test_the_page_still_says_the_cloudwatch_logs_reporter_sends_no_findings(
    path: Path,
) -> None:
    text = _page(path)
    assert (
        "The CloudWatch Logs reporter sends the scan summary and configuration, "
        "not individual findings." in text
    ), f"{path.name} lost the CloudWatch Logs half of the claim"


def test_the_aws_reporters_page_still_says_what_the_platform_page_relies_on() -> None:
    """The page this one points to makes the same two statements."""
    text = _page(AWS_PAGE)
    assert "The CloudWatch Logs reporter does not send individual findings." in text
    assert (
        "The S3 reporter sends them only as the SARIF report inside its object." in text
    )
