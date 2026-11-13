# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The repository scan runs for pull requests whose base branch name contains a slash.

GitHub branch filters treat ``*`` as matching any character except ``/``, so
``branches: ["*"]`` skips a pull request whose base is a nested branch such as
``feature/x``. ``**`` matches across ``/``. ``ash-unified-ci.yml`` already uses ``**``
for the same reason.
"""

from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-repo-scan.yml"


def _pull_request_branches() -> list[str]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = doc.get("on", doc.get(True))
    return list(triggers["pull_request"]["branches"])


def test_pull_request_filter_matches_nested_base_branches():
    branches = _pull_request_branches()

    assert branches, "the pull_request trigger has no branch filter to check"
    assert "**" in branches
    assert "*" not in branches
