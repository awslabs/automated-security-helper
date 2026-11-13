# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``link_locations`` follows as many links as the platform's own lookup does.

Linux follows 40 symlinks on one path; Windows resolves up to 63 reparse points.
At 40 everywhere, on Windows the walk stopped reporting links on a path the OS
still opened, so the locations between the 40th and the 63rd link went unjudged.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.utils.link_locations import MAX_LINKS_FOLLOWED

pytestmark = pytest.mark.unit


def test_the_cap_is_the_platforms():
    assert MAX_LINKS_FOLLOWED == (63 if os.name == "nt" else 40)
