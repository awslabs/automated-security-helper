# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/generate_config_reference.py: what the discovery section reads from the CLI.

The configuration page's "Where ASH finds its configuration" section opens with the
ways to name a config file outright, read from the scan command's ``--config``
option. ``ash scan`` became a group whose subjects carry the scan's options, so a
lookup on the group found no ``--config`` and the generator dropped the sentence
from the page without any error.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


def test_the_explicit_config_option_is_read_from_the_scan_subject(script_loader):
    generator = script_loader("generate_config_reference")

    assert generator.explicit_config_option() == ["--config", "-c", "ASH_CONFIG"]
