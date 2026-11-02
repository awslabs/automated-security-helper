# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge``'s remedy does not offer ``--config`` for what it replaces there.

``ash merge`` reads its ``--config`` file as a file that may be the scanned tree's
own for the reporters that send findings off the host, and replaces that file's
enabled and destination options with the defaults and the overrides
(``MERGE_CONFIG_FILE``). The remedy a shard-recorded warning ends with named
``--config`` as a way to keep any setting, so it sent the operator to a flag that
changes nothing for those reporter settings. It now names ``--config-overrides``
as the only way for them, and still offers ``--config`` for the rest.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.untrusted_source import SHARD_RECORDED

pytestmark = pytest.mark.unit

_BOTH = "ash merge's --config-overrides or --config"


def test_the_remedy_still_offers_both_options_for_a_setting_that_stays_on_the_host():
    assert SHARD_RECORDED.remedy.startswith("To keep a setting, ")
    assert _BOTH in SHARD_RECORDED.remedy


def test_the_remedy_sends_an_off_host_reporter_setting_to_the_overrides_only():
    _, _, exception = SHARD_RECORDED.remedy.partition(_BOTH)

    assert "sends findings off the host" in exception
    assert "pass it with --config-overrides" in exception
