# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every wording ``ContentDbAgeRecord.message()`` can produce, for every declared database.

The message is what an operator reads on the console, in the log and in every report when a
scanner ran against an old vulnerability database or ruleset. Its shape has three independent
switches -- whether a build time could be read, whether the policy is ``fail`` or ``warn``, and
whether the bound is the tool's own or ASH's -- and the refresh advice differs per database, so
the snapshot is the full product over the four declared databases rather than one example.

Ages and the measurement instant are fixed in console_inputs, so ``33d 4h old`` is part of the
contract while the ISO timestamps beside it are masked by the shared normalizer.
"""

from __future__ import annotations

from datetime import timedelta

from automated_security_helper.utils import content_databases as cdb
from automated_security_helper.utils.content_db_staleness import OPT_OUT_HINT
from tests.snapshot.console.console_inputs import content_db_record


def test_message_variants(snapshot):
    messages = {}
    for entry in cdb.CONTENT_DATABASES:
        for policy in (cdb.STALENESS_FAIL, cdb.STALENESS_WARN):
            stale = content_db_record(
                entry.name,
                policy=policy,
                age=entry.max_age + timedelta(days=3, hours=4),
            )
            unreadable = content_db_record(
                entry.name,
                policy=policy,
                age=None,
                error=f"ValueError: {entry.scanner} printed no build time",
            )
            messages[f"{entry.name} / {policy} / stale"] = stale.message()
            messages[f"{entry.name} / {policy} / unreadable"] = unreadable.message()

    assert messages == snapshot


def test_opt_out_hint(snapshot):
    """Quoted on its own because the CLI flag and config key in it are an interface."""
    assert OPT_OUT_HINT == snapshot
