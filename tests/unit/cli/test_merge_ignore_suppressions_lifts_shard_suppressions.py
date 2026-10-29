# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--ignore-suppressions`` on a merge lifts the suppressions the shards applied.

Why this file exists
--------------------
The flag's help text promises every finding regardless of suppression status,
mirroring ``ash scan --ignore-suppressions``. A scan run with the flag attaches
no config or inline suppression, so every such finding counts as actionable. The
shards of a sharded scan run without the flag and attach theirs, and the merge
under the flag only skipped its own suppression pass: the shards' suppressions
stayed on the results, the metrics counted them as suppressed, and the flag
changed nothing. The merge now removes the suppressions ASH applied. A
scanner's own suppression stays, as it does on a scan run with the flag, and so
does one a client-supplied configuration applied, which a scan run with the
flag applies as well.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.merge import apply_aggregated_suppressions
from automated_security_helper.schemas.sarif_schema_model import (
    Kind1,
    PropertyBag,
    Suppression,
)
from tests.unit.cli.merge_shard_support import SCANNERS, build_shard

pytestmark = pytest.mark.unit

CONFIG_SUPPRESSED = "bandit-RULE-0"
INLINE_SUPPRESSED = "checkov-RULE-0"
CLIENT_SUPPRESSED = "detect-secrets-RULE-0"
NATIVELY_SUPPRESSED = "bandit-RULE-1"


def _result(model, rule_id: str):
    return next(
        result
        for run in model.sarif.runs
        for result in run.results or []
        if result.ruleId == rule_id
    )


def _results_as_the_shards_left_them():
    """One shard's results, carrying the suppressions its own pass attached."""
    model = build_shard(0, 1, SCANNERS)
    _result(model, CONFIG_SUPPRESSED).suppressions = [
        Suppression(
            kind=Kind1.inSource,
            justification=(
                f"(ASH) Suppressing finding for rule '{CONFIG_SUPPRESSED}' in "
                "'src/bandit_0.py' with reason: fixture"
            ),
        )
    ]
    _result(model, INLINE_SUPPRESSED).suppressions = [
        Suppression(kind=Kind1.inSource, justification="(ASH inline) fixture")
    ]
    _result(model, CLIENT_SUPPRESSED).suppressions = [
        Suppression(
            kind=Kind1.external,
            justification=(
                "(ASH, client-supplied config) Ignoring finding under ignore path "
                "'src/' with reason: fixture"
            ),
            properties=PropertyBag(clientSupplied=True),
        )
    ]
    _result(model, NATIVELY_SUPPRESSED).suppressions = [
        Suppression(kind=Kind1.inSource, justification="nosec comment in source")
    ]
    return model


def _merged(tmp_path, ignore_suppressions: bool):
    model = _results_as_the_shards_left_them()
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=model.ash_config,
        ignore_suppressions=ignore_suppressions,
    )
    return apply_aggregated_suppressions(model, context)


def test_the_flag_lifts_the_suppressions_ash_applied_on_the_shards(tmp_path):
    merged = _merged(tmp_path, ignore_suppressions=True)

    assert _result(merged, CONFIG_SUPPRESSED).suppressions is None
    assert _result(merged, INLINE_SUPPRESSED).suppressions is None


def test_the_flag_keeps_native_and_client_supplied_suppressions(tmp_path):
    merged = _merged(tmp_path, ignore_suppressions=True)

    native = _result(merged, NATIVELY_SUPPRESSED).suppressions
    assert [s.justification for s in native] == ["nosec comment in source"]
    client = _result(merged, CLIENT_SUPPRESSED).suppressions
    assert len(client) == 1
    assert getattr(client[0].properties, "clientSupplied", None) is True


def test_the_metrics_follow_the_lifted_suppressions(tmp_path):
    kept = _merged(tmp_path, ignore_suppressions=False)
    lifted = _merged(tmp_path, ignore_suppressions=True)

    # Two results lost their only suppression; the other two kept theirs.
    assert (
        lifted.metadata.summary_stats.suppressed
        == kept.metadata.summary_stats.suppressed - 2
    )
    assert lifted.metadata.summary_stats.actionable > (
        kept.metadata.summary_stats.actionable
    )


def test_without_the_flag_every_shard_suppression_stays(tmp_path):
    kept = _merged(tmp_path, ignore_suppressions=False)

    for rule_id in (
        CONFIG_SUPPRESSED,
        INLINE_SUPPRESSED,
        CLIENT_SUPPRESSED,
        NATIVELY_SUPPRESSED,
    ):
        assert len(_result(kept, rule_id).suppressions) == 1, rule_id
