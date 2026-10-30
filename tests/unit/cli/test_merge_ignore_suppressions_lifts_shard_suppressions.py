# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--ignore-suppressions`` on a merge lifts the suppressions the shards applied.

Why this file exists
--------------------
The flag's help text promises every finding regardless of suppression status,
mirroring ``ash scan --ignore-suppressions``. A scan run with the flag never
calls ``apply_suppressions_to_sarif`` (``ScanResultProcessor`` skips it and runs
the output-directory exclusion alone), so no config, inline or client-supplied
suppression reaches its results and every such finding counts as actionable. The
shards of a sharded scan run without the flag and attach theirs, and the merge
under the flag only skipped its own suppression pass: the shards' suppressions
stayed on the results, the metrics counted them as suppressed, and the flag
changed nothing. The merge now removes every suppression that function attaches,
the client-supplied ones included (a first cut kept those, on the mistaken
premise that a flagged scan applies them). A scanner's own suppression stays, as
it does on a scan run with the flag.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.merge import apply_aggregated_suppressions
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    Kind1,
    PropertyBag,
    Suppression,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
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
    """One shard's results, carrying the suppressions its own pass attached.

    Typed in the shapes an older shard wrote (the justification prefixes, the
    ``clientSupplied`` mark); the test below that runs the real function covers
    the shape a current shard writes.
    """
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


def _context(tmp_path, config, ignore_suppressions: bool) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=config,
        ignore_suppressions=ignore_suppressions,
    )


def _merged(tmp_path, ignore_suppressions: bool):
    model = _results_as_the_shards_left_them()
    return apply_aggregated_suppressions(
        model, _context(tmp_path, model.ash_config, ignore_suppressions)
    )


def test_the_flag_lifts_the_suppressions_ash_applied_on_the_shards(tmp_path):
    merged = _merged(tmp_path, ignore_suppressions=True)

    assert _result(merged, CONFIG_SUPPRESSED).suppressions is None
    assert _result(merged, INLINE_SUPPRESSED).suppressions is None
    assert _result(merged, CLIENT_SUPPRESSED).suppressions is None


def test_the_flag_keeps_a_scanners_own_suppression(tmp_path):
    merged = _merged(tmp_path, ignore_suppressions=True)

    native = _result(merged, NATIVELY_SUPPRESSED).suppressions
    assert [s.justification for s in native] == ["nosec comment in source"]


def test_the_flag_clears_the_record_of_the_suppressions_the_shards_matched(tmp_path):
    """``used_suppressions`` is the union of what the shards' passes matched. With
    the suppressions lifted from every result, a record that still said they
    matched would describe a SARIF the merged results file no longer holds; a
    scan run with the flag records none, since it never runs the pass."""
    model = _results_as_the_shards_left_them()
    model.used_suppressions = {"bandit:B101:src/bandit_0.py"}

    merged = apply_aggregated_suppressions(
        model, _context(tmp_path, model.ash_config, ignore_suppressions=True)
    )

    assert merged.used_suppressions == set()


def test_without_the_flag_the_shards_record_is_kept(tmp_path):
    """The control: the pass adds to the set the shards filled, never replaces it."""
    model = _results_as_the_shards_left_them()
    model.used_suppressions = {"bandit:B101:src/bandit_0.py"}

    merged = apply_aggregated_suppressions(
        model, _context(tmp_path, model.ash_config, ignore_suppressions=False)
    )

    assert "bandit:B101:src/bandit_0.py" in merged.used_suppressions


def test_the_metrics_follow_the_lifted_suppressions(tmp_path):
    kept = _merged(tmp_path, ignore_suppressions=False)
    lifted = _merged(tmp_path, ignore_suppressions=True)

    # Three results lost their only suppression; the fourth kept its own.
    assert (
        lifted.metadata.summary_stats.suppressed
        == kept.metadata.summary_stats.suppressed - 3
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


def test_a_client_supplied_ignore_path_the_shard_applied_is_lifted(tmp_path):
    # The shard's own pass, as it runs without the flag: the real function, with a
    # client-supplied ignore path covering one finding.
    shard = build_shard(0, 1, SCANNERS)
    shard.ash_config.global_settings.ignore_paths = [
        IgnorePathWithReason(
            path="src/bandit_0.py", reason="client policy", client_supplied=True
        )
    ]
    apply_suppressions_to_sarif(
        shard.sarif, _context(tmp_path, shard.ash_config, ignore_suppressions=False)
    )
    attached = _result(shard, CONFIG_SUPPRESSED).suppressions
    assert attached and len(attached) == 1, attached
    assert getattr(attached[0].properties, "clientSupplied", None) is True
    assert attached[0].justification.startswith("(ASH, client-supplied config) ")

    # The merge under the flag answers as a scan under the flag would: that scan
    # never calls the function, so its results carry nothing of the kind.
    lifted = apply_aggregated_suppressions(
        shard, _context(tmp_path, shard.ash_config, ignore_suppressions=True)
    )
    never_applied = build_shard(0, 1, SCANNERS)
    reference = apply_aggregated_suppressions(
        never_applied,
        _context(tmp_path, never_applied.ash_config, ignore_suppressions=True),
    )

    assert _result(lifted, CONFIG_SUPPRESSED).suppressions is None
    assert (
        lifted.metadata.summary_stats.suppressed
        == reference.metadata.summary_stats.suppressed
    )
    assert (
        lifted.metadata.summary_stats.actionable
        == reference.metadata.summary_stats.actionable
    )


def test_a_config_suppression_the_real_pass_wrote_is_marked_and_lifted(tmp_path):
    # The shape a current shard writes: the real function marks what it attaches
    # with properties.ashApplied, and the lift reads that mark, not the wording.
    shard = build_shard(0, 1, SCANNERS)
    shard.ash_config.global_settings.suppressions = [
        AshSuppression(
            rule_id=CONFIG_SUPPRESSED, path="src/bandit_0.py", reason="fixture"
        )
    ]
    apply_suppressions_to_sarif(
        shard.sarif, _context(tmp_path, shard.ash_config, ignore_suppressions=False)
    )
    attached = _result(shard, CONFIG_SUPPRESSED).suppressions
    assert attached and len(attached) == 1, attached
    assert getattr(attached[0].properties, "ashApplied", None) is True
    assert attached[0].justification.startswith("(ASH) ")

    lifted = apply_aggregated_suppressions(
        shard, _context(tmp_path, shard.ash_config, ignore_suppressions=True)
    )

    assert _result(lifted, CONFIG_SUPPRESSED).suppressions is None


def test_a_marked_suppression_is_lifted_whatever_its_wording(tmp_path):
    # The mark decides; the prefixes are the fallback for a shard written before
    # the mark existed (the hand-typed fixtures above).
    model = build_shard(0, 1, SCANNERS)
    _result(model, NATIVELY_SUPPRESSED).suppressions = [
        Suppression(
            kind=Kind1.inSource,
            justification="worded by a future version",
            properties=PropertyBag(ashApplied=True),
        )
    ]

    lifted = apply_aggregated_suppressions(
        model, _context(tmp_path, model.ash_config, ignore_suppressions=True)
    )

    assert _result(lifted, NATIVELY_SUPPRESSED).suppressions is None
