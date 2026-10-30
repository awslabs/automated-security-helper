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

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.merge import (
    apply_aggregated_suppressions,
    lift_ash_suppressions,
)
from automated_security_helper.models.asharp_model import (
    ConverterStatusInfo,
    FailedInputInfo,
)
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
)
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


def test_a_result_holding_both_kinds_keeps_only_the_scanners_own(tmp_path):
    """Every fixture result above carries one suppression, so the keep/drop over
    a mixed list was never exercised: a lift that emptied the list whenever an
    ASH suppression was present passed them all and would un-suppress a native
    ``nosec`` finding beside it. The count the lift returns is pinned too."""
    model = _results_as_the_shards_left_them()
    _result(model, NATIVELY_SUPPRESSED).suppressions = [
        Suppression(
            kind=Kind1.inSource,
            justification=f"(ASH) Suppressing finding for rule '{NATIVELY_SUPPRESSED}'",
        ),
        Suppression(kind=Kind1.inSource, justification="nosec comment in source"),
    ]
    _result(model, CONFIG_SUPPRESSED).suppressions = None
    _result(model, INLINE_SUPPRESSED).suppressions = None
    _result(model, CLIENT_SUPPRESSED).suppressions = None

    removed = lift_ash_suppressions(model.sarif)

    assert removed == 1
    kept = _result(model, NATIVELY_SUPPRESSED).suppressions
    assert [s.justification for s in kept] == ["nosec comment in source"]


def test_the_lift_counts_every_suppression_it_removes(tmp_path):
    """The four fixture results: three ASH-applied suppressions removed, the
    scanner's own kept, and the count says three."""
    model = _results_as_the_shards_left_them()

    assert lift_ash_suppressions(model.sarif) == 3
    assert _result(model, NATIVELY_SUPPRESSED).suppressions is not None
    # A second pass finds nothing of ASH's left to remove.
    assert lift_ash_suppressions(model.sarif) == 0


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


ACCEPTED_INPUT = "notebooks/a.ipynb"
ACCEPTANCE_ID = "ash-unconverted-input:notebooks/a.ipynb"
SHARD_MATCHED = "bandit:B101:src/bandit_0.py"


def _accepted(path: str, accepted_by: str | None) -> FailedInputInfo:
    return FailedInputInfo(
        path=path,
        reason="nbconvert could not read it",
        kind="input",
        accepted=True,
        accepted_reason="fixture",
        accepted_by=accepted_by,
    )


def test_the_flag_records_the_lift_on_the_merged_metadata(tmp_path):
    """A later ``ash report`` over the merged results file runs under a context
    carrying no flag; the unused-suppressions reporter reads this field to say
    the suppressions were not evaluated. Red at the base: no such attribute."""
    merged = _merged(tmp_path, ignore_suppressions=True)

    assert merged.metadata.suppressions_ignored is True


def test_without_the_flag_the_metadata_records_no_lift(tmp_path):
    """The control for the field: without the flag the merge never writes it, so
    it reads as the field's declared default. ReportMetadata admits the attribute
    ahead of a declaration (extra="allow"), where it is absent; declared, its
    default is None ("not recorded"), not False ("recorded as not ignored"). The
    reporter reads it through bool(), so either reads as "not ignored"."""
    merged = _merged(tmp_path, ignore_suppressions=False)

    assert getattr(merged.metadata, "suppressions_ignored", None) in (None, False)
    assert not getattr(merged.metadata, "suppressions_ignored", None)


def test_the_unused_reporter_reads_the_merged_file_as_not_evaluated(tmp_path):
    """The reporter driven over the merged model under a context with no flag,
    the shape ``ash report`` takes over the written file. Red at the base: with
    the record emptied and nothing else said, every configured entry read as
    unused, and ``ash config lint --fix-unused`` would comment them all out."""
    model = _results_as_the_shards_left_them()
    model.ash_config.global_settings.suppressions = [
        AshSuppression(path="src/bandit_0.py", rule_id="RULE-0", reason="one"),
        AshSuppression(path="src/other.py", rule_id="RULE-9", reason="two"),
    ]
    merged = apply_aggregated_suppressions(
        model, _context(tmp_path, model.ash_config, ignore_suppressions=True)
    )
    reporting = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "report",
        work_dir=tmp_path / "work",
        config=model.ash_config,
        ignore_suppressions=False,
    )

    report = json.loads(UnusedSuppressionsReporter(context=reporting).report(merged))

    assert report["unused_suppressions"] == []
    assert report["summary"]["evaluated"] is False


def test_a_converter_acceptance_survives_the_clear(tmp_path):
    """The convert phase registers, in the same set, the id of the suppression
    that accepted a failed input on a shard (``accepted_by`` on the record); the
    lift undoes nothing of that acceptance. Red at the base: the clear emptied
    the set whole."""
    model = _results_as_the_shards_left_them()
    model.converter_results["jupyter"] = ConverterStatusInfo(
        failed_inputs=[_accepted(ACCEPTED_INPUT, ACCEPTANCE_ID)]
    )
    model.used_suppressions = {ACCEPTANCE_ID, SHARD_MATCHED}

    merged = apply_aggregated_suppressions(
        model, _context(tmp_path, model.ash_config, ignore_suppressions=True)
    )

    assert merged.used_suppressions == {ACCEPTANCE_ID}


def test_an_acceptance_with_no_recorded_id_is_rederived_from_its_path(tmp_path):
    """A record carrying no ``accepted_by`` (a third-party converter's, or one
    written before the field existed) names the entry its path matches now, the
    way the convert phase derives it."""
    from automated_security_helper.utils.suppression_matcher import (
        recorded_suppressions,
        written_suppression_id,
    )

    model = _results_as_the_shards_left_them()
    accepting = AshSuppression(
        path="notebooks/*.ipynb", rule_id="ash-unconverted-input", reason="fixture"
    )
    model.ash_config.global_settings.suppressions = [accepting]
    expected = written_suppression_id(
        accepting, recorded_suppressions(model.ash_config)
    )
    model.converter_results["jupyter"] = ConverterStatusInfo(
        failed_inputs=[_accepted(ACCEPTED_INPUT, None)]
    )
    model.used_suppressions = {expected, SHARD_MATCHED}

    merged = apply_aggregated_suppressions(
        model, _context(tmp_path, model.ash_config, ignore_suppressions=True)
    )

    assert merged.used_suppressions == {expected}


def test_a_record_a_suppression_did_not_accept_keeps_nothing(tmp_path):
    """The control: an unaccepted failed input, and an accepted one whose path
    matches no entry any more, name nothing, so the clear stays whole."""
    model = _results_as_the_shards_left_them()
    unaccepted = FailedInputInfo(
        path="notebooks/b.ipynb", reason="nbconvert could not read it", kind="input"
    )
    model.converter_results["jupyter"] = ConverterStatusInfo(
        failed_inputs=[unaccepted, _accepted("notebooks/gone.ipynb", None)]
    )
    model.used_suppressions = {SHARD_MATCHED}

    merged = apply_aggregated_suppressions(
        model, _context(tmp_path, model.ash_config, ignore_suppressions=True)
    )

    assert merged.used_suppressions == set()
