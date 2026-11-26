# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash merge`` records the merged run in its own output directory's history.

The gap these tests close (documented as excluded in
the scan-history hardening change): a sharded CI's only completed run is the
merged one, and the merge recorded nothing, so ``global_settings.history.enabled``
built no history there at all. The merge now records the way a scan does
(``cli/merge._record_merge_history``): the gate is the merge's config of record
(the shards' recorded config with ``--config-overrides`` applied), the owning
output directory is the merge's own ``--output-dir``, and one record per merge
is written under the merged report's own ``report_id``, so a re-merge of the
same shards replaces its record rather than appending a second run.

The merge is driven through the CLI the way ``test_merge.TestMergeCli`` drives
it (plugin discovery narrowed to reporters whose dependency checks stay off the
network), so the record asserted on is the one a real merge writes after its
reports, not one written by calling the recorder directly.
"""

import json
from pathlib import Path
from typing import Sequence
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.merge import RESULTS_FILE_NAME
from automated_security_helper.config.ash_config import AshHistoryConfig
from automated_security_helper.utils import scan_history
from tests.unit.cli.merge_shard_support import (
    FINDINGS,
    SCANNERS,
    build_shards,
    write_shards,
)

pytestmark = pytest.mark.unit


def _invoke(args: Sequence[str]):
    """Run ``ash results merge`` with plugin discovery narrowed, as test_merge does."""
    from automated_security_helper.cli.main import app
    from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
        CsvReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )

    manager = MagicMock()
    manager.plugin_modules.return_value = [SarifReporter, CsvReporter]

    with (
        patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
        patch("automated_security_helper.cli.merge.load_plugins"),
    ):
        return CliRunner().invoke(app, ["results", "merge", *args])


def _shards_with_history(enabled: bool):
    """Shards whose recorded config says what the scans' config said about history."""
    shards = build_shards(3)
    for shard in shards:
        shard.ash_config.global_settings.history = AshHistoryConfig(enabled=enabled)
    return shards


def _merge_args(shard_paths: Sequence[str], output_dir: Path) -> list[str]:
    args: list[str] = []
    for path in shard_paths:
        args += ["--results", path]
    return [*args, "--output-dir", str(output_dir), "--output-formats", "sarif"]


def test_a_merge_with_history_enabled_records_the_merged_run(tmp_path):
    shard_paths = write_shards(tmp_path / "artifacts", _shards_with_history(True))
    output_dir = tmp_path / "merged"

    result = _invoke(_merge_args(shard_paths, output_dir))

    # These shards carry actionable findings, so the merge's own verdict is 2;
    # recording happens when the merged results file is written, before it.
    assert result.exit_code == 2, result.output
    assert (output_dir / RESULTS_FILE_NAME).is_file()
    names = list(scan_history.record_names(output_dir))
    assert len(names) == 1, names
    record = scan_history.read_run_record(
        scan_history.history_dir(output_dir) / names[0]
    )
    assert record is not None

    # The record is the merged run's: its id is the merged report's own
    # (one entry per merge, not one per shard), orderable by the key
    # ``ash trend`` sorts the series with, and its findings and coverage are
    # the union's, not one shard's.
    merged = json.loads((output_dir / RESULTS_FILE_NAME).read_text(encoding="utf-8"))
    assert record["report_id"] == merged["metadata"]["report_id"]
    assert scan_history.run_order_key(record["report_id"]) is not None
    assert record["coverage"]["evaluated_scanners"] == sorted(SCANNERS)
    assert len(record["findings"]) == sum(len(rows) for rows in FINDINGS.values())


def test_a_merge_with_history_disabled_records_nothing(tmp_path):
    shard_paths = write_shards(tmp_path / "artifacts", _shards_with_history(False))
    output_dir = tmp_path / "merged"

    result = _invoke(_merge_args(shard_paths, output_dir))

    assert result.exit_code == 2, result.output
    assert (output_dir / RESULTS_FILE_NAME).is_file()
    assert list(scan_history.record_names(output_dir)) == []
    assert not scan_history.history_dir(output_dir).exists()


def test_config_overrides_enable_recording_at_the_merge(tmp_path):
    # The shards' scans did not enable history; the operator turns it on at the
    # merge with --config-overrides, the knob the merge gives the operator for
    # settings the shards recorded (apply_operator_overrides).
    shard_paths = write_shards(tmp_path / "artifacts", build_shards(3))
    output_dir = tmp_path / "merged"
    args = _merge_args(shard_paths, output_dir) + [
        "--config-overrides",
        "global_settings.history.enabled=true",
    ]

    result = _invoke(args)

    assert result.exit_code == 2, result.output
    assert len(list(scan_history.record_names(output_dir))) == 1


def test_a_re_merge_of_the_same_shards_replaces_its_record(tmp_path):
    # The merged report_id is derived from the shard ids (_union_report_id), so
    # merging the same shards again writes the same record name: the history
    # holds one run, not one entry per invocation of ``ash merge``.
    shard_paths = write_shards(tmp_path / "artifacts", _shards_with_history(True))
    output_dir = tmp_path / "merged"

    first = _invoke(_merge_args(shard_paths, output_dir))
    assert first.exit_code == 2, first.output
    second = _invoke(_merge_args(shard_paths, output_dir))
    assert second.exit_code == 2, second.output

    assert len(list(scan_history.record_names(output_dir))) == 1
