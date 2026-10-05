# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash merge`` prints, and exits with, for every reason it refuses a shard set.

Each case writes the smallest shard results that trip exactly one refusal and runs the
real command against them. The shards carry scanner rows and a shard stamp and nothing
else: no SARIF, no findings. The refusals read only those two things, so anything
more would be noise in the fixture.

The verdict lines a merge that did go through ends with are covered twice: once
end to end for the incomplete-union exit 1, and once by calling the summary printer
directly for exit 2, because producing actionable findings through the real report
phase needs a SARIF fixture far larger than the line it would test.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from automated_security_helper.cli.merge import (
    MERGED_SHARD_COUNT_KEY,
    MERGED_SHARD_INDICES_KEY,
    _print_merge_summary,
    stamp_shard_assignment,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.sharding import ShardAssignment
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)

RESULTS = "ash_aggregated_results.json"


def _shard(
    rows: Mapping[str, str],
    *,
    index: int | None,
    count: int = 2,
    owned: Sequence[str] = (),
    candidates: Sequence[str] | None = None,
    selected: Sequence[str] | None = None,
) -> AshAggregatedResults:
    """One shard's results: a status per scanner and, unless ``index`` is None, a stamp."""
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="snapshot")
    for name, status in rows.items():
        model.scanner_results[name] = ScannerStatusInfo(
            status=ScannerStatus(status),
            excluded=status == "SKIPPED",
            dependencies_satisfied=status != "MISSING",
        )
    if index is not None:
        stamp_shard_assignment(
            model,
            ShardAssignment(
                shard_index=index,
                shard_count=count,
                assigned_scanners=list(owned),
                candidate_scanners=list(candidates) if candidates is not None else None,
                selected_scanners=list(selected) if selected is not None else None,
            ),
        )
    return model


def _write_shards(root: Path, *shards: AshAggregatedResults) -> list[str]:
    """Write each shard under ``shardN/`` and return the ``--results`` arguments."""
    args: list[str] = []
    for position, shard in enumerate(shards):
        directory = root / f"shard{position}"
        directory.mkdir(parents=True)
        (directory / RESULTS).write_text(shard.model_dump_json(), encoding="utf-8")
        args += ["--results", f"shard{position}"]
    return args


def _merge(run_cli, results_args: Sequence[str], *extra: str):
    return run_cli(["merge", *results_args, "--output-dir", "merged", *extra])


# Two shards that split bandit and semgrep cleanly; every case below perturbs this.
def _a(**overrides):
    kwargs = {"index": 0, "owned": ["bandit"]}
    kwargs.update(overrides)
    rows = kwargs.pop("rows", {"bandit": "PASSED", "semgrep": "SKIPPED"})
    return _shard(rows, **kwargs)


def _b(**overrides):
    kwargs = {"index": 1, "owned": ["semgrep"]}
    kwargs.update(overrides)
    rows = kwargs.pop("rows", {"bandit": "SKIPPED", "semgrep": "PASSED"})
    return _shard(rows, **kwargs)


class TestResultsPathRefusals:
    def test_path_does_not_exist(self, run_cli, snapshot):
        assert _merge(run_cli, ["--results", "shard-missing"]) == snapshot

    def test_directory_without_results(self, run_cli, snapshot, in_tmp):
        (in_tmp / "empty").mkdir()
        assert _merge(run_cli, ["--results", "empty"]) == snapshot

    def test_directory_with_two_results_files(self, run_cli, snapshot, in_tmp):
        for sub in ("x", "y"):
            (in_tmp / "both" / sub).mkdir(parents=True)
            (in_tmp / "both" / sub / RESULTS).write_text("{}", encoding="utf-8")
        assert _merge(run_cli, ["--results", "both"]) == snapshot

    def test_results_file_is_not_json(self, run_cli, snapshot, in_tmp):
        # Named directly and kept in the working directory: this message quotes the
        # file as a native path, so a directory in it would read differently on
        # Windows.
        (in_tmp / "shard0.json").write_text("{ truncated", encoding="utf-8")
        assert _merge(run_cli, ["--results", "shard0.json"]) == snapshot

    def test_no_results_option(self, run_cli, snapshot):
        assert run_cli(["merge", "--output-dir", "merged"]) == snapshot

    def test_invalid_output_format(self, run_cli, snapshot, in_tmp):
        args = _write_shards(in_tmp, _a(), _b())
        assert _merge(run_cli, args, "--output-formats", "sarif,pdf") == snapshot


@pytest.mark.parametrize(
    "shards",
    [
        pytest.param(lambda: (_a(index=None), _b()), id="unstamped_shard"),
        pytest.param(lambda: (_a(), _b(count=3)), id="shard_counts_disagree"),
        pytest.param(lambda: (_a(), _b(index=0)), id="duplicate_index"),
        pytest.param(lambda: (_a(),), id="missing_index"),
        pytest.param(
            lambda: (_a(), _b(), _b(index=2, owned=[], rows={})),
            id="index_outside_count",
        ),
        pytest.param(lambda: (_a(), _b(owned=["semgrep", "bandit"])), id="overlap"),
        pytest.param(
            lambda: (_a(candidates=["bandit", "semgrep"]), _b()),
            id="candidate_set_on_some_shards_only",
        ),
        pytest.param(
            lambda: (
                _a(candidates=["bandit", "semgrep"]),
                _b(candidates=["bandit", "semgrep", "grype"]),
            ),
            id="candidate_sets_differ",
        ),
        pytest.param(
            lambda: (
                _a(candidates=["bandit", "grype", "semgrep"]),
                _b(candidates=["bandit", "grype", "semgrep"]),
            ),
            id="candidate_assigned_to_no_shard",
        ),
        pytest.param(
            lambda: (_a(candidates=["bandit"]), _b(candidates=["bandit"])),
            id="assigned_scanner_not_a_candidate",
        ),
        pytest.param(
            lambda: (_a(selected=["bandit", "semgrep"]), _b()),
            id="shard_selected_another_shards_scanner",
        ),
        pytest.param(
            lambda: (
                _a(rows={"bandit": "PASSED", "semgrep": "SKIPPED", "trivy": "PASSED"}),
                _b(),
            ),
            id="scanner_in_results_owned_by_no_shard",
        ),
        pytest.param(
            lambda: (_a(), _b(rows={"bandit": "SKIPPED"})),
            id="owning_shard_recorded_no_result",
        ),
        pytest.param(
            lambda: (_a(), _b(rows={"bandit": "SKIPPED", "semgrep": "MISSING"})),
            id="shard_completed_none_of_its_scanners",
        ),
    ],
)
def test_refusal(run_cli, snapshot, in_tmp, shards):
    assert _merge(run_cli, _write_shards(in_tmp, *shards())) == snapshot


def test_merge_of_an_incomplete_union_exits_1(run_cli, snapshot, in_tmp):
    """A shard that ran one of its two scanners is merged, and the verdict says why 1.

    ``--log-level ERROR`` keeps the INFO lines about the files written out of the
    snapshot. They quote those files as native paths, so they would read differently
    on Windows, and they are not what this case is about: the summary and the
    verdict line below them are printed whatever the log level.
    """
    args = _write_shards(
        in_tmp,
        _a(
            owned=["bandit", "grype"],
            rows={"bandit": "PASSED", "grype": "MISSING", "semgrep": "SKIPPED"},
        ),
        _b(rows={"bandit": "SKIPPED", "grype": "SKIPPED", "semgrep": "PASSED"}),
    )
    assert (
        _merge(run_cli, args, "--output-formats", "sarif", "--log-level", "ERROR")
        == snapshot
    )


def test_verdict_line_for_actionable_findings(snapshot, capsys, in_tmp):
    merged = AshAggregatedResults()
    merged.ash_config = AshConfig(project_name="snapshot")
    merged.metadata.summary_stats.total = 5
    merged.metadata.summary_stats.actionable = 3
    merged.metadata.summary_stats.suppressed = 1
    setattr(merged.metadata, MERGED_SHARD_INDICES_KEY, [0, 1, 2])
    setattr(merged.metadata, MERGED_SHARD_COUNT_KEY, 3)
    _print_merge_summary(merged, Path("merged") / RESULTS, exit_code=2)
    captured = capsys.readouterr()
    assert {"stdout": captured.out, "stderr": captured.err} == snapshot
