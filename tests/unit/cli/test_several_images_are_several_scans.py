# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan --image a --image b`` runs one one-subject scan per image.

A scan has one subject, so the command runs ``run_ash_scan`` once per image: each
into its own report directory, each with its own identity scope (the scan keys
on the image it was handed, never on a list), the exit code the worst of the
per-image codes (utils/image_batch lists the order). The rows pin what the
command hands each run, the refusals that keep their words for a batch (shards,
convert-only, ``--staged``, ``--baseline``), and the aggregate.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.utils.image_batch import (
    ImageListRefused,
    aggregate_exit_code,
    exit_code_of,
    report_directory,
    run_image_batch,
    split_image_arguments,
)

pytestmark = pytest.mark.unit

A = "registry.example.com/team/a:1"
B = "registry.example.com/team/b:2"
C = "registry.example.com/team/c@sha256:" + "ab" * 32


@pytest.fixture(autouse=True)
def _here(tmp_path, monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)


def _scan(*options: str):
    return CliRunner().invoke(app, ["scan", "fs", *options])


def _exits_by_image(codes: dict):
    """A run_ash_scan double that ends each scan with the code its image maps to."""

    def run(**kwargs):
        code = codes.get(kwargs["image"], 0)
        raise SystemExit(code)

    return run


class TestTheListOfImages:
    def test_repeated_and_comma_forms_are_one_list_in_order(self):
        assert split_image_arguments([A, f"{B},{C}"]) == [A, B, C]

    def test_blanks_around_a_comma_are_dropped(self):
        assert split_image_arguments([f" {A} , {B} "]) == [A, B]

    def test_no_values_is_no_images(self):
        assert split_image_arguments(None) == []
        assert split_image_arguments([]) == []

    @pytest.mark.parametrize("values", [[""], [f"{A},,{B}"], [","], [A, " "]])
    def test_an_empty_piece_is_refused(self, values):
        with pytest.raises(ImageListRefused, match="empty image reference"):
            split_image_arguments(values)

    def test_an_image_named_twice_is_refused(self):
        with pytest.raises(ImageListRefused, match="more than once"):
            split_image_arguments([A, f"{B},{A}"])


class TestTheAggregateExit:
    @pytest.mark.parametrize(
        "codes,expected",
        [
            ([], 0),
            ([0, 0], 0),
            ([0, 2], 2),
            ([2, 1], 1),
            ([1, 2, 0], 1),
            ([2, 3], 3),
            ([1, 5], 5),
            ([0, 99], 99),
            ([2, 99], 99),
        ],
    )
    def test_the_worst_code_wins(self, codes, expected):
        assert aggregate_exit_code(codes) == expected

    def test_an_unknown_code_ranks_with_an_error(self):
        assert aggregate_exit_code([2, 77]) == 77
        assert aggregate_exit_code([1, 77]) in (1, 77)

    def test_the_code_an_exit_carries(self):
        assert exit_code_of(SystemExit(2)) == 2
        assert exit_code_of(SystemExit()) == 0
        assert exit_code_of(SystemExit("text")) == 1


class TestTheReportDirectories:
    def test_each_image_has_its_own_ordered_readable_directory(self, tmp_path):
        first = report_directory(tmp_path, A, 1)
        second = report_directory(tmp_path, B, 2)
        assert first != second
        assert first.parent == second.parent == tmp_path
        assert first.name.startswith("01-registry.example.com_team_a_1-")
        assert second.name.startswith("02-")

    def test_two_references_with_one_readable_form_do_not_collide(self, tmp_path):
        assert report_directory(tmp_path, "a/b:c", 1) != report_directory(
            tmp_path, "a:b/c", 1
        )

    def test_a_reference_that_reads_as_nothing_still_has_a_directory(self, tmp_path):
        assert report_directory(tmp_path, "///", 3).name.startswith("03-image-")


class TestTheBatchRuns:
    def test_each_image_is_scanned_in_order_with_its_own_directory(self, tmp_path):
        calls = []
        lines = []
        code, per_image = run_image_batch(
            [A, B],
            tmp_path,
            lambda ref, directory: calls.append((ref, directory)),
            say=lines.append,
        )
        assert code == 0
        assert per_image == {A: 0, B: 0}
        assert [ref for ref, _ in calls] == [A, B]
        assert calls[0][1] != calls[1][1]
        assert any("Scanning image 1 of 2" in line for line in lines)

    def test_a_failing_image_does_not_stop_the_others(self, tmp_path):
        def run(ref, directory):
            raise SystemExit({A: 2, B: 1}.get(ref, 0))

        code, per_image = run_image_batch([A, B, C], tmp_path, run, say=lambda _: None)
        assert per_image == {A: 2, B: 1, C: 0}
        assert code == 1

    @pytest.mark.parametrize("refusal", [3, 5])
    def test_a_refusal_that_does_not_depend_on_the_image_ends_the_batch(
        self, tmp_path, refusal
    ):
        seen = []

        def run(ref, directory):
            seen.append(ref)
            raise SystemExit(refusal)

        lines = []
        code, per_image = run_image_batch([A, B, C], tmp_path, run, say=lines.append)
        assert seen == [A]
        assert code == refusal
        assert per_image == {A: refusal}
        text = "\n".join(lines)
        assert "were not scanned" in text
        assert f"{B}: not scanned" in text
        assert f"{C}: not scanned" in text

    def test_an_interrupt_is_not_caught(self, tmp_path):
        def run(ref, directory):
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            run_image_batch([A, B], tmp_path, run, say=lambda _: None)

    def test_an_ordinary_error_is_not_swallowed(self, tmp_path):
        def run(ref, directory):
            raise RuntimeError("defect")

        with pytest.raises(RuntimeError, match="defect"):
            run_image_batch([A], tmp_path, run, say=lambda _: None)


class TestWhatTheCommandHandsEachRun:
    def test_one_run_per_image_each_handed_its_own_image_and_directory(self):
        with patch(
            "automated_security_helper.cli.scan.run_ash_scan",
            side_effect=_exits_by_image({}),
        ) as run:
            result = _scan("--image", A, "--image", f"{B},{C}")
        assert result.exit_code == 0, result.output
        assert run.call_count == 3
        handed = [call.kwargs for call in run.call_args_list]
        assert [kwargs["image"] for kwargs in handed] == [A, B, C]
        assert all(kwargs["source_dir"] is None for kwargs in handed)
        assert all(kwargs["image_archive"] is None for kwargs in handed)
        directories = [Path(str(kwargs["output_dir"])) for kwargs in handed]
        assert len(set(directories)) == 3
        assert len({directory.parent for directory in directories}) == 1

    def test_the_exit_code_is_the_worst_of_theirs(self):
        with patch(
            "automated_security_helper.cli.scan.run_ash_scan",
            side_effect=_exits_by_image({A: 2, B: 1}),
        ):
            result = _scan("--image", f"{A},{B},{C}")
        assert result.exit_code == 1
        assert f"{A}: exit 2" in result.output
        assert f"{B}: exit 1" in result.output
        assert f"{C}: exit 0" in result.output

    def test_findings_in_one_image_alone_exit_two(self):
        with patch(
            "automated_security_helper.cli.scan.run_ash_scan",
            side_effect=_exits_by_image({B: 2}),
        ):
            result = _scan("--image", A, "--image", B)
        assert result.exit_code == 2

    def test_one_image_keeps_the_directory_it_always_had(self, tmp_path):
        with patch(
            "automated_security_helper.cli.scan.run_ash_scan",
            side_effect=_exits_by_image({}),
        ) as run:
            result = _scan("--image", A, "--output-dir", str(tmp_path / "out"))
        assert result.exit_code == 0, result.output
        assert Path(str(run.call_args.kwargs["output_dir"])) == tmp_path / "out"
        assert "Scanning image 1 of" not in result.output

    def test_a_batch_beside_an_output_dir_puts_each_below_it(self, tmp_path):
        with patch(
            "automated_security_helper.cli.scan.run_ash_scan",
            side_effect=_exits_by_image({}),
        ) as run:
            result = _scan("--image", f"{A},{B}", "--output-dir", str(tmp_path / "out"))
        assert result.exit_code == 0, result.output
        for call in run.call_args_list:
            assert Path(str(call.kwargs["output_dir"])).parent == tmp_path / "out"


class TestTheRefusalsKeepTheirWordsForABatch:
    @pytest.mark.parametrize(
        "other,named",
        [
            (("--staged",), "--staged"),
            (("--use-existing",), "--use-existing"),
            (("--baseline", "base.json"), "--baseline"),
        ],
    )
    def test_each_is_refused_before_any_scan(self, other, named):
        with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
            result = _scan("--image", f"{A},{B}", *other)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert named in result.output
        assert run.call_count == 0

    def test_the_baseline_refusal_says_why_no_baseline_can_stand_for_an_image(self):
        result = _scan("--image", f"{A},{B}", "--baseline", "base.json")
        assert "scoped to a scanned directory" in result.output
        assert "digest" in result.output

    def test_a_list_beside_another_image_option_is_refused(self):
        result = _scan("--image", f"{A},{B}", "--image-archive", "image.tar")
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "only one may be given" in result.output

    def test_a_list_beside_source_dir_is_refused(self, tmp_path):
        result = _scan("--image", f"{A},{B}", "--source-dir", str(tmp_path))
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "one scan has one subject" in result.output

    @pytest.mark.parametrize("value", [f"{A},,{B}", ","])
    def test_an_empty_piece_is_a_usage_error(self, value):
        with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
            result = _scan("--image", value)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "empty image reference" in result.output
        assert run.call_count == 0

    def test_an_image_named_twice_is_a_usage_error(self):
        with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
            result = _scan("--image", A, "--image", A)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "more than once" in result.output
        assert run.call_count == 0

    @pytest.mark.parametrize(
        "other",
        [
            pytest.param(("--shard-index", "0", "--shard-count", "2"), id="shard"),
            pytest.param(("--phases", "convert"), id="convert-only"),
        ],
    )
    def test_the_real_run_refuses_a_batch_at_its_first_image(self, other):
        # Not patched: run_ash_scan's own refusal (usage exit) reaches the loop,
        # which stops there instead of repeating the refusal for every image.
        result = _scan("--image", f"{A},{B}", *other)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        assert f"{B}: not scanned" in result.output

    def test_a_shard_refusal_that_the_scan_makes_ends_the_batch_at_the_first(self):
        # run_ash_scan refuses a shard beside an image scan (exit 5); the same
        # refusal would repeat for every image, so the batch stops at the first.
        with patch(
            "automated_security_helper.cli.scan.run_ash_scan",
            side_effect=_exits_by_image({A: 5, B: 5}),
        ) as run:
            result = _scan(
                "--image", f"{A},{B}", "--shard-index", "0", "--shard-count", "2"
            )
        assert run.call_count == 1
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert f"{B}: not scanned" in result.output
