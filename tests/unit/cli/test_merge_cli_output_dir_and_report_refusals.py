# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash merge`` writes, and where, when its output directory is a bad choice.

An ``--output-dir`` that held one of the ``--results`` files replaced that
shard's results with the merged report, and a second merge over the same
directory then read the merged report as one shard of itself. A report path
refused after the merged results file was written left that file behind, so a
later ``ash report`` read a refused merge as a completed one. The relocation
that keeps the output directory from being an ancestor of the working directory
relocated once without looking again, so a working directory inside the
relocated path still had it as an ancestor. And the merge named its work
directory ``work`` where every other component derives ``converted``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from automated_security_helper.cli import merge as merge_module
from automated_security_helper.cli.merge import (
    RESULTS_FILE_NAME,
    _relocate_colliding_output_dir,
)
from automated_security_helper.core.constants import (
    ASH_EXIT_USAGE_ERROR,
    ASH_WORK_DIR_NAME,
)
from tests.unit.cli.test_merge import TestMergeCli, build_shards, write_shards

pytestmark = pytest.mark.unit


def _args(shard_paths, output_dir):
    args = []
    for path in shard_paths:
        args += ["--results", path]
    return args + ["--output-dir", str(output_dir), "--output-formats", "sarif"]


class TestAnOutputDirHoldingAShardIsRefused:
    def test_the_shards_results_file_is_left_as_written(self, tmp_path):
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(2))
        shard_file = Path(shard_paths[0])
        before = shard_file.read_bytes()

        result = TestMergeCli()._invoke(_args(shard_paths, shard_file.parent))

        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        assert shard_file.read_bytes() == before
        console = " ".join(result.output.split())
        assert "holds the shard results file" in console, result.output

    def test_a_shard_given_as_a_directory_is_compared_by_its_file(self, tmp_path):
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(2))
        shard_dir = Path(shard_paths[1]).parent
        before = Path(shard_paths[1]).read_bytes()
        args = ["--results", shard_paths[0], "--results", str(shard_dir)]
        args += ["--output-dir", str(shard_dir), "--output-formats", "sarif"]

        result = TestMergeCli()._invoke(args)

        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        assert Path(shard_paths[1]).read_bytes() == before

    def test_an_output_dir_beside_the_shards_merges(self, tmp_path):
        """The control: a sibling directory is not the shard's."""
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(2))
        output_dir = tmp_path / "artifacts" / "merged"

        result = TestMergeCli()._invoke(_args(shard_paths, output_dir))

        assert result.exit_code == 2, result.output
        assert (output_dir / RESULTS_FILE_NAME).is_file()


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
class TestARefusedReportLeavesNoMergedFile:
    def test_the_merged_results_file_is_removed_with_the_refusal(self, tmp_path):
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(2))
        output_dir = tmp_path / "merged"
        (output_dir / "reports").mkdir(parents=True)
        outside = tmp_path / "outside.sarif"
        outside.write_text("unchanged", encoding="utf-8")
        (output_dir / "reports" / "ash.sarif").symlink_to(outside)

        result = TestMergeCli()._invoke(_args(shard_paths, output_dir))

        assert result.exit_code == 1, result.output
        assert not (output_dir / RESULTS_FILE_NAME).exists(), result.output
        console = "".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        assert "".join(
            f"{RESULTS_FILE_NAME} written by this run was removed".split()
        ) in (console), result.output
        assert outside.read_text(encoding="utf-8") == "unchanged"


class TestTheRelocatedOutputDirIsCheckedAgain:
    def test_a_cwd_inside_the_relocation_target_is_relocated_further(
        self, tmp_path, monkeypatch
    ):
        output_dir = tmp_path / "out"
        inside = output_dir / ".ash" / "ash_output"
        inside.mkdir(parents=True)
        monkeypatch.chdir(inside)

        relocated = _relocate_colliding_output_dir(output_dir)

        assert not Path.cwd().resolve().is_relative_to(relocated.resolve()), relocated

    def test_an_ordinary_collision_is_relocated_once(self, tmp_path, monkeypatch):
        """The control: the first relocation is kept when it already suffices."""
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        monkeypatch.chdir(output_dir)

        relocated = _relocate_colliding_output_dir(output_dir)

        assert relocated == output_dir / ".ash" / "ash_output"


class TestTheWorkDirIsNamedAsEveryOtherComponentNamesIt:
    def test_the_plugin_context_work_dir_is_the_converted_directory(
        self, tmp_path, monkeypatch
    ):
        contexts = []
        real = merge_module.PluginContext

        def recording(*args, **kwargs):
            context = real(*args, **kwargs)
            contexts.append(context)
            return context

        monkeypatch.setattr(merge_module, "PluginContext", recording)
        shard_paths = write_shards(tmp_path / "artifacts", build_shards(2))
        output_dir = tmp_path / "merged"

        result = TestMergeCli()._invoke(_args(shard_paths, output_dir))

        assert result.exit_code == 2, result.output
        assert contexts, "the merge built no plugin context"
        assert {Path(context.work_dir).name for context in contexts} == {
            ASH_WORK_DIR_NAME
        }
        assert ASH_WORK_DIR_NAME == "converted"
