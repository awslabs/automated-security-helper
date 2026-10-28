# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Telling committed files from ASH's own output walks nothing and writes nothing.

``committed_output_files`` names the files a repository committed to ASH's output
directories, so that the executor's drop and the suppression step keep the results
located in them. It read them from the scan set, built by ``scan_set_of`` when the
run had written none. ``ash merge`` has no run and writes no scan set, so its
suppression step walked the whole working directory the first time a result fell
in the merge output directory, and wrote ``ash-scan-set-files-list.txt`` and
``ash-ignore-report.txt`` into it. Measured with merge's context, ``--output-dir .``
(relocated to ``./.ash/ash_output``) and results at ``a.py``,
``.ash/ash_output/hidden/x.py`` (committed) and ``.ash/ash_output/reports/ash.sarif``:
one walk of the working directory and both files written, in a git checkout and
outside one.

The list is read only when this run wrote it and it is intact (run ID and
digests, ``get_scan_set``). Otherwise git is asked which files it tracks in each
named directory, which is what the walk asked it: the same files are kept, with no
walk and nothing written. A context with no run ID, as ``ash merge`` builds, never
reads a list back and always asks git.

``ash merge`` itself does not apply the output-directory exclusion: each shard
applies it with its own git answer and run ID, and outside git the merge's answer
would drop a committed file every shard kept. The tests that call
``apply_suppressions_to_sarif`` with merge's context pin the exclusion for any
caller that builds one.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.merge import _relocate_colliding_output_dir
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PhysicalLocation2,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils import scan_output_dirs
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.utils.scan_output_dirs import committed_output_files
from tests.unit.workspace.test_execution import _git as _fixture_git

AshConfig.model_rebuild()
PluginContext.model_rebuild()

LISTS = (
    "ash-ignore-report.txt",
    "ash-scan-set-files-list.txt",
    "ash-scan-set-run.json",
)
COMMITTED = ".ash/ash_output/hidden/x.py"
ASH_WROTE = ".ash/ash_output/reports/ash.sarif"
RUN_A = "a" * 32


def _git(cwd: Path, *args: str) -> None:
    """The fixtures' git (``test_execution._git``, which reads none of the
    developer's own config), required to succeed."""
    result = _fixture_git(cwd, *args)
    assert result.returncode == 0, (args, result.stderr)


@pytest.fixture
def isolated_git(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))


def _checkout(tmp_path: Path, *, in_git: bool) -> Path:
    root = tmp_path / "repo"
    for relative in ("a.py", COMMITTED, ASH_WROTE):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value = 'x'\n", encoding="utf-8")
    if in_git:
        _git(root, "init", "-q")
        _git(root, "add", "a.py", COMMITTED)
    return root


def _merge_context() -> PluginContext:
    """The context ``ash merge --output-dir .`` builds (cli/merge.py)."""
    output_dir_path = _relocate_colliding_output_dir(Path("."))
    output_dir_path.mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=Path.cwd(),
        output_dir=output_dir_path,
        work_dir=output_dir_path.joinpath("work"),
        config=AshConfig(),
        ignore_suppressions=False,
    )


def _result(uri: str) -> Result:
    return Result(
        ruleId="R1",
        level="error",
        message=Message(text=f"finding in {uri}"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(artifactLocation=ArtifactLocation(uri=uri))
                )
            )
        ],
    )


def _kept_by_the_suppression_step(context: PluginContext, uris) -> list[str]:
    report = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="merged")),
                results=[_result(uri) for uri in uris],
            )
        ]
    )
    report = apply_suppressions_to_sarif(sarif_report=report, plugin_context=context)
    return sorted(
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    )


def _walk_spy():
    return patch.object(
        gss,
        "_collect_ignorefiles_and_all_files",
        wraps=gss._collect_ignorefiles_and_all_files,
    )


def test_merge_keeps_a_committed_file_without_a_walk_or_a_write(
    tmp_path, monkeypatch, isolated_git
):
    root = _checkout(tmp_path, in_git=True)
    monkeypatch.chdir(root)
    context = _merge_context()

    with _walk_spy() as walk:
        kept = _kept_by_the_suppression_step(context, ["a.py", COMMITTED, ASH_WROTE])

    assert kept == sorted(["a.py", COMMITTED])
    assert walk.call_count == 0
    output = root / ".ash" / "ash_output"
    assert [name for name in LISTS if (output / name).exists()] == []


def test_merge_outside_git_walks_nothing_and_writes_nothing(
    tmp_path, monkeypatch, isolated_git
):
    root = _checkout(tmp_path, in_git=False)
    monkeypatch.chdir(root)
    context = _merge_context()

    with _walk_spy() as walk:
        kept = _kept_by_the_suppression_step(context, ["a.py", ASH_WROTE])

    assert kept == ["a.py"]
    assert walk.call_count == 0
    output = root / ".ash" / "ash_output"
    assert [name for name in LISTS if (output / name).exists()] == []


def _merged_uris(merged) -> list[str]:
    return sorted(
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in merged.sarif.runs[0].results
    )


@pytest.mark.parametrize("in_git", [False, True], ids=["outside-git", "in-git"])
def test_merge_keeps_a_committed_file_every_shard_kept(
    tmp_path, monkeypatch, isolated_git, in_git
):
    """Each shard decided which results in its output directories are committed
    files, with its own git answer and run ID, and dropped the rest. ash merge has
    no run ID and may run outside git, where that answer is "nothing is
    committed", so the merge does not decide again: it keeps a committed x.py
    every shard kept, in git or not."""
    from automated_security_helper.cli.merge import apply_aggregated_suppressions
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    root = _checkout(tmp_path, in_git=in_git)
    monkeypatch.chdir(root)
    context = _merge_context()
    merged = AshAggregatedResults()
    merged.sarif = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="merged")),
                results=[_result("a.py"), _result(COMMITTED)],
            )
        ]
    )

    with _walk_spy() as walk:
        merged = apply_aggregated_suppressions(merged, context)

    assert _merged_uris(merged) == sorted(["a.py", COMMITTED])
    assert walk.call_count == 0


def test_merge_applies_the_merged_configs_suppressions(
    tmp_path, monkeypatch, isolated_git
):
    """Only the output-directory exclusion is the shards' to decide; a suppression
    in the configuration the shards recorded applies at merge."""
    from automated_security_helper.cli.merge import apply_aggregated_suppressions
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.core import AshSuppression

    root = _checkout(tmp_path, in_git=False)
    monkeypatch.chdir(root)
    context = _merge_context()
    context.config.global_settings.suppressions = [
        AshSuppression(rule_id="R1", path=COMMITTED, reason="reviewed")
    ]
    merged = AshAggregatedResults()
    merged.sarif = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="merged")),
                results=[_result("a.py"), _result(COMMITTED)],
            )
        ]
    )

    merged = apply_aggregated_suppressions(merged, context)

    suppressed = {
        r.locations[0].physicalLocation.root.artifactLocation.uri: bool(r.suppressions)
        for r in merged.sarif.runs[0].results
    }
    assert suppressed == {"a.py": False, COMMITTED: True}


def test_merge_leaves_a_committed_scan_set_pair_as_it_was(
    tmp_path, monkeypatch, isolated_git
):
    """A repository that commits the two list files to its .ash/ash_output keeps
    them byte for byte through ``ash merge``."""
    root = _checkout(tmp_path, in_git=True)
    output = root / ".ash" / "ash_output"
    committed_pair = {
        "ash-ignore-report.txt": b"# the repository's own report\n",
        "ash-scan-set-files-list.txt": b"a.py\n",
    }
    for name, data in committed_pair.items():
        (output / name).write_bytes(data)
    _git(root, "add", *(f".ash/ash_output/{name}" for name in committed_pair))
    monkeypatch.chdir(root)
    context = _merge_context()

    kept = _kept_by_the_suppression_step(context, [COMMITTED, ASH_WROTE])

    assert kept == [COMMITTED]
    assert {name: (output / name).read_bytes() for name in committed_pair} == (
        committed_pair
    )
    assert not (output / "ash-scan-set-run.json").exists()


def test_a_run_reads_its_own_list_and_asks_git_nothing(
    tmp_path, monkeypatch, isolated_git
):
    """In a scan, the list the orchestrator wrote under the run's ID decides, as
    it decides what the scanners were given."""
    root = _checkout(tmp_path, in_git=True)
    output = tmp_path / "out"
    scan_set(source=str(root), output=str(output), run_id=RUN_A)
    context = PluginContext(
        source_dir=root, output_dir=output, config=AshConfig(), run_id=RUN_A
    )
    named = [root / ".ash" / "ash_output"]

    with (
        patch.object(
            gss,
            "_collect_ignorefiles_and_all_files",
            side_effect=AssertionError("walked the tree"),
        ),
        patch.object(
            scan_output_dirs,
            "tracked_files_in",
            side_effect=AssertionError("asked git"),
        ),
    ):
        committed = committed_output_files(context, dirs=named)

    assert committed == {(root / COMMITTED).resolve()}


@pytest.mark.parametrize("run_id", [None, "b" * 32], ids=["no-run-id", "other-run"])
def test_without_this_runs_list_git_is_asked_and_nothing_is_walked(
    tmp_path, monkeypatch, isolated_git, run_id
):
    root = _checkout(tmp_path, in_git=True)
    output = tmp_path / "out"
    scan_set(source=str(root), output=str(output), run_id=RUN_A)
    before = {name: (output / name).read_bytes() for name in LISTS}
    context = PluginContext(
        source_dir=root, output_dir=output, config=AshConfig(), run_id=run_id
    )

    with _walk_spy() as walk:
        committed = committed_output_files(context)

    assert committed == {(root / COMMITTED).resolve()}
    assert walk.call_count == 0
    assert {name: (output / name).read_bytes() for name in LISTS} == before
