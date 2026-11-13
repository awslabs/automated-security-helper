# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scan_set(restrict_to=...)``: the one seam that scopes a --staged run.

The orchestrator records the run's scan set with ``restrict_to`` set to the
staged files. Everything that enumerates its own inputs from the run's scan set
-- detect-secrets, cdk-nag, cfn-nag, npm-audit, and the converters' candidate
counts -- then sees the staged files and nothing else, which is how a converter
with no staged notebook is skipped without any converter-side code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set

pytestmark = pytest.mark.unit

NOTEBOOK = json.dumps({"cells": [], "metadata": {}, "nbformat": 4, "nbformat_minor": 5})


@pytest.fixture
def tree(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n")
    (source / "nb.ipynb").write_text(NOTEBOOK)
    output = tmp_path / "output"
    output.mkdir()
    return source, output


def _names(entries):
    return sorted(Path(entry).name for entry in entries)


def test_restrict_to_limits_the_returned_and_the_recorded_list(tree):
    source, output = tree
    first = scan_set(
        source=str(source), output=str(output), run_id="r1", restrict_to=["a.py"]
    )
    assert _names(first) == ["a.py"]

    recorded = (output / "ash-scan-set-files-list.txt").read_text().splitlines()
    assert any(line.endswith("a.py") for line in recorded)
    assert not any(line.endswith("nb.ipynb") for line in recorded)

    # A later call of the same run without the argument -- every scanner's --
    # reads the restricted list back rather than walking the tree.
    second = scan_set(source=str(source), output=str(output), run_id="r1")
    assert _names(second) == ["a.py"]


def test_without_restrict_to_the_walk_is_the_whole_tree(tree):
    """The control: the same tree, no staged scope, both files."""
    source, output = tree
    everything = scan_set(source=str(source), output=str(output), run_id="r2")
    assert _names(everything) == ["a.py", "nb.ipynb"]


def test_a_restriction_no_walked_file_matches_empties_the_scan_set(tree):
    source, output = tree
    nothing = scan_set(
        source=str(source),
        output=str(output),
        run_id="r3",
        restrict_to=["not-here.txt"],
    )
    assert nothing == []


def test_the_results_filter_under_a_staged_set_keeps_what_it_cannot_place(tmp_path):
    """The staged set rides the same engine filter as --changed-files-only
    (utils/changed_files.filter_results_to_changed_files), whose documented
    shape holds under --staged too: a finding in a staged file is kept, one in
    an unstaged file is dropped, one with NO location is kept (it cannot be
    placed outside the staged files), and one in a CONVERTED file is placed by
    the source the converter read, so a staged notebook keeps its findings."""
    from automated_security_helper.interactions.run_ash_scan import (
        _staged_findings_filter_set,
    )
    from automated_security_helper.utils.changed_files import (
        filter_results_to_changed_files,
    )
    from automated_security_helper.utils.finding_identity import (
        CONVERTED_PATH_PROPERTY,
    )
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Location,
        Message1,
        PhysicalLocation,
        PhysicalLocation2,
        PropertyBag,
        Region,
        Result,
        Run,
        SarifReport,
        Tool,
        ToolComponent,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    def located(uri):
        return Result(
            message=Message1(text="finding"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        root=PhysicalLocation2(
                            artifactLocation=ArtifactLocation(uri=uri),
                            region=Region(startLine=1),
                        )
                    )
                )
            ],
        )

    source = tmp_path / "repo"
    source.mkdir()
    staged_set = _staged_findings_filter_set(source, ["app.py", "nb/analysis.ipynb"])

    converted = located("jupyter/analysis-converted.py")
    converted.properties = PropertyBag()
    setattr(
        converted.properties, CONVERTED_PATH_PROPERTY, "jupyter/analysis-converted.py"
    )
    unlocated = Result(message=Message1(text="no location"))

    results = AshAggregatedResults()
    results.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="test-tool")),
                results=[
                    located("app.py"),
                    located("other.py"),
                    unlocated,
                    converted,
                ],
            )
        ],
    )

    filtered = filter_results_to_changed_files(
        results,
        staged_set,
        source,
        converted_sources={"jupyter/analysis-converted.py": "nb/analysis.ipynb"},
    )

    survivors = filtered.sarif.runs[0].results
    uris = [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        if r.locations
        else None
        for r in survivors
    ]
    assert "app.py" in uris, "the staged file's finding survives"
    assert "other.py" not in uris, "an unstaged file's finding is out of scope"
    assert None in uris, "a finding with no location is kept"
    assert "jupyter/analysis-converted.py" in uris, (
        "a converted finding is placed by its staged source and kept"
    )


def test_a_converter_with_no_staged_candidate_counts_zero(tree):
    """The converter-skip case of --staged, measured end to end: the run's
    recorded scan set holds only a staged .py, so the Jupyter converter's
    candidate count -- what ConvertPhase skips on -- is zero while a notebook
    sits in the tree; restricted TO the notebook, it counts one."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
        JupyterConverterConfig,
    )

    source, output = tree
    work = output / "work"
    work.mkdir()

    scan_set(source=str(source), output=str(output), run_id="r4", restrict_to=["a.py"])
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=work,
        config=AshConfig(project_name="test"),
        run_id="r4",
        staged_files=["a.py"],
    )
    converter = JupyterConverter(context=context, config=JupyterConverterConfig())
    assert converter.candidate_input_count() == 0

    output_with_notebook = output.parent / "output2"
    output_with_notebook.mkdir()
    (output_with_notebook / "work").mkdir()
    scan_set(
        source=str(source),
        output=str(output_with_notebook),
        run_id="r5",
        restrict_to=["nb.ipynb"],
    )
    staged_context = PluginContext(
        source_dir=source,
        output_dir=output_with_notebook,
        work_dir=output_with_notebook / "work",
        config=AshConfig(project_name="test"),
        run_id="r5",
        staged_files=["nb.ipynb"],
    )
    staged_converter = JupyterConverter(
        context=staged_context, config=JupyterConverterConfig()
    )
    assert staged_converter.candidate_input_count() == 1
