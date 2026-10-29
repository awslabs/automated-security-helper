# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value under the scan's output or work directory is refused by default.

``honored_path`` refuses a value that is not the operator's own write when it
resolves under a directory the scan derived from the repository (the output and
work directories). The directories are recorded on the config by every
``PluginContext`` that holds it, and ``operator_written`` defaults to False, so a
caller that passes neither ``derived_dirs`` nor an origin still gets the clause.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import (
    honored_path,
    reset_path_refusal_warnings,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture
def layout(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    output = tmp_path / "out"
    work = output / ASH_WORK_DIR_NAME
    work.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    product_in_output = output / "derived.yaml"
    product_in_work = work / "derived.yaml"
    unrelated = outside / "operator.yaml"
    for path in (product_in_output, product_in_work, unrelated):
        path.write_text("")
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    return {
        "source": source,
        "output": output,
        "work": work,
        "outside": outside,
        "in_output": product_in_output,
        "in_work": product_in_work,
        "unrelated": unrelated,
        "context": context,
    }


def test_a_path_under_the_output_dir_is_refused_with_no_kwargs(layout):
    refused = honored_path(
        layout["in_output"],
        source_dir=layout["source"],
        key="config_file",
        config=layout["context"].config,
    )
    assert refused is None


def test_a_path_under_the_work_dir_is_refused_with_no_kwargs(layout):
    refused = honored_path(
        layout["in_work"],
        source_dir=layout["source"],
        key="config_file",
        config=layout["context"].config,
    )
    assert refused is None


def test_the_operators_own_write_under_the_output_dir_is_honored(layout):
    honored = honored_path(
        layout["in_output"],
        source_dir=layout["source"],
        key="config_file",
        config=layout["context"].config,
        operator_written=True,
    )
    assert honored == layout["in_output"].resolve()


def test_a_path_outside_both_dirs_and_the_tree_is_honored_for_a_derived_value(
    layout,
):
    honored = honored_path(
        layout["unrelated"],
        source_dir=layout["source"],
        key="config_file",
        config=layout["context"].config,
    )
    assert honored == layout["unrelated"].resolve()


def test_a_path_under_a_repointed_work_dir_is_refused_with_no_kwargs(layout, tmp_path):
    moved = tmp_path / "moved-work"
    moved.mkdir()
    product = moved / "derived.yaml"
    product.write_text("")
    context = layout["context"]
    with pytest.warns(DeprecationWarning):
        context.work_dir = moved
    refused = honored_path(
        product,
        source_dir=layout["source"],
        key="config_file",
        config=context.config,
    )
    assert refused is None


def test_a_second_context_on_the_same_config_adds_its_dirs(layout, tmp_path):
    config = layout["context"].config
    other_output = tmp_path / "other-out"
    other_output.mkdir()
    product = other_output / "derived.yaml"
    product.write_text("")
    PluginContext(source_dir=layout["source"], output_dir=other_output, config=config)
    for path in (product, layout["in_output"]):
        assert (
            honored_path(
                path, source_dir=layout["source"], key="config_file", config=config
            )
            is None
        )
    assert len(config._derived_roots) == len(set(config._derived_roots))


def test_without_a_config_a_path_outside_the_tree_is_unchanged(layout):
    honored = honored_path(
        layout["in_output"],
        source_dir=layout["source"],
        key="config_file",
    )
    assert honored == layout["in_output"].resolve()


def test_a_config_copys_derived_roots_stay_its_own(layout, tmp_path):
    """The record is per configuration object. ``model_copy`` copies the
    private state shallowly, so an in-place append through a copy changed the
    original and every other copy; the recorder replaces the list instead."""
    config = layout["context"].config
    before = list(config._derived_roots)
    copied = config.model_copy()
    other_output = tmp_path / "copy-out"
    other_output.mkdir()
    PluginContext(source_dir=layout["source"], output_dir=other_output, config=copied)
    assert list(config._derived_roots) == before
    assert any(
        str(root).startswith(str(other_output.resolve()))
        for root in copied._derived_roots
    )


def test_a_path_under_the_workspace_output_dir_is_refused_with_no_kwargs(
    layout, tmp_path
):
    """Each workspace project scans with its own config, and one project's
    config can name a file under another project's slice of the workspace
    output, derived from that other repository: the workspace output
    directory is a derived root too."""
    ws_out = tmp_path / "workspace-out"
    product = ws_out / "other-project" / ASH_WORK_DIR_NAME / "derived.yaml"
    product.parent.mkdir(parents=True)
    product.write_text("")
    config = AshConfig()
    PluginContext(
        source_dir=layout["source"],
        output_dir=layout["output"],
        workspace_output_dir=ws_out,
        config=config,
    )
    refused = honored_path(
        product, source_dir=layout["source"], key="config_file", config=config
    )
    assert refused is None


def test_a_context_copy_that_moves_the_output_dir_records_it(layout, tmp_path):
    """A copy built with ``model_copy(update=...)`` runs neither validators
    nor assignments, so the context records the copy's directories itself."""
    config = layout["context"].config
    moved = tmp_path / "copied-out"
    product = moved / "derived.yaml"
    product.parent.mkdir(parents=True)
    product.write_text("")
    layout["context"].model_copy(update={"output_dir": moved})
    refused = honored_path(
        product, source_dir=layout["source"], key="config_file", config=config
    )
    assert refused is None


def test_a_context_built_without_validation_records_its_dirs(layout, tmp_path):
    """``model_construct`` skips the validators that record the directories,
    so the context records them itself."""
    config = AshConfig()
    out = tmp_path / "constructed-out"
    product = out / "derived.yaml"
    product.parent.mkdir(parents=True)
    product.write_text("")
    PluginContext.model_construct(
        source_dir=layout["source"], output_dir=out, config=config
    )
    refused = honored_path(
        product, source_dir=layout["source"], key="config_file", config=config
    )
    assert refused is None


def test_a_workspace_output_dir_assigned_later_is_recorded_too(layout, tmp_path):
    """The record follows an assignment of ``workspace_output_dir``, as it
    follows the output and work directories."""
    ws_out = tmp_path / "late-workspace-out"
    product = ws_out / "other-project" / ASH_WORK_DIR_NAME / "derived.yaml"
    product.parent.mkdir(parents=True)
    product.write_text("")
    config = AshConfig()
    context = PluginContext(
        source_dir=layout["source"], output_dir=layout["output"], config=config
    )
    context.workspace_output_dir = ws_out
    refused = honored_path(
        product, source_dir=layout["source"], key="config_file", config=config
    )
    assert refused is None
