# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What every built-in reporter writes, for each of the three model shapes.

One snapshot file per reporter and shape, stored with the extension of the file ASH
writes (``ash.summary.md`` is snapshotted as ``.md``), so a change to any report a
user opens shows up as a diff of that document. The model is the canonical fixture
scan from tests/snapshot/support/fixture_model.py, built through ASH's own
aggregation, so a change to aggregation, suppression or metrics shows up here too.

The two workspace shapes render each reporter against the unified workspace model
with the context ``emit_workspace_reports`` uses. That is the document a MERGED or
WORKSPACE_SCOPED reporter writes to the workspace ``reports/`` directory. For a
PER_PROJECT reporter ASH withholds the document and writes a manifest entry instead
(snapshotted in test_snapshot_reporters_workspace.py); its snapshot here records what
it would emit for an N-project model, which is the evidence behind that ruling.
"""

from __future__ import annotations

import pytest

from tests.snapshot.support.reporter_catalog import (
    AWS_REPORTER_NAMES,
    BUILTIN_REPORTER_NAMES,
    MODEL_VARIANTS,
    build_reporter,
    reporter_classes,
    snapshot_extension,
)


def test_every_registered_reporter_is_snapshotted():
    """The registry and the snapshotted set are the same set of names.

    Read from both places a reporter can be registered: the plugin packages'
    ``ASH_REPORTERS`` lists, which plugin discovery reads, and the decorator
    registry, filtered to ASH's own plugin modules so a test double registered
    elsewhere in the session cannot affect the answer.
    """
    from automated_security_helper.plugins import ash_plugin_manager

    classes = reporter_classes()
    assert set(classes) == set(BUILTIN_REPORTER_NAMES) | set(AWS_REPORTER_NAMES)

    registered = {
        name
        for name, registration in ash_plugin_manager.plugin_library.reporters.items()
        if registration.plugin_module_path.startswith(
            "automated_security_helper.plugin_modules."
        )
    }
    assert registered == {cls.__name__ for cls in classes.values()}


@pytest.mark.parametrize("variant", MODEL_VARIANTS)
@pytest.mark.parametrize("reporter_name", BUILTIN_REPORTER_NAMES)
def test_builtin_reporter_output(
    reporter_name, variant, fixture_variant, text_snapshot
):
    model, context = fixture_variant(variant)
    reporter = build_reporter(reporter_classes()[reporter_name], context)

    document = reporter.report(model)

    assert document == text_snapshot(snapshot_extension(reporter))


@pytest.mark.parametrize("variant", ["workspace", "skipped-workspace"])
def test_workspace_project_rows(variant, fixture_variant, snapshot):
    """The per-project rows the markdown, text and html Projects sections render."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
        workspace_project_rows,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_skipped_rows import (
        skipped_project_detail,
        skipped_projects,
    )

    model, _ = fixture_variant(variant)

    assert {
        "project_rows": workspace_project_rows(model),
        "skipped_projects": [
            {
                "entry": entry.model_dump(mode="json"),
                "detail": skipped_project_detail(entry),
            }
            for entry in skipped_projects(model)
        ],
    } == snapshot
