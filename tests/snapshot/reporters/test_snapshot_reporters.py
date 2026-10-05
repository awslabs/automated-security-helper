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

# Every reporter renders the fixture scan under the pinned clock, so each duration
# and "time since scan" it prints is a fixed value a user reads.
pytestmark = pytest.mark.snapshot_masking(
    mask_durations=False, mask_duration_keys=False
)


def test_every_registered_reporter_is_snapshotted():
    """The registry and the snapshotted set are the same set of names.

    Read from both places a reporter can be registered: the plugin packages'
    ``ASH_REPORTERS`` lists, which plugin discovery reads, and every class under
    ``automated_security_helper.plugin_modules`` that ``@ash_reporter_plugin``
    marked. The second is found by importing the modules rather than by reading
    the plugin manager's registry, which is process-global state that only the
    manager may touch (tests/unit/workspace/test_project_isolation.py).
    """
    import importlib
    import pkgutil

    import automated_security_helper.plugin_modules as plugin_modules

    classes = reporter_classes()
    assert set(classes) == set(BUILTIN_REPORTER_NAMES) | set(AWS_REPORTER_NAMES)

    decorated: set[str] = set()
    unimportable: dict[str, str] = {}
    for info in pkgutil.walk_packages(
        plugin_modules.__path__, prefix=f"{plugin_modules.__name__}."
    ):
        try:
            module = importlib.import_module(info.name)
        except ImportError as exc:  # an optional scanner dependency, say
            unimportable[info.name] = str(exc)
            continue
        decorated.update(
            obj.__name__
            for obj in vars(module).values()
            if isinstance(obj, type)
            and getattr(obj, "ash_plugin_type", None) == "reporter"
            and obj.__module__ == module.__name__
        )
    # A reporter module that cannot be imported would be missing from both
    # sides of the comparison, so it has to fail here instead.
    assert not {name for name in unimportable if "reporter" in name}, unimportable
    assert decorated == {cls.__name__ for cls in classes.values()}


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
