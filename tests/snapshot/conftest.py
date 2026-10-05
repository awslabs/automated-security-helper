# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures every snapshot test uses. Read DEVELOPMENT.md "Snapshot tests" first.

A snapshot here is a statement of what a user sees. Changing one is a decision, so:

- a snapshot only changes when someone runs ``pytest --snapshot-update`` and commits
  the result with a ``Snapshot-Update: <reason>`` trailer (checked in CI by
  .github/scripts/check-snapshot-trailers.py);
- CI never passes ``--snapshot-update`` (asserted by
  tests/snapshot/test_snapshot_policy.py, and refused at configure time below);
- a missing snapshot fails, and a snapshot nothing asserts any more fails the session
  as unused.

Use ``snapshot`` for structured data and ``text_snapshot(ext)`` for rendered text. Both
apply the one shared :class:`SnapshotNormalizer`; never normalize inside a test.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest
from syrupy.assertion import SnapshotAssertion

from tests.snapshot.support.extensions import (
    NormalizingAmberExtension,
    NormalizingTextFileExtension,
    bind,
)
from tests.snapshot.support.normalize import (
    SnapshotNormalizer,
    default_normalizer,
    pinned_terminal_env,
)

#: Environment that changes what ASH prints. Unset for every snapshot test, so a
#: snapshot taken on a laptop matches the one CI takes: ASH switches its console
#: output on CI and CODEBUILD_BUILD_ID, and the colour variables override NO_COLOR.
_UNSET_FOR_SNAPSHOTS = (
    "CI",
    "ISCI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CODEBUILD_BUILD_ID",
    "FORCE_COLOR",
    "CLICOLOR_FORCE",
    "PY_COLORS",
    "ASH_DEBUG",
    "ASH_VERBOSE",
    "ASH_LOG_TO_STDERR",
    "ASH_ACTUAL_OUTPUT_DIR",
    "ASH_CONFIG",
    "ASH_DEFAULT_SEVERITY_LEVEL",
    "ASH_PROJECT_NAME",
    "ASH_IN_CONTAINER",
    "ASH_OFFLINE",
)


def pytest_configure(config: pytest.Config) -> None:
    # Belt and braces with test_snapshot_policy.py, which reads the workflow files: a
    # CI job that somehow passes --snapshot-update would turn every intended diff into
    # a silent rewrite, so the session refuses to start.
    if config.getoption("--snapshot-update", default=False) and (
        os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI") == "true"
    ):
        raise pytest.UsageError(
            "--snapshot-update is refused under CI. Update snapshots locally, review "
            "the diff, and commit it with a 'Snapshot-Update: <reason>' trailer."
        )


@pytest.fixture(autouse=True)
def _pinned_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render every snapshot for the same terminal: 100 columns, no colour, no TTY."""
    for name in _UNSET_FOR_SNAPSHOTS:
        monkeypatch.delenv(name, raising=False)
    for name, value in pinned_terminal_env().items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def snapshot_normalizer(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> SnapshotNormalizer:
    """The shared normalizer, with this test's temp dirs registered.

    A test that creates paths elsewhere registers them with ``add_root`` before it
    asserts; a test that learns an id it cannot choose (a scan id) uses ``add_literal``.
    """
    return default_normalizer(tmp_paths=[tmp_path, tmp_path_factory.getbasetemp()])


@pytest.fixture
def snapshot(
    snapshot: SnapshotAssertion, snapshot_normalizer: SnapshotNormalizer
) -> SnapshotAssertion:
    """syrupy's ``snapshot``, normalized. For dicts, lists and short strings."""
    return snapshot.use_extension(bind(NormalizingAmberExtension, snapshot_normalizer))


@pytest.fixture
def text_snapshot(
    snapshot: SnapshotAssertion, snapshot_normalizer: SnapshotNormalizer
) -> Callable[[str], SnapshotAssertion]:
    """``text_snapshot("md")`` -> an assertion storing one ``.md`` file per snapshot.

    The file lands in ``__snapshots__/<test module>/<test name>.<ext>``. Pass
    ``name=`` through syrupy as usual (``text_snapshot("md")(name="narrow")``) when one
    test asserts more than one document.
    """

    def _for(extension: str) -> SnapshotAssertion:
        return snapshot.use_extension(
            bind(
                NormalizingTextFileExtension,
                snapshot_normalizer,
                file_extension=extension,
            )
        )

    return _for


# --------------------------------------------------------------------------- #
# The canonical fixture scan. Built by tests/snapshot/support/fixture_model.py
# through ASH's own aggregation; its findings and scanner statuses are listed in
# tests/test_data/snapshot_fixture/README.md. Imports are local so this section
# stays an append to the fixtures above.
# --------------------------------------------------------------------------- #


@pytest.fixture
def pinned_clock(monkeypatch: pytest.MonkeyPatch):
    """Pin datetime.now() and uuid4 in every module that stamps them into output.

    Returns the clock; the fixture-model builders advance it from scan start to
    report time themselves.
    """
    from tests.snapshot.support.fixture_model import pin_clock

    return pin_clock(monkeypatch)


@pytest.fixture
def fixture_context(tmp_path: Path):
    """The PluginContext of the single-directory fixture scan."""
    from tests.snapshot.support.fixture_model import fixture_plugin_context

    return fixture_plugin_context(tmp_path)


@pytest.fixture
def fixture_model(pinned_clock, fixture_context, tmp_path: Path):
    """The single-directory fixture scan, as reporters receive it."""
    from tests.snapshot.support.fixture_model import build_fixture_model

    return build_fixture_model(tmp_path, fixture_context)


@pytest.fixture
def fixture_workspace_model(
    pinned_clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The two-project workspace fixture scan, as merged reporters receive it."""
    from tests.snapshot.support.fixture_model import build_fixture_workspace_model

    return build_fixture_workspace_model(tmp_path, monkeypatch)


@pytest.fixture
def fixture_skipped_workspace_model(
    pinned_clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The workspace fixture scan with a third, skipped project (``docs``)."""
    from tests.snapshot.support.fixture_model import build_fixture_workspace_model

    return build_fixture_workspace_model(
        tmp_path, monkeypatch, with_skipped_project=True
    )


@pytest.fixture
def fixture_variant(request: pytest.FixtureRequest, tmp_path: Path):
    """``fixture_variant("single" | "workspace" | "skipped-workspace")`` -> (model, context).

    The context is the one ASH gives reporters for that shape: the fixture
    repository's own config for a single scan, and the workspace-level default
    config ``emit_workspace_reports`` uses for the two workspace shapes.
    """
    from tests.snapshot.support.fixture_model import workspace_reporter_context

    def _for(variant: str):
        if variant == "single":
            return (
                request.getfixturevalue("fixture_model"),
                request.getfixturevalue("fixture_context"),
            )
        name = {
            "workspace": "fixture_workspace_model",
            "skipped-workspace": "fixture_skipped_workspace_model",
        }[variant]
        model = request.getfixturevalue(name)
        return model, workspace_reporter_context(model, tmp_path)

    return _for
