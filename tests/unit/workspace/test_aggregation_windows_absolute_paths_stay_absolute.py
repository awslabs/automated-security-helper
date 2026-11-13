# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded Windows absolute path is shown as recorded, not placed under the project.

``inputs_not_scanned_for_project`` and ``converter_refusals_for_project`` keep an
absolute recorded path as it is and put the project's workspace-relative path in
front of a relative one. Both decided "absolute" with
``PurePosixPath(path).is_absolute()``, which is False for ``C:\\ws\\api\\nb.ipynb``,
so a Windows scanner's or converter's absolute path was shown as
``api/C:\\ws\\api\\nb.ipynb``: a path that names nothing, against the fields' own
contract ("the recorded path itself when absolute"). The module already reads a
drive anchor for scanner URIs (``_DRIVE_ANCHOR``); these tests pin that both
readers use the same rooted test, on both platforms, for both path spellings.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.workspace import aggregation

pytestmark = pytest.mark.unit


def _refusal(path: str) -> SimpleNamespace:
    return SimpleNamespace(
        converter="jupyter",
        path=path,
        member=None,
        reason="too large",
        limit=None,
        failed=False,
        accepted=False,
        scan_incomplete=True,
        # None, as ConverterRefusal records it: the field is an Optional count of
        # members, and the record model refuses a tuple.
        unlisted_members=None,
    )


@pytest.mark.parametrize(
    "recorded",
    ["C:\\ws\\api\\nb.ipynb", "C:/ws/api/nb.ipynb", "/ws/api/nb.ipynb"],
)
def test_an_absolute_converter_path_is_kept_as_recorded(monkeypatch, recorded):
    monkeypatch.setattr(
        "automated_security_helper.utils.converter_refusals.converter_refusals",
        lambda results: [_refusal(recorded)],
    )

    [record] = aggregation.converter_refusals_for_project(object(), "api")

    assert record.path == recorded


def test_a_relative_converter_path_gains_the_project_prefix(monkeypatch):
    """Control: the relative shape is still placed under the project."""
    monkeypatch.setattr(
        "automated_security_helper.utils.converter_refusals.converter_refusals",
        lambda results: [_refusal("notebooks/nb.ipynb")],
    )

    [record] = aggregation.converter_refusals_for_project(object(), "api")

    assert record.path == "api/notebooks/nb.ipynb"


@pytest.mark.parametrize(
    "recorded",
    ["C:\\ws\\api\\package-lock.json", "C:/ws/api/package-lock.json", "/ws/api/x"],
)
def test_an_absolute_not_scanned_input_is_kept_as_recorded(monkeypatch, recorded):
    monkeypatch.setattr(
        "automated_security_helper.core.unified_metrics.inputs_not_scanned",
        lambda results: [("npm-audit", recorded, "offline")],
    )

    [entry] = aggregation.inputs_not_scanned_for_project(object(), "api")

    assert entry.path == recorded


def test_a_relative_not_scanned_input_gains_the_project_prefix(monkeypatch):
    """Control for the other reader."""
    monkeypatch.setattr(
        "automated_security_helper.core.unified_metrics.inputs_not_scanned",
        lambda results: [("npm-audit", "web/package-lock.json", "offline")],
    )

    [entry] = aggregation.inputs_not_scanned_for_project(object(), "api")

    assert entry.path == "api/web/package-lock.json"
