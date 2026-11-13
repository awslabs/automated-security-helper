# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``file:`` artifact uri is written back percent-encoded after it is rebased.

``rebase_run_for_project`` decodes a ``file:`` URI to compare paths and then
wrote the decoded text into ``artifactLocation.uri``. That field is a URI
reference, so a reader decodes it again: ``x%2541.py`` (a file named ``x%41.py``)
was written ``x%41.py`` and read as ``xA.py``, and ``a%23b.py`` (a file named
``a#b.py``) was written ``a#b.py``, whose ``#`` starts a fragment. The decoded
form is still what every comparison and ``workspace_uri`` use; only the written
uri is encoded again, and only when the source was a ``file:`` URI.
"""

from __future__ import annotations

import pytest

from automated_security_helper.workspace.aggregation import (
    PROJECT_ROOT_URI_BASE_ID,
    rebase_run_for_project,
)
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit


@pytest.fixture
def project(tmp_path):
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=(tmp_path / "ws" / "api").as_posix(),
        label="api",
        display_label="api",
    )


def _run(uri: str) -> dict:
    return {
        "tool": {"driver": {"name": "bandit"}},
        "results": [
            {
                "ruleId": "B101",
                "level": "error",
                "properties": {"scanner_name": "bandit"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            }
        ],
    }


def _artifact(run: dict) -> dict:
    return run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]


@pytest.mark.parametrize(
    ("name", "written"),
    [("x%41.py", "x%2541.py"), ("a#b.py", "a%23b.py"), ("my file.py", "my%20file.py")],
)
def test_a_file_uri_is_written_with_the_name_encoded_again(
    project, tmp_path, name, written
):
    absolute = (tmp_path / "ws" / "api" / name).as_uri()

    rebased, unconvertible = rebase_run_for_project(_run(absolute), project)

    # RED at the base for each name: the decoded name was written, which a reader
    # of the uri decodes a second time (xA.py), reads a fragment from (a#b.py) or
    # takes a space in (my file.py) where a URI reference has none.
    assert unconvertible == 0
    assert _artifact(rebased)["uri"] == written
    assert _artifact(rebased)["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID


def test_the_workspace_uri_keeps_the_decoded_name(project, tmp_path):
    """The comparison form is unchanged: the file is named ``x%41.py``."""
    absolute = (tmp_path / "ws" / "api" / "x%41.py").as_uri()

    rebased, _ = rebase_run_for_project(_run(absolute), project)

    assert rebased["results"][0]["properties"]["workspace_uri"] == "api/x%41.py"


def test_a_bare_rooted_path_keeps_its_percent_sign(project, tmp_path):
    """Control, green on both sides: without a scheme the ``%`` is part of the name."""
    bare = (tmp_path / "ws" / "api" / "x%41.py").as_posix()

    rebased, _ = rebase_run_for_project(_run(bare), project)

    assert _artifact(rebased)["uri"] == "x%41.py"
