"""A derived root spares a file only in a tree that holds the file and sits under the root.

``refused_derived_product`` skips a derived root that contains a scanned tree, so
a repository file is not judged a work product because the output directory sits
above it. In workspace mode there are two scanned trees (the workspace root and
the project), and the two tests that decide the skip, "the file is inside a tree"
and "the root contains a tree", were answered against different trees: a file the
workspace root held passed because the root also contained the project. A work
product under the root that the project does not hold is refused.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config.path_trust import (
    refused_derived_product,
    reset_path_refusal_warnings,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


def _workspace(tmp_path: Path) -> dict:
    """A workspace root ``w``, a project ``w/a/sub``, and a derived root ``w/a``
    that contains the project but also holds files the project does not."""
    workspace = tmp_path / "w"
    project = workspace / "a" / "sub"
    derived = workspace / "a"
    outside_project = derived / "scanners" / "x.yaml"
    inside_project = project / "x.yaml"
    for path in (outside_project, inside_project):
        path.parent.mkdir(parents=True)
        path.write_text("a: b\n")
    return {
        "config": SimpleNamespace(_scanned_root=workspace),
        "project": project,
        "derived": derived,
        "outside_project": outside_project,
        "inside_project": inside_project,
    }


def _refused(layout: dict, value: Path) -> bool:
    return refused_derived_product(
        value,
        source_dir=layout["project"],
        key="scanners.example.options.config_file",
        config=layout["config"],
        derived_dirs=[layout["derived"]],
    )


def test_a_work_product_the_workspace_holds_but_the_project_does_not_is_refused(
    tmp_path,
):
    layout = _workspace(tmp_path)

    assert _refused(layout, layout["outside_project"]) is True


def test_a_file_inside_the_project_under_the_derived_root_is_not_refused(tmp_path):
    layout = _workspace(tmp_path)

    assert _refused(layout, layout["inside_project"]) is False


def test_a_derived_root_that_is_not_above_the_file_refuses_it(tmp_path):
    """The control: with no scanned tree under the root, the old and the new test
    agree, and a file under the root is refused."""
    source = tmp_path / "repo"
    source.mkdir()
    output = tmp_path / "out"
    product = output / "work" / "converted" / "c.yaml"
    product.parent.mkdir(parents=True)
    product.write_text("a: b\n")

    refused = refused_derived_product(
        product,
        source_dir=source,
        key="scanners.example.options.config_file",
        config=SimpleNamespace(_scanned_root=source),
        derived_dirs=[output],
    )

    assert refused is True
