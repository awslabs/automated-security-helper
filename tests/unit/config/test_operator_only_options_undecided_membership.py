# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which files ``RepositorySettings`` reports as placed only by an unfinished walk.

A config file is the repository's when its resolved path or the name that
reached it is inside a tree. The name's link walk can end before the last link;
the file then counts as the repository's and its places are listed as undecided, so
a warning does not claim a location. That holds only where nothing else
established one:

* A file whose resolved path is inside a tree is decided, whatever the walk of
  the name it was reached by did.
* A place that a file with an established location also left out is not
  undecided, in whichever order the two files were read.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.config.operator_only_options import RepositorySettings

pytestmark = pytest.mark.unit

LIMIT_PLACE = "scanners.detect-secrets.options.max_worker_output_mib"
SCOPE_PLACE = "reporters.aws-security-hub.options.findings_scope"

_LIMIT = {"scanners": {"detect-secrets": {"options": {"max_worker_output_mib": 1024}}}}
_LIMIT_AND_SCOPE = {
    **_LIMIT,
    "reporters": {"aws-security-hub": {"options": {"findings_scope": "a-scope"}}},
}


@pytest.fixture
def walk_stops(monkeypatch):
    """Every link walk of a name stops before it reaches the end."""
    monkeypatch.setattr(sandbox_grants, "_walk_links", lambda path: ([], False))


def _files(tmp_path):
    """A tree, a file in it, a file outside it, and a name for the outside file
    that sits outside the tree too."""
    tree = tmp_path / "tree"
    tree.mkdir()
    inside = tree / "inside.yaml"
    inside.write_text("project_name: inside\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    outside = elsewhere / "outside.yaml"
    outside.write_text("project_name: outside\n", encoding="utf-8")
    names = tmp_path / "names"
    names.mkdir()
    return tree, inside, outside, names / "outside.yaml"


def test_a_file_inside_the_tree_is_decided_whatever_its_name_walk_did(
    tmp_path, walk_stops
):
    """The resolved path is inside the tree; the name that reached it is not,
    and its walk stopped. The file is in the tree by where it is, so nothing is
    undecided."""
    tree, inside, _outside, name = _files(tmp_path)
    repository = RepositorySettings([tree], any_checkout=False)

    repository.confine(inside, name, _LIMIT)

    assert repository.repository_files == [inside]
    assert repository.found, "the control: the option was left out"
    assert repository.undecided_places == set()


def test_a_file_only_an_unfinished_walk_places_stays_undecided(tmp_path, walk_stops):
    """The control: neither the resolved path nor the name is inside the tree,
    and the name's walk stopped, so the file is the repository's by the
    fail-closed rule alone."""
    tree, _inside, outside, name = _files(tmp_path)
    repository = RepositorySettings([tree], any_checkout=False)

    repository.confine(outside, name, _LIMIT)

    assert repository.repository_files == [outside]
    assert repository.undecided_places == {LIMIT_PLACE}


@pytest.mark.parametrize(
    "located_first", [True, False], ids=["located-first", "undecided-first"]
)
def test_a_place_a_located_file_also_left_out_is_not_undecided(
    tmp_path, walk_stops, located_first
):
    """A file inside the tree and a file only an unfinished walk places both
    write the limit; the second also writes a scope. The limit was left out of a
    file whose location is known, so only the scope is undecided."""
    tree, inside, outside, name = _files(tmp_path)
    repository = RepositorySettings([tree], any_checkout=False)
    reads = [(inside, inside, _LIMIT), (outside, name, _LIMIT_AND_SCOPE)]
    if not located_first:
        reads.reverse()

    for real, named, data in reads:
        repository.confine(real, named, data)

    assert {entry[3] for entry in repository.found} == {
        "max_worker_output_mib",
        "findings_scope",
    }
    assert repository.undecided_places == {SCOPE_PLACE}
