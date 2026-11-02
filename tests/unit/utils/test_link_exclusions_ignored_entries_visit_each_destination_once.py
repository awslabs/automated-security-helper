# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ignored_entries`` follows a chain of links without rescanning every link.

A link whose destination is not hidden whole unmakes every directory holding the
link, and that can unmake another link's destination, so the discard runs to a
fixpoint. Each link taken off the work list used to be followed by a scan of all
the links for the ones whose destination had stopped being whole: with P links
discarded among L, P x L steps, tens of seconds on a pnpm layout with some
thirty thousand in-tree directory links. The links are now indexed by
destination once, and a discarded directory queues only the links that lead to
it.

The count is of ``items()`` calls on the mapping the function copies its links
into, which a recording ``dict`` takes the place of. The scan-per-link shape
makes one such call per discarded link; the indexed one makes a handful, however
long the chain is.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import link_exclusions
from automated_security_helper.utils.link_exclusions import ignored_entries

pytestmark = pytest.mark.unit

_CHAIN = 40
_TARGET = Path("/does/not/matter")


def _ignore(*paths: str):
    return [SimpleNamespace(path=path) for path in paths]


def _a_chain_that_unmakes_every_link(length: int):
    """``d0`` holds a link to ``d1``, which holds a link to ``d2``, and so on. Every
    ``d<i>/f.txt`` is ignored, and the last directory also holds ``keep.py``, which
    is not: the last destination is not whole, which unmakes ``d<length-2>``, which
    unmakes the destination of the link before it, one link at a time."""
    files = [f"d{i}/f.txt" for i in range(length)] + [f"d{length - 1}/keep.py"]
    links = {f"d{i}/hop": f"d{i + 1}" for i in range(length - 1)}
    return files, links, _ignore(*(f"d{i}/f.txt" for i in range(length)))


def test_a_long_chain_is_followed_without_a_scan_of_every_link_per_link(monkeypatch):
    files, links, patterns = _a_chain_that_unmakes_every_link(_CHAIN)
    scans: list[int] = []

    class Recording(dict):
        def items(self):
            scans.append(1)
            return super().items()

    monkeypatch.setattr(link_exclusions, "dict", Recording, raising=False)

    found = ignored_entries(_TARGET, _TARGET, patterns, files, directory_links=links)

    assert len(scans) <= 6
    # The whole chain was unmade: no directory is hidden whole, and every ignored
    # file is returned by name.
    assert not any(entry.endswith("/") for entry in found)
    assert {f"d{i}/f.txt" for i in range(_CHAIN)} <= set(found)


def test_the_chain_unmakes_the_first_directory_as_it_did_link_by_link():
    """Every directory on the chain holds a link that leads on to the one that is
    not whole, so none is hidden whole, the first included."""
    files, links, patterns = _a_chain_that_unmakes_every_link(5)

    found = ignored_entries(_TARGET, _TARGET, patterns, files, directory_links=links)

    assert "d0/" not in found
    assert "d0/f.txt" in found


def test_control_an_unrelated_whole_directory_stays_hidden_whole():
    files, links, patterns = _a_chain_that_unmakes_every_link(5)
    files = files + ["z/f.txt"]
    patterns = patterns + _ignore("z/f.txt")

    found = ignored_entries(_TARGET, _TARGET, patterns, files, directory_links=links)

    assert "z/" in found
    assert "z/f.txt" not in found


def test_control_a_link_to_a_whole_directory_is_hidden_itself():
    files = ["lib/f.txt", "app/main.py"]
    links = {"app/vendored": "lib"}

    found = ignored_entries(
        _TARGET, _TARGET, _ignore("lib/f.txt"), files, directory_links=links
    )

    assert found == ["app/vendored/", "lib/"]
