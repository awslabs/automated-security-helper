# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The find_executable cache cannot carry one test's world into the next.

The failure this pins
---------------------
A test that resolved a fake tool left its entry in
``subprocess_utils._find_executable_cache``, and a later test in the same
process read it back and passed on it -- a false green that only showed when
the reader ran alone. The cache key carries PATH and ASH_BIN_PATH and a
remembered path is revalidated as an executable file, so the leak needs the
same environment and a still-live fake file.

The guard against it is the autouse fixture in ``tests/unit/conftest.py``,
whose teardown clears the caches UNCONDITIONALLY -- for a guarded test the
tool guard's own setup clears them again, so the teardown reset is
load-bearing exactly for a guardless (``runs_real_tools``) test followed by
another. These cells reproduce that shape on purpose: both are marked
``runs_real_tools`` and START NO TOOL -- the mark only drops the per-test
guard, whose private stand-in directory on PATH otherwise keys the plant
under an environment no later lookup repeats (measured: with the teardown
reset deleted, a guarded pair stayed green). Both cells pin one PATH, so
the plant and the lookup share an environment and the pair can actually
fail: with the teardown reset deleted, the reader IS served the plant
(measured red; green restored). Under xdist the two cells can land on
different workers, in which case the reader is green trivially -- the
discriminating run is the same-worker order.
"""

import pytest

from automated_security_helper.utils import subprocess_utils

#: One PATH both cells pin, so the planted key and the reader's lookup key
#: are equal; without this the keys differ and the reader is vacuously green.
_PINNED_PATH = "/usr/bin:/bin"

_REASON = (
    "starts no tool: unguarded on purpose, so the autouse teardown cache "
    "reset is the ONLY clearer between these two cells and deleting it "
    "turns the reader red"
)


@pytest.mark.runs_real_tools(reason=_REASON)
def test_the_cache_is_empty_at_test_setup_and_a_plant_is_cleaned(tmp_path, monkeypatch):
    assert subprocess_utils._find_executable_cache == {}, (
        subprocess_utils._find_executable_cache
    )
    monkeypatch.setenv("PATH", _PINNED_PATH)
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    fake = tmp_path / "zz-cache-isolation-plant"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    key = ("zz-cache-isolation-plant", _PINNED_PATH, "")
    subprocess_utils._find_executable_cache[key] = str(fake)
    # The plant answers its own lookup NOW (the cell can fail): a lookup
    # under the same environment is served the entry while it exists.
    assert subprocess_utils.find_executable("zz-cache-isolation-plant") == str(fake)
    # The autouse teardown clears this entry; the cell below, and every
    # later test on this worker, must not be served it.


@pytest.mark.runs_real_tools(reason=_REASON)
def test_a_planted_entry_from_another_test_is_not_served(monkeypatch):
    monkeypatch.setenv("PATH", _PINNED_PATH)
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    assert subprocess_utils.find_executable("zz-cache-isolation-plant") is None
