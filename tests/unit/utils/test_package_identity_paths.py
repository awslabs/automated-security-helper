# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``package_path`` stays inside the scan root, and a lockfile is opened by its own name.

* ``install_path`` normalizes the joined path whatever directory the lockfile is
  in, and answers ``""`` (no ``package_path``) for a key that climbs out of the
  scan root or is absolute. Before, a key with ``..`` under a root lockfile came
  back unnormalized, and under a nested lockfile it was normalized into ANOTHER
  directory of the scan root, named as the package's.
* ``NpmLockIndex.entries`` reads a record-form path back to the name the file
  has on disk before opening it, so a lockfile under a non-UTF-8 directory name
  is found.
"""

from __future__ import annotations

import json
import sys

import pytest

from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    install_path,
)
from automated_security_helper.utils.undecodable_text import text_of_undecodable

pytestmark = pytest.mark.unit


class TestInstallPathStaysInsideTheScanRoot:
    def test_a_key_climbing_out_of_a_root_lockfile_claims_no_path(self):
        assert install_path("package-lock.json", "../shared-lib") == ""

    def test_a_key_climbing_out_of_a_nested_lockfile_claims_no_path(self):
        """``deploy/..`` would have named ``shared-lib`` at the scan root."""
        assert install_path("deploy/package-lock.json", "../shared-lib") == ""
        assert install_path("deploy/package-lock.json", "../../x") == ""

    def test_an_absolute_key_claims_no_path(self):
        assert install_path("package-lock.json", "/etc/node_modules/x") == ""

    def test_a_root_lockfiles_key_is_normalized(self):
        assert (
            install_path("package-lock.json", "node_modules/./a/../b")
            == "node_modules/b"
        )

    def test_the_ordinary_shapes_are_unchanged(self):
        """The control."""
        assert install_path("package-lock.json", "node_modules/a") == "node_modules/a"
        assert (
            install_path(
                "deploy/cdk/package-lock.json", "node_modules/a/node_modules/b"
            )
            == "deploy/cdk/node_modules/a/node_modules/b"
        )
        assert install_path("package-lock.json", "") == ""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX byte file names")
def test_a_lockfile_under_a_non_utf8_directory_is_found(tmp_path):
    # A directory whose name is latin-1 bytes, listed by Python as a lone
    # surrogate; a record spells it as the six-character escape.
    directory = tmp_path / ("caf" + "\udce9")
    directory.mkdir()
    lockfile = directory / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/left-pad": {"version": "1.3.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    index = NpmLockIndex(tmp_path)
    record_form = text_of_undecodable(directory.name) + "/package-lock.json"
    assert "\\udce9" in record_form
    entries = index.entries(record_form)
    assert entries is not None
    assert [entry.name for entry in entries] == ["left-pad"]
