# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The vendored polars Cargo.lock stays true to what uv.lock resolves.

Why these tests exist
---------------------
polars-runtime-32, the compiled half of ASH's polars runtime dependency, statically
links hundreds of Rust crates that no scanner can read from the wheel: its shared
library carries no cargo-auditable ``.dep-v0`` section, so syft and trivy each see
one PyPI package and zero cargo components. third_party_locks/polars_runtime_32/
therefore vendors the upstream Cargo.lock, extracted from the sdist uv.lock pins by
hash, so the SBOM and vulnerability scanners that already run over this repository
index the crate tree through their ordinary Cargo.lock support.

A vendored lockfile left behind after a polars bump would make ASH's own SBOM
describe a release uv.lock no longer resolves, and would keep vulnerability findings
pointing at crates a newer polars already replaced. These tests hold the record file
to uv.lock, and the committed Cargo.lock to the record, so the bump fails here until
the lockfile is refreshed (the record file names the refresh steps).

What is deliberately not here: whether the crate list is the one the wheel links.
The lockfile covers the whole upstream workspace and is an upper bound; the record
file says so and names the wheel-embedded-paths cross-check that bounds it below.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pyproject.toml declares tomli for Python below 3.11
    import tomli as tomllib

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCK_DIR = REPO_ROOT / "third_party_locks" / "polars_runtime_32"
RECORD = LOCK_DIR / "cargo-lock-record.txt"
CARGO_LOCK = LOCK_DIR / "Cargo.lock"


def _locked_package(name: str) -> dict:
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    entries = [p for p in lock["package"] if p["name"] == name]
    assert len(entries) == 1, f"{name} resolves to {len(entries)} entries in uv.lock"
    return entries[0]


def _field(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}: (.+)$", text, re.MULTILINE)
    assert match, f"the record has no '{name}:' line"
    return match.group(1).strip()


def test_the_record_names_the_version_uv_lock_resolves():
    text = RECORD.read_text(encoding="utf-8")
    assert (
        _field(text, "polars-runtime-32")
        == _locked_package("polars-runtime-32")["version"]
    )


def test_the_record_names_the_sdist_uv_lock_pins():
    text = RECORD.read_text(encoding="utf-8")
    entry = _locked_package("polars-runtime-32")
    sdist_hash = entry["sdist"]["hash"]
    assert sdist_hash.startswith("sha256:"), f"unexpected hash form {sdist_hash!r}"
    assert _field(text, "Sdist SHA-256") == sdist_hash.removeprefix("sha256:")
    assert _field(text, "Sdist") in entry["sdist"]["url"]


def test_the_committed_lockfile_matches_the_record_digest():
    text = RECORD.read_text(encoding="utf-8")
    digest = hashlib.sha256(CARGO_LOCK.read_bytes()).hexdigest()
    assert _field(text, "Cargo.lock SHA-256") == digest


def test_the_record_counts_match_the_lockfile():
    text = RECORD.read_text(encoding="utf-8")
    lock = tomllib.loads(CARGO_LOCK.read_text(encoding="utf-8"))
    packages = lock["package"]
    workspace = [p for p in packages if "source" not in p]
    assert int(_field(text, "Packages in the lockfile")) == len(packages)
    assert int(_field(text, "Workspace crates")) == len(workspace)
    assert int(_field(text, "Registry crates")) == len(packages) - len(workspace)
    # The lockfile really is polars' own workspace, not a stray file: the root
    # crate of the sdist is among the workspace members.
    assert any(p["name"] == "polars-python" for p in workspace)
