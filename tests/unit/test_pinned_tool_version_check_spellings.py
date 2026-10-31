# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/check_pinned_tool_versions.py`` orders post-releases and spells tags.

Why this file exists
--------------------
Two readings of a version string in the pin checker were wrong in ways its own
report hid:

* ``parse_version`` keyed every suffix as a pre-release, so a PEP 440 post-release
  on PyPI (``1.2.3.post1``) sorted before ``1.2.3`` and a pin of ``1.2.3`` was
  reported ``ahead`` of it instead of ``outdated``.
* The bump steps for a uv-tool pin spelled the new version as PyPI's bare number,
  while the tool's license entry records the release tag with its ``v``, so the
  steps named an entry value that is not the tag and a ``gh api .../commits/<ref>``
  lookup that resolves no ref.

No network: these call the two pure functions on hand-built inputs.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_tool_versions_spellings", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


class TestPostReleasesSortAfterTheFinalRelease:
    @pytest.mark.parametrize(
        "post", ["1.2.3.post1", "1.2.3-post1", "1.2.3.rev1", "1.2.3r2"]
    )
    def test_a_post_release_is_newer_than_its_release(self, post):
        assert checker.compare("1.2.3", post) == "outdated"
        assert checker.compare(post, "1.2.3") == "ahead"

    def test_a_pre_release_is_still_older_than_its_release(self):
        """The control: the pre-release ordering this changes nothing about."""
        assert checker.compare("1.2.3", "1.2.3rc1") == "ahead"
        assert checker.compare("1.2.3rc1", "1.2.3") == "outdated"

    def test_post_releases_order_among_themselves(self):
        assert checker.compare("1.2.3.post1", "1.2.3.post2") == "outdated"
        assert checker.compare("1.2.3.post1", "1.2.4") == "outdated"


class TestUvToolStepsSpellTheReleaseTag:
    def _pins(self, version: str):
        entry = SimpleNamespace(
            repository="https://github.com/semgrep/semgrep",
            version=version,
            files=(),
            distribution="semgrep",
        )
        return SimpleNamespace(THIRD_PARTY_LICENSES={"semgrep": entry})

    def test_a_v_tagged_entry_gets_a_v_tagged_bump(self):
        steps = checker._license_steps(self._pins("v1.180.0"), "semgrep", "1.181.0")
        assert any(step.endswith("-> v1.181.0") for step in steps), steps
        assert any("commits/v1.181.0 " in step for step in steps), steps
        assert not any("commits/1.181.0 " in step for step in steps), steps

    def test_a_bare_entry_keeps_a_bare_bump(self):
        steps = checker._license_steps(self._pins("1.180.0"), "semgrep", "1.181.0")
        assert any(step.endswith("-> 1.181.0") for step in steps), steps
        assert any("commits/1.181.0 " in step for step in steps), steps

    def test_a_tag_already_spelled_is_left_alone(self):
        steps = checker._license_steps(self._pins("v1.180.0"), "semgrep", "v1.181.0")
        assert any(step.endswith("-> v1.181.0") for step in steps), steps
        assert not any("vv1" in step for step in steps), steps
