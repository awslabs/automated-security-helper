# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A gem release is installable only if the image's RubyGems admits it too.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` compared a gem pin with the newest release
whose ``ruby_version`` the image's Ruby admits, and never read the release's
``rubygems_version``. A release the image's Ruby admits but its RubyGems does not was
reported as the outdated pin's target and failed ``--fail-on-outdated``, although the
image could not install it. The checker now holds the RubyGems the image has
(``IMAGE_RUBYGEMS``) and skips such a release for the previous admitted one.

The number is not pinned by the Dockerfile; it is what the Debian Ruby package
bundles. ``IMAGE_RUBYGEMS_RUBY_PIN`` records the ``ruby=`` pin it was taken for, and a
test here fails when the Dockerfile's pin differs.

No network: the RubyGems answers are hand-built lists.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_tool_gem_rubygems_requirement", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


def _release(number: str, ruby: str | None, rubygems: str | None = None) -> dict:
    entry: dict[str, Any] = {
        "number": number,
        "prerelease": False,
        "platform": "ruby",
        "ruby_version": ruby,
    }
    if rubygems is not None:
        entry["rubygems_version"] = rubygems
    return entry


def _gem_pin(version: str) -> Any:
    return checker.Pin(
        tool="bundler",
        version=version,
        ecosystem=checker.RUBYGEMS,
        project="bundler",
        pinned_in=("BUNDLER_VERSION",),
        kind=checker.GEM,
    )


class TestRubygemsAdmits:
    @pytest.mark.parametrize(
        ("requirement", "admits"),
        [
            (None, True),
            ("", True),
            (">= 0", True),
            (">= 3.2.3", True),
            (">= 3.3.7", True),
            (">= 3.3.8", False),
            (">= 3.5.0", False),
            ("~> 3.3", True),
            ("< 3.0", False),
            (">= 3.0, < 3.4", True),
        ],
    )
    def test_the_requirement_is_judged_against_the_images_rubygems(
        self, requirement, admits
    ):
        assert checker.rubygems_admits(requirement) is admits

    def test_an_explicit_rubygems_is_used_over_the_images(self):
        assert checker.rubygems_admits(">= 3.5.0", (3, 6)) is True
        assert checker.rubygems_admits(">= 3.5.0", (3, 4)) is False

    @pytest.mark.parametrize("requirement", ["newer", ">= three", 3])
    def test_a_requirement_it_cannot_read_is_refused_by_name(self, requirement):
        with pytest.raises(ValueError, match="required RubyGems version"):
            checker.rubygems_admits(requirement)

    def test_the_ruby_requirement_keeps_its_message(self):
        """Control: the Ruby reader's refusal names Ruby, as the tests of it expect."""
        with pytest.raises(ValueError, match="required Ruby version"):
            checker.ruby_admits("newer", (3, 1))


class TestNewestInstallable:
    RUBY = (3, 1)

    def test_a_release_the_ruby_admits_but_the_rubygems_does_not_is_skipped(self):
        # Red at the base: rubygems_version was never read, so 3.0.0 was the target.
        releases = [
            _release("3.0.0", ">= 3.0", ">= 99.0"),
            _release("2.7.0", ">= 3.0", ">= 3.2.3"),
            _release("2.6.9", ">= 3.0", ">= 3.2.3"),
        ]
        target, note = checker.newest_installable(releases, self.RUBY, "2.6.9")
        assert target == "2.7.0"
        assert "3.0.0 is the newest release, but it needs RubyGems >= 99.0" in note
        assert "the image installs RubyGems 3.3.7" in note
        assert note.endswith("2.7.0 is the newest release the image can run")

    def test_a_pin_at_the_last_admitted_release_is_current(self):
        releases = [
            _release("3.0.0", ">= 3.0", ">= 99.0"),
            _release("2.6.9", ">= 3.0", ">= 3.2.3"),
        ]
        target, note = checker.newest_installable(releases, self.RUBY, "2.6.9")
        assert target == "2.6.9"
        assert "3.0.0" in note

    @pytest.mark.parametrize("missing", [None, ""])
    def test_a_release_with_no_rubygems_requirement_is_admitted(self, missing):
        """Control: absent or empty means admitted, as it does for Ruby."""
        entry = _release("3.0.0", ">= 3.0")
        if missing is not None:
            entry["rubygems_version"] = missing
        releases = [entry, _release("2.6.9", ">= 3.0")]
        target, note = checker.newest_installable(releases, self.RUBY, "2.6.9")
        assert (target, note) == ("3.0.0", "")

    def test_a_release_that_fails_both_requirements_names_both(self):
        releases = [
            _release("3.0.0", ">= 3.3", ">= 99.0"),
            _release("2.6.9", ">= 3.0", ">= 3.2.3"),
        ]
        _, note = checker.newest_installable(releases, self.RUBY, "2.6.9")
        assert "needs Ruby >= 3.3 and the image installs Ruby 3.1 and RubyGems" in note

    def test_a_release_the_ruby_refuses_still_reads_as_it_did(self):
        """Control: the existing Ruby-only note, word for word."""
        releases = [_release("4.0.22", ">= 3.2.0"), _release("2.6.9", ">= 3.1.0")]
        _, note = checker.newest_installable(releases, self.RUBY, "2.6.9")
        assert note == (
            "4.0.22 is the newest release, but it needs Ruby >= 3.2.0 and the image "
            "installs Ruby 3.1; 2.6.9 is the newest release the image can run"
        )

    def test_an_unreadable_rubygems_requirement_is_a_lookup_error(self):
        releases = [_release("3.0.0", ">= 3.0", "whatever"), _release("2.6.9", None)]
        fetchers = {checker.RUBYGEMS: lambda project: releases}
        (result,) = checker.check([_gem_pin("2.6.9")], fetchers, ruby=self.RUBY)
        assert result.status == "error"
        assert "whatever" in result.detail

    def test_check_reports_the_pin_current_when_only_rubygems_blocks_the_newer_one(
        self,
    ):
        releases = [
            _release("3.0.0", ">= 3.0", ">= 99.0"),
            _release("2.6.9", ">= 3.0", ">= 3.2.3"),
        ]
        fetchers = {checker.RUBYGEMS: lambda project: releases}
        (result,) = checker.check([_gem_pin("2.6.9")], fetchers, ruby=self.RUBY)
        assert (result.status, result.latest) == ("current", "2.6.9")
        assert "RubyGems" in result.note
        assert checker.exit_code([result], fail_on_outdated=True) == checker.EXIT_OK


class TestTheImagesRubygemsFollowsTheRubyPin:
    def test_the_number_was_taken_for_the_dockerfiles_ruby_pin(self):
        """Fails when the Dockerfile's ruby= pin changes and this number is not revisited."""
        pins = {p.package: p.version for p in checker.enumerate_apt_pins()}
        assert pins["ruby"] == checker.IMAGE_RUBYGEMS_RUBY_PIN, (
            f"the Dockerfile pins ruby={pins['ruby']}, but IMAGE_RUBYGEMS "
            f"{checker.IMAGE_RUBYGEMS} was taken for ruby="
            f"{checker.IMAGE_RUBYGEMS_RUBY_PIN}. Read the RubyGems the new Ruby bundles, "
            "update both constants in scripts/check_pinned_tool_versions.py."
        )

    def test_the_pin_is_the_one_image_ruby_reads(self):
        """Control: the recorded pin names a Ruby the checker can read."""
        ruby = checker.image_ruby(
            [checker.AptPin("ruby", checker.IMAGE_RUBYGEMS_RUBY_PIN, (1,))]
        )
        assert ruby == (3, 1)
