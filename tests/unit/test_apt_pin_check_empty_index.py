# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An apt index with no packages is read as empty, and one with only text as broken.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` refuses an index that parses to no package,
so that an error page answered with HTTP 200 does not make every pin look retired.
That refusal also caught a genuinely empty ``Packages`` file. Debian empties
``<suite>-updates`` at each point release and may leave it empty, and then every pin
read ``error`` and the weekly run exited 2 for a reason that is not a fault. An empty
body is now an index with no packages; a body that has text and no package stanza is
still refused.

No network: the indexes are strings handed to ``check_apt``.
"""

from __future__ import annotations

import importlib.util
import lzma
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_apt_empty_index", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()

PIN = checker.AptPin("curl", "7.1-1", (3,))
LISTED = "Package: curl\nVersion: 7.1-1\n"
INDEXES = [
    checker.AptIndex("main", "https://deb.debian.org/main/{arch}/Packages"),
    checker.AptIndex("updates", "https://deb.debian.org/updates/{arch}/Packages"),
]


def _check(bodies: dict[str, str]):
    return checker.check_apt(
        [PIN],
        INDEXES,
        lambda url: bodies["updates" if "/updates/" in url else "main"],
        architectures=("amd64",),
    )


class TestAnEmptyIndex:
    @pytest.mark.parametrize("empty", ["", "\n", "  \n\n"])
    def test_an_empty_updates_index_does_not_fail_the_run(self, empty):
        # Red at the base: the empty body raised "the index lists no packages" and the
        # pin read "error" on every architecture.
        (result,) = _check({"main": LISTED, "updates": empty})
        assert (result.status, result.candidate) == ("current", "7.1-1")
        assert checker.apt_exit_code([result], fail_on_outdated=True) == checker.EXIT_OK

    def test_a_pin_the_other_indexes_do_not_list_is_unavailable_not_an_error(self):
        (result,) = _check({"main": "", "updates": ""})
        assert result.status == "unavailable"
        assert result.detail == "no index lists the package"

    def test_a_body_with_text_and_no_package_is_still_refused(self):
        """Control: the error-page case the refusal exists for."""
        (result,) = _check({"main": LISTED, "updates": "<html>try again</html>"})
        assert result.status == "error"
        assert "has text but lists no packages" in result.detail

    def test_an_index_that_lists_the_package_still_judges_it(self):
        """Control: the ordinary case."""
        (result,) = _check({"main": LISTED, "updates": LISTED})
        assert result.status == "current"


XZ_INDEXES = [
    checker.AptIndex("main", "https://deb.debian.org/main/{arch}/Packages.xz"),
    checker.AptIndex("updates", "https://deb.debian.org/updates/{arch}/Packages.xz"),
]


class TestAnEmptyXzIndex:
    """The path Debian serves: an ``xz`` stream whose content is empty."""

    @staticmethod
    def _serve(monkeypatch, updates: bytes) -> None:
        main = lzma.compress(LISTED.encode("utf-8"))
        monkeypatch.setattr(
            checker,
            "_get_bytes",
            lambda url, headers=None: updates if "/updates/" in url else main,
        )

    def test_an_empty_xz_updates_index_does_not_fail_the_run(self, monkeypatch):
        # Control (the empty-body case is cured at the base): the xz stream decodes
        # to "", and fetch_index hands that body to the empty-index check.
        self._serve(monkeypatch, lzma.compress(b""))
        (result,) = checker.check_apt(
            [PIN], XZ_INDEXES, checker.fetch_index, architectures=("amd64",)
        )
        assert (result.status, result.candidate) == ("current", "7.1-1")
        assert checker.apt_exit_code([result], fail_on_outdated=True) == checker.EXIT_OK

    def test_an_xz_index_that_decodes_to_an_error_page_is_still_refused(
        self, monkeypatch
    ):
        """Control: text with no package stanza stays an error through the xz path."""
        self._serve(monkeypatch, lzma.compress(b"<html>try again</html>"))
        (result,) = checker.check_apt(
            [PIN], XZ_INDEXES, checker.fetch_index, architectures=("amd64",)
        )
        assert result.status == "error"
        assert "has text but lists no packages" in result.detail
