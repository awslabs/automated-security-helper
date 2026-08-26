# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SARIF URIs must relativize even when the source directory path has symlinks.

Why this file exists
--------------------
`sanitize_sarif_paths` resolves the source directory (`Path(source_dir)
.resolve()`) but a scanner's SARIF URI is whatever spelling the scanner was
handed. `Path.relative_to` is purely lexical, so the two only line up when
neither side crosses a symlink. When they disagree the ValueError was suppressed
and the URI was left absolute.

An absolute URI then fails suppression matching, because a suppression `path` is
written relative to the source directory ("src/insecure.js"), and
`file_path_matches` compares the two as strings. The reported symptom is the
worst kind: the finding stays actionable *and* the unused-suppressions reporter
declares the suppression unused, so the config looks wrong rather than the
matcher.

macOS hits this on every scan under /tmp, because /tmp is a symlink to
/private/tmp. The reporter also found it with OneDrive on macOS, where the
visible `~/OneDrive - <Tenant>/...` path is a symlink into `~/Library/CloudStorage`.

Why a symlink rather than a mocked path
--------------------------------------
The bug is a property of real filesystem resolution, so a test that stubs
`Path.resolve` would pass against a matcher that still cannot see through a
symlink. These tests build an actual symlinked tree, which is why they are
skipped on Windows: creating one there needs either developer mode or elevation,
and a skip is better than a test that fails for a reason unrelated to the fix.
"""

import os

import pytest

from automated_security_helper.utils.sarif_utils import _sanitize_uri
from automated_security_helper.utils.suppression_matcher import file_path_matches

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="Creating symlinks on Windows requires developer mode or elevation",
)


@pytest.fixture
def symlinked_source(tmp_path):
    """A source tree reachable by two different absolute paths.

    Mirrors macOS /tmp -> /private/tmp: `link/proj` and `real/proj` are the same
    directory, spelled differently.
    """
    real = tmp_path / "real" / "proj"
    (real / "src").mkdir(parents=True)
    (real / "src" / "insecure.js").write_text("// finding here\n", encoding="utf-8")

    link = tmp_path / "link"
    link.symlink_to(tmp_path / "real", target_is_directory=True)

    return {
        "real_source": real,
        "link_source": link / "proj",
    }


class TestAbsoluteUriThroughASymlink:
    def test_uri_spelled_via_symlink_is_made_relative(self, symlinked_source):
        """The reported case, in the shape sanitize_sarif_paths produces.

        sanitize_sarif_paths resolves source_dir before calling _sanitize_uri, so
        source_dir_path is the /real spelling while the scanner reported /link.
        """
        source_dir_path = symlinked_source["link_source"].resolve()
        source_dir_str = str(source_dir_path) + "/"
        uri = str(symlinked_source["link_source"] / "src" / "insecure.js")

        sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)

        assert sanitized == "src/insecure.js"

    def test_the_reverse_spelling_also_relativizes(self, symlinked_source):
        """source_dir given as the resolved path, URI reported through the link.

        Covered separately because which side holds the symlink depends on how
        the scanner was invoked, and only one direction was ever exercised.
        """
        source_dir_path = symlinked_source["real_source"]
        source_dir_str = str(source_dir_path) + "/"
        uri = str(symlinked_source["link_source"] / "src" / "insecure.js")

        sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)

        assert sanitized == "src/insecure.js"

    def test_sanitized_uri_then_matches_a_relative_suppression(self, symlinked_source):
        """The point of the fix, asserted end to end.

        A suppression path is written relative to the source directory, so an
        absolute URI silently fails to match. This is the assertion that would
        have caught the reported behaviour.
        """
        source_dir_path = symlinked_source["link_source"].resolve()
        source_dir_str = str(source_dir_path) + "/"
        uri = str(symlinked_source["link_source"] / "src" / "insecure.js")

        sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)

        assert file_path_matches(sanitized, "src/insecure.js")

    def test_missing_file_under_a_symlinked_dir_still_relativizes(
        self, symlinked_source
    ):
        """Path.resolve() is non-strict, so the file need not exist.

        Scanners report paths for files that may have been cleaned up, and a
        converted-target URI need not exist on disk at sanitize time. Only the
        symlinked directory has to be resolvable.
        """
        source_dir_path = symlinked_source["link_source"].resolve()
        source_dir_str = str(source_dir_path) + "/"
        uri = str(symlinked_source["link_source"] / "src" / "never-existed.js")

        sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)

        assert sanitized == "src/never-existed.js"


class TestNoBehaviourChangeElsewhere:
    def test_uri_outside_the_source_dir_stays_absolute(
        self, symlinked_source, tmp_path
    ):
        """Guard against over-correcting.

        A finding genuinely outside the source tree has no relative form. It must
        keep its absolute path rather than acquire a misleading `../..` one.
        """
        source_dir_path = symlinked_source["real_source"]
        source_dir_str = str(source_dir_path) + "/"
        outside = tmp_path / "elsewhere" / "other.js"
        outside.parent.mkdir(parents=True)
        outside.write_text("// unrelated\n", encoding="utf-8")

        sanitized = _sanitize_uri(str(outside), source_dir_path, source_dir_str)

        assert sanitized == str(outside).replace("\\", "/")

    def test_plain_absolute_uri_under_source_dir_is_unaffected(self, symlinked_source):
        """The common case, with no symlink involved, must not change."""
        source_dir_path = symlinked_source["real_source"]
        source_dir_str = str(source_dir_path) + "/"
        uri = str(source_dir_path / "src" / "insecure.js")

        sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)

        assert sanitized == "src/insecure.js"

    def test_relative_uri_is_unaffected(self, symlinked_source):
        source_dir_path = symlinked_source["real_source"]
        source_dir_str = str(source_dir_path) + "/"

        assert (
            _sanitize_uri("src/insecure.js", source_dir_path, source_dir_str)
            == "src/insecure.js"
        )
