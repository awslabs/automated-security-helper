# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``file://`` SARIF URI has to reduce to a path pathlib recognizes.

Why this file exists
--------------------
``_sanitize_uri`` reduced ``file://`` URIs with ``urlparse(uri).path`` and fed
the result straight to ``Path``. On Windows that leaves ``/C:/proj/src/a.py``,
and pathlib calls it absolute by no measure: a Windows path needs a drive *and*
a root, and ``PureWindowsPath("/C:/proj").drive`` is empty. So
``path_obj.is_absolute()`` was False, the source-prefix fallback could not match
either (see below), and the URI was returned untouched -- an absolute host path
in the place a repository-relative one belongs.

What that cost, concretely. A GitLab SAST report carries
``location.file = "/C:/Users/runneradmin/AppData/Local/Temp/.../src/config.py"``
instead of ``src/config.py``, so the finding links nowhere in the MR view. And a
suppression ``path``, which is written relative to the source directory, is
compared as a string by ``file_path_matches`` and therefore never matches -- the
finding stays actionable while the unused-suppressions reporter declares the
suppression unused, so the config looks wrong rather than the matcher. Both
symptoms are silent.

Measured on ``awslabs/automated-security-helper`` CI: four Windows unit-test
legs (py3.10 through py3.13) reproduced it, and every Linux and macOS leg of the
same run passed, which is why no existing test caught it.

Three defects, one code path
----------------------------
1. The drive separator, above.
2. ``source_dir_str`` was built as ``str(source_dir_path) + "/"``. ``str()`` on
   Windows is backslashed, while a SARIF URI is forward-slashed by convention,
   so the ``startswith`` fallback compared ``/C:/proj/...`` against
   ``C:\\proj/`` and could not fire on Windows for any input.
3. ``urlparse().path`` is still percent-encoded. ``Path.as_uri()`` encodes, and
   nothing downstream decoded, so a source directory containing a space arrived
   as ``my%20dir``. That one misses on every platform.

Why the assertions are platform-independent
-------------------------------------------
The reduction is pure text, so it is asserted as text and runs everywhere. A
test that only exercised the native platform would have gone on passing on the
Linux legs, which is exactly how this shipped. ``PureWindowsPath`` is used to
state the property that was actually violated -- the reduced text has to be
absolute under Windows semantics -- rather than asserting a string shape that
happens to be right.

Known limitation
----------------
``file://host/share/x`` still loses ``host``: ``urlparse`` puts it in ``netloc``
and only ``path`` is read, so a UNC path is reduced to ``/share/x``.
``TestBug47FileUriHostSegment`` in ``test_sarif_utils_regression.py`` pins that
behavior deliberately, so it is left alone here; a genuine UNC source directory
is a separate change.
"""

from pathlib import Path, PureWindowsPath

import pytest

from automated_security_helper.utils.sarif_utils import (
    _file_uri_to_path_text,
    _sanitize_uri,
)


class TestAWindowsDriveUriReducesToAUsablePath:
    """The reduction itself, asserted as text so every platform runs it."""

    def test_the_separator_before_the_drive_is_dropped(self):
        assert (
            _file_uri_to_path_text("file:///C:/proj/src/config.py")
            == "C:/proj/src/config.py"
        )

    def test_the_reduced_text_is_absolute_under_windows_semantics(self):
        """The property that was violated, stated as a property.

        ``/C:/proj`` has a root and no drive, so ``is_absolute()`` is False and
        ``_sanitize_uri`` skipped relativization entirely. Asserting this rather
        than the string shape means a future reduction that produces some other
        correct spelling still satisfies the test.
        """
        reduced = _file_uri_to_path_text("file:///C:/proj/src/config.py")

        assert PureWindowsPath(reduced).is_absolute(), (
            f"{reduced!r} is not absolute on Windows, so _sanitize_uri will "
            "skip relativization and report the host path verbatim"
        )
        assert PureWindowsPath(reduced).drive == "C:"

    def test_it_relativizes_against_a_windows_source_directory(self):
        """End to end under Windows semantics, without needing a Windows host."""
        source = PureWindowsPath("C:/proj")
        reduced = PureWindowsPath(
            _file_uri_to_path_text("file:///C:/proj/src/config.py")
        )

        assert reduced.relative_to(source).as_posix() == "src/config.py"

    @pytest.mark.parametrize("drive", ["C", "D", "Z"])
    def test_any_drive_letter_is_handled(self, drive):
        assert (
            _file_uri_to_path_text(f"file:///{drive}:/proj/a.py")
            == f"{drive}:/proj/a.py"
        )

    def test_a_posix_uri_keeps_its_leading_separator(self):
        """The guard is keyed on the colon, so it must not eat a POSIX root."""
        assert _file_uri_to_path_text("file:///tmp/proj/a.py") == "/tmp/proj/a.py"

    def test_a_host_segment_still_does_not_become_a_path_segment(self):
        """Pinned so the unquoting change cannot regress TestBug47."""
        assert _file_uri_to_path_text("file://hostname/project/app.py") == (
            "/project/app.py"
        )


class TestThePremiseOfEveryAssertionAbove:
    """The control: the reduction this file rejects has to be seen failing.

    Every assertion above compares one reduction against an expected string, and
    a passing comparison proves nothing unless the rejected form would have
    failed it. So the rejected form -- ``urlparse(uri).path``, which is what
    ``_sanitize_uri`` used -- is spelled out here and asserted to violate the
    same property. Without this, a future refactor back to the bare parse would
    have to be caught by a Windows leg, which is what failed to happen the first
    time.
    """

    def test_the_bare_parse_is_not_absolute_on_windows(self):
        from urllib.parse import urlparse

        bare = urlparse("file:///C:/proj/src/config.py").path

        assert bare == "/C:/proj/src/config.py"
        assert not PureWindowsPath(bare).is_absolute(), (
            "the rejected reduction now looks absolute on Windows, so the "
            "assertions in this file no longer distinguish it from the fix"
        )
        assert _file_uri_to_path_text("file:///C:/proj/src/config.py") != bare

    def test_the_bare_parse_leaves_percent_encoding(self):
        from urllib.parse import urlparse

        uri = "file:///tmp/my%20proj/src/a.py"

        assert urlparse(uri).path == "/tmp/my%20proj/src/a.py"
        assert _file_uri_to_path_text(uri) == "/tmp/my proj/src/a.py"


class TestPercentEncodingIsDecoded:
    """``as_uri()`` encodes; a path that is still encoded matches nothing."""

    def test_a_space_is_decoded(self):
        assert (
            _file_uri_to_path_text("file:///tmp/my%20proj/src/a.py")
            == "/tmp/my proj/src/a.py"
        )

    def test_a_space_is_decoded_on_a_windows_drive_uri(self):
        """Both fixes on one input, because the real failure carried both."""
        assert (
            _file_uri_to_path_text("file:///C:/My%20Proj/src/a.py")
            == "C:/My Proj/src/a.py"
        )

    def test_as_uri_round_trips_through_the_reduction(self, tmp_path):
        """The scanner-shaped input: whatever ``as_uri()`` encodes must come back.

        Uses the native platform, so on Windows this is the drive case and on
        POSIX it is the encoding case. Neither alone is sufficient, which is why
        the text assertions above exist as well.
        """
        target = tmp_path / "my proj" / "src" / "a.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n", encoding="utf-8")

        assert Path(_file_uri_to_path_text(target.as_uri())) == target


class TestSanitizeUriOnAScannerReportedFileUri:
    """The caller, on the native platform, with a real tree."""

    def test_an_absolute_file_uri_becomes_source_relative(self, tmp_path):
        """The ferret shape: an absolute ``file://`` URI inside the source tree.

        A scanner that reports ``Path.as_uri()`` produces exactly this, and the
        GitLab SAST reporter needs ``src/config.py`` out of it for the finding to
        link anywhere.
        """
        source_dir = tmp_path / "source"
        finding = source_dir / "src" / "config.py"
        finding.parent.mkdir(parents=True)
        finding.write_text("SETTING = 'placeholder'\n", encoding="utf-8")

        source_dir_path = source_dir.resolve()
        source_dir_str = source_dir_path.as_posix() + "/"

        assert (
            _sanitize_uri(finding.as_uri(), source_dir_path, source_dir_str)
            == "src/config.py"
        )

    def test_a_directory_with_a_space_still_relativizes(self, tmp_path):
        """The cross-platform half of the same defect."""
        source_dir = tmp_path / "my source"
        finding = source_dir / "src" / "config.py"
        finding.parent.mkdir(parents=True)
        finding.write_text("SETTING = 'placeholder'\n", encoding="utf-8")

        source_dir_path = source_dir.resolve()
        source_dir_str = source_dir_path.as_posix() + "/"

        assert (
            _sanitize_uri(finding.as_uri(), source_dir_path, source_dir_str)
            == "src/config.py"
        )

    def test_a_uri_outside_the_source_tree_is_left_alone(self, tmp_path):
        """Relativization must not invent a path for a file outside the source.

        ``..``-escaping a finding into the source tree would misattribute it, so
        the absolute spelling is the correct output here.
        """
        source_dir = tmp_path / "source"
        (source_dir / "src").mkdir(parents=True)
        outside = tmp_path / "elsewhere" / "other.py"
        outside.parent.mkdir(parents=True)
        outside.write_text("y = 2\n", encoding="utf-8")

        source_dir_path = source_dir.resolve()
        source_dir_str = source_dir_path.as_posix() + "/"

        sanitized = _sanitize_uri(outside.as_uri(), source_dir_path, source_dir_str)

        assert sanitized == outside.resolve().as_posix()
        assert ".." not in sanitized
