"""The volume layout guard.

The scenario each test describes is a *green* scan of a tree with findings in it,
which is why these are unit tests and not a comment.
"""

from __future__ import annotations

import pytest

from ash_operator.constants import OUTPUT_MOUNT, SOURCE_MOUNT
from ash_operator.volumes import (
    VolumeLayoutError,
    assert_layout_is_sane,
    assert_output_escapes_source,
    is_ancestor_or_equal,
)


class TestAncestry:
    @pytest.mark.parametrize(
        "candidate,other,expected",
        [
            ("/src", "/src", True),
            ("/src", "/src/app", True),
            ("/src", "/src/app/deep", True),
            ("/src/app", "/src", False),
            ("/workspace/out", "/workspace/src", False),
            ("/workspace", "/workspace/src", True),
            # Lexical, not filesystem: /srcx is not an ancestor of /src even
            # though the strings share a prefix.
            ("/srcx", "/src", False),
            ("/src", "/srcx", False),
        ],
    )
    def test_ancestry(self, candidate, other, expected):
        assert is_ancestor_or_equal(candidate, other) is expected

    def test_a_relative_path_is_refused(self):
        with pytest.raises(VolumeLayoutError, match="must be absolute"):
            is_ancestor_or_equal("src", "/src")


class TestOutputEscapesSource:
    def test_the_operator_layout_is_accepted(self):
        # Positive control: without it, every refusal below could be a function
        # that refuses everything.
        assert_output_escapes_source(source_dir=SOURCE_MOUNT, output_dir=OUTPUT_MOUNT)

    def test_equal_paths_are_refused(self):
        with pytest.raises(VolumeLayoutError):
            assert_output_escapes_source(source_dir="/src", output_dir="/src")

    def test_an_output_dir_that_is_an_ancestor_is_refused(self):
        # `ash scan` accepts this: it compares the two paths for equality only, and
        # /src != /src/app. The symptom is a report of zero findings, because
        # apply_suppressions_to_sarif excludes findings whose location resolves
        # inside output_dir, which when output_dir is an ancestor is every finding.
        with pytest.raises(VolumeLayoutError, match="only checks equality"):
            assert_output_escapes_source(source_dir="/src/app", output_dir="/src")

    def test_an_output_dir_inside_the_source_is_refused(self):
        with pytest.raises(VolumeLayoutError, match="requires a writable source"):
            assert_output_escapes_source(source_dir="/src", output_dir="/src/.ash")

    def test_the_refusal_names_the_symptom_not_just_the_rule(self):
        with pytest.raises(VolumeLayoutError) as err:
            assert_output_escapes_source(source_dir="/src/app", output_dir="/src")
        assert "zero findings" in str(err.value)


class TestLayoutIsSane:
    def test_the_shipped_mounts_are_all_siblings(self):
        assert_layout_is_sane()

    def test_nesting_two_mounts_is_caught(self, monkeypatch):
        # Guards against the plausible future change of "share one PVC" by putting
        # the results mount under the source mount.
        import ash_operator.volumes as volumes

        monkeypatch.setattr(volumes, "RESULTS_MOUNT", "/workspace/src/results")
        with pytest.raises(VolumeLayoutError, match="are not siblings"):
            volumes.assert_layout_is_sane()
