# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A uri reading that cannot be resolved names no file, wherever it is read.

Two places resolve the text of a SARIF ``artifactLocation.uri`` through the
shared guard: ``utils.scan_output_dirs._result_paths`` and
``utils.package_identity.scan_relative_path``. Both go through
``utils.undecodable_text.resolve_uri_reading``, so a reading whose resolution
raises -- a NUL from a percent-decoded ``%00``, a symlink loop on CPython
3.10-3.12 -- names no file instead of raising out of a loop over results.

That one-guard shape matters most for ``_result_paths``: its callers
(``drop_results_in_ash_output_dirs``, ``mark_converted_results``) run per
scanner result inside the scan, stages earlier than the changed-files filter,
so an exception there would end the scan before the filter's own guard was
ever reached. The ``file:///no%00where.py`` probe below is the same input the
filter's own ``%00`` cells use.
"""

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.scan_output_dirs import _result_paths
from automated_security_helper.utils.undecodable_text import (
    path_in_record_form,
    resolve_uri_reading,
)


def _located(*uris: str) -> SimpleNamespace:
    """A result object with one location per uri, in the SARIF attribute shape."""
    return SimpleNamespace(
        locations=[
            SimpleNamespace(
                physicalLocation=SimpleNamespace(
                    root=SimpleNamespace(
                        artifactLocation=SimpleNamespace(uri=uri),
                    ),
                ),
            )
            for uri in uris
        ]
    )


class TestResolveUriReading:
    def test_a_relative_name_resolves_below_the_base(self, tmp_path):
        assert (
            resolve_uri_reading("x.py", base=tmp_path) == (tmp_path / "x.py").resolve()
        )

    def test_an_absolute_name_ignores_the_base(self, tmp_path):
        target = tmp_path / "y.py"
        assert (
            resolve_uri_reading(str(target), base=tmp_path / "sub") == target.resolve()
        )

    def test_a_text_holding_a_nul_names_no_file(self, tmp_path):
        assert resolve_uri_reading("no\x00where.py", base=tmp_path) is None

    @pytest.mark.skipif(
        sys.platform == "win32", reason="creating a symlink needs a privilege"
    )
    def test_a_symlink_loop_does_not_raise(self, tmp_path):
        """CPython 3.10-3.12 raises RuntimeError resolving ``loop -> loop``
        (its non-strict resolve stats the result); 3.13 returns the path. The
        contract is only that neither raises out: None there, a path here."""
        (tmp_path / "loop").symlink_to("loop")

        out = resolve_uri_reading("loop", base=tmp_path)

        assert out is None or out.name == "loop"


class TestResultPathsSkipAReadingThatCannotResolve:
    """``_result_paths`` places a result nowhere for an unresolvable reading.

    ``no%00where.py`` takes the relative branch: the literal name does not
    exist, so the decoded reading (holding a NUL) is the one resolved.
    ``file:///no%00where.py`` takes the ``file://`` branch, whose parser
    percent-decodes. Before the shared guard, both raised
    ``ValueError: embedded null byte`` out of the generator.
    """

    def test_a_decoded_nul_reading_is_skipped_and_later_locations_decide(
        self, tmp_path
    ):
        result = _located("no%00where.py", "kept.py")

        got = list(_result_paths(result, tmp_path))

        assert got == [path_in_record_form((tmp_path / "kept.py").resolve())]

    def test_a_nul_in_a_file_uri_is_skipped_not_raised(self, tmp_path):
        result = _located("file:///no%00where.py")

        assert list(_result_paths(result, tmp_path)) == []
