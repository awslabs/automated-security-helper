# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two scans compare only when their finding ids key on one basis.

An image scan's ids key on the image's digest when one was named and on the
reference text otherwise (``utils/finding_identity``), and the recorded scan
source carries which (``image:<digest>`` against ``image:<reference>``,
``utils/image_attribution.image_scan_source``). A digest lookup that failed on
one side of a comparison would otherwise make every finding read as new and
every old one as resolved, silently, off one scan-time log line: here the
mismatch is a refusal naming the remedy (``finding_diff.check_same_id_basis``,
run by ``comparable_findings`` for the CLI diff and the MCP tool alike).
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.finding_diff import (
    ComparabilityRefusal,
    check_same_id_basis,
    comparable_findings,
)

pytestmark = pytest.mark.unit

DIGEST = "sha256:" + "ab" * 32


def _results(scan_source: str | None) -> AshAggregatedResults:
    results = AshAggregatedResults()
    if scan_source is not None:
        results.metadata.scan_source = scan_source
    return results


def test_two_digest_keyed_scans_compare():
    check_same_id_basis(_results(f"image:{DIGEST}"), _results(f"image:{DIGEST}"))


def test_two_reference_keyed_scans_compare():
    ref = "image:registry.example.com/team/app:1.2"
    check_same_id_basis(_results(ref), _results(ref))


def test_two_directory_scans_compare():
    check_same_id_basis(_results("src"), _results("src"))


def test_mixed_bases_are_refused_with_the_remedy():
    with pytest.raises(ComparabilityRefusal, match="different bases"):
        check_same_id_basis(
            _results(f"image:{DIGEST}"),
            _results("image:registry.example.com/team/app:1.2"),
        )
    with pytest.raises(ComparabilityRefusal, match="pin the reference by digest"):
        check_same_id_basis(
            _results("image:registry.example.com/team/app:1.2"),
            _results(f"image:{DIGEST}"),
        )


def test_an_image_scan_never_compares_with_a_directory_scan():
    with pytest.raises(ComparabilityRefusal, match="directory scan"):
        check_same_id_basis(_results(f"image:{DIGEST}"), _results("src"))


def test_comparable_findings_runs_the_basis_check():
    # The gate the CLI diff and the MCP tool share, not only the helper.
    with pytest.raises(ComparabilityRefusal, match="different bases"):
        comparable_findings(
            _results(f"image:{DIGEST}"),
            _results("image:registry.example.com/team/app:1.2"),
        )


def test_a_truncated_digest_is_a_reference_basis():
    # Only the full sha256 form is the digest basis; a digest-looking prefix
    # keys as text, exactly as the identity does.
    with pytest.raises(ComparabilityRefusal):
        check_same_id_basis(_results(f"image:{DIGEST}"), _results("image:sha256:abcd"))


def test_two_different_image_subjects_compare_with_a_warning():
    # One basis (both digests), two subjects: nothing can pair, so everything
    # reads new or resolved. That IS the intended rebuild reading -- the doc's
    # contract says so -- so the pair is admitted and the coverage warnings
    # name the two subjects instead of refusing.
    from automated_security_helper.utils.finding_diff import coverage_warnings

    other = "sha256:" + "cd" * 32
    baseline, current = _results(f"image:{DIGEST}"), _results(f"image:{other}")
    check_same_id_basis(baseline, current)
    warnings = coverage_warnings(baseline, current)
    assert any("two different images" in warning for warning in warnings)
    # The control: one subject warns nothing of the kind.
    same = coverage_warnings(_results(f"image:{DIGEST}"), _results(f"image:{DIGEST}"))
    assert not any("two different images" in warning for warning in same)
