# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal record's size cap counts bytes, a nested record is no record, and
the host's directory replaces the container's before a period or a colon.

read_refusal_outcome read the file in text mode with a byte-named cap, so a file
of up to about four times the cap was read and parsed; it now reads bytes. A record
nested deeper than the parser follows made json.loads raise RecursionError, which
escaped instead of answering None. as_seen_from_the_host left the container's
output directory in place where a period or a colon ended the sentence or the
clause after it.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.utils.inner_run_outcome import (
    INNER_RUN_OUTCOME_FILE,
    REPORT_PATH_REFUSED_CHECKPOINT,
    as_seen_from_the_host,
    read_refusal_outcome,
)

pytestmark = pytest.mark.unit

RUN_ID = "0" * 32


def _record(message: str) -> str:
    return json.dumps(
        {
            "type": REPORT_PATH_REFUSED_CHECKPOINT,
            "message": message,
            "metadata": {"run_id": RUN_ID, "output_dir": "/out"},
        },
        ensure_ascii=False,
    )


def test_the_size_cap_counts_bytes(tmp_path):
    # 600,000 two-byte characters: under the cap in characters, over it in bytes.
    big = tmp_path / INNER_RUN_OUTCOME_FILE
    big.write_text(_record("é" * 600_000), encoding="utf-8")
    assert big.stat().st_size > 1 << 20, "the control: the file is over a MiB"
    assert read_refusal_outcome(tmp_path, RUN_ID) is None

    small = tmp_path / "small"
    small.mkdir()
    (small / INNER_RUN_OUTCOME_FILE).write_text(_record("é" * 10), encoding="utf-8")
    refusal = read_refusal_outcome(small, RUN_ID)
    assert refusal is not None and refusal.message == "é" * 10


def test_a_record_nested_past_the_parsers_depth_is_no_record(tmp_path):
    (tmp_path / INNER_RUN_OUTCOME_FILE).write_text(
        "[" * 100_000 + "]" * 100_000, encoding="utf-8"
    )
    assert read_refusal_outcome(tmp_path, RUN_ID) is None


@pytest.mark.parametrize(
    ("message", "shown"),
    [
        ("cannot write /out.", "cannot write /host."),
        ("/out: permission denied", "/host: permission denied"),
        ("refused /out", "refused /host"),
        ("refused /out/reports", "refused /host/reports"),
        # A longer name, or a path inside another, is not the directory.
        ("kept /out.bak", "kept /out.bak"),
        ("kept /out:/y", "kept /out:/y"),
        ("kept /src/out", "kept /src/out"),
    ],
)
def test_the_hosts_directory_replaces_the_containers_before_punctuation(message, shown):
    assert as_seen_from_the_host(message, "/out", "/host") == shown
