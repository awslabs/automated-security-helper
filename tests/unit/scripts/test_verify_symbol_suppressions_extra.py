# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_symbol_suppressions_extra.py: the control cannot pass for nothing.

The script is the CI control behind the repository's symbol-scoped suppressions.
Four ways it could pass without proving anything are pinned here:

- fail-closed passed whenever an entry matched nothing, for any reason, so a pin
  that had drifted out of its definition passed too: the probe line is now held
  to the row's recorded span first (a stale-pin row names the line its flagged
  code really sits on in `flagged_line`), so only the missing extra can be what
  rejects the entry;
- an empty record passed;
- `resolves` stopped at the first broken row (a deleted file, an unparsable
  file, a file type with no grammar, a malformed symbol or path), so the later
  rows were never checked.

None of these tests needs the `symbols` extra: the resolver is a stand-in, and the
broken rows fail before any grammar is loaded.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

ROW = {
    "rule_id": "B608",
    "path": "automated_security_helper/utils/content_db_refresh.py",
    "old_line_start": 837,
    "old_line_end": 837,
    "symbol": "_say_grype_auto_update_once",
    "span_at_migration": [827, 843],
}


class _NeverContains:
    """A resolver as the missing extra leaves it: no span is ever known."""

    def contains(self, *args, **kwargs) -> bool:
        return False


@pytest.fixture
def script(script_loader):
    return script_loader("verify_symbol_suppressions_extra")


def _run(script, mode, rows, *, available):
    lines: list[str] = []
    code = script.run(
        mode, rows, _NeverContains(), available=available, out=lines.append
    )
    return code, "\n".join(lines)


@pytest.mark.parametrize(
    ("mode", "available"), [("fail-closed", False), ("resolves", True)]
)
def test_an_empty_record_is_a_failure_not_a_pass(script, mode, available):
    code, text = _run(script, mode, [], available=available)

    assert code == 1
    assert "nothing to probe" in text


def test_fail_closed_passes_a_row_that_only_the_symbol_clause_rejects(script):
    code, text = _run(script, "fail-closed", [ROW], available=False)

    assert code == 0, text


def test_fail_closed_refuses_a_row_with_no_line_to_probe(script):
    """A row whose old line is null is rejected by the matcher's no-line rule, so
    "matched nothing" there would be the line's doing, not the missing extra's."""
    row = {**ROW, "old_line_start": None}

    code, text = _run(script, "fail-closed", [row], available=False)

    assert code == 1
    assert "no old_line_start" in text


def test_fail_closed_refuses_a_pin_that_drifted_out_of_its_recorded_span(script):
    """The drift case the probe exists to catch. The symbol-less entry matches on
    rule and path alone, so a pin whose line left its definition passed both legs
    when the probe sat on the pin. Now the probe line must lie inside the row's
    span_at_migration, or a non-match there says nothing about the extra."""
    row = {**ROW, "old_line_start": 900, "old_line_end": 900}

    code, text = _run(script, "fail-closed", [row], available=False)

    assert code == 1
    assert "outside" in text
    assert "span_at_migration" in text


def test_fail_closed_probes_a_stale_pin_row_at_its_flagged_line(script):
    """A stale-pin row's old line was never inside its definition; the line its
    flagged code really sits on is, and that is where the probe goes."""
    row = {
        **ROW,
        "old_line_start": 1785,
        "old_line_end": 1785,
        "old_pin_stale_at_migration": True,
        "flagged_line": 830,
    }

    code, text = _run(script, "fail-closed", [row], available=False)

    assert code == 0, text


def test_fail_closed_refuses_a_stale_pin_row_with_no_flagged_line(script):
    row = {
        **ROW,
        "old_line_start": 1785,
        "old_line_end": 1785,
        "old_pin_stale_at_migration": True,
    }

    code, text = _run(script, "fail-closed", [row], available=False)

    assert code == 1
    assert "outside" in text


def test_fail_closed_refuses_a_flagged_line_outside_the_recorded_span(script):
    row = {**ROW, "flagged_line": 900}

    code, text = _run(script, "fail-closed", [row], available=False)

    assert code == 1
    assert "outside" in text


def test_fail_closed_refuses_a_row_with_no_recorded_span(script):
    row = {k: v for k, v in ROW.items() if k != "span_at_migration"}

    code, text = _run(script, "fail-closed", [row], available=False)

    assert code == 1
    assert "no span_at_migration" in text


def test_fail_closed_refuses_a_row_the_symbol_less_entry_does_not_match_either(
    script, monkeypatch
):
    """The in-environment positive control: when the same entry minus its symbol
    also matches nothing, the missing extra is not what rejected it."""
    from automated_security_helper.utils import suppression_frame

    monkeypatch.setattr(suppression_frame, "matches", lambda *a, **k: False)

    code, text = _run(script, "fail-closed", [ROW], available=False)

    assert code == 1
    assert "without its symbol" in text


def test_fail_closed_flags_a_row_that_matched_without_the_extra(script):
    class _AlwaysContains:
        def contains(self, *args, **kwargs) -> bool:
            return True

    lines: list[str] = []
    code = script.run(
        "fail-closed",
        [ROW],
        _AlwaysContains(),
        available=False,
        out=lines.append,
    )

    assert code == 1
    assert "MATCHED without the extra" in "\n".join(lines)


def test_fail_closed_refuses_to_run_with_the_extra_installed(script):
    code, text = _run(script, "fail-closed", [ROW], available=True)

    assert code == 1
    assert "proves nothing" in text


def test_resolves_names_every_broken_row_instead_of_stopping_at_the_first(script):
    rows = [
        {**ROW, "path": "no/such/file.py", "symbol": "gone_file"},
        {**ROW, "path": "docs/content/index.md", "symbol": "no_grammar"},
        {"rule_id": "B608", "symbol": "missing_path_key"},
        # a symbol that is not a name at all (a list, as a hand edit can leave it)
        # and a null path: both raise outside the file-level error classes
        {**ROW, "symbol": ["not", "a", "name"]},
        {**ROW, "path": None, "symbol": "null_path"},
    ]

    code, text = _run(script, "resolves", rows, available=True)

    assert code == 1
    assert "5 of 5 probes violated" in text
    assert "gone_file" in text
    assert "no_grammar" in text
    assert "missing_path_key" in text
    assert "null_path" in text
    assert "could not be probed (TypeError" in text
