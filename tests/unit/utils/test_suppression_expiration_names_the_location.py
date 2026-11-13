# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ignore path or suppression is named by its location, never its values.

A config file with an expiration that is not a YYYY-MM-DD date is refused when
it loads, but a configuration kept from a results file keeps the date as
written, and ``ash merge`` applies that configuration to the shards' findings.
The entry does not apply, with a warning; the warning, the debug line for an
expired entry, and the scan-start notice name the entry by where it is
(``global_settings.ignore_paths[0]``), not by its date or its path: both are
the file's data, and either can be a value read from the environment where the
scan ran.
"""

from __future__ import annotations

import json
import re
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.merge import stamp_shard_assignment
from automated_security_helper.config.ash_config import (
    AshConfig,
    resolve_env_references,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.sharding import ShardAssignment
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.event_handlers import (
    suppression_expiration_checker as checker,
)
from automated_security_helper.utils import suppression_matcher as matcher

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"
REFERENCE = "${ASH_PROBE_EXP}"


def _assert_no_value(text: str) -> None:
    """Whitespace and box-drawing characters removed, so a value wrapped across
    lines or a panel border still counts; and its leading part, so a truncated
    one does too."""
    squeezed = re.sub(r"[\s─-╿]", "", text)
    # Booleans here and in _assert_says, so a failure never prints the text,
    # which then may hold the value.
    shown = CANARY in squeezed or CANARY[:12] in squeezed
    assert not shown, "the text holds the value"


def _assert_says(text: str, words: str) -> None:
    said = words in text
    assert said, f"{words!r} is not in the text"


def _logged(log) -> str:
    return " ".join(str(call) for call in log.mock_calls)


def _kept_ignore_path(**fields) -> IgnorePathWithReason:
    """An entry as a stored configuration keeps it: not validated again."""
    values = {"path": "vendor/**", "reason": "vendored", "expiration": CANARY}
    values.update(fields)
    return IgnorePathWithReason.model_construct(**values)


def _kept_suppression(**fields) -> AshSuppression:
    values = {
        "rule_id": "B101",
        "path": "src/app.py",
        "reason": "accepted",
        "expiration": CANARY,
    }
    values.update(fields)
    return AshSuppression.model_construct(**values)


@pytest.mark.parametrize(
    ("where", "named"),
    [
        (None, "global_settings.ignore_paths[1]"),
        (
            "scanners.bandit.options.excluded_paths",
            "scanners.bandit.options.excluded_paths[1]",
        ),
    ],
)
def test_an_ignore_path_s_date_that_does_not_parse(where, named):
    entries = [
        IgnorePathWithReason(path="docs/**", reason="docs"),
        _kept_ignore_path(),
    ]
    kwargs = {} if where is None else {"where": where}
    with patch.object(matcher, "ASH_LOGGER") as log:
        active = matcher.active_ignore_paths(entries, **kwargs)
    assert active == entries[:1]
    _assert_says(_logged(log), named)
    _assert_no_value(_logged(log))


def test_an_expired_ignore_path_is_named_by_location_not_path():
    entry = IgnorePathWithReason(
        path=f"{CANARY}/**", reason="vendored", expiration="2000-01-01"
    )
    with patch.object(matcher, "ASH_LOGGER") as log:
        assert matcher.active_ignore_paths([entry]) == []
    _assert_says(_logged(log), "global_settings.ignore_paths[0]")
    _assert_no_value(_logged(log))


def test_a_suppression_s_date_that_does_not_parse():
    finding = FlatVulnerability(
        id="f1",
        title="assert used",
        description="assert used",
        severity="LOW",
        scanner="bandit",
        scanner_type="SAST",
        rule_id="B101",
        file_path="src/app.py",
        line_start=1,
    )
    with patch.object(matcher, "ASH_LOGGER") as log:
        suppressed, _ = matcher.should_suppress_finding(finding, [_kept_suppression()])
    assert not suppressed
    _assert_says(_logged(log), "global_settings.suppressions[0]")
    _assert_no_value(_logged(log))


def test_the_expiring_soon_checks_name_the_location():
    with patch.object(matcher, "ASH_LOGGER") as log:
        assert matcher.check_for_expiring_suppressions([_kept_suppression()]) == []
        assert matcher.check_for_expiring_ignore_paths([_kept_ignore_path()]) == []
    text = _logged(log)
    _assert_says(text, "global_settings.suppressions[0]")
    _assert_says(text, "global_settings.ignore_paths[0]")
    _assert_no_value(text)


def test_the_scan_start_notice_does_not_quote_the_date():
    lists = [("Ignore path", [_kept_ignore_path()], "global_settings.ignore_paths")]
    with patch.object(checker, "ASH_LOGGER") as log:
        checker._warn_about_expired_entries(lists, [_kept_suppression()])
        checker._warn_about_expiring_ignore_paths(lists)
    text = _logged(log)
    _assert_says(text, "not YYYY-MM-DD")
    _assert_no_value(text)


# ash merge, end to end: a 1-of-1 shard whose stored configuration keeps an
# ignore path with such a date.


def _shard_record(expiration: str) -> str:
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="demo")
    model.scanner_results["bandit"] = ScannerStatusInfo(
        status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
    )
    stamp_shard_assignment(
        model,
        ShardAssignment(shard_index=0, shard_count=1, assigned_scanners=["bandit"]),
    )
    data = json.loads(model.model_dump_json(by_alias=True))
    data["ash_config"]["global_settings"]["ignore_paths"] = [
        {"path": "vendor/**", "reason": "vendored", "expiration": expiration}
    ]
    return json.dumps(data)


@pytest.mark.parametrize("debug", [False, True], ids=["default", "debug"])
@pytest.mark.parametrize("expiration", [CANARY, REFERENCE], ids=["text", "reference"])
def test_merge_names_the_entry_by_location(tmp_path, monkeypatch, expiration, debug):
    """What the matcher logs in a real merge, what merge prints, and the reports
    merge writes.

    The merged results file is left out for the text: it records the stored
    configuration, which keeps the date as written. For the reference it is
    checked too, since the record keeps the reference and not the value. What
    merge prints is checked for both.
    """
    monkeypatch.setenv("ASH_PROBE_EXP", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    # Control: the reference resolves to the canary in this process.
    assert resolve_env_references(REFERENCE) == CANARY
    monkeypatch.chdir(tmp_path)
    shard = tmp_path / "shard0"
    shard.mkdir()
    (shard / "ash_aggregated_results.json").write_text(
        _shard_record(expiration), encoding="utf-8"
    )
    merged = tmp_path / "merged"
    args = ["merge", "--results", str(shard), "--output-dir", str(merged)]
    with patch.object(matcher, "ASH_LOGGER", wraps=matcher.ASH_LOGGER) as log:
        result = CliRunner().invoke(
            app, [*args, *(["--debug"] if debug else [])], env={"COLUMNS": "300"}
        )

    printed = f"{result.stdout}\n{result.stderr}"
    record = merged / "ash_aggregated_results.json"
    wrote = record.exists()
    assert wrote, "merge wrote no results"
    written = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(merged.rglob("*"))
        if path.is_file() and (expiration == REFERENCE or path != record)
    )
    _assert_says(_logged(log), "global_settings.ignore_paths[0]")
    _assert_no_value(_logged(log))
    _assert_no_value(written)
    # What merge prints names the entry by its location, and holds neither form
    # of its date: as the stored configuration kept it, nor the value a
    # reference resolves to.
    named = "global_settings.ignore_paths[0]" in printed
    assert named, "the entry is not named"
    # The matcher's own warning is printed. The note on the stored
    # configuration names the same location, so the check above passes on
    # that note alone.
    flat = re.sub(r"\s+", " ", printed)
    warned = "format for global_settings.ignore_paths[0]." in flat
    assert warned, "the matcher's warning is not printed"
    _assert_no_value(printed)
