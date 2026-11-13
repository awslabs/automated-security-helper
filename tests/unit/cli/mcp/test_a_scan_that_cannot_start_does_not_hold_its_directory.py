# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan the directory tool registers but cannot start gives everything back.

The tool registers the scan before it creates the output directory, sets the
previous results aside and starts the runner's task. Until that task exists
nothing else will close the entry: an entry left pending occupies its
directory, so the registry refuses every later scan of that directory as one
already running, and it counts against max_concurrent_scans for the rest of
the process. The cells fail the start after the registration and check that
the entry is closed as failed with the reason, that the directory and the
slot are free for the next scan, and that previous results set aside for the
scan are put back.
"""

import asyncio
import json
from pathlib import Path

import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    PreviousResults,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.utils.log import ASHLogger
from tests.utils.scan_task_stubs import end_the_scans_scope_as_its_task_would

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"
_RESULTS = "ash_aggregated_results.json"


def _close_the_runner(scan_id, runner, **_start_options):
    # A start that never runs the scan: the cells test the tool, not the
    # runner. The scope ends as the real task's completion ends it. The real
    # start's keywords (ran, if_never_run) are accepted and left alone, as in
    # every start stand-in below.
    runner.close()
    end_the_scans_scope_as_its_task_would()


def _with_previous_reports(tmp_path):
    """An output directory holding a previous scan's report and results."""
    output = tmp_path / ".ash" / "ash_output"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "ash.sarif").write_text('{"previous": "sarif"}')
    (output / _RESULTS).write_text('{"previous": 1}')
    return output


def _assert_previous_reports_held(output):
    held = output / HELD_DIR_NAME
    assert (held / "reports" / "ash.sarif").is_file(), (
        "the previous report did not survive",
        sorted(p.relative_to(output).as_posix() for p in output.rglob("*")),
    )
    assert (held / "reports" / "ash.sarif").read_text() == '{"previous": "sarif"}'
    assert (held / _RESULTS).read_text() == '{"previous": 1}'


def _the_only_scan(registry):
    scans = registry.list_scans()
    if len(scans) != 1:
        raise RuntimeError(("control: expected one registered scan", scans))
    return registry.get_scan(scans[0]["scan_id"])


def test_a_scan_whose_previous_results_cannot_be_set_aside_frees_its_directory(
    tmp_path, monkeypatch
):
    """set_aside raises something the tool does not answer as a warning."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=_close_the_runner) as start,
    ):
        with patch.object(
            PreviousResults, "set_aside", side_effect=ValueError("not set aside")
        ):
            failed = asyncio.run(
                mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
            )
        entry = _the_only_scan(registry)
        again = asyncio.run(mcp_tools.mcp_scan_directory(str(tmp_path)))

    if failed.get("success") is not False:
        raise RuntimeError(("control: the first start did not fail", failed))
    assert entry.status == MCScanStatus.FAILED, entry.status
    assert "not set aside" in (entry.error_message or ""), entry.error_message
    assert not entry.occupies_its_directory(), "the scan still holds its directory"
    assert again.get("success") is True, ("the next scan was refused", again)
    assert start.call_count == 1, "the second scan did not start"


def test_a_scan_whose_task_cannot_start_puts_the_previous_results_back(
    tmp_path, monkeypatch
):
    """The previous results were set aside for the scan; no runner will settle
    them, so the tool puts them back."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output = tmp_path / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / _RESULTS).write_text('{"previous": 1}')
    registry = ScanRegistry()

    def a_start_that_fails(scan_id, runner, **_start_options):
        runner.close()
        raise RuntimeError("the task could not be started")

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=a_start_that_fails),
    ):
        failed = asyncio.run(
            mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
        )
    entry = _the_only_scan(registry)

    if failed.get("success") is not False:
        raise RuntimeError(("control: the start did not fail", failed))
    assert entry.status == MCScanStatus.FAILED, entry.status
    assert "the task could not be started" in (entry.error_message or "")
    assert not entry.occupies_its_directory(), "the scan still holds its directory"
    assert (output / _RESULTS).is_file(), "the previous results were not put back"
    assert (output / _RESULTS).read_text() == '{"previous": 1}'
    # As the runner records them, so progress does not read the previous
    # scan's results as this one's.
    assert entry.output_holds_previous_results is True, (
        "the entry does not say its directory holds the previous results"
    )


def test_a_set_aside_stopped_halfway_leaves_the_previous_results_whole(
    tmp_path, monkeypatch
):
    """set_aside raises, after it moved one entry, something that is not a
    refused move: the tool gives the scan back, and the previous results are
    all at the top of the output directory, none of them left staged. The next
    clean_output scan then sets all of them aside."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output = _with_previous_reports(tmp_path)
    registry = ScanRegistry()
    real_set_aside = PreviousResults.set_aside
    real_rename = Path.rename

    def set_aside_stopped_halfway(self):
        calls = {"n": 0}

        def rename(path, target):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("stopped halfway")
            return real_rename(path, target)

        with patch.object(Path, "rename", rename):
            real_set_aside(self)

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=_close_the_runner),
    ):
        with patch.object(PreviousResults, "set_aside", set_aside_stopped_halfway):
            failed = asyncio.run(
                mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
            )
        entry = _the_only_scan(registry)
        left = sorted(p.name for p in output.iterdir())
        rescan = asyncio.run(
            mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
        )

    if failed.get("success") is not False or entry.status != MCScanStatus.FAILED:
        raise RuntimeError(("control: the start did not fail", failed))
    if rescan.get("success") is not True:
        raise RuntimeError(("control: the rescan did not start", rescan))
    assert {_RESULTS, "reports"} <= set(left), ("the previous results were split", left)
    assert f"{HELD_DIR_NAME}.partial" not in left, ("an entry was left staged", left)
    _assert_previous_reports_held(output)


def test_what_a_killed_start_left_staged_survives_the_next_clean_output_scan(
    tmp_path, monkeypatch
):
    """A server killed while set_aside was moving left reports/ staged: the next
    clean_output scan holds it with the rest, and nothing is deleted."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output = _with_previous_reports(tmp_path)
    (output / f"{HELD_DIR_NAME}.partial").mkdir()
    (output / "reports").rename(output / f"{HELD_DIR_NAME}.partial" / "reports")
    registry = ScanRegistry()

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=_close_the_runner),
    ):
        rescan = asyncio.run(
            mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
        )

    if rescan.get("success") is not True:
        raise RuntimeError(("control: the scan did not start", rescan))
    _assert_previous_reports_held(output)
    assert not (output / f"{HELD_DIR_NAME}.partial").exists()


def test_a_start_failure_shows_no_value_the_scan_config_read(tmp_path, monkeypatch):
    """A start failure's reason is shown on four surfaces -- the registry's
    error_message, the progress answer built from it, the tool's own answer and
    the ERROR log line -- and each shows the text with any value the scan's
    config read from the environment redacted. The pre-check resolves the
    config's ``${...}`` references before the scan is registered; no error the
    registration block raises today quotes one, so the injected error pins the
    defense-in-depth contract: a text that ever carries one stays hidden."""
    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_HELD", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_HELD:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    def a_start_that_quotes_the_value(scan_id, runner, **_start_options):
        runner.close()
        raise RuntimeError(f"the task could not be started: {secret}")

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        # The progress answer is built by scan_management, which reads the
        # registry through its own import: patched too, so the progress cell
        # below reads this scan's entry and can fail. With only the first
        # patch it read the real (empty) registry, and the cell passed with
        # the redaction mutated away.
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", logger),
        patch(f"{_TOOLS}._start_scan_task", side_effect=a_start_that_quotes_the_value),
    ):
        failed = asyncio.run(mcp_tools.mcp_scan_directory(str(tmp_path)))
        scans = registry.list_scans()
        if len(scans) != 1:
            raise RuntimeError(("control: expected one registered scan", scans))
        entry = registry.get_scan(scans[0]["scan_id"])
        progress = asyncio.run(mcp_tools.mcp_get_scan_progress(scans[0]["scan_id"]))

    if failed.get("success") is not False:
        raise RuntimeError(("control: the start did not fail", failed))
    # Controls for the redaction cells below. The raised message's own words,
    # not just the wrapper's prefix, survive in the entry around the redacted
    # value, which shows as the placeholder; a reason that dropped the error's
    # text, or redacted all of it, fails here.
    assert entry.status == MCScanStatus.FAILED, entry.status
    message = entry.error_message or ""
    assert "the task could not be started: " in message, message
    assert "<value>" in message, message
    # The progress answer reports the failure WITH the entry's reason: a
    # progress read that misses this scan's registry answers neither.
    assert progress.get("status") == "failed", progress
    assert "the task could not be started: " in str(progress.get("error_message")), (
        progress
    )
    # The ERROR line was written through .error; the redaction check below
    # reads every method's calls, so a traceback logged another way is covered.
    assert logger.error.called, logger.mock_calls
    for surface, text in (
        ("the registry's error_message", message),
        ("the progress answer", json.dumps(progress, default=str)),
        ("the tool's answer", json.dumps(failed, default=str)),
        ("the log, every method", str(logger.mock_calls)),
    ):
        assert secret not in text, (surface, text)


def test_a_start_failures_context_and_suggestions_show_no_value(tmp_path, monkeypatch):
    """The refused answer's error text is redacted with the values the scan's
    config read; the answer's context strings and suggestions ride the same
    reply, so they are redacted the same way. No refusal raised in the
    registration block carries a value in them today; the injected error pins
    the defense-in-depth contract for the surfaces beside the text."""
    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_HELD", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_HELD:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()

    def a_start_that_quotes_the_value_beside_the_text(
        scan_id, runner, **_start_options
    ):
        runner.close()
        raise MCPResourceError(
            f"the task could not be started: {secret}",
            context={
                "error_message": f"the reason holds {secret}",
                "suggestions": [f"retry after reading {secret}"],
            },
        )

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(
            f"{_TOOLS}._start_scan_task",
            side_effect=a_start_that_quotes_the_value_beside_the_text,
        ),
    ):
        failed = asyncio.run(mcp_tools.mcp_scan_directory(str(tmp_path)))

    if failed.get("success") is not False:
        raise RuntimeError(("control: the start did not fail", failed))
    # Controls: the error's own words and its suggestion survive around the
    # redacted value, which shows as the placeholder.
    blob = json.dumps(failed, default=str)
    assert "the task could not be started: " in blob, failed
    assert "retry after reading " in blob, failed
    assert "<value>" in blob, failed
    assert secret not in blob, failed


@pytest.mark.parametrize("leaf", ["path-object", "dict-key", "nested-tuple"])
def test_a_start_failures_context_leaves_show_no_value(tmp_path, monkeypatch, leaf):
    """The context's NON-STRING pieces, pinned beside the string cells above:
    a Path leaf and a dict key render as text in the response exactly like a
    string item, so they are redacted the same way (the Path as its redacted
    str()). The nested tuple is the already-covered shape, kept as the
    control that the walk still reaches it."""
    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_HELD", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_HELD:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()
    if leaf == "path-object":
        context = {"where": Path("/somewhere") / secret}
    elif leaf == "dict-key":
        context = {"detail": {secret: "a value for the keyed entry"}}
    else:
        context = {"detail": ("a", ("b", f"in {secret}"))}

    def a_start_that_quotes_it_beside_the_text(scan_id, runner, **_start_options):
        runner.close()
        raise MCPResourceError("the task could not be started", context=context)

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(
            f"{_TOOLS}._start_scan_task",
            side_effect=a_start_that_quotes_it_beside_the_text,
        ),
    ):
        failed = asyncio.run(mcp_tools.mcp_scan_directory(str(tmp_path)))

    if failed.get("success") is not False:
        raise RuntimeError(("control: the start did not fail", failed))
    blob = json.dumps(failed, default=str)
    # Controls: the error's words and the redaction marker survive around the
    # hidden value, so the absence below is redaction, not a dropped context.
    assert "the task could not be started" in blob, failed
    assert "<value>" in blob, failed
    assert secret not in blob, failed


def test_a_start_failure_shows_no_value_the_operator_config_read(tmp_path, monkeypatch):
    """Every scan starts from the operator's ASH_CONFIG file too (the resource
    limits are its section), and that file can read the environment the same
    way a target's config does: its values join the redaction set, so a start
    failure's text hides them on the same four surfaces."""
    secret = "an-operator-value-read-from-the-environment"
    target = tmp_path / "repo"
    target.mkdir()
    operator_config = tmp_path / "op.ash.yaml"
    operator_config.write_text(
        "project_name: ${ASH_OPERATOR_HELD:unset}\n", encoding="utf-8"
    )
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    monkeypatch.setenv("ASH_OPERATOR_HELD", secret)
    monkeypatch.setenv("ASH_CONFIG", str(operator_config))
    monkeypatch.chdir(tmp_path)
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    def a_start_that_quotes_the_value(scan_id, runner, **_start_options):
        runner.close()
        raise RuntimeError(f"the task could not be started: {secret}")

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", logger),
        patch(f"{_TOOLS}._start_scan_task", side_effect=a_start_that_quotes_the_value),
    ):
        failed = asyncio.run(mcp_tools.mcp_scan_directory(str(target)))
        scans = registry.list_scans()
        if len(scans) != 1:
            raise RuntimeError(("control: expected one registered scan", scans))
        entry = registry.get_scan(scans[0]["scan_id"])
        progress = asyncio.run(mcp_tools.mcp_get_scan_progress(scans[0]["scan_id"]))

    if failed.get("success") is not False:
        raise RuntimeError(("control: the start did not fail", failed))
    assert entry.status == MCScanStatus.FAILED, entry.status
    assert "could not be started" in (entry.error_message or ""), entry.error_message
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", json.dumps(progress, default=str)),
        ("the tool's answer", json.dumps(failed, default=str)),
        ("the ERROR line", " ".join(str(c) for c in logger.error.call_args_list)),
    ):
        assert secret not in text, (surface, text)


def test_an_unmakeable_output_directory_shows_no_value_the_config_read(
    tmp_path, monkeypatch
):
    """A scan whose output directory cannot be created closes its entry with
    the operating system's words. Those words are shown to the client and
    recorded, so this arm redacts with the config's environment values as the
    other failure arms do."""
    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_HELD", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_HELD:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()
    real_mkdir = Path.mkdir

    def an_unmakeable_output(self, *args, **kwargs):
        if self.name == "ash_output":
            raise OSError(13, f"denied by policy {secret}")
        return real_mkdir(self, *args, **kwargs)

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=_close_the_runner),
        patch.object(Path, "mkdir", an_unmakeable_output),
    ):
        refused = asyncio.run(mcp_tools.mcp_scan_directory(str(tmp_path)))
    entry = _the_only_scan(registry)

    if refused.get("success") is not False:
        raise RuntimeError(("control: the scan was not refused", refused))
    assert entry.status == MCScanStatus.FAILED, entry.status
    # Control: the operating system's words survive around the redacted value.
    assert "denied by policy" in (entry.error_message or ""), entry.error_message
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the tool's answer", json.dumps(refused, default=str)),
    ):
        assert secret not in text, (surface, text)


def test_a_set_aside_warning_shows_no_value_the_scan_config_read(tmp_path, monkeypatch):
    """A set-aside refusal the tool answers as a warning quotes the operating
    system's words, which go into the started reply's warnings and the log:
    both show them with any value the scan's config read redacted, as the
    failure arms do."""
    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_HELD", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_HELD:unset}\n", encoding="utf-8"
    )
    output = tmp_path / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / _RESULTS).write_text('{"previous": 1}')
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", logger),
        patch(f"{_TOOLS}._start_scan_task", side_effect=_close_the_runner),
        patch.object(
            PreviousResults,
            "set_aside",
            side_effect=OSError(13, f"denied by policy {secret}"),
        ),
    ):
        started = asyncio.run(
            mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
        )

    if started.get("success") is not True:
        raise RuntimeError(("control: the scan did not start", started))
    warnings_text = json.dumps(started.get("warnings"), default=str)
    # Control: the warning and the system's words survive around the value.
    assert "Could not set the previous results aside" in warnings_text, started
    assert "denied by policy" in warnings_text, warnings_text
    assert secret not in warnings_text, warnings_text
    assert secret not in str(logger.mock_calls), logger.mock_calls


def test_a_registration_refusal_shows_no_value_the_scan_config_read(
    tmp_path, monkeypatch
):
    """No refusal the registry raises today quotes a value the scan's config
    read from the environment, but the refusal arm shows the error's own text
    to the client: it redacts like the sibling arms, so a refusal that ever
    carries one shows the redacted form."""
    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_HELD", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_HELD:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()

    def a_refusal_that_quotes_the_value(*args, **kwargs):
        raise MCPResourceError(f"refused at registration: {secret}")

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch.object(registry, "register_scan", a_refusal_that_quotes_the_value),
    ):
        refused = asyncio.run(mcp_tools.mcp_scan_directory(str(tmp_path)))

    if refused.get("success") is not False:
        raise RuntimeError(("control: the registration was not refused", refused))
    text = json.dumps(refused, default=str)
    # Control: the refusal's own words survive around the redacted value.
    assert "refused at registration" in text, text
    assert secret not in text, text


def test_a_scan_that_cannot_start_gives_its_concurrency_slot_back(
    tmp_path, monkeypatch
):
    """With max_concurrent_scans at 1, a scan of another directory starts
    after one that could not."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    registry = ScanRegistry()
    limits = SimpleNamespace(max_concurrent_scans=1, scan_timeout_seconds=None)
    starts = []

    def fail_the_first_start(scan_id, runner, **_start_options):
        runner.close()
        starts.append(scan_id)
        if len(starts) == 1:
            raise RuntimeError("the task could not be started")
        end_the_scans_scope_as_its_task_would()

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._resource_limits", return_value=limits),
        patch(f"{_TOOLS}._start_scan_task", side_effect=fail_the_first_start),
    ):
        failed = asyncio.run(mcp_tools.mcp_scan_directory(str(first)))
        started = asyncio.run(mcp_tools.mcp_scan_directory(str(second)))

    if failed.get("success") is not False or len(starts) < 1:
        raise RuntimeError(("control: the first start did not fail", failed))
    assert started.get("success") is True, (
        "the slot the failed scan took is still counted",
        started,
    )
