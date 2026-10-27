# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan that fails while running records its reason redacted.

The runner writes the failure's text into the registry entry's
error_message, which get_scan_progress hands to the client, and logs it.
The scan runs with the resolved config in use, so an error raised there is
the live producer of a text that can quote a value the config read from the
environment: an error that carries the values (error_text reads an error's
carried values itself) was already shown redacted, and these cells pin that
one that does not carry them is redacted too, through the values the scan's
pre-check resolution read.

Driven end to end: the directory tool starts the real runner task, with only
``run_ash_scan`` replaced by a failure that quotes the value, so the values
travel the production path from the pre-check into the runner's arms.
"""

import asyncio
import contextlib
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.previous_results import PreviousResults
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger
from tests.utils.mcp_sessions import a_session_with_a_bound_profile
from tests.utils.tasks import drain

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"
_TRACKING = "automated_security_helper.core.resource_management.scan_tracking"


def _register_profiles(entries):
    """Register each ``name -> path`` as the operator's profile of that name.

    The policy a delivered config is checked against is read from the
    REGISTERED profile, never from the binding
    (profile_registry.session_profile_entry), and a bound name no profile is
    registered under refuses every config a client delivers ("is not
    registered, so the runtime-override policy it sets cannot be read"). The
    entry's config is the plain default the tests bind, so the policy is the
    default one. The tests clear the registry when they end.
    """
    profile_registry.set_profile_registry(
        {
            name: profile_registry.ProfileEntry(
                name=name,
                path=Path(path),
                config=AshConfig(),
                path_sha256=hashlib.sha256(
                    str(Path(path).resolve()).encode("utf-8")
                ).hexdigest(),
            )
            for name, path in entries.items()
        }
    )


def _bind_as_the_trusted_base(session_id, profile, profile_name="held"):
    """Register the helper's profile and bind it as the scan's trusted base.

    The runner copies the profile the binding's ``trusted_config_path`` names
    (_run_scan_async reads resolve_session_trusted_config_path, never the
    session's ``config_path``): bound without it, a delivered config runs with
    no trusted base, no snapshot is taken, and no profile value joins the
    redaction set.
    """
    _register_profiles({profile_name: profile})
    profile_registry.bind_session_config(
        session_id,
        config=AshConfig(),
        profile_name=profile_name,
        config_path=str(profile),
        trusted_config_path=str(profile),
    )


def _a_session_with_a_bound_profile(
    ws, monkeypatch, session_id, profile_text, base_text=None
):
    """A real session sandbox whose trusted profile is bound through the
    profile registry: the delivered file is the client's and the profile is
    the operator's by the sandbox's own classification, with no stand-in, so
    these cells measure whose profile the runner resolves for which session.
    """
    target, delivered, profile, _config_dir = a_session_with_a_bound_profile(
        ws,
        monkeypatch,
        session_id,
        profile_text=profile_text,
        base_text=base_text,
        allowed_roots=False,
        clear_config_env=False,
    )
    _bind_as_the_trusted_base(session_id, profile)
    return target, delivered


def _a_failing_scan_in_the_session(
    target, delivered, session_id, run, extra=(), clean_output=False
):
    """Start the real runner task through the directory tool and gather it,
    returning the registry entry, the log calls, and the progress answer."""
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(
            str(target),
            config_path=str(delivered),
            session_id=session_id,
            clean_output=clean_output,
        )
        await drain(return_exceptions=True)
        return started

    try:
        with contextlib.ExitStack() as stack:
            for manager in (
                patch.object(ras, "run_ash_scan", run),
                patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
                patch(f"{_MGMT}.get_scan_registry", return_value=registry),
                patch(f"{_TOOLS}._logger", logger),
                *extra,
            ):
                stack.enter_context(manager)
            started = asyncio.run(start_and_wait_for_the_runner())
            scans = registry.list_scans()
            if len(scans) != 1 or started.get("success") is not True:
                raise RuntimeError(("control: the scan did not start", started, scans))
            entry = registry.get_scan(scans[0]["scan_id"])
            progress = asyncio.run(
                mcp_tools.mcp_get_scan_progress(
                    scans[0]["scan_id"], session_id=session_id
                )
            )
    finally:
        profile_registry.clear_session_state(session_id)
        profile_registry.clear_profile_registry()
    return entry, str(logger.mock_calls), json.dumps(progress, default=str)


def test_a_runner_failure_shows_no_value_the_config_read(tmp_path, monkeypatch):
    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_TOKEN", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_TOKEN:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    def a_run_that_quotes_the_value(*args, **kwargs):
        raise RuntimeError(f"the tool crashed: {secret}")

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(str(tmp_path))
        await drain(return_exceptions=True)
        return started

    with (
        patch.object(ras, "run_ash_scan", a_run_that_quotes_the_value),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", logger),
    ):
        started = asyncio.run(start_and_wait_for_the_runner())
        scans = registry.list_scans()
        if len(scans) != 1 or started.get("success") is not True:
            raise RuntimeError(("control: the scan did not start", started, scans))
        entry = registry.get_scan(scans[0]["scan_id"])
        progress = asyncio.run(mcp_tools.mcp_get_scan_progress(scans[0]["scan_id"]))

    assert entry.status == MCScanStatus.FAILED, entry.status
    # Controls: the runner's frame and the raised message's own words reached
    # the entry, so the redaction cells below measure redaction, not absence.
    assert "Error executing scan" in (entry.error_message or ""), entry.error_message
    assert "the tool crashed: " in (entry.error_message or ""), entry.error_message
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", json.dumps(progress, default=str)),
        ("the log", str(logger.mock_calls)),
    ):
        assert secret not in text, (surface, text)


_PROFILE_SECRET = "a-profile-value-read-from-the-environment"
_BASE_SECRET = "a-base-value-read-from-the-environment"
_SESSION_PROFILE_TEXT = (
    "extends: base.ash.yaml\nproject_name: ${ASH_PROFILE_TOKEN:unset}\n"
)
_SESSION_BASE_TEXT = (
    "global_settings:\n"
    "  ignore_paths:\n"
    "    - path: nothing-here\n"
    "      reason: ${ASH_PROFILE_BASE_TOKEN:unset}\n"
)


@pytest.mark.parametrize("source", ["profile", "base"])
@pytest.mark.parametrize(
    "arm", ["error", "refused-exit", "settle", "assess", "assess-incomplete"]
)
def test_a_runner_arm_shows_no_value_the_trusted_profile_read(
    tmp_path, monkeypatch, arm, source
):
    """A client-delivered config runs with the session's trusted profile as
    its base, and that operator profile can read the environment the way any
    operator file does (an environment-reading DELIVERED file is refused, so
    the delivered chain itself never contributes values). The profile's and
    its own base's values join the redaction set once, before the scan, so
    EVERY reason this runner records or logs hides them: the failure text,
    the refused exit's text, the settle failure's line, and both coverage
    assessment lines, not only the error arm's."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    monkeypatch.setenv("ASH_PROFILE_TOKEN", _PROFILE_SECRET)
    monkeypatch.setenv("ASH_PROFILE_BASE_TOKEN", _BASE_SECRET)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    target, delivered = _a_session_with_a_bound_profile(
        tmp_path / "ws",
        monkeypatch,
        "arm-session",
        _SESSION_PROFILE_TEXT,
        base_text=_SESSION_BASE_TEXT,
    )
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    secret = {"profile": _PROFILE_SECRET, "base": _BASE_SECRET}[source]
    extra = []
    clean = False
    if arm == "error":

        def run(*args, **kwargs):
            raise RuntimeError(f"the tool crashed: {secret}")

        expected = (MCScanStatus.FAILED, "Error executing scan")
    elif arm == "refused-exit":

        def run(*args, **kwargs):
            raise ras.ScanRefusedExit(3, f"refused because {secret}")

        expected = (MCScanStatus.FAILED, "ASH exited with code 3: refused because")
    elif arm == "settle":
        clean = True

        def run(*args, **kwargs):
            raise RuntimeError("the tool crashed")

        extra.append(
            patch.object(
                PreviousResults,
                "restore",
                side_effect=OSError(13, f"settle refused {secret}"),
            )
        )
        expected = (MCScanStatus.FAILED, "could not settle the previous results")
    elif arm == "assess":

        def run(*args, **kwargs):
            return AshAggregatedResults()

        extra.append(
            patch(
                f"{_TRACKING}.assess_coverage",
                side_effect=ValueError(f"bad coverage {secret}"),
            )
        )
        expected = (MCScanStatus.COMPLETED, "could not assess coverage")
    else:

        def run(*args, **kwargs):
            raise ras.ScanIncompleteExit(
                ras.ScanIncompleteness(scanners=(("bandit", "ERROR"),)),
                AshAggregatedResults(),
            )

        extra.append(
            patch(
                f"{_TRACKING}.assess_coverage",
                side_effect=ValueError(f"bad coverage {secret}"),
            )
        )
        expected = (
            MCScanStatus.INCOMPLETE,
            "reporting the exit code's reasons instead",
        )

    entry, logged, progress = _a_failing_scan_in_the_session(
        target, delivered, "arm-session", run, extra=extra, clean_output=clean
    )

    assert entry.status == expected[0], (entry.status, entry.error_message)
    # Control: the arm's own line was written with the system's words, so the
    # assertions below measure redaction, not absence.
    assert expected[1] in (entry.error_message or "") + logged, (
        entry.error_message,
        logged,
    )
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", progress),
        ("the log", logged),
    ):
        assert secret not in text, (surface, arm, text)


def test_each_sessions_scan_redacts_with_its_own_profile(tmp_path, monkeypatch):
    """Two sessions with distinct bound profiles: each session's scan hides
    the value its own profile read. The runner resolves the profile for the
    scan's session through the profile registry, so a runner that read some
    other session's profile would leave this session's value in clear."""
    first_secret = "a-first-sessions-profile-value"
    second_secret = "a-second-sessions-profile-value"
    monkeypatch.setenv("ASH_FIRST_SESSION_TOKEN", first_secret)
    monkeypatch.setenv("ASH_SECOND_SESSION_TOKEN", second_secret)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    ws = tmp_path / "ws"
    for session_id, reference, secret in (
        ("first-session", "ASH_FIRST_SESSION_TOKEN", first_secret),
        ("second-session", "ASH_SECOND_SESSION_TOKEN", second_secret),
    ):
        target, delivered = _a_session_with_a_bound_profile(
            ws,
            monkeypatch,
            session_id,
            f"project_name: ${{{reference}:unset}}\n",
        )
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))

        def run(*args, **kwargs):
            raise RuntimeError(f"the tool crashed: {secret}")  # noqa: B023

        entry, logged, progress = _a_failing_scan_in_the_session(
            target, delivered, session_id, run
        )
        assert entry.status == MCScanStatus.FAILED, entry.status
        assert "the tool crashed: " in (entry.error_message or ""), entry.error_message
        for surface, text in (
            ("the registry's error_message", entry.error_message or ""),
            ("the progress answer", progress),
            ("the log", logged),
        ):
            assert secret not in text, (session_id, surface, text)


def test_a_timed_out_scan_names_its_limit_in_the_token_form(tmp_path, monkeypatch):
    """A scan the server stops at scan_timeout_seconds records the limit
    through the timeout token, the one form every timeout message prints its
    limit in, so a limit that ever comes from the environment cannot ride the
    reason as a bare number."""
    import time

    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)
    scan_id = registry.register_scan(
        directory_path=str(tmp_path),
        output_directory=str(tmp_path / ".ash" / "ash_output"),
    )

    def a_run_that_outlives_the_limit(*args, **kwargs):
        time.sleep(0.5)
        raise RuntimeError("the tool crashed")

    with (
        patch.object(ras, "run_ash_scan", a_run_that_outlives_the_limit),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", logger),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(tmp_path),
                output_dir=str(tmp_path / ".ash" / "ash_output"),
                severity_threshold=None,
                scan_timeout_seconds=0.05,
            )
        )
    entry = registry.get_scan(scan_id)

    assert entry.status == MCScanStatus.FAILED, entry.status
    message = entry.error_message or ""
    assert "exceeded the server's scan_timeout_seconds" in message, message
    # The limit prints as the timeout token writes it, never as a bare number.
    assert "'0.05' s" in message, message


def test_a_timed_out_scan_hides_a_limit_the_profile_also_read(tmp_path, monkeypatch):
    """A session whose trusted profile read a value that types to the limit:
    the timeout reason names the option instead of the number, because the
    number is now a value the environment held. Without the environment
    value, the cell above shows the token still prints the plain limit."""
    import time

    monkeypatch.setenv("ASH_LIMIT_TWIN_TOKEN", "0.05")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    target, delivered = _a_session_with_a_bound_profile(
        tmp_path / "ws",
        monkeypatch,
        "limit-session",
        "project_name: ${ASH_LIMIT_TWIN_TOKEN:unset}\n",
    )
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)
    scan_id = registry.register_scan(
        directory_path=str(target),
        output_directory=str(target / ".ash" / "ash_output"),
        session_id="limit-session",
    )

    def a_run_that_outlives_the_limit(*args, **kwargs):
        time.sleep(0.5)
        raise RuntimeError("the tool crashed")

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_outlives_the_limit),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", logger),
        ):
            asyncio.run(
                mcp_tools._run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(target),
                    output_dir=str(target / ".ash" / "ash_output"),
                    severity_threshold=None,
                    config_path=str(delivered),
                    session_id="limit-session",
                    scan_timeout_seconds=0.05,
                )
            )
    finally:
        profile_registry.clear_session_state("limit-session")
        profile_registry.clear_profile_registry()
    entry = registry.get_scan(scan_id)

    assert entry.status == MCScanStatus.FAILED, entry.status
    message = entry.error_message or ""
    assert "exceeded the server's configured scan_timeout_seconds" in message, message
    assert "0.05" not in message, message
    assert "0.05" not in str(logger.mock_calls), logger.mock_calls


def test_a_settle_failure_shows_no_value_the_config_read(tmp_path, monkeypatch):
    """A scan that ends without results puts the previous results back, and a
    restore that fails is logged with the failure's text: that line redacts
    like every other reason the runner logs."""
    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_TOKEN", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_TOKEN:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    def a_run_that_fails(*args, **kwargs):
        raise RuntimeError("the tool crashed")

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
        await drain(return_exceptions=True)
        return started

    with (
        patch.object(ras, "run_ash_scan", a_run_that_fails),
        patch.object(
            PreviousResults,
            "restore",
            side_effect=OSError(13, f"settle refused {secret}"),
        ),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", logger),
    ):
        started = asyncio.run(start_and_wait_for_the_runner())

    if started.get("success") is not True:
        raise RuntimeError(("control: the scan did not start", started))
    logged = str(logger.mock_calls)
    # Control: the settle failure's line was written with the system's words.
    assert "could not settle the previous results" in logged, logged
    assert "settle refused" in logged, logged
    assert secret not in logged, logged


def test_an_incomplete_scans_assessment_failure_shows_no_value(tmp_path, monkeypatch):
    """The incomplete arm's own assess line, pinned like the completed arm's
    above: a scan that exits incomplete WITH results in hand re-assesses its
    coverage for the record, and an assessment that fails there is logged at
    WARNING with the exit code's reasons kept as the fallback. That line
    redacts like every other reason the runner logs, and the entry still
    lands INCOMPLETE."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_TOKEN", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_TOKEN:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    def a_run_that_exits_incomplete(*args, **kwargs):
        raise ras.ScanIncompleteExit(
            ras.ScanIncompleteness(scanners=(("bandit", "ERROR"),)),
            AshAggregatedResults(),
        )

    def an_assessment_that_quotes_the_value(results):
        raise ValueError(f"bad coverage {secret}")

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(str(tmp_path))
        await drain(return_exceptions=True)
        return started

    with (
        patch.object(ras, "run_ash_scan", a_run_that_exits_incomplete),
        patch(
            f"{_TRACKING}.assess_coverage",
            side_effect=an_assessment_that_quotes_the_value,
        ),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", logger),
    ):
        started = asyncio.run(start_and_wait_for_the_runner())
        scans = registry.list_scans()
        if len(scans) != 1 or started.get("success") is not True:
            raise RuntimeError(("control: the scan did not start", started, scans))
        entry = registry.get_scan(scans[0]["scan_id"])

    # The failed assessment falls back to the exit code's reasons; the scan
    # stays the incomplete arm's.
    assert entry.status == MCScanStatus.INCOMPLETE, entry.status
    logged = str(logger.mock_calls)
    # Control: the WARNING line was written with the assessment's own words.
    assert "reporting the exit code's reasons instead" in logged, logged
    assert "bad coverage" in logged, logged
    assert secret not in logged, logged


def test_a_coverage_assessment_failure_shows_no_value_the_config_read(
    tmp_path, monkeypatch
):
    """A finished scan whose coverage cannot be described logs the failure's
    text at WARNING without failing the scan: that line redacts like every
    other reason the runner logs."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    secret = "a-value-read-from-the-environment"
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.setenv("ASH_SCAN_START_TOKEN", secret)
    (tmp_path / ".ash.yaml").write_text(
        "project_name: ${ASH_SCAN_START_TOKEN:unset}\n", encoding="utf-8"
    )
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    def a_run_that_finishes(*args, **kwargs):
        return AshAggregatedResults()

    def an_assessment_that_quotes_the_value(results):
        raise ValueError(f"bad coverage {secret}")

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(str(tmp_path))
        await drain(return_exceptions=True)
        return started

    with (
        patch.object(ras, "run_ash_scan", a_run_that_finishes),
        patch(
            f"{_TRACKING}.assess_coverage",
            side_effect=an_assessment_that_quotes_the_value,
        ),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", logger),
    ):
        started = asyncio.run(start_and_wait_for_the_runner())
        scans = registry.list_scans()
        if len(scans) != 1 or started.get("success") is not True:
            raise RuntimeError(("control: the scan did not start", started, scans))
        entry = registry.get_scan(scans[0]["scan_id"])

    # The failure to describe coverage must not fail the scan.
    assert entry.status == MCScanStatus.COMPLETED, entry.status
    logged = str(logger.mock_calls)
    # Control: the WARNING line was written with the assessment's own words.
    assert "could not assess coverage" in logged, logged
    assert "bad coverage" in logged, logged
    assert secret not in logged, logged
