# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GuardDog reads the resolver's answer for its route, as the other five scanners do.

When GuardDog is not found through uv, its dependency check asks
``get_uv_tool_command`` once more, in two places: the branch taken when the
runner's availability check says uv is unavailable, and the last fallback, taken
after uv's install of it failed. The resolver answers ``["uv", "tool", "run",
...]`` when uv runs the tool and the path of a binary it found otherwise, so the
answer is the route.

Both places used to take any answer for "the binary is on PATH". The first turned
uv off and declared the dependency satisfied, the uv answer included, and kept the
uv probe's version for a copy that runs directly. The second set no route and
recorded no verdict. The runner's availability check is False for a probe that
failed (it timed out, was killed, or exited with a code uv does not use for an
answer) as well as for a uv that is absent, and the resolver's own probe can
succeed in the same moment. So a uv answer reached the first place with uv
installed and GuardDog not on PATH, and the scan started ``guarddog`` by name.

Every test states the route the scan takes and the record that route owes: a copy
on PATH is verified against the scan's requirement and its own version recorded,
and the uv route keeps what the uv probe recorded.

A probe that timed out opens a retry window in which the runner's availability
check keeps answering "unavailable" without probing again, and the resolver, which
never reads that window, can answer the uv form in the same moment. Every run of
the scan passes that check, which refuses a uv run while it says no and starts
nothing in its place, so a uv answer there is not a route the scan can run. The
tests of that input put the window's answer where the unit tests' tool guard puts
uv-absent's, and let the mixin's own check, version probe and gates read it.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_guarddog_plugins import (
    guarddog_scanner as guarddog_module,
)
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GuardDogScanner,
    GuardDogScannerConfig,
    GuardDogScannerConfigOptions,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

TOOL = "guarddog"

#: A copy of GuardDog on PATH, as the resolver names a binary it found.
COPY = "/opt/bin/guarddog"

#: What the resolver answers when uv runs GuardDog: uv, ``tool run``, ``--from`` the
#: spec, then the tool.
UV_ANSWER = ["uv", "tool", "run", "--from", f"{TOOL}==3.2.0", TOOL]

#: The failure the runner's availability check carries inside the retry window a
#: probe that timed out opens: the probe's own words.
PROBE_TIMED_OUT = "the probe timed out after 10 seconds"

#: What ``_uv_probe_from_spec`` answers in the tests of the resolver's arguments: a
#: value the scan's own spec cannot equal, so the argument is shown to come from
#: that method.
SPEC = "guarddog==9.9.9"

#: uv as the resolver can name it: the bare word, its path, and a Windows
#: executable in either letter case.
UV_NAMES = pytest.mark.parametrize(
    "uv",
    ["uv", "/opt/uv/bin/uv", "C:\\Users\\me\\.local\\bin\\uv.exe", "C:/tools/UV.EXE"],
    ids=["bare", "posix-path", "windows-exe", "upper-case-exe"],
)

#: What the uv probe left on the scanner: the version it answered, or a probe
#: still owed.
UV_RECORDS = pytest.mark.parametrize(
    ("version", "owed"),
    [("9.9.9", False), (None, True)],
    ids=["probe-answered", "probe-owed"],
)

OFFLINE_MODES = pytest.mark.parametrize(
    "offline", [True, False], ids=["offline", "online"]
)


@pytest.fixture(autouse=True)
def _a_supported_host(monkeypatch):
    """GuardDog cannot be installed on Windows, and its check says so before it asks
    the resolver anything. These tests are about the resolver's answer, whatever
    the host."""
    monkeypatch.setattr(
        GuardDogScanner, "unsupported_platform_reason", lambda self: None
    )


def _scanner(tmp_path: Path) -> GuardDogScanner:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return GuardDogScanner(
        context=context,
        config=GuardDogScannerConfig(
            enabled=True, options=GuardDogScannerConfigOptions()
        ),
    )


def _copy(tmp_path: Path) -> Path:
    """An executable stand-in for a copy on PATH."""
    copy = tmp_path / "pathbin" / TOOL
    copy.parent.mkdir(exist_ok=True)
    copy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    copy.chmod(0o755)
    return copy


class _Resolver:
    """Stands in for ``get_uv_tool_command``: gives one answer, records each call."""

    def __init__(self, answer: List[str] | None) -> None:
        self.answer = answer
        self.calls: List[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> List[str] | None:
        self.calls.append((args, kwargs))
        return self.answer


def _verdict(
    status: str, version: str | None = None, detail: str = "", summary: str = ""
) -> Any:
    return SimpleNamespace(
        status=status,
        executable=COPY,
        detail=detail,
        summary=summary,
        from_nix=False,
        version=version,
    )


class _Verifier:
    """Stands in for ``verify_pre_installed_tool``: gives one verdict, records what
    it was asked."""

    def __init__(self, verdict: Any) -> None:
        self.verdict = verdict
        self.asked: List[tuple[Any, ...]] = []

    def __call__(
        self, executable, package, extras=None, version_constraint=None, **kwargs
    ):
        self.asked.append((executable, package, extras, version_constraint))
        return self.verdict


def _never_verified(*args: Any, **kwargs: Any) -> Any:
    pytest.fail("the answer is not verified as the tool")


def _answering(
    monkeypatch, answer, verifier=_never_verified, on_path: str | None = None
) -> _Resolver:
    """The resolver answers ``answer``, and ``on_path`` is what a lookup of the tool's
    name finds on PATH: nothing unless a copy is given."""
    resolver = _Resolver(answer)
    monkeypatch.setattr(guarddog_module, "get_uv_tool_command", resolver)
    monkeypatch.setattr(guarddog_module, "verify_pre_installed_tool", verifier)
    monkeypatch.setattr(
        guarddog_module,
        "find_executable",
        lambda name: on_path if name == TOOL else None,
    )
    return resolver


def _inside_the_retry_window(monkeypatch) -> None:
    """The runner's availability check as it answers inside the window a timed-out
    probe opened: no, with the probe's failure, and without probing again.

    Nothing else is replaced. The check of the mixin, its version probe and its gates
    all read this one answer, as they do in a run. The unit tests' tool guard puts
    uv-absent's answer there, which carries no failure; this puts the window's in its
    place."""
    monkeypatch.setattr(
        UVToolRunner, "uv_availability", lambda runner: (False, PROBE_TIMED_OUT)
    )


def _without_uv(monkeypatch, scanner, answer, verifier=_never_verified) -> _Resolver:
    """The check as it runs when the runner says uv is unavailable."""
    cls = type(scanner)
    monkeypatch.setattr(cls, "resolve_deferred_tool_version", lambda self: None)
    monkeypatch.setattr(cls, "_validate_uv_tool_availability", lambda self: False)
    return _answering(monkeypatch, answer, verifier)


def _at_the_last_fallback(
    monkeypatch, scanner, answer, verifier=_never_verified
) -> _Resolver:
    """The check as it runs when uv is available, GuardDog is not found and uv's
    install of it failed (a scanner already off uv skips the same steps)."""
    cls = type(scanner)
    monkeypatch.setattr(cls, "resolve_deferred_tool_version", lambda self: None)
    monkeypatch.setattr(cls, "_validate_uv_tool_availability", lambda self: True)
    monkeypatch.setattr(
        cls, "_get_tool_installation_info", lambda self: {"available": False}
    )
    monkeypatch.setattr(cls, "_install_uv_tool", lambda self, **kwargs: False)
    return _answering(monkeypatch, answer, verifier)


# ---------------------------------------------------------------------------
# The runner says uv is unavailable
# ---------------------------------------------------------------------------


@UV_NAMES
@UV_RECORDS
def test_a_uv_answer_with_uv_unavailable_keeps_the_uv_route(
    tmp_path, monkeypatch, uv, version, owed
):
    """The runner's availability check says uv is unavailable while the resolver's
    own probe of GuardDog through uv succeeded. The answer is the route, uv however
    it is named: the dependency is satisfied, the answer is not verified as if it
    were the tool, and what the uv probe recorded (its version, or the probe still
    owed) stays.

    Fails at the base: any answer turned uv off, so the scan started ``guarddog``
    by name."""
    scanner = _scanner(tmp_path)
    scanner.use_uv_tool = True
    scanner.tool_version = version
    scanner._deferred_tool_version_probe = (TOOL, None) if owed else None
    _without_uv(monkeypatch, scanner, [uv, "tool", "run", TOOL])

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.dependencies_satisfied is True
    assert scanner.tool_version == version
    assert scanner._deferred_tool_version_probe == ((TOOL, None) if owed else None)


def test_no_answer_with_uv_unavailable_is_not_satisfied(tmp_path, monkeypatch):
    """Neither uv nor a copy on PATH: the check says so, as it did before."""
    scanner = _scanner(tmp_path)
    _without_uv(monkeypatch, scanner, None)

    assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependencies_satisfied is False
    assert any("UV is not available but required" in line for line in scanner.errors)


def test_a_copy_that_falls_short_is_missing_with_the_reason(tmp_path, monkeypatch):
    """With uv unavailable, the copy on PATH is the scan's GuardDog, so it is
    verified against the scan's requirement (its extras and version constraint).
    One that falls short is MISSING, with the reason recorded for the row and
    logged.

    Fails at the base: the copy was never verified, and was declared satisfied."""
    scanner = _scanner(tmp_path)
    detail = "guarddog 2.9.0 does not satisfy ==3.2.0"
    verifier = _Verifier(_verdict("unsatisfied", version="2.9.0", detail=detail))
    _without_uv(monkeypatch, scanner, [COPY], verifier)

    assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependencies_satisfied is False
    reason = scanner.dependency_unavailable_reason
    assert reason is not None and COPY in reason and detail in reason
    assert any(reason in line for line in scanner.errors)
    assert verifier.asked == [
        (
            COPY,
            TOOL,
            scanner._get_tool_package_extras(),
            scanner._get_tool_version_constraint(),
        )
    ]


@pytest.mark.parametrize("answered", ["3.2.0", None], ids=["a-version", "none"])
def test_a_copy_that_satisfies_runs_directly_with_its_own_version(
    tmp_path, monkeypatch, answered
):
    """A copy that satisfies the requirement runs directly. The version the uv
    probe recorded names uv's environment, which does not run, so the copy's own
    answer replaces it (nothing, when the copy answered none) and the probe is no
    longer owed.

    Fails at the base: the probe's version stayed, for a copy no one had asked."""
    scanner = _scanner(tmp_path)
    scanner.use_uv_tool = True
    scanner.tool_version = "9.9.9"  # the uv probe's answer
    scanner._deferred_tool_version_probe = (TOOL, None)
    verifier = _Verifier(_verdict("satisfied", version=answered, detail="ok"))
    _without_uv(monkeypatch, scanner, [COPY], verifier)

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.dependencies_satisfied is True
    assert scanner.tool_version == answered
    assert scanner._deferred_tool_version_probe is None
    assert [asked[:2] for asked in verifier.asked] == [(COPY, TOOL)]


def test_a_copy_that_cannot_be_verified_runs_with_a_warning(
    tmp_path, monkeypatch, capture
):
    """A copy the check could not verify runs, since nothing better is at hand, and
    the log says it was not verified. It names no version, so none is recorded for
    it: the uv probe's names another environment.

    Fails at the base: the copy was never verified, so no line said so, and the
    probe's version stayed."""
    scanner = _scanner(tmp_path)
    scanner.tool_version = "9.9.9"  # the uv probe's answer
    verifier = _Verifier(_verdict("unverifiable", detail="the version probe timed out"))
    _without_uv(monkeypatch, scanner, [COPY], verifier)

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.dependencies_satisfied is True
    assert scanner.dependency_unavailable_reason is None
    assert scanner.tool_version is None
    assert "could not be verified" in capture.text
    assert COPY in capture.text


@OFFLINE_MODES
def test_the_uv_absent_branch_asks_the_resolver_under_the_scans_spec_and_mode(
    tmp_path, monkeypatch, offline
):
    """The resolver's probe is the scan's own: ``--from`` the spec the scan runs
    under, and offline when the scanner is. Without them it probed the bare tool
    name, an environment the scan never uses, and online for a scan that was
    offline.

    Fails at the base: the resolver was called with the tool name alone."""
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(GuardDogScanner, "_uv_probe_from_spec", lambda self: SPEC)
    monkeypatch.setattr(GuardDogScanner, "_is_offline_mode", lambda self: offline)
    resolver = _without_uv(monkeypatch, scanner, ["uv", "tool", "run", TOOL])

    assert scanner.validate_plugin_dependencies() is True

    assert resolver.calls == [((TOOL,), {"from_spec": SPEC, "offline": offline})]


# ---------------------------------------------------------------------------
# A uv answer inside the retry window of a probe that timed out
# ---------------------------------------------------------------------------


def test_a_uv_answer_inside_the_window_runs_a_copy_that_satisfies_directly(
    tmp_path, monkeypatch
):
    """The runner's probe of uv timed out, so inside its retry window the availability
    check says no, while the resolver's own probe answers the uv form. Every run of
    the scan passes that check, which refuses a uv run and starts nothing in its
    place, so the uv route the answer names cannot run now. The copy on PATH that a
    direct run would start is verified against the scan's requirement as the copy a
    binary answer names is, and a copy that satisfies it runs: its own version is
    recorded, and the version probe the uv route owed is dropped.

    Without the fix the scan kept the uv route, and inside the window every run of
    it was refused although a usable copy was on PATH."""
    scanner = _scanner(tmp_path)
    _inside_the_retry_window(monkeypatch)
    verifier = _Verifier(_verdict("satisfied", version="3.2.0 (on PATH)", detail="ok"))
    _answering(monkeypatch, UV_ANSWER, verifier, on_path=COPY)

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.dependencies_satisfied is True
    assert scanner.tool_version == "3.2.0 (on PATH)"
    assert scanner._deferred_tool_version_probe is None
    assert verifier.asked == [
        (
            COPY,
            TOOL,
            scanner._get_tool_package_extras(),
            scanner._get_tool_version_constraint(),
        )
    ]


def test_a_uv_answer_inside_the_window_runs_a_copy_that_cannot_be_verified_with_a_warning(
    tmp_path, monkeypatch, capture
):
    """A copy the check could not verify runs, since nothing else can run inside the
    window, and the log says it was not verified. It names no version, so none is
    recorded for it and the probe the uv route owed is dropped.

    Without the fix the scan kept the uv route, and inside the window every run of
    it was refused."""
    scanner = _scanner(tmp_path)
    _inside_the_retry_window(monkeypatch)
    verifier = _Verifier(_verdict("unverifiable", detail="the version probe timed out"))
    _answering(monkeypatch, UV_ANSWER, verifier, on_path=COPY)

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.dependencies_satisfied is True
    assert scanner.dependency_unavailable_reason is None
    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe is None
    assert "could not be verified" in capture.text
    assert COPY in capture.text


def test_a_uv_answer_inside_the_window_keeps_uv_over_a_copy_that_falls_short(
    tmp_path, monkeypatch, capture
):
    """A copy that falls short of the scan's requirement is not run, and it is not a
    reason to give up the scanner either: the uv route runs GuardDog under the
    scan's own requirement once the availability check passes. The scan keeps that
    route and what the uv probe recorded for it (here the probe, still owed), and
    the log says why the copy on PATH is not run.

    Without the fix the copy was never checked, and nothing said why it was not run."""
    scanner = _scanner(tmp_path)
    _inside_the_retry_window(monkeypatch)
    detail = "guarddog 2.9.0 does not satisfy ==3.2.0"
    summary = "version 2.9.0 is below the required ==3.2.0"
    verifier = _Verifier(
        _verdict("unsatisfied", version="2.9.0", detail=detail, summary=summary)
    )
    _answering(monkeypatch, UV_ANSWER, verifier, on_path=COPY)

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.dependencies_satisfied is True
    assert scanner.dependency_unavailable_reason is None
    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe == (TOOL, scanner._uv_from_spec())
    assert verifier.asked == [
        (
            COPY,
            TOOL,
            scanner._get_tool_package_extras(),
            scanner._get_tool_version_constraint(),
        )
    ]
    # The verdict's summary names the shortfall; its detail can quote the copy's own
    # output, so the line does not carry it.
    assert COPY in capture.text
    assert summary in capture.text
    assert detail not in capture.text


# ---------------------------------------------------------------------------
# The last fallback, after uv's install failed
# ---------------------------------------------------------------------------


@UV_NAMES
@UV_RECORDS
def test_a_uv_answer_after_a_failed_install_keeps_the_uv_route(
    tmp_path, monkeypatch, uv, version, owed
):
    """After uv's install of GuardDog failed, an answer that names uv is still the
    uv route, however uv is named. The dependency is recorded as satisfied, and
    what the uv probe recorded stays.

    Fails at the base: the fallback returned True and recorded no verdict."""
    scanner = _scanner(tmp_path)
    scanner.use_uv_tool = True
    scanner.tool_version = version
    scanner._deferred_tool_version_probe = (TOOL, None) if owed else None
    _at_the_last_fallback(monkeypatch, scanner, [uv, "tool", "run", TOOL])

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.dependencies_satisfied is True
    assert scanner.tool_version == version
    assert scanner._deferred_tool_version_probe == ((TOOL, None) if owed else None)


def test_a_binary_after_a_failed_install_takes_the_direct_route(tmp_path, monkeypatch):
    """After uv's install failed, a binary the resolver found on PATH has to run
    directly: with the uv route left on, every scan went through the uv whose
    install had just failed. It runs unverified, as checkov and cfn-lint run theirs
    here, and the copy's version is not read, so the uv probe's, which names
    another environment, is dropped with the probe still owed.

    Fails at the base: the route stayed on uv."""
    scanner = _scanner(tmp_path)
    scanner.use_uv_tool = True
    scanner.tool_version = "9.9.9"  # the uv probe's answer
    scanner._deferred_tool_version_probe = (TOOL, None)
    _at_the_last_fallback(monkeypatch, scanner, [COPY])

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.dependencies_satisfied is True
    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe is None


@OFFLINE_MODES
def test_the_last_fallback_asks_the_resolver_under_the_scans_spec_and_mode(
    tmp_path, monkeypatch, offline
):
    """The same arguments as the uv-absent branch's call: the scan's spec, and the
    scanner's own offline mode.

    Fails at the base: the resolver was called with the tool name alone."""
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(GuardDogScanner, "_uv_probe_from_spec", lambda self: SPEC)
    monkeypatch.setattr(GuardDogScanner, "_is_offline_mode", lambda self: offline)
    resolver = _at_the_last_fallback(monkeypatch, scanner, ["uv", "tool", "run", TOOL])

    assert scanner.validate_plugin_dependencies() is True

    assert resolver.calls == [((TOOL,), {"from_spec": SPEC, "offline": offline})]


def test_a_revalidation_already_off_uv_keeps_the_version_of_the_copy_that_runs(
    tmp_path, monkeypatch
):
    """A re-validation of a scanner already on a direct route sees the same binary
    again. It must not erase the version of the copy that keeps running."""
    scanner = _scanner(tmp_path)
    scanner.use_uv_tool = False
    scanner.tool_version = "3.2.0"  # the copy that runs, recorded when it was chosen
    scanner._deferred_tool_version_probe = None
    _at_the_last_fallback(monkeypatch, scanner, [COPY])

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.tool_version == "3.2.0"


def test_the_resolver_returning_to_uv_takes_the_old_version_with_the_route(
    tmp_path, monkeypatch
):
    """A scanner on a direct route whose resolver now answers uv goes back to the
    uv route. The version recorded for the copy goes with the route, and the uv
    probe is owed again.

    Fails at the base: the fallback left the route where it was."""
    scanner = _scanner(tmp_path)
    scanner.use_uv_tool = False
    scanner.tool_version = "1.2.3"
    scanner._deferred_tool_version_probe = None
    _at_the_last_fallback(monkeypatch, scanner, ["uv", "tool", "run", TOOL])

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe == (TOOL, None)


def test_a_verified_copy_still_on_path_is_honored_without_asking_the_resolver(
    tmp_path, monkeypatch
):
    """A copy on PATH an earlier validation of this instance verified, and chose to
    run directly, is honored while it still exists. Re-running selection from a
    scanner already off uv falls to the resolver, whose uv answer flipped the scan
    back through uv, with a cold probe paid to do it, so the verified copy never
    ran. checkov, cfn-lint and bandit consult the record first; GuardDog's fallback
    re-points the route from the answer as theirs do, so it consults it too.

    Fails at the base: the resolver was asked."""
    scanner = _scanner(tmp_path)
    scanner.use_uv_tool = False
    scanner._verified_pre_installed_executable = str(_copy(tmp_path))
    scanner.tool_version = "3.2.0"  # the verified copy's own version
    scanner._deferred_tool_version_probe = None
    resolver = _at_the_last_fallback(monkeypatch, scanner, ["uv", "tool", "run", TOOL])

    assert scanner.validate_plugin_dependencies() is True

    assert resolver.calls == []
    assert scanner.use_uv_tool is False
    assert scanner.dependencies_satisfied is True
    assert scanner.tool_version == "3.2.0"
