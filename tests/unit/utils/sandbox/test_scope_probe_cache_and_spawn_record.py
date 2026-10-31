# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox scope remembers only lasting probe answers, and records any argv.

``resolve_backend`` probes a backend once per process and tree scope. A probe
whose reason is a passing condition (the probe process timed out, a resource was
busy) used to be remembered like a missing program, so every later scan in the
process was refused or downgraded; an answer reached through such a condition
(the refusal, or under auto a fallback taken past a transient skip) is now kept
for a short window, so one scan's scanners share one answer, and probed again
after it. A missing backend is still remembered for the process.

``_plan_spawn``'s DEBUG record of the planned argv used to join the arguments
as text, which raised TypeError for a path object (subprocess accepts one) after
the plan's writable-root registrations had been made and before anything could
release them, and ran two arguments holding blanks into one. The record now shows
each argument's ``str``, shell-quoted; an env-read value whose quoted spelling
differs from its text is hidden in both spellings.

``prepare_spawn`` used to count a plan that failed for any reason as a sandbox
refusal, so a program Landlock could not find read on a converter's row as "the
scanner sandbox refused" it while the same missing program under bwrap, failing at
Popen, was never counted. A failed plan is now counted apart (``failed_spawns``,
``last_failure``), and only a ``SandboxUnavailable`` is a refusal.
"""

from __future__ import annotations

import platform
import shlex
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.utils.sandbox import scope
from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    SandboxUnavailable,
)

pytestmark = pytest.mark.unit

# The shape SandboxBackend.probe gives a probe that raised subprocess's
# TimeoutExpired, and the one a backend returns for a missing program.
TIMED_OUT = (
    "bwrap probe failed: Command '['/usr/bin/bwrap', '--ro-bind', '/', '/', "
    "'/usr/bin/true']' timed out after 20 seconds"
)
NOT_INSTALLED = "bwrap is not installed (install the 'bubblewrap' package)"


@pytest.fixture
def fresh_cache():
    scope.clear_backend_cache()
    yield
    scope.clear_backend_cache()


def _probe_answers(monkeypatch, answers):
    """Replace the probe: each call takes the next answer, the last one repeating.

    An exception answer is raised; any other is returned as the backend. Returns
    the list of backend names probed, in order.
    """
    probes: list = []

    def probe(name):
        probes.append(name)
        answer = answers[min(len(probes) - 1, len(answers) - 1)]
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(scope, "_probe_backend", probe)
    return probes


def _backend(name="bwrap"):
    backend = MagicMock()
    backend.name = name
    return backend


class _Clock:
    """A monotonic clock the test advances by hand."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    """The scope module's clock, replaced so a transient window can be crossed."""
    clock = _Clock()
    monkeypatch.setattr(scope, "time", clock)
    return clock


PAST_THE_WINDOW = scope._TRANSIENT_RETRY_SECONDS + 1.0


def test_a_probe_that_timed_out_is_probed_again_after_the_window(
    fresh_cache, monkeypatch, clock
):
    """Inside the window the refusal is served from memory (one timeout per tree
    scope, not one per scanner); past it the next request probes again."""
    backend = _backend()
    probes = _probe_answers(monkeypatch, [SandboxUnavailable(TIMED_OUT), backend])

    with pytest.raises(scope.SandboxBackendUnavailable) as first:
        scope.resolve_backend("bwrap")
    assert TIMED_OUT in str(first.value)

    with pytest.raises(scope.SandboxBackendUnavailable) as second:
        scope.resolve_backend("bwrap")
    assert TIMED_OUT in str(second.value)
    assert probes == ["bwrap"]

    clock.advance(PAST_THE_WINDOW)
    assert scope.resolve_backend("bwrap") is backend
    assert probes == ["bwrap", "bwrap"]


def test_a_busy_resource_is_probed_again_after_the_window(
    fresh_cache, monkeypatch, clock
):
    backend = _backend()
    probes = _probe_answers(
        monkeypatch,
        [
            SandboxUnavailable(
                "bwrap probe failed: [Errno 11] Resource temporarily unavailable"
            ),
            backend,
        ],
    )

    with pytest.raises(scope.SandboxBackendUnavailable):
        scope.resolve_backend("bwrap")

    clock.advance(PAST_THE_WINDOW)
    assert scope.resolve_backend("bwrap") is backend
    assert probes == ["bwrap", "bwrap"]


def test_the_window_runs_from_the_end_of_a_slow_probe(fresh_cache, monkeypatch, clock):
    """A probe that itself takes 40 s must not use that time out of the window:
    the answer is served for the full window after the probe ended."""
    probes: list = []

    def slow_probe(name):
        probes.append(name)
        clock.advance(40.0)
        raise SandboxUnavailable(TIMED_OUT)

    monkeypatch.setattr(scope, "_probe_backend", slow_probe)

    with pytest.raises(scope.SandboxBackendUnavailable):
        scope.resolve_backend("bwrap")

    # Red at the base: the window was counted from before the probe, so it ended
    # 40 s earlier and this call probed again.
    clock.advance(scope._TRANSIENT_RETRY_SECONDS - 1.0)
    with pytest.raises(scope.SandboxBackendUnavailable):
        scope.resolve_backend("bwrap")
    assert probes == ["bwrap"]

    clock.advance(2.0)
    with pytest.raises(scope.SandboxBackendUnavailable):
        scope.resolve_backend("bwrap")
    assert probes == ["bwrap", "bwrap"]


def test_a_missing_backend_is_remembered(fresh_cache, monkeypatch, clock):
    """A missing program has no window: it is remembered for the process."""
    probes = _probe_answers(monkeypatch, [SandboxUnavailable(NOT_INSTALLED)])

    for _ in range(2):
        with pytest.raises(scope.SandboxBackendUnavailable, match="not installed"):
            scope.resolve_backend("bwrap")
        clock.advance(PAST_THE_WINDOW)

    assert probes == ["bwrap"]


def test_under_auto_one_timed_out_member_is_probed_again(
    fresh_cache, monkeypatch, clock
):
    """The joined auto reason is transient when one backend's probe timed out."""
    monkeypatch.setattr(
        scope, "AUTO_ORDER", {platform.system().lower(): ("bwrap", "firejail")}
    )
    backend = _backend()
    answers = {
        "bwrap": [SandboxUnavailable(TIMED_OUT), backend],
        "firejail": [SandboxUnavailable("firejail is not installed")],
    }
    probes: list = []

    def probe(name):
        probes.append(name)
        answer = answers[name].pop(0) if len(answers[name]) > 1 else answers[name][0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(scope, "_probe_backend", probe)

    with pytest.raises(scope.SandboxBackendUnavailable) as first:
        scope.resolve_backend("auto")

    assert "timed out" in str(first.value)
    assert "firejail is not installed" in str(first.value)
    with pytest.raises(scope.SandboxBackendUnavailable):
        scope.resolve_backend("auto")
    assert probes == ["bwrap", "firejail"]

    clock.advance(PAST_THE_WINDOW)
    assert scope.resolve_backend("auto") is backend
    assert probes == ["bwrap", "firejail", "bwrap"]


def test_under_auto_a_fallback_past_a_transient_skip_expires(
    fresh_cache, monkeypatch, clock
):
    """bwrap times out, firejail works: firejail answers for the window, not for
    the process; past the window the preferred backend is tried again."""
    monkeypatch.setattr(
        scope, "AUTO_ORDER", {platform.system().lower(): ("bwrap", "firejail")}
    )
    bwrap = _backend("bwrap")
    firejail = _backend("firejail")
    answers = {
        "bwrap": [SandboxUnavailable(TIMED_OUT), bwrap],
        "firejail": [firejail],
    }
    probes: list = []

    def probe(name):
        probes.append(name)
        answer = answers[name].pop(0) if len(answers[name]) > 1 else answers[name][0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(scope, "_probe_backend", probe)

    assert scope.resolve_backend("auto") is firejail
    assert scope.resolve_backend("auto") is firejail
    assert probes == ["bwrap", "firejail"]

    clock.advance(PAST_THE_WINDOW)
    assert scope.resolve_backend("auto") is bwrap
    assert probes == ["bwrap", "firejail", "bwrap"]

    clock.advance(PAST_THE_WINDOW)
    assert scope.resolve_backend("auto") is bwrap
    assert probes == ["bwrap", "firejail", "bwrap"]


class _PlanningBackend:
    """A backend whose plan is the argv it was given, as the real ones keep it."""

    name = "fake"

    def plan(self, argv, env, policy):
        return SpawnPlan(argv=list(argv), env=dict(env))


class _Logger:
    def __init__(self):
        self.debug_lines: list = []

    def isEnabledFor(self, level):
        return True

    def debug(self, message, *args, **kwargs):
        self.debug_lines.append(message)

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


def _scope(tmp_path, backend=None, **fields) -> scope.SandboxScope:
    return scope.SandboxScope(
        backend=backend or _PlanningBackend(),
        scanner_name="scanner",
        requirements=SandboxRequirements(),
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        results_dir=tmp_path / "out" / "scanner",
        scan_target=None,
        offline=True,
        **fields,
    )


@pytest.fixture
def debug_record(monkeypatch):
    """A DEBUG-delivering logger in the scope module, and a policy that grants nothing."""
    logger = _Logger()
    monkeypatch.setattr(scope, "ASH_LOGGER", logger)
    monkeypatch.setattr(scope, "delivers", lambda *args: True)
    monkeypatch.setattr(
        scope,
        "build_scanner_policy",
        lambda *args, **kwargs: SimpleNamespace(network=False, writable=[]),
    )
    return logger


def _record(logger: _Logger) -> str:
    (line,) = [
        text for text in logger.debug_lines if text.startswith("Scanner sandbox")
    ]
    return line


def test_a_path_argument_is_recorded_not_a_type_error(tmp_path, debug_record):
    sandbox_scope = _scope(tmp_path)
    target = tmp_path / "a dir"
    argv = ["tool", target, "--flag"]

    with scope.sandbox_scope(sandbox_scope):
        plan = scope._plan_spawn(sandbox_scope, argv, {}, None)

    assert plan.argv == argv
    assert _record(debug_record).endswith(
        f"for scanner: tool {shlex.quote(str(target))} --flag"
    )


def test_an_argument_holding_a_blank_stays_one_argument(tmp_path, debug_record):
    sandbox_scope = _scope(tmp_path)

    with scope.sandbox_scope(sandbox_scope):
        scope._plan_spawn(sandbox_scope, ["tool", "two words", "three"], {}, None)

    assert _record(debug_record).endswith("for scanner: tool 'two words' three")


def test_the_record_names_the_backend_and_the_network(tmp_path, debug_record):
    sandbox_scope = _scope(tmp_path)

    with scope.sandbox_scope(sandbox_scope):
        scope._plan_spawn(sandbox_scope, [Path("tool")], {}, None)

    assert (
        _record(debug_record) == "Scanner sandbox (fake, network=no) for scanner: tool"
    )


def test_an_env_read_value_holding_a_quote_is_hidden_in_both_spellings(
    tmp_path, debug_record
):
    value = "it's-the-value-read-from-the-environment"
    sandbox_scope = _scope(tmp_path, environment_values=(value,))

    with scope.sandbox_scope(sandbox_scope):
        scope._plan_spawn(sandbox_scope, ["tool", f"--token={value}"], {}, None)

    record = _record(debug_record)
    assert value not in record
    assert shlex.quote(value)[1:-1] not in record
    assert "the-value-read-from-the-environment" not in record


def test_quoted_spellings_cover_only_texts_quoting_rewrites(tmp_path):
    plain = "no-quote-here"
    quoted = "has'quote"
    sandbox_scope = _scope(tmp_path, environment_values=(plain, quoted, "", quoted))

    spellings = scope._quoted_spellings(sandbox_scope)

    assert spellings == [shlex.quote(quoted)[1:-1]]
    assert "'" in spellings[0] and '"' in spellings[0]


def test_a_hidden_plugin_input_holding_a_quote_stays_hidden_when_quoted(
    tmp_path, debug_record
):
    """A plugin input is hidden by origin: when it holds an env-read value, the
    uv layer hides the whole input. Quoting respells a quote character inside
    it, so without the cover the rest of the input would print once the value
    inside is hidden; with the cover the input's quoted spelling is hidden too.
    An input holding no value is shown by design (a constraint stays
    diagnosable), so that shape is not what this test measures."""
    value = "example.invalid"
    spec = f"tool @ git+https://{value}/it's-a-spec.git"
    sandbox_scope = _scope(
        tmp_path, environment_values=(value,), plugin_inputs=(spec,), command="tool"
    )

    with scope.sandbox_scope(sandbox_scope):
        scope._plan_spawn(
            sandbox_scope, ["uv", "tool", "run", "--from", spec], {}, None
        )

    record = _record(debug_record)
    assert value not in record
    assert spec not in record
    assert shlex.quote(spec)[1:-1] not in record
    assert "it's-a-spec" not in record and "it'\"'\"'s-a-spec" not in record


def test_a_value_that_is_not_text_does_not_stop_the_spawn(tmp_path, debug_record):
    """A non-text entry is passed over by the quoted-spelling cover, so the
    record step raises nothing after the plan's registrations are made."""
    values = (None, 7, "it's-text")
    sandbox_scope = _scope(tmp_path, environment_values=values)  # type: ignore[arg-type]

    assert scope._quoted_spellings(sandbox_scope) == [shlex.quote("it's-text")[1:-1]]

    with scope.sandbox_scope(sandbox_scope):
        plan = scope._plan_spawn(sandbox_scope, ["tool", "--x=it's-text"], {}, None)

    assert plan.argv == ["tool", "--x=it's-text"]
    assert len(debug_record.debug_lines) == 1


class _ProgramlessBackend:
    """A backend that resolves the program itself and finds none, as Landlock does."""

    name = "landlock"

    def plan(self, argv, env, policy):
        raise FileNotFoundError(f"no program named {argv[0]!r} was found")


def test_a_program_the_backend_cannot_find_is_a_failed_spawn_not_a_refusal(
    tmp_path, debug_record
):
    """Under Landlock a missing program fails at planning time; under bwrap the
    same program fails at Popen and the scope never sees it. Counting the first as
    a sandbox refusal made the converter's row differ by backend for one missing
    tool; it is counted as a failed plan, with the error's type and text."""
    sandbox_scope = _scope(tmp_path, backend=_ProgramlessBackend())

    with scope.sandbox_scope(sandbox_scope):
        with pytest.raises(FileNotFoundError):
            scope.prepare_spawn(["tool", "--version"], {}, None)

    # Red at the parent: refused_spawns 1, last_refusal "FileNotFoundError: ...".
    assert sandbox_scope.failed_spawns == 1
    assert (sandbox_scope.last_failure or "").startswith("FileNotFoundError: ")
    assert "'tool'" in (sandbox_scope.last_failure or "")
    assert sandbox_scope.refused_spawns == 0
    assert sandbox_scope.last_refusal is None


def test_a_refusal_is_counted_as_a_refusal_only(tmp_path, monkeypatch):
    """The control: a SandboxUnavailable from the plan is a refusal, and the
    failure counter does not move."""

    def refusing(sandbox_scope, argv, env, cwd):
        raise SandboxUnavailable("the policy has no writable root for this tool")

    monkeypatch.setattr(scope, "_plan_spawn", refusing)
    sandbox_scope = _scope(tmp_path)

    with scope.sandbox_scope(sandbox_scope):
        with pytest.raises(SandboxUnavailable):
            scope.prepare_spawn(["tool"], {}, None)

    assert sandbox_scope.refused_spawns == 1
    assert sandbox_scope.last_refusal == "the policy has no writable root for this tool"
    assert sandbox_scope.failed_spawns == 0
    assert sandbox_scope.last_failure is None


def test_a_refusing_scope_counts_refusals_and_carries_the_failure_fields():
    """A RefusingScope refuses before any planning, so it counts refusals only, and
    it carries the failure fields so a converter's row reads one shape from either
    scope."""
    refusing = scope.RefusingScope(scanner_name="tool", reason="no backend")

    with scope.sandbox_scope(refusing):
        with pytest.raises(SandboxUnavailable):
            scope.prepare_spawn(["tool"], {}, None)

    assert refusing.refused_spawns == 1
    assert "no backend" in (refusing.last_refusal or "")
    assert refusing.failed_spawns == 0
    assert refusing.last_failure is None
