# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox scope remembers only lasting probe answers, and records any argv.

``resolve_backend`` probes a backend once per process and tree scope. A probe
whose reason is a passing condition (the probe process timed out, a resource was
busy) used to be remembered like a missing program, so every later scan in the
process was refused or downgraded; such a refusal is now raised and the next
request probes again. A missing backend is still remembered.

``_plan_spawn``'s DEBUG record of the planned argv used to join the arguments
as text, which raised TypeError for a path object (subprocess accepts one) after
the plan's writable-root registrations had been made and before anything could
release them, and ran two arguments holding blanks into one. The record now shows
each argument's ``str``, shell-quoted; an env-read value whose quoted spelling
differs from its text is hidden in both spellings.
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


def test_a_probe_that_timed_out_is_probed_again(fresh_cache, monkeypatch):
    backend = _backend()
    probes = _probe_answers(monkeypatch, [SandboxUnavailable(TIMED_OUT), backend])

    with pytest.raises(scope.SandboxBackendUnavailable) as first:
        scope.resolve_backend("bwrap")

    assert TIMED_OUT in str(first.value)
    assert scope.resolve_backend("bwrap") is backend
    assert probes == ["bwrap", "bwrap"]


def test_a_busy_resource_is_probed_again(fresh_cache, monkeypatch):
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

    assert scope.resolve_backend("bwrap") is backend
    assert probes == ["bwrap", "bwrap"]


def test_a_missing_backend_is_remembered(fresh_cache, monkeypatch):
    probes = _probe_answers(monkeypatch, [SandboxUnavailable(NOT_INSTALLED)])

    for _ in range(2):
        with pytest.raises(scope.SandboxBackendUnavailable, match="not installed"):
            scope.resolve_backend("bwrap")

    assert probes == ["bwrap"]


def test_under_auto_one_timed_out_member_is_probed_again(fresh_cache, monkeypatch):
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
    assert scope.resolve_backend("auto") is backend
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


def _scope(tmp_path, **fields) -> scope.SandboxScope:
    return scope.SandboxScope(
        backend=_PlanningBackend(),
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


def test_a_plugin_input_holding_a_quote_is_hidden_in_both_spellings(
    tmp_path, debug_record
):
    spec = "tool @ git+https://example.invalid/it's-a-spec.git"
    sandbox_scope = _scope(tmp_path, plugin_inputs=(spec,), command="tool")

    with scope.sandbox_scope(sandbox_scope):
        scope._plan_spawn(
            sandbox_scope, ["uv", "tool", "run", "--from", spec], {}, None
        )

    record = _record(debug_record)
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
