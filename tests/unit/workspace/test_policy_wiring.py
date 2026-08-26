# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The contract the policy wiring must satisfy. Written before the wiring.

These tests fail until `execution.py` hands the orchestrator a pre-resolved
config. That is the intended starting state: the failure mode they exist to
prevent is silent, so it must be prevented by an assertion rather than by care.

Why the wiring cannot simply pass the resolver's config
------------------------------------------------------
`resolver.py:_resolve_project_config` calls `resolve_config` with **no**
`config_overrides`. Today that is harmless, because `execution.py` passes
`config_overrides` to the orchestrator and the orchestrator resolves again. Once
the orchestrator is handed a `resolved_config` it skips resolution entirely, so
reusing the resolver's object would **silently drop every `--config-overrides`
value**. No error, no warning, operator-chosen settings quietly ignored.

That is the same fail-open class as routing workspace policy through
`apply_config_overrides`, which was refused for the same reason. The naive
wiring is the dangerous one, and `test_a_config_override_reaches_the_project`
is the assertion that fails under it.

Why passing both is not an option either
----------------------------------------
`ASHScanOrchestrator` rejects `resolved_config` combined with a truthy
`config_path` or `config_overrides` -- a `model_validator(mode="after")`, so it
raises at construction. That refusal is correct: those are inputs to the
resolution being skipped. So the wiring must fold the overrides into the config
it resolves and stop passing both, which is what these tests pin.

The `--compact-report` trap
---------------------------
`cli/scan.py` appends `reporters.markdown.options.compact=true` to
`config_overrides` when `--compact-report` is set. So `config_overrides` is
non-empty for a user who never heard of `--config-overrides`, and
`ash --workspace X --compact-report` against a project with its own
`.ash/ash.yaml` is the minimal reproduction of the refusal.

What these tests deliberately do NOT pin
----------------------------------------
Whether the plan's `severity_threshold` or an override's value wins for the
gate when both are present. That is a policy-precedence decision, not a wiring
detail, and inventing an answer here would bake it in silently. The tests
assert only that the override REACHES the project's config.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.resolver import resolve_workspace

AshConfig.model_rebuild()


class RecordingOrchestrator:
    """Captures exactly what the executor passed, and nothing else.

    The assertions here are about the call boundary rather than about scan
    results, so this records kwargs and returns an empty model. Using the real
    ASHScanOrchestrator would couple these tests to config resolution, which is
    the thing under test.
    """

    # ClassVar, not a mutable field: this is deliberately shared across
    # instances so the test can inspect every construction, and the autouse
    # fixture resets it between tests.
    built: ClassVar[list[RecordingOrchestrator]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs: dict[str, Any] = kwargs
        self.key = str(kwargs["source_dir"]).rstrip("/").rsplit("/", 1)[-1]
        RecordingOrchestrator.built.append(self)

    @classmethod
    def create(cls, **kwargs: Any) -> RecordingOrchestrator:
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        return AshAggregatedResults()


@pytest.fixture(autouse=True)
def _reset():
    RecordingOrchestrator.built = []
    yield
    RecordingOrchestrator.built = []


def _project(root, name, body=None):
    project = root / name
    (project / "src").mkdir(parents=True, exist_ok=True)
    (project / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
    if body is not None:
        ash_dir = project / ".ash"
        ash_dir.mkdir(exist_ok=True)
        (ash_dir / "ash.yaml").write_text(body, encoding="utf-8")
    return project


def _workspace(root, names):
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": n} for n in names]}), encoding="utf-8"
    )
    return path


def _run(tmp_path, plan, **overrides):
    settings_kwargs: dict[str, Any] = {
        "output_dir": tmp_path / "out",
        "phases": ("scan",),
        "max_parallel_projects": 1,
    }
    settings_kwargs.update(overrides)
    return execute_workspace(
        plan,
        ProjectScanSettings(**settings_kwargs),
        orchestrator_factory=RecordingOrchestrator.create,
    )


def _kwargs_for(key):
    matches = [o.kwargs for o in RecordingOrchestrator.built if o.key == key]
    assert matches, (
        f"no orchestrator was built for {key!r}; built="
        f"{[o.key for o in RecordingOrchestrator.built]}"
    )
    return matches[0]


# ---------------------------------------------------------------------------
# 1. The orchestrator is handed a resolved config, not the inputs to resolution
# ---------------------------------------------------------------------------


def test_the_orchestrator_receives_a_resolved_config(tmp_path):
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan)
    kwargs = _kwargs_for("api")

    assert kwargs.get("resolved_config") is not None, (
        "the executor still lets the orchestrator resolve; workspace policy "
        "cannot be applied through a config the caller does not own"
    )
    assert isinstance(kwargs["resolved_config"], AshConfig)


def test_neither_input_to_resolution_is_passed_alongside_it(tmp_path):
    """The orchestrator refuses both together, so the executor must send one.

    Asserted as absent-or-falsy rather than absent, because the refusal itself
    tests truthiness -- an empty list is explicitly not a conflict.
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan)
    kwargs = _kwargs_for("api")

    assert not kwargs.get("config_path"), (
        f"config_path={kwargs.get('config_path')!r} would be refused alongside "
        f"resolved_config"
    )
    assert not kwargs.get("config_overrides"), (
        f"config_overrides={kwargs.get('config_overrides')!r} would be refused "
        f"alongside resolved_config"
    )


# ---------------------------------------------------------------------------
# 2. The assertion that fails under the naive wiring
# ---------------------------------------------------------------------------


def test_a_config_override_reaches_the_project(tmp_path):
    """The fail-open guard. Reusing the resolver's config drops overrides.

    `resolver.py` resolves without `config_overrides`, so a wiring that hands
    that object over passes this project a config where the operator's override
    never applied -- silently. This asserts the override's EFFECT on the config
    the orchestrator actually receives, not that a list was forwarded.
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(
        tmp_path,
        plan,
        config_overrides=("global_settings.severity_threshold=LOW",),
    )
    resolved = _kwargs_for("api")["resolved_config"]

    assert resolved.global_settings.severity_threshold == "LOW", (
        "the --config-overrides value did not reach the project's config; the "
        "wiring is reusing the resolver's config, which is resolved without "
        "overrides"
    )


def test_without_an_override_the_projects_own_setting_survives(tmp_path):
    """Control. Without this, a wiring that hardcoded LOW would pass the above."""
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]

    assert resolved.global_settings.severity_threshold == "HIGH"


def test_each_project_gets_its_own_resolved_config(tmp_path):
    """Two projects, two configs. A shared object would let one project's
    policy push-down mutate the other's."""
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    _project(tmp_path, "web", "global_settings:\n  severity_threshold: LOW\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api", "web"]))

    _run(tmp_path, plan)
    api = _kwargs_for("api")["resolved_config"]
    web = _kwargs_for("web")["resolved_config"]

    assert api is not web
    assert api.global_settings.severity_threshold == "HIGH"
    assert web.global_settings.severity_threshold == "LOW"


# ---------------------------------------------------------------------------
# 2b. Threshold precedence: the override sets declared(P), the ceiling still applies
# ---------------------------------------------------------------------------


def test_an_override_cannot_loosen_a_project_past_the_workspace_ceiling(tmp_path):
    """The decided rule:

        declared(P)  = override value if present else the project's config value
        effective(P) = stricter_of(declared(P), workspace ceiling)

    So an override may tighten without limit, and may loosen a project relative
    to its own file, but never past the workspace's stated maximum. A ceiling any
    CLI flag can step over guarantees nothing -- the same argument that refused
    ``!ENV`` substitution on ``max_severity_threshold``, and a flag is the easier
    of the two to reach for.

    The fixture is chosen to DISCRIMINATE, which took a check rather than an
    assumption. The project must declare something STRICTER than the ceiling:

        project LOW,      override CRITICAL, ceiling MEDIUM
          rule not applied -> stricter_of(LOW, MEDIUM)      = LOW
          rule applied     -> stricter_of(CRITICAL, MEDIUM) = MEDIUM   <- differs

    With the project at MEDIUM, HIGH or CRITICAL both answers are MEDIUM and the
    test proves nothing. That is why this does not use the more obvious
    "project HIGH" fixture.

    Overrides are passed to BOTH resolution and execution on purpose. The plan is
    what ``--dry-run`` prints, and the RFC's carve-out for a workspace overriding
    a project is conditioned on the override being **visible** -- so the plan has
    to carry the enforced value, not just the scan.
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: LOW\n")
    (tmp_path / ".ash").mkdir(exist_ok=True)
    (tmp_path / ".ash" / "ash-workspace.yaml").write_text(
        "workspace:\n  max_severity_threshold: MEDIUM\n", encoding="utf-8"
    )
    overrides = ("global_settings.severity_threshold=CRITICAL",)

    plan = resolve_workspace(_workspace(tmp_path, ["api"]), config_overrides=overrides)
    project = plan.projects[0]

    # declared(P) is the override, not the project's file.
    assert project.severity_threshold == "CRITICAL", (
        f"declared(P) should be the override value; got "
        f"{project.severity_threshold!r}. Resolution is not seeing "
        f"config_overrides, so --dry-run would print a threshold that is not "
        f"the one enforced."
    )
    # The ceiling still applies to it.
    assert project.effective_severity_threshold == "MEDIUM", (
        f"the ceiling did not apply to the overridden value; got "
        f"{project.effective_severity_threshold!r}"
    )
    # Visibly, which is the RFC's condition for a workspace overriding a project.
    assert project.threshold_tightened_by_policy is True

    # And the gate actually uses it.
    outcome = _run(tmp_path, plan, config_overrides=overrides)
    assert outcome.payload.projects[0].severity_threshold == "MEDIUM"


def test_an_override_may_tighten_past_the_ceiling_without_limit(tmp_path):
    """The other direction, and the reason this is not pure restriction.

    Tightening is never refused, so an override to ALL is honoured even though it
    is far stricter than the ceiling. Without this the rule above could be
    implemented as "the ceiling always wins", which would also loosen.
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: CRITICAL\n")
    (tmp_path / ".ash").mkdir(exist_ok=True)
    (tmp_path / ".ash" / "ash-workspace.yaml").write_text(
        "workspace:\n  max_severity_threshold: MEDIUM\n", encoding="utf-8"
    )
    overrides = ("global_settings.severity_threshold=ALL",)

    plan = resolve_workspace(_workspace(tmp_path, ["api"]), config_overrides=overrides)
    project = plan.projects[0]

    assert project.effective_severity_threshold == "ALL", (
        f"an override stricter than the ceiling must be honoured in full; got "
        f"{project.effective_severity_threshold!r}"
    )
    # The ceiling did not move it, so nothing was tightened by policy.
    assert project.threshold_tightened_by_policy is False


# ---------------------------------------------------------------------------
# 3. The --compact-report reproduction
# ---------------------------------------------------------------------------


def test_compact_report_alone_does_not_break_a_project_with_its_own_config(tmp_path):
    """`--compact-report` makes config_overrides non-empty without the operator
    passing --config-overrides, so it is the shape a user hits by accident.

    cli/scan.py appends `reporters.markdown.options.compact=true`. Combined with
    a project that has its own .ash/ash.yaml -- which supplies a truthy
    config_path -- this is the minimal reproduction of the orchestrator's
    refusal.
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))
    assert plan.projects[0].config_source, (
        "control: this project must have its own config file, or the refusal "
        "being reproduced cannot fire"
    )

    outcome = _run(
        tmp_path,
        plan,
        config_overrides=("reporters.markdown.options.compact=true",),
    )

    entry = outcome.payload.projects[0]
    assert entry.status.value != "failed", f"project failed: {entry.error}"
    resolved = _kwargs_for("api")["resolved_config"]
    assert resolved.reporters.markdown.options.compact is True, (
        "the synthesised --compact-report override did not reach the config"
    )


# ---------------------------------------------------------------------------
# 4. Workspace policy is merged on top of the resolved config
# ---------------------------------------------------------------------------


def test_policy_suppressions_are_merged_into_the_projects_config(tmp_path):
    """The point of the wiring: the scanners must see the policy suppression.

    The plan already carries `policy_suppressions` rewritten into this project's
    coordinates. Until they reach the config the scanners read, the field
    validates and changes nothing -- which is worse than not existing, because
    the operator believes findings are suppressed.
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    (tmp_path / ".ash").mkdir(exist_ok=True)
    (tmp_path / ".ash" / "ash-workspace.yaml").write_text(
        "workspace:\n"
        "  suppressions:\n"
        "    - path: api/src/app.py\n"
        "      reason: wiring fixture\n",
        encoding="utf-8",
    )
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    # Control: the push-down happened at resolution, so a failure below is the
    # wiring's and not the resolver's.
    assert [s.path for s in plan.projects[0].policy_suppressions] == ["src/app.py"]

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]

    paths = [s.path for s in resolved.global_settings.suppressions]
    assert "src/app.py" in paths, (
        f"the workspace suppression never reached the project's config; "
        f"suppressions={paths}"
    )


def test_a_projects_own_suppressions_are_not_lost_to_policy(tmp_path):
    """Policy is additive. Replacing the list would silently un-suppress
    whatever the project itself had declared."""
    _project(
        tmp_path,
        "api",
        "global_settings:\n"
        "  severity_threshold: HIGH\n"
        "  suppressions:\n"
        "    - path: src/legacy.py\n"
        "      reason: the project's own\n",
    )
    (tmp_path / ".ash").mkdir(exist_ok=True)
    (tmp_path / ".ash" / "ash-workspace.yaml").write_text(
        "workspace:\n"
        "  suppressions:\n"
        "    - path: api/src/app.py\n"
        "      reason: the workspace's\n",
        encoding="utf-8",
    )
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]
    paths = [s.path for s in resolved.global_settings.suppressions]

    assert "src/legacy.py" in paths, f"the project's own suppression was lost: {paths}"
    assert "src/app.py" in paths, f"the policy suppression is missing: {paths}"


def test_policy_ignore_paths_are_merged_too(tmp_path):
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    (tmp_path / ".ash").mkdir(exist_ok=True)
    (tmp_path / ".ash" / "ash-workspace.yaml").write_text(
        "workspace:\n"
        "  ignore_paths:\n"
        "    - path: '**/vendor'\n"
        "      reason: third party\n",
        encoding="utf-8",
    )
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]

    paths = [p.path for p in resolved.global_settings.ignore_paths]
    assert "**/vendor" in paths, f"the policy ignore path is missing: {paths}"


def test_no_policy_leaves_the_projects_config_untouched(tmp_path):
    """Control for the whole group. With no policy file, the config the
    orchestrator receives must match what the project declared -- otherwise a
    wiring that always appended something would satisfy every test above."""
    _project(
        tmp_path,
        "api",
        "global_settings:\n"
        "  severity_threshold: HIGH\n"
        "  suppressions:\n"
        "    - path: src/legacy.py\n"
        "      reason: the project's own\n",
    )
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]

    assert [s.path for s in resolved.global_settings.suppressions] == ["src/legacy.py"]
    assert resolved.global_settings.ignore_paths == []
