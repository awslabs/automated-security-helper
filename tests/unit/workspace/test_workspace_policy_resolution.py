# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace policy as resolution applies it -- Phase 3, criteria 19-21.

``test_workspace_policy.py`` covers the policy file and the push-down in
isolation. This file covers the part an operator actually experiences: policy
found next to the workspace file, applied to every project, and visible in
``--dry-run`` BEFORE anything is scanned.

That visibility is the point of the render assertions below rather than an
aesthetic preference. A severity ceiling silently tightens projects whose own
config says something else, so an operator has to be able to see which projects
it moved without running a scan and diffing finding counts.
"""

import json

import pytest

from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.workspace.resolver import resolve_workspace

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _workspace(root, folders, name="dev.code-workspace"):
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": p} for p in folders]}), encoding="utf-8"
    )
    return path


def _project(root, relative, threshold=None, disabled_scanners=None):
    """A project directory, with a config when a threshold or scanners are given.

    ``disabled_scanners`` rather than ``enabled``: ASH enables all ten builtin
    scanners by default, so listing a scanner as enabled says nothing. A project
    that does NOT have a given scanner is one that explicitly turned it off, and
    that is the only shape in which ``additional_scanners`` has anything to add.
    """
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    if threshold is None and disabled_scanners is None:
        return project

    lines = ["global_settings:", f"  severity_threshold: {threshold or 'MEDIUM'}"]
    if disabled_scanners:
        lines.append("scanners:")
        for scanner in disabled_scanners:
            lines.append(f"  {scanner}:")
            lines.append("    enabled: false")
    ash_dir = project / ".ash"
    ash_dir.mkdir(exist_ok=True)
    (ash_dir / "ash.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return project


def _policy_file(root, body, name="ash-workspace.yaml"):
    ash_dir = root / ".ash"
    ash_dir.mkdir(parents=True, exist_ok=True)
    path = ash_dir / name
    path.write_text(body, encoding="utf-8")
    return path


def _by_key(plan):
    return {project.key: project for project in plan.projects}


# ---------------------------------------------------------------------------
# 1. The ceiling reaches every project, and only tightens
# ---------------------------------------------------------------------------


def test_the_ceiling_tightens_a_lax_project_and_leaves_a_strict_one(tmp_path):
    _project(tmp_path, "lax", threshold="CRITICAL")
    _project(tmp_path, "strict", threshold="LOW")
    workspace = _workspace(tmp_path, ["lax", "strict"])
    _policy_file(tmp_path, "workspace:\n  max_severity_threshold: MEDIUM\n")

    plan = resolve_workspace(workspace)
    projects = _by_key(plan)

    # The project's own setting is preserved as declared, so an operator can see
    # what the ceiling changed rather than only its result.
    assert projects["lax"].severity_threshold == "CRITICAL"
    assert projects["lax"].effective_severity_threshold == "MEDIUM"
    assert projects["lax"].threshold_tightened_by_policy is True

    assert projects["strict"].severity_threshold == "LOW"
    assert projects["strict"].effective_severity_threshold == "LOW"
    assert projects["strict"].threshold_tightened_by_policy is False


def test_without_a_policy_file_the_effective_threshold_is_the_projects_own(tmp_path):
    """Phase 2b behaviour has to survive: no policy means nothing changes."""
    _project(tmp_path, "api", threshold="CRITICAL")
    workspace = _workspace(tmp_path, ["api"])

    plan = resolve_workspace(workspace)
    project = _by_key(plan)["api"]

    assert plan.workspace_config_source is None
    assert project.effective_severity_threshold == "CRITICAL"
    assert project.threshold_tightened_by_policy is False


def test_a_skipped_project_gets_no_policy_at_all(tmp_path):
    """Policy must not be applied to a project that will not be scanned.

    Two reasons, and the second is the one with teeth. A threshold recorded for
    work that never happens is misleading in the plan; and pushing patterns into
    a skipped project can refuse the ENTIRE workspace over a pattern that is only
    unrewritable for a project nobody is scanning -- fail-closed aimed at the
    wrong target.
    """
    _project(tmp_path, "api", threshold="CRITICAL")
    workspace = _workspace(tmp_path, ["api", "absent"])
    _policy_file(
        tmp_path,
        "workspace:\n"
        "  max_severity_threshold: MEDIUM\n"
        "  suppressions:\n"
        "    - path: '**/legacy.py'\n"
        "      reason: everywhere\n",
    )

    plan = resolve_workspace(workspace, allow_missing_projects=True)
    projects = _by_key(plan)

    # Companion assertion: the skip really happened, so the checks below are not
    # passing because the project was scanned after all.
    assert projects["absent"].skipped is True
    assert projects["api"].skipped is False

    assert projects["absent"].effective_severity_threshold is None
    assert projects["absent"].threshold_tightened_by_policy is False
    assert projects["absent"].policy_suppressions == []
    assert projects["absent"].policy_scanners == []

    # The project that does run still gets the full policy.
    assert projects["api"].effective_severity_threshold == "MEDIUM"
    assert [s.path for s in projects["api"].policy_suppressions] == ["**/legacy.py"]


def test_the_plan_records_which_policy_file_was_used(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])
    policy = _policy_file(tmp_path, "workspace:\n  max_severity_threshold: HIGH\n")

    plan = resolve_workspace(workspace)
    assert plan.workspace_config_source == policy.resolve().as_posix()


def test_an_explicit_policy_file_overrides_discovery(tmp_path):
    _project(tmp_path, "api", threshold="CRITICAL")
    workspace = _workspace(tmp_path, ["api"])
    _policy_file(tmp_path, "workspace:\n  max_severity_threshold: HIGH\n")
    chosen = tmp_path / "other-policy.yaml"
    chosen.write_text("workspace:\n  max_severity_threshold: LOW\n", encoding="utf-8")

    plan = resolve_workspace(workspace, workspace_config=chosen)
    assert plan.workspace_config_source == chosen.resolve().as_posix()
    assert _by_key(plan)["api"].effective_severity_threshold == "LOW"


# ---------------------------------------------------------------------------
# 2. The collision the RFC names, at the resolution layer
# ---------------------------------------------------------------------------


def test_a_workspace_root_that_is_also_a_project_keeps_its_config_separate(tmp_path):
    """The root's .ash/ash.yaml is the root project's config, not workspace policy.

    Reading it as policy would apply one project's threshold to its siblings.
    Here the root project declares CRITICAL and the policy declares a MEDIUM
    ceiling, so mixing them up is visible in the sibling's effective threshold.
    """
    root_project = _project(tmp_path, "root-app", threshold="CRITICAL")
    assert (root_project / ".ash" / "ash.yaml").exists()
    _project(tmp_path, "sibling", threshold="CRITICAL")
    # The workspace root's own config, distinct from the policy beside it.
    (tmp_path / ".ash").mkdir(exist_ok=True)
    (tmp_path / ".ash" / "ash.yaml").write_text(
        "global_settings:\n  severity_threshold: ALL\n", encoding="utf-8"
    )
    _policy_file(tmp_path, "workspace:\n  max_severity_threshold: MEDIUM\n")
    workspace = _workspace(tmp_path, ["root-app", "sibling"])

    plan = resolve_workspace(workspace)
    projects = _by_key(plan)

    # ALL from the root's own config must not have become the ceiling.
    assert plan.workspace_config_source.endswith("ash-workspace.yaml")
    assert projects["sibling"].effective_severity_threshold == "MEDIUM"
    assert projects["root-app"].effective_severity_threshold == "MEDIUM"


def test_naming_a_project_config_as_the_policy_file_is_refused(tmp_path):
    project = _project(tmp_path, "api", threshold="HIGH")
    workspace = _workspace(tmp_path, ["api"])

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace(workspace, workspace_config=project / ".ash" / "ash.yaml")
    assert "ash.yaml" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 3. Patterns land on the right project, or refuse
# ---------------------------------------------------------------------------


def test_a_workspace_suppression_reaches_only_the_project_it_names(tmp_path):
    _project(tmp_path, "api")
    _project(tmp_path, "web")
    workspace = _workspace(tmp_path, ["api", "web"])
    _policy_file(
        tmp_path,
        "workspace:\n"
        "  suppressions:\n"
        "    - path: api/src/legacy.py\n"
        "      reason: tracked in TICKET-1\n",
    )

    plan = resolve_workspace(workspace)
    projects = _by_key(plan)

    assert [s.path for s in projects["api"].policy_suppressions] == ["src/legacy.py"]
    assert projects["web"].policy_suppressions == []


def test_an_unrewritable_policy_pattern_refuses_naming_project_and_pattern(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])
    _policy_file(
        tmp_path,
        "workspace:\n"
        "  suppressions:\n"
        "    - path: '*/sub/*.py'\n"
        "      reason: ambiguous on purpose\n",
    )

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace(workspace)

    message = str(excinfo.value)
    assert "*/sub/*.py" in message
    assert "api" in message


def test_workspace_ignore_paths_are_pushed_into_each_project(tmp_path):
    _project(tmp_path, "api")
    _project(tmp_path, "web")
    workspace = _workspace(tmp_path, ["api", "web"])
    _policy_file(
        tmp_path,
        "workspace:\n"
        "  ignore_paths:\n"
        "    - path: '**/vendor'\n"
        "      reason: third party\n",
    )

    plan = resolve_workspace(workspace)
    projects = _by_key(plan)

    for key in ("api", "web"):
        assert [p.path for p in projects[key].policy_ignore_paths] == ["**/vendor"]


def test_a_trailing_double_star_after_a_double_star_is_refused(tmp_path):
    """``**/vendor/**`` has no sound rewrite, and an operator will write it.

    It is the most natural way to say "any vendor directory, at any depth, in any
    project", so its refusal is the limitation of the push-down most likely to be
    hit. Pinned as a test rather than left to be discovered, with the working
    alternatives named in the message the operator sees.

    The cause is workspace_paths' family 1: the remainder ``vendor/**`` is
    multi-component and contains a glob, so prefixing it with ``**`` moves the
    whole pattern from fnmatch to component-anchored matching and silently
    re-interprets the trailing ``**``.
    """
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])
    _policy_file(
        tmp_path,
        "workspace:\n"
        "  ignore_paths:\n"
        "    - path: '**/vendor/**'\n"
        "      reason: third party\n",
    )

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace(workspace)
    assert "**/vendor/**" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 4. Policy-added scanners, per project
# ---------------------------------------------------------------------------


def test_a_policy_scanner_the_project_already_enables_is_not_policy_origin(tmp_path):
    """Only the project that turned bandit off gets it back as policy-origin.

    The project that still has it runs bandit under its own config, so those
    findings are the project's and gate normally.
    """
    _project(tmp_path, "has-it", threshold="MEDIUM")
    _project(tmp_path, "lacks-it", threshold="MEDIUM", disabled_scanners=["bandit"])
    workspace = _workspace(tmp_path, ["has-it", "lacks-it"])
    _policy_file(tmp_path, "workspace:\n  additional_scanners:\n    - bandit\n")

    plan = resolve_workspace(workspace)
    projects = _by_key(plan)

    # Companion assertion: confirm the passing path is the one intended, i.e.
    # has-it really does enable bandit rather than the comparison silently
    # matching nothing.
    assert "bandit" in projects["has-it"].scanners
    assert "bandit" not in projects["lacks-it"].scanners

    assert projects["has-it"].policy_scanners == []
    assert projects["lacks-it"].policy_scanners == ["bandit"]


def test_policy_scanners_do_not_gate_unless_the_operator_opts_in(tmp_path):
    _project(tmp_path, "api", threshold="MEDIUM", disabled_scanners=["bandit"])
    workspace = _workspace(tmp_path, ["api"])
    _policy_file(tmp_path, "workspace:\n  additional_scanners:\n    - bandit\n")

    plan = resolve_workspace(workspace)
    # Companion assertion: the gate flag is only meaningful if bandit really is
    # policy-origin here, so confirm that before asserting on the flag.
    assert _by_key(plan)["api"].policy_scanners == ["bandit"]
    assert _by_key(plan)["api"].policy_scanners_gate is False

    _policy_file(
        tmp_path,
        "workspace:\n"
        "  additional_scanners:\n"
        "    - bandit\n"
        "  policy_scanners_gate: true\n",
    )
    plan = resolve_workspace(workspace)
    assert _by_key(plan)["api"].policy_scanners_gate is True


# ---------------------------------------------------------------------------
# 5. --dry-run shows the policy, so a ceiling is visible before it applies
# ---------------------------------------------------------------------------


def test_dry_run_names_the_policy_file_and_marks_the_projects_it_tightened(tmp_path):
    _project(tmp_path, "lax", threshold="CRITICAL")
    _project(tmp_path, "strict", threshold="LOW")
    workspace = _workspace(tmp_path, ["lax", "strict"])
    _policy_file(tmp_path, "workspace:\n  max_severity_threshold: MEDIUM\n")

    rendered = resolve_workspace(workspace).render()

    assert "ash-workspace.yaml" in rendered
    # The tightened project shows both values and says policy moved it; the
    # untouched one must not claim a change it did not undergo.
    assert "CRITICAL" in rendered and "MEDIUM" in rendered
    lax_block = rendered.split("1. lax")[1].split("2. strict")[0]
    strict_block = rendered.split("2. strict")[1]
    assert "workspace policy" in lax_block
    assert "workspace policy" not in strict_block


def test_dry_run_without_policy_does_not_mention_it(tmp_path):
    _project(tmp_path, "api", threshold="MEDIUM")
    workspace = _workspace(tmp_path, ["api"])

    rendered = resolve_workspace(workspace).render()
    assert "workspace policy" not in rendered
    assert "policy:" not in rendered
