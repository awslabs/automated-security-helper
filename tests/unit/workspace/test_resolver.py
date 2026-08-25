# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for workspace resolution and the execution plan.

These are the acceptance criteria for Phase 1. The bias throughout is
fail-closed: a workspace ASH cannot fully understand is refused rather than
partly scanned, because a partly-scanned workspace exits 0 and reports the
projects it did reach, which reads in CI as a clean bill of health for code
nothing examined.
"""

import json

import pytest

from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.models.workspace import SkippedProjectReason
from automated_security_helper.workspace.resolver import resolve_workspace


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _symlink_or_skip(link, target, target_is_directory=True):
    """Create a symlink, skipping the test where the platform forbids it."""
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def _workspace(root, folders, name="dev.code-workspace"):
    """Write a workspace file listing *folders* and return its path."""
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": p} for p in folders]}), encoding="utf-8"
    )
    return path


def _project(root, relative, config=None):
    """Create a project directory, optionally with an ``.ash/ash.yaml``."""
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    if config is not None:
        ash_dir = project / ".ash"
        ash_dir.mkdir(exist_ok=True)
        (ash_dir / "ash.yaml").write_text(config, encoding="utf-8")
    return project


def _by_key(plan):
    return {project.key: project for project in plan.projects}


# ---------------------------------------------------------------------------
# 1. A missing project path is fatal by default, and every one is named
# ---------------------------------------------------------------------------


def test_missing_project_is_fatal_by_default(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "absent"])

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace(workspace)

    assert "absent" in str(excinfo.value)


def test_every_unresolved_path_is_named_not_just_the_first(tmp_path):
    """A definition with three typos must report three, or the operator fixes
    one per run."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["gone-a", "api", "gone-b", "gone-c"])

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace(workspace)

    message = str(excinfo.value)
    assert "gone-a" in message
    assert "gone-b" in message
    assert "gone-c" in message


def test_a_file_where_a_directory_was_expected_is_missing(tmp_path):
    (tmp_path / "api").write_text("not a directory", encoding="utf-8")
    workspace = _workspace(tmp_path, ["api"])

    with pytest.raises(WorkspaceDefinitionError, match="api"):
        resolve_workspace(workspace)


def test_unreadable_project_is_fatal_by_default(tmp_path):
    project = _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])
    project.chmod(0o000)
    try:
        if project.is_dir() and _is_readable(project):  # pragma: no cover - root
            pytest.skip("running as a user that ignores directory permissions")
        with pytest.raises(WorkspaceDefinitionError, match="readable|api"):
            resolve_workspace(workspace)
    finally:
        project.chmod(0o755)


def _is_readable(path):
    import os

    return os.access(path, os.R_OK | os.X_OK)


# ---------------------------------------------------------------------------
# 2. --allow-missing-projects skips, and the skip is disclosed in the payload
# ---------------------------------------------------------------------------


def test_allow_missing_projects_skips_and_records_the_skip(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "absent"])

    plan = resolve_workspace(workspace, allow_missing_projects=True)

    assert [p.key for p in plan.projects] == ["api", "absent"]
    assert [p.key for p in plan.active_projects] == ["api"]

    skipped = plan.skipped_projects
    assert len(skipped) == 1
    assert skipped[0].project == "absent"
    assert skipped[0].reason is SkippedProjectReason.ERROR
    assert skipped[0].detail
    assert "absent" in skipped[0].detail


def test_skipped_projects_survive_serialisation(tmp_path):
    """A log line is not disclosure -- downstream consumers cannot read stderr."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "absent"])

    payload = resolve_workspace(workspace, allow_missing_projects=True).model_dump()

    assert [entry["project"] for entry in payload["skipped_projects"]] == ["absent"]
    assert payload["skipped_projects"][0]["reason"] == SkippedProjectReason.ERROR.value


def test_allow_missing_projects_still_refuses_when_nothing_is_left(tmp_path):
    """Skipping every project would exit 0 having scanned nothing."""
    workspace = _workspace(tmp_path, ["gone-a", "gone-b"])

    with pytest.raises(WorkspaceDefinitionError, match="no project"):
        resolve_workspace(workspace, allow_missing_projects=True)


# ---------------------------------------------------------------------------
# 3. Incompatible scanner pins refuse the workspace
# ---------------------------------------------------------------------------


def test_incompatible_scanner_pins_refuse_and_name_both_constraints(tmp_path):
    _project(
        tmp_path,
        "api",
        "project_name: api\nscanners:\n  semgrep:\n"
        '    options:\n      tool_version: ">=1.125.0,<2.0.0"\n',
    )
    _project(
        tmp_path,
        "web",
        "project_name: web\nscanners:\n  semgrep:\n"
        '    options:\n      tool_version: ">=2.0.0"\n',
    )
    workspace = _workspace(tmp_path, ["api", "web"])

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace(workspace)

    message = str(excinfo.value)
    assert "semgrep" in message
    assert "api" in message
    assert "web" in message
    assert ">=1.125.0,<2.0.0" in message
    assert ">=2.0.0" in message


def test_compatible_but_different_pins_are_accepted_and_recorded(tmp_path):
    _project(
        tmp_path,
        "api",
        'project_name: api\nscanners:\n  semgrep:\n    options:\n      tool_version: ">=1.125.0,<2.0.0"\n',
    )
    _project(
        tmp_path,
        "web",
        'project_name: web\nscanners:\n  semgrep:\n    options:\n      tool_version: ">=1.130.0"\n',
    )
    workspace = _workspace(tmp_path, ["api", "web"])

    plan = resolve_workspace(workspace)

    projects = _by_key(plan)
    assert projects["api"].scanner_pins["semgrep"] == ">=1.125.0,<2.0.0"
    assert projects["web"].scanner_pins["semgrep"] == ">=1.130.0"


def test_pins_that_cannot_be_proven_compatible_are_refused(tmp_path):
    """Undecidable is refused, not assumed compatible: a project scanned by a
    version it excluded is the outcome worth designing against."""
    _project(
        tmp_path,
        "api",
        'project_name: api\nscanners:\n  semgrep:\n    options:\n      tool_version: ">=1.125.0rc1"\n',
    )
    _project(
        tmp_path,
        "web",
        'project_name: web\nscanners:\n  semgrep:\n    options:\n      tool_version: ">=2.0.0"\n',
    )
    workspace = _workspace(tmp_path, ["api", "web"])

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace(workspace)

    assert "semgrep" in str(excinfo.value)


def test_a_single_project_pin_is_never_a_conflict(tmp_path):
    """One project declaring an exotic pin has nothing to conflict with."""
    _project(
        tmp_path,
        "api",
        'project_name: api\nscanners:\n  semgrep:\n    options:\n      tool_version: ">=1.125.0rc1"\n',
    )
    _project(tmp_path, "web")
    workspace = _workspace(tmp_path, ["api", "web"])

    plan = resolve_workspace(workspace)

    assert _by_key(plan)["api"].scanner_pins["semgrep"] == ">=1.125.0rc1"
    assert "semgrep" not in _by_key(plan)["web"].scanner_pins


def test_shared_default_pins_do_not_conflict(tmp_path):
    """Every project inherits bandit's built-in pin; that must not refuse."""
    _project(tmp_path, "api")
    _project(tmp_path, "web")
    workspace = _workspace(tmp_path, ["api", "web"])

    plan = resolve_workspace(workspace)

    projects = _by_key(plan)
    assert projects["api"].scanner_pins == projects["web"].scanner_pins


def test_pins_from_a_skipped_project_are_not_compared(tmp_path):
    """A project that will not be scanned cannot conflict with one that will."""
    _project(
        tmp_path,
        "api",
        'project_name: api\nscanners:\n  semgrep:\n    options:\n      tool_version: ">=2.0.0"\n',
    )
    workspace = _workspace(tmp_path, ["api", "absent"])

    plan = resolve_workspace(workspace, allow_missing_projects=True)

    assert _by_key(plan)["api"].scanner_pins["semgrep"] == ">=2.0.0"


# ---------------------------------------------------------------------------
# 4. Overlapping entries, including symlink aliases
# ---------------------------------------------------------------------------


def test_duplicate_entries_are_rejected(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "api"])

    with pytest.raises(WorkspaceDefinitionError, match="same directory|overlap"):
        resolve_workspace(workspace)


def test_nested_entries_are_rejected(tmp_path):
    _project(tmp_path, "api/inner")
    workspace = _workspace(tmp_path, ["api", "api/inner"])

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace(workspace)

    message = str(excinfo.value)
    assert "api" in message
    assert "inner" in message


def test_nested_entries_are_rejected_in_either_order(tmp_path):
    _project(tmp_path, "api/inner")
    workspace = _workspace(tmp_path, ["api/inner", "api"])

    with pytest.raises(WorkspaceDefinitionError):
        resolve_workspace(workspace)


def test_symlink_aliased_entries_resolving_to_one_real_path_are_rejected(tmp_path):
    """Phase 0's containment check accepts ``alias/sub``; overlap detection on
    the canonicalised real path is what catches the alias."""
    _project(tmp_path, "api/sub")
    _symlink_or_skip(tmp_path / "alias", tmp_path / "api")
    workspace = _workspace(tmp_path, ["api/sub", "alias/sub"])

    with pytest.raises(WorkspaceDefinitionError, match="same directory|overlap"):
        resolve_workspace(workspace)


def test_a_nested_git_repo_that_is_not_its_own_entry_is_not_an_overlap(tmp_path):
    project = _project(tmp_path, "api")
    (project / "vendor" / "submodule" / ".git").mkdir(parents=True)
    workspace = _workspace(tmp_path, ["api"])

    plan = resolve_workspace(workspace)

    assert [p.key for p in plan.projects] == ["api"]


def test_sibling_prefix_directories_are_not_an_overlap(tmp_path):
    """``api`` and ``api-v2`` share a string prefix but neither contains the
    other."""
    _project(tmp_path, "api")
    _project(tmp_path, "api-v2")
    workspace = _workspace(tmp_path, ["api", "api-v2"])

    plan = resolve_workspace(workspace)

    assert sorted(p.key for p in plan.projects) == ["api", "api-v2"]


def test_an_entry_naming_the_workspace_root_is_rejected(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["."])

    with pytest.raises(WorkspaceDefinitionError, match="workspace root"):
        resolve_workspace(workspace)


# ---------------------------------------------------------------------------
# 5. and 6. Containment: outside the root, and symlinked entries
# ---------------------------------------------------------------------------


def test_entry_outside_the_workspace_root_is_rejected(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    _project(root, "api")
    (tmp_path / "outside").mkdir()
    workspace = _workspace(root, ["api", "../outside"])

    with pytest.raises(WorkspaceDefinitionError, match="outside|'\\.\\.'"):
        resolve_workspace(workspace)


def test_absolute_entry_outside_the_workspace_root_is_rejected(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    _project(root, "api")
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = _workspace(root, ["api", outside.as_posix()])

    with pytest.raises(WorkspaceDefinitionError, match="outside"):
        resolve_workspace(workspace)


def test_absolute_entry_inside_the_workspace_root_is_accepted(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    project = _project(root, "api")
    workspace = _workspace(root, [project.as_posix()])

    plan = resolve_workspace(workspace)

    assert [p.key for p in plan.projects] == ["api"]


def test_symlinked_folder_entry_is_rejected(tmp_path):
    _project(tmp_path, "api")
    _symlink_or_skip(tmp_path / "link", tmp_path / "api")
    workspace = _workspace(tmp_path, ["link"])

    with pytest.raises(WorkspaceDefinitionError, match="symlink"):
        resolve_workspace(workspace)


def test_symlinked_entry_is_rejected_even_with_allow_missing_projects(tmp_path):
    """--allow-missing-projects opts out of missing, never out of containment."""
    _project(tmp_path, "api")
    _symlink_or_skip(tmp_path / "link", tmp_path / "api")
    workspace = _workspace(tmp_path, ["api", "link"])

    with pytest.raises(WorkspaceDefinitionError, match="symlink"):
        resolve_workspace(workspace, allow_missing_projects=True)


def test_outside_root_entry_is_rejected_even_with_allow_missing_projects(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    _project(root, "api")
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = _workspace(root, ["api", outside.as_posix()])

    with pytest.raises(WorkspaceDefinitionError, match="outside"):
        resolve_workspace(workspace, allow_missing_projects=True)


# ---------------------------------------------------------------------------
# 10. and 11. Project keys and display labels
# ---------------------------------------------------------------------------


def test_nested_paths_become_dash_separated_keys(tmp_path):
    _project(tmp_path, "services/api")
    workspace = _workspace(tmp_path, ["services/api"])

    plan = resolve_workspace(workspace)

    assert [p.key for p in plan.projects] == ["services-api"]
    assert plan.projects[0].relative_path == "services/api"


def test_same_basename_in_different_parents_yields_distinct_keys(tmp_path):
    _project(tmp_path, "foo/api")
    _project(tmp_path, "bar/api")
    workspace = _workspace(tmp_path, ["foo/api", "bar/api"])

    plan = resolve_workspace(workspace)

    assert sorted(p.key for p in plan.projects) == ["bar-api", "foo-api"]


def test_a_key_collision_between_distinct_paths_is_refused(tmp_path):
    """Replacing separators with dashes is not injective: ``a/b`` and a
    directory literally named ``a-b`` both key to ``a-b``. They would share an
    output path, so the workspace is refused rather than silently merged."""
    _project(tmp_path, "a/b")
    _project(tmp_path, "a-b")
    workspace = _workspace(tmp_path, ["a/b", "a-b"])

    with pytest.raises(WorkspaceDefinitionError, match="same project key"):
        resolve_workspace(workspace)


def test_label_uses_project_name_when_the_config_declares_one(tmp_path):
    _project(tmp_path, "api", "project_name: Payments API\n")
    workspace = _workspace(tmp_path, ["api"])

    plan = resolve_workspace(workspace)

    assert plan.projects[0].label == "Payments API"
    assert plan.projects[0].key == "api"


def test_label_falls_back_to_the_key_without_a_config(tmp_path):
    _project(tmp_path, "services/api")
    workspace = _workspace(tmp_path, ["services/api"])

    plan = resolve_workspace(workspace)

    assert plan.projects[0].label == "services-api"


def test_duplicate_labels_are_disambiguated_by_key(tmp_path):
    """Two projects may legitimately carry the same project_name; the label is
    never a uniqueness key."""
    _project(tmp_path, "foo/api", "project_name: API\n")
    _project(tmp_path, "bar/api", "project_name: API\n")
    workspace = _workspace(tmp_path, ["foo/api", "bar/api"])

    plan = resolve_workspace(workspace)

    labels = sorted(p.display_label for p in plan.projects)
    assert labels == ["API (bar-api)", "API (foo-api)"]
    # The raw label is untouched; only the rendered form disambiguates.
    assert {p.label for p in plan.projects} == {"API"}


def test_a_unique_label_is_not_decorated(tmp_path):
    _project(tmp_path, "foo/api", "project_name: API\n")
    _project(tmp_path, "bar/web", "project_name: Web\n")
    workspace = _workspace(tmp_path, ["foo/api", "bar/web"])

    plan = resolve_workspace(workspace)

    assert sorted(p.display_label for p in plan.projects) == ["API", "Web"]


# ---------------------------------------------------------------------------
# 12. Empty folders and a malformed file are refused by the resolver too
# ---------------------------------------------------------------------------


def test_empty_folders_list_is_refused(tmp_path):
    path = tmp_path / "dev.code-workspace"
    path.write_text(json.dumps({"folders": []}), encoding="utf-8")

    with pytest.raises(WorkspaceDefinitionError, match="at least one folder"):
        resolve_workspace(path)


def test_malformed_workspace_file_is_refused(tmp_path):
    path = tmp_path / "dev.code-workspace"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(WorkspaceDefinitionError, match="not valid JSON"):
        resolve_workspace(path)


# ---------------------------------------------------------------------------
# 13. Config resolution per project
# ---------------------------------------------------------------------------


def test_project_without_a_config_gets_the_default_config(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])

    plan = resolve_workspace(workspace)

    project = plan.projects[0]
    assert project.config_source is None
    assert project.severity_threshold == "MEDIUM"
    assert "bandit" in project.scanners


def test_each_project_config_is_resolved_independently(tmp_path):
    _project(
        tmp_path,
        "api",
        "project_name: api\nglobal_settings:\n  severity_threshold: CRITICAL\n",
    )
    _project(
        tmp_path,
        "web",
        "project_name: web\nglobal_settings:\n  severity_threshold: ALL\n",
    )
    workspace = _workspace(tmp_path, ["api", "web"])

    plan = resolve_workspace(workspace)

    projects = _by_key(plan)
    assert projects["api"].severity_threshold == "CRITICAL"
    assert projects["web"].severity_threshold == "ALL"


def test_config_source_names_the_file_that_was_used(tmp_path):
    project = _project(tmp_path, "api", "project_name: api\n")
    workspace = _workspace(tmp_path, ["api"])

    plan = resolve_workspace(workspace)

    assert (
        plan.projects[0].config_source
        == (project / ".ash" / "ash.yaml").resolve().as_posix()
    )


def test_a_disabled_scanner_is_absent_from_the_scanner_set(tmp_path):
    _project(
        tmp_path,
        "api",
        "project_name: api\nscanners:\n  bandit:\n    enabled: false\n",
    )
    workspace = _workspace(tmp_path, ["api"])

    plan = resolve_workspace(workspace)

    assert "bandit" not in plan.projects[0].scanners
    assert "checkov" in plan.projects[0].scanners


def test_an_invalid_project_config_is_an_invalid_config_error_naming_the_project(
    tmp_path,
):
    """Exit code 3, not 2: the workspace is fine, one project is not."""
    _project(tmp_path, "api", "project_name: api\nglobal_settings: 7\n")
    workspace = _workspace(tmp_path, ["api"])

    with pytest.raises(ASHConfigValidationError) as excinfo:
        resolve_workspace(workspace)

    assert "api" in str(excinfo.value)


def test_a_skipped_project_has_no_config_or_scanners(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api", "absent"])

    plan = resolve_workspace(workspace, allow_missing_projects=True)

    skipped = _by_key(plan)["absent"]
    assert skipped.skipped is True
    assert skipped.config_source is None
    assert skipped.scanners == []
    assert skipped.severity_threshold is None


# ---------------------------------------------------------------------------
# Plan shape
# ---------------------------------------------------------------------------


def test_plan_records_the_workspace_root_as_the_scan_source(tmp_path):
    """Container mode mounts this directory at /src, so the plan has to name
    it explicitly rather than leave it implied by the project paths."""
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])

    plan = resolve_workspace(workspace)

    assert plan.workspace_root == tmp_path.resolve().as_posix()
    assert plan.workspace_file == workspace.resolve().as_posix()


def test_plan_records_absolute_project_paths(tmp_path):
    project = _project(tmp_path, "services/api")
    workspace = _workspace(tmp_path, ["services/api"])

    plan = resolve_workspace(workspace)

    assert plan.projects[0].path == project.resolve().as_posix()


def test_plan_records_whether_missing_projects_were_allowed(tmp_path):
    _project(tmp_path, "api")
    workspace = _workspace(tmp_path, ["api"])

    assert resolve_workspace(workspace).allow_missing_projects is False
    assert (
        resolve_workspace(workspace, allow_missing_projects=True).allow_missing_projects
        is True
    )


def test_plan_renders_every_project_and_its_skip_status(tmp_path):
    _project(tmp_path, "api", "project_name: Payments API\n")
    workspace = _workspace(tmp_path, ["api", "absent"])

    plan = resolve_workspace(workspace, allow_missing_projects=True)
    rendered = plan.render()

    assert "api" in rendered
    assert "Payments API" in rendered
    assert "absent" in rendered
    assert "skipped" in rendered.lower()
    assert rendered.isascii()
