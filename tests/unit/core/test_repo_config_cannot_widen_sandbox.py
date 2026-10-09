# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file inside the scanned tree cannot widen the scanner sandbox.

Each test resolves a config the way a scan does and asks build_scanner_policy what a
scanner would get, so a grant that survives anywhere between the file and the
policy fails here. See config/sandbox_grants.py.
"""

import os
from pathlib import Path

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

REPO_CONFIG = """project_name: scanned
sandbox:
  mode: bwrap
  network_scanners: [checkov]
  extra_read_paths: ["~"]
"""


def _repo(tmp_path: Path, config: str = REPO_CONFIG) -> Path:
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(config)
    return source


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")


def _network(sandbox, name: str, declared: bool, tmp_path: Path, **requirements):
    """Whether `name` gets a network under `sandbox`, given what it declares."""
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    return build_scanner_policy(
        name,
        SandboxRequirements(network=declared, **requirements),
        argv0="/bin/true",
        source_dir=tmp_path,
        output_dir=tmp_path,
        results_dir=results,
        scan_target=None,
        cwd=None,
        offline=False,
        network_scanners=sandbox.network_scanners,
        extra_read_paths=sandbox.extra_read_paths,
        network_limit=sandbox.network_limit,
    ).network


def test_grants_from_a_discovered_config_in_the_tree_are_ignored(tmp_path):
    sandbox = resolve_config(source_dir=_repo(tmp_path)).sandbox
    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []
    assert _network(sandbox, "checkov", False, tmp_path) is False


def test_grants_from_an_explicit_config_inside_the_tree_are_ignored(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    config = source / "ash.yaml"
    config.write_text(REPO_CONFIG)
    sandbox = resolve_config(config_path=config, source_dir=source).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_grants_from_a_config_in_a_nested_directory_are_ignored(tmp_path):
    source = tmp_path / "repo"
    nested = source / "src" / "sub" / ".ash"
    nested.mkdir(parents=True)
    (nested / ".ash.yaml").write_text(REPO_CONFIG)
    sandbox = resolve_config(
        config_path=nested / ".ash.yaml", source_dir=source
    ).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_grants_from_a_config_outside_the_tree_are_kept(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    config = tmp_path / "trusted.yaml"
    config.write_text(REPO_CONFIG)
    sandbox = resolve_config(config_path=config, source_dir=source).sandbox
    assert sandbox.network_scanners == ["checkov"]
    assert sandbox.extra_read_paths == ["~"]
    assert sandbox.network_limit is None
    assert _network(sandbox, "checkov", False, tmp_path) is True


def test_grants_from_command_line_overrides_are_kept(tmp_path):
    sandbox = resolve_config(
        source_dir=_repo(tmp_path),
        config_overrides=[
            "sandbox.network_scanners=[grype]",
            "sandbox.extra_read_paths=[/opt/ca]",
        ],
    ).sandbox
    assert sandbox.network_scanners == ["grype"]
    assert sandbox.extra_read_paths == ["/opt/ca"]
    assert _network(sandbox, "grype", False, tmp_path) is True


def test_an_append_override_does_not_keep_the_repositorys_entries(tmp_path):
    sandbox = resolve_config(
        source_dir=_repo(tmp_path),
        config_overrides=[
            "sandbox.network_scanners+=[grype]",
            "sandbox.extra_read_paths+=[/opt/ca]",
        ],
    ).sandbox
    assert sandbox.network_scanners == ["grype"]
    assert sandbox.extra_read_paths == ["/opt/ca"]
    assert _network(sandbox, "checkov", False, tmp_path) is False
    assert _network(sandbox, "grype", False, tmp_path) is True


def test_the_dashed_spelling_of_an_override_is_the_same_override(tmp_path):
    sandbox = resolve_config(
        source_dir=_repo(tmp_path),
        config_overrides=["sandbox.network-scanners=[grype]"],
    ).sandbox
    assert _network(sandbox, "checkov", False, tmp_path) is False
    assert _network(sandbox, "grype", False, tmp_path) is True


def test_a_whole_section_override_keeps_its_restriction(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    sandbox = resolve_config(
        source_dir=source,
        config_overrides=['sandbox={"mode": "bwrap", "network_scanners": []}'],
    ).sandbox
    assert sandbox.network_scanners == []
    assert _network(sandbox, "grype", True, tmp_path) is False


def test_a_repository_can_take_network_away_from_its_own_scan(tmp_path):
    sandbox = resolve_config(
        source_dir=_repo(
            tmp_path,
            "project_name: x\nsandbox:\n  mode: bwrap\n  network_scanners: []\n",
        )
    ).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.network_limit == []
    assert _network(sandbox, "grype", True, tmp_path) is False


def test_a_repository_list_limits_but_does_not_grant(tmp_path):
    sandbox = resolve_config(source_dir=_repo(tmp_path)).sandbox
    assert sandbox.network_limit == ["checkov"]
    # checkov is named but declares no need: the repository cannot grant it one.
    assert _network(sandbox, "checkov", False, tmp_path) is False
    # grype declares a need but is not named: the repository's list removes it.
    assert _network(sandbox, "grype", True, tmp_path) is False


def test_a_trusted_grant_still_passes_a_repository_limit_that_names_it(tmp_path):
    sandbox = resolve_config(
        source_dir=_repo(tmp_path),
        config_overrides=["sandbox.network_scanners=[checkov]"],
    ).sandbox
    assert _network(sandbox, "checkov", False, tmp_path) is True


def test_an_outside_config_extending_a_base_in_the_tree_loses_the_bases_grants(
    tmp_path,
):
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / "base.yaml").write_text(REPO_CONFIG)
    outside = tmp_path / "ash.yaml"
    outside.write_text("project_name: x\nextends: repo/.ash/base.yaml\n")
    sandbox = resolve_config(config_path=outside, source_dir=source).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []
    assert _network(sandbox, "checkov", False, tmp_path) is False


def test_a_symlinked_source_dir_does_not_hide_the_config(tmp_path):
    real = _repo(tmp_path)
    link = tmp_path / "link"
    _symlink(link, real)
    for config_path in (None, link / ".ash" / ".ash.yaml", real / ".ash" / ".ash.yaml"):
        sandbox = resolve_config(config_path=config_path, source_dir=link).sandbox
        assert sandbox.network_scanners is None, config_path
        assert sandbox.extra_read_paths == [], config_path


def test_a_symlink_outside_the_tree_to_a_config_inside_it_is_inside(tmp_path):
    source = _repo(tmp_path)
    outside = tmp_path / "looks-trusted.yaml"
    _symlink(outside, source / ".ash" / ".ash.yaml")
    sandbox = resolve_config(config_path=outside, source_dir=source).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_dot_dot_segments_do_not_hide_the_config(tmp_path):
    source = _repo(tmp_path)
    detour = source / ".ash" / ".." / ".ash" / ".ash.yaml"
    sandbox = resolve_config(config_path=detour, source_dir=source / "..").sandbox
    assert sandbox.network_scanners is None
    sandbox = resolve_config(
        config_path=detour, source_dir=source / ".ash" / ".."
    ).sandbox
    assert sandbox.network_scanners is None


def test_a_case_only_difference_does_not_hide_the_config(tmp_path, monkeypatch):
    source = _repo(tmp_path)
    variant = tmp_path / "REPO" / ".ash" / ".ash.yaml"
    if not variant.exists():
        # A case-sensitive filesystem (Linux): emulate a case-insensitive one, where
        # both spellings are one directory. A comparison of path strings fails this.
        real_samefile = os.path.samefile

        def case_insensitive_samefile(a, b):
            return os.path.normcase(str(a)).lower() == os.path.normcase(
                str(b)
            ).lower() or real_samefile(a, b)

        monkeypatch.setattr(
            sandbox_grants.os.path, "samefile", case_insensitive_samefile
        )
        monkeypatch.setattr(sandbox_grants.os.path, "realpath", lambda p: str(p))
    assert sandbox_grants.is_within(variant, source)
    assert not sandbox_grants.is_within(tmp_path / "elsewhere.yaml", source)


def test_ash_config_pointing_into_the_tree_is_inside(tmp_path, monkeypatch):
    source = tmp_path / "repo"
    source.mkdir()
    config = source / "ci-ash.yaml"
    config.write_text(REPO_CONFIG)
    monkeypatch.setenv("ASH_CONFIG", str(config))
    sandbox = resolve_config(source_dir=source).sandbox
    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_ash_config_outside_the_tree_keeps_its_grants(tmp_path, monkeypatch):
    source = _repo(tmp_path, "project_name: x\n")
    config = tmp_path / "operator.yaml"
    config.write_text(REPO_CONFIG)
    monkeypatch.setenv("ASH_CONFIG", str(config))
    # No config file of its own in use: the operator's default applies as is.
    sandbox = resolve_config(source_dir=tmp_path / "empty-tree").sandbox
    assert sandbox.network_scanners == ["checkov"]
    # The repository's own config is in the tree; ASH_CONFIG is the trusted base.
    sandbox = resolve_config(source_dir=source).sandbox
    assert sandbox.network_scanners == ["checkov"]
    assert sandbox.extra_read_paths == ["~"]


def test_a_config_named_by_another_project_in_the_workspace_is_inside(tmp_path):
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )
    from automated_security_helper.workspace.plan import ProjectPlan

    workspace = tmp_path / "workspace"
    project_dir = workspace / "services" / "api"
    project_dir.mkdir(parents=True)
    shared = workspace / ".ash" / "shared.yaml"
    shared.parent.mkdir()
    shared.write_text(REPO_CONFIG)
    project = ProjectPlan(
        key="api",
        relative_path="services/api",
        path=project_dir.as_posix(),
        label="api",
        display_label="api",
        severity_threshold="MEDIUM",
        config_source=shared.as_posix(),
    )
    settings = ProjectScanSettings(output_dir=tmp_path / "out")
    sandbox = _project_config_with_policy(project, settings).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_workspace_mode_keeps_a_command_line_restriction(tmp_path):
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )
    from automated_security_helper.workspace.plan import ProjectPlan

    workspace = tmp_path / "workspace"
    project_dir = workspace / "api"
    project_dir.mkdir(parents=True)
    project = ProjectPlan(
        key="api",
        relative_path="api",
        path=project_dir.as_posix(),
        label="api",
        display_label="api",
        severity_threshold="MEDIUM",
    )
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out",
        config_overrides=("sandbox.mode=bwrap", "sandbox.network_scanners=[]"),
    )
    sandbox = _project_config_with_policy(project, settings).sandbox
    assert sandbox.network_scanners == []
    assert _network(sandbox, "grype", True, tmp_path) is False


def test_a_settings_derived_network_need_is_not_granted_by_default(tmp_path):
    sandbox = resolve_config(source_dir=tmp_path).sandbox
    assert (
        _network(sandbox, "detect-secrets", True, tmp_path, network_requires_grant=True)
        is False
    )


def test_a_settings_derived_network_need_is_granted_when_trusted_config_names_it(
    tmp_path,
):
    sandbox = resolve_config(
        source_dir=_repo(tmp_path),
        config_overrides=["sandbox.network_scanners=[detect-secrets]"],
    ).sandbox
    assert (
        _network(sandbox, "detect-secrets", True, tmp_path, network_requires_grant=True)
        is True
    )


def test_detect_secrets_verification_from_the_repository_gets_no_network(tmp_path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    source = _repo(
        tmp_path,
        "project_name: x\n"
        "sandbox:\n  mode: bwrap\n"
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      scan_settings:\n"
        "        plugins_used: [{name: AWSKeyDetector}]\n"
        "        filters_used:\n"
        "          - path: detect_secrets.filters.common.is_ignored_due_to_verification_policies\n"
        "            min_level: 2\n",
    )
    config = resolve_config(source_dir=source)
    context = PluginContext(
        source_dir=source,
        output_dir=source / "out",
        work_dir=source / "out" / "work",
        config=config,
    )
    scanner = DetectSecretsScanner(
        context=context,
        config=config.get_plugin_config(
            plugin_type="scanner", plugin_name="detect-secrets"
        ),
    )
    requirements = scanner.sandbox_requirements
    assert requirements.network is True
    assert requirements.network_requires_grant is True
    results = tmp_path / "results"
    results.mkdir()
    policy = build_scanner_policy(
        "detect-secrets",
        requirements,
        argv0="/bin/true",
        source_dir=source,
        output_dir=tmp_path,
        results_dir=results,
        scan_target=None,
        cwd=None,
        offline=False,
        network_scanners=config.sandbox.network_scanners,
        extra_read_paths=config.sandbox.extra_read_paths,
        network_limit=config.sandbox.network_limit,
    )
    assert policy.network is False


def test_only_sandbox_overrides_are_replayed_onto_the_trusted_defaults(
    tmp_path, monkeypatch
):
    from automated_security_helper.config import resolve_config as module

    replayed = []
    real = module.apply_config_overrides

    def recording(config, overrides):
        replayed.append(list(overrides))
        return real(config, overrides)

    monkeypatch.setattr(module, "apply_config_overrides", recording)
    resolve_config(
        source_dir=_repo(tmp_path),
        config_overrides=[
            "project_name=renamed",
            "sandbox.network_scanners+=[grype]",
        ],
    )
    # Once for the scan's config, once for the trusted defaults.
    assert replayed == [
        ["project_name=renamed", "sandbox.network_scanners+=[grype]"],
        ["sandbox.network_scanners+=[grype]"],
    ]


TRUSTED_BWRAP = """project_name: operator
sandbox:
  mode: bwrap
  network_scanners: [checkov]
"""


def test_a_repository_config_cannot_turn_off_a_sandbox_ash_config_turns_on(
    tmp_path, monkeypatch
):
    operator = tmp_path / "operator.yaml"
    operator.write_text(TRUSTED_BWRAP)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    for repo_config in (
        "project_name: x\n",
        "project_name: x\nsandbox:\n  mode: 'off'\n",
    ):
        source = tmp_path / f"repo-{len(repo_config)}"
        (source / ".ash").mkdir(parents=True)
        (source / ".ash" / ".ash.yaml").write_text(repo_config)
        sandbox = resolve_config(source_dir=source).sandbox
        assert sandbox.mode == "bwrap", repo_config
        assert sandbox.network_scanners == ["checkov"], repo_config


def test_a_repository_config_cannot_switch_the_sandbox_to_another_backend(
    tmp_path, monkeypatch
):
    operator = tmp_path / "operator.yaml"
    operator.write_text(TRUSTED_BWRAP)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    source = _repo(tmp_path, "project_name: x\nsandbox:\n  mode: firejail\n")
    assert resolve_config(source_dir=source).sandbox.mode == "bwrap"


def test_a_repository_config_can_turn_the_sandbox_on(tmp_path):
    source = _repo(tmp_path, "project_name: x\nsandbox:\n  mode: landlock\n")
    assert resolve_config(source_dir=source).sandbox.mode == "landlock"


def test_workspace_mode_takes_the_sandbox_from_the_operators_config(tmp_path):
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )
    from automated_security_helper.workspace.plan import ProjectPlan

    operator = tmp_path / "operator.yaml"
    operator.write_text(TRUSTED_BWRAP)
    workspace = tmp_path / "workspace"
    project_dir = workspace / "api"
    (project_dir / ".ash").mkdir(parents=True)
    own = project_dir / ".ash" / ".ash.yaml"
    own.write_text("project_name: api\nsandbox:\n  mode: 'off'\n")
    project = ProjectPlan(
        key="api",
        relative_path="api",
        path=project_dir.as_posix(),
        label="api",
        display_label="api",
        severity_threshold="MEDIUM",
        config_source=own.as_posix(),
    )
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", default_config_path=str(operator)
    )
    sandbox = _project_config_with_policy(project, settings).sandbox
    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners == ["checkov"]


def test_an_operator_config_inside_the_workspace_is_not_trusted(tmp_path):
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )
    from automated_security_helper.workspace.plan import ProjectPlan

    workspace = tmp_path / "workspace"
    project_dir = workspace / "api"
    (project_dir / ".ash").mkdir(parents=True)
    own = project_dir / ".ash" / ".ash.yaml"
    own.write_text("project_name: api\n")
    in_tree_default = workspace / "default.yaml"
    in_tree_default.write_text(TRUSTED_BWRAP)
    project = ProjectPlan(
        key="api",
        relative_path="api",
        path=project_dir.as_posix(),
        label="api",
        display_label="api",
        severity_threshold="MEDIUM",
        config_source=own.as_posix(),
    )
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", default_config_path=str(in_tree_default)
    )
    sandbox = _project_config_with_policy(project, settings).sandbox
    assert sandbox.network_scanners is None


def test_a_config_elsewhere_in_the_scanned_repository_is_inside(tmp_path):
    repository = tmp_path / "checkout"
    (repository / ".git").mkdir(parents=True)
    (repository / ".ash").mkdir()
    (repository / ".ash" / "ci.yaml").write_text(REPO_CONFIG)
    service = repository / "services" / "api"
    service.mkdir(parents=True)
    sandbox = resolve_config(
        config_path=repository / ".ash" / "ci.yaml", source_dir=service
    ).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_a_git_file_marks_a_checkout_as_well(tmp_path):
    # A linked worktree or a submodule has a .git file rather than a directory.
    repository = tmp_path / "worktree"
    repository.mkdir()
    (repository / ".git").write_text("gitdir: /elsewhere/.git/worktrees/x\n")
    (repository / "ash.yaml").write_text(REPO_CONFIG)
    service = repository / "api"
    service.mkdir()
    sandbox = resolve_config(
        config_path=repository / "ash.yaml", source_dir=service
    ).sandbox
    assert sandbox.network_scanners is None


def test_the_limit_reaches_the_policy_of_a_real_spawn(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    from automated_security_helper.utils.sandbox import scope as scope_module
    from automated_security_helper.utils.sandbox.backends import SpawnPlan

    class Recorder:
        name = "recorder"

        def __init__(self):
            self.policies = []

        def plan(self, argv, env, policy):
            self.policies.append(policy)
            return SpawnPlan(argv=list(argv), env=dict(env))

    recorder = Recorder()
    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: recorder)
    monkeypatch.setattr(
        "automated_security_helper.core.constants.is_offline_mode", lambda: False
    )
    source = _repo(tmp_path)
    config = resolve_config(source_dir=source)
    context = SimpleNamespace(
        config=config, source_dir=source, output_dir=tmp_path / "out"
    )

    def network_of(name):
        plugin = SimpleNamespace(
            config=SimpleNamespace(name=name),
            sandbox_requirements=SandboxRequirements(network=True),
            results_dir=None,
        )
        scope = scope_module.scanner_sandbox_scope(plugin, context, source)
        with scope_module.sandbox_scope(scope):
            scope_module.prepare_spawn([sys.executable, "--version"], {}, None)
        return recorder.policies[-1].network

    # Both declare a need. The repository's list names checkov only.
    assert network_of("checkov") is True
    assert network_of("grype") is False


REPO_OFF = "project_name: thirdparty\nsandbox:\n  mode: 'off'\n"


@pytest.mark.parametrize("layout", ["operator-checkout", "home-is-a-checkout"])
def test_an_operator_config_inside_a_checkout_still_sets_the_mode_floor(
    tmp_path, monkeypatch, caplog, layout
):
    # A .git above both the operator's ASH_CONFIG and the scanned tree makes the
    # operator's file "in the tree". Its grants are dropped, but its mode holds.
    top = tmp_path / layout
    (top / ".git").mkdir(parents=True)
    operator = top / "ash" / "operator.yaml"
    operator.parent.mkdir()
    operator.write_text(TRUSTED_BWRAP)
    target = top / "targets" / "thirdparty"
    (target / ".ash").mkdir(parents=True)
    (target / ".ash" / ".ash.yaml").write_text(REPO_OFF)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    caplog.set_level("WARNING")
    sandbox = resolve_config(source_dir=target).sandbox
    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners is None
    assert any("sandbox.mode" in record.getMessage() for record in caplog.records)


def test_the_sandbox_flag_still_turns_off_an_operator_floor(tmp_path, monkeypatch):
    top = tmp_path / "checkout"
    (top / ".git").mkdir(parents=True)
    operator = top / "operator.yaml"
    operator.write_text(TRUSTED_BWRAP)
    target = top / "thirdparty"
    (target / ".ash").mkdir(parents=True)
    (target / ".ash" / ".ash.yaml").write_text("project_name: x\n")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    sandbox = resolve_config(
        source_dir=target, config_overrides=["sandbox.mode=off"]
    ).sandbox
    assert sandbox.mode == "off"


def _workspace_project(workspace: Path, own_config: str):
    from automated_security_helper.workspace.plan import ProjectPlan

    project_dir = workspace / "api"
    (project_dir / ".ash").mkdir(parents=True)
    own = project_dir / ".ash" / ".ash.yaml"
    own.write_text(own_config)
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=project_dir.as_posix(),
        label="api",
        display_label="api",
        severity_threshold="MEDIUM",
        config_source=own.as_posix(),
    )


def test_a_workspace_operator_config_inside_a_checkout_still_sets_the_mode_floor(
    tmp_path,
):
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )

    top = tmp_path / "checkout"
    (top / ".git").mkdir(parents=True)
    operator = top / "operator.yaml"
    operator.write_text(TRUSTED_BWRAP)
    project = _workspace_project(top / "workspace", REPO_OFF)
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", default_config_path=str(operator)
    )
    sandbox = _project_config_with_policy(project, settings).sandbox
    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners is None


def test_an_operator_config_extending_into_the_tree_still_sets_the_mode_floor(
    tmp_path,
):
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )

    workspace = tmp_path / "workspace"
    project = _workspace_project(workspace, REPO_OFF)
    (workspace / "shared").mkdir()
    (workspace / "shared" / "base.yaml").write_text("project_name: shared\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(TRUSTED_BWRAP + "extends: workspace/shared/base.yaml\n")
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", default_config_path=str(operator)
    )
    sandbox = _project_config_with_policy(project, settings).sandbox
    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners is None


def test_an_invalid_operator_config_is_refused_like_any_config(tmp_path):
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )

    project = _workspace_project(tmp_path / "workspace", "project_name: api\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(TRUSTED_BWRAP + "fail_on_findings: 'true'\n")
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", default_config_path=str(operator)
    )
    with pytest.raises(ASHConfigValidationError):
        _project_config_with_policy(project, settings)


def test_a_git_file_below_the_checkout_does_not_move_the_superproject_outside(
    tmp_path,
):
    superproject = tmp_path / "super"
    (superproject / ".git").mkdir(parents=True)
    (superproject / ".ash").mkdir()
    (superproject / ".ash" / "ci.yaml").write_text(REPO_CONFIG)
    submodule = superproject / "src"
    submodule.mkdir()
    (submodule / ".git").write_text("gitdir: ../.git/modules/src\n")
    sandbox = resolve_config(
        config_path=superproject / ".ash" / "ci.yaml", source_dir=submodule
    ).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_a_dangling_git_symlink_still_marks_a_checkout(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    _symlink(checkout / ".git", tmp_path / "gone")
    (checkout / "ci.yaml").write_text(REPO_CONFIG)
    (checkout / "api").mkdir()
    sandbox = resolve_config(
        config_path=checkout / "ci.yaml", source_dir=checkout / "api"
    ).sandbox
    assert sandbox.network_scanners is None


def test_a_scan_root_symlinked_out_of_the_checkout_still_counts_the_checkout(
    tmp_path,
):
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "ci.yaml").write_text(REPO_CONFIG)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _symlink(checkout / "vendor", elsewhere)
    sandbox = resolve_config(
        config_path=checkout / "ci.yaml", source_dir=checkout / "vendor"
    ).sandbox
    assert sandbox.network_scanners is None


def test_a_scan_root_symlinked_into_a_checkout_counts_that_checkout(tmp_path):
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "ci.yaml").write_text(REPO_CONFIG)
    (checkout / "api").mkdir()
    link = tmp_path / "api-link"
    _symlink(link, checkout / "api")
    sandbox = resolve_config(config_path=checkout / "ci.yaml", source_dir=link).sandbox
    assert sandbox.network_scanners is None


def test_dropping_a_grant_says_which_file_and_which_settings(tmp_path, caplog):
    source = _repo(tmp_path)
    caplog.set_level("WARNING")
    resolve_config(source_dir=source)
    messages = [record.getMessage() for record in caplog.records]
    assert any(
        "sandbox.network_scanners" in message
        and "sandbox.extra_read_paths" in message
        and ".ash.yaml" in message
        for message in messages
    ), messages


def test_withholding_a_settings_derived_need_is_logged(tmp_path, monkeypatch, caplog):
    from types import SimpleNamespace

    from automated_security_helper.utils.sandbox import scope as scope_module

    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: None)
    monkeypatch.setattr(
        "automated_security_helper.core.constants.is_offline_mode", lambda: False
    )
    config = resolve_config(
        source_dir=_repo(tmp_path, "project_name: x\nsandbox:\n  mode: bwrap\n")
    )
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="detect-secrets"),
        sandbox_requirements=SandboxRequirements(
            network=True, network_requires_grant=True
        ),
        results_dir=None,
    )
    context = SimpleNamespace(
        config=config, source_dir=tmp_path, output_dir=tmp_path / "out"
    )
    caplog.set_level("WARNING")
    scope_module.scanner_sandbox_scope(plugin, context, tmp_path)
    assert any(
        "detect-secrets" in record.getMessage()
        and "sandbox.network_scanners" in record.getMessage()
        for record in caplog.records
    )


def _vendor_link_out(tmp_path: Path):
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".ash").mkdir()
    ci = checkout / ".ash" / "ci.yaml"
    ci.write_text(REPO_CONFIG)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "sub").mkdir(parents=True)
    _symlink(checkout / "vendor", elsewhere)
    return checkout, ci


def test_scanning_the_working_directory_inside_a_symlink_counts_the_checkout(
    tmp_path, monkeypatch
):
    # `cd checkout/vendor && ashx scan`: the operating system reports the physical
    # directory, outside the checkout; only $PWD still says where the shell is.
    checkout, ci = _vendor_link_out(tmp_path)
    monkeypatch.chdir(checkout / "vendor")
    monkeypatch.setenv("PWD", str(checkout / "vendor"))
    for root in (Path("."), Path.cwd(), Path.cwd() / "sub", Path("sub")):
        sandbox = resolve_config(config_path=ci, source_dir=root).sandbox
        assert sandbox.network_scanners is None, root
        assert sandbox.extra_read_paths == [], root


def test_a_pwd_that_names_another_directory_is_not_used(tmp_path, monkeypatch):
    checkout, ci = _vendor_link_out(tmp_path)
    monkeypatch.chdir(tmp_path / "elsewhere")
    # Points into the checkout, but is not the working directory.
    monkeypatch.setenv("PWD", str(checkout))
    assert sandbox_grants._logical_paths(Path(".")) == []


def test_a_relative_scan_root_from_a_subdirectory_counts_the_checkout(
    tmp_path, monkeypatch
):
    checkout, ci = _vendor_link_out(tmp_path)
    (checkout / "a").mkdir()
    _symlink(checkout / "a" / "vendor", tmp_path / "elsewhere")
    monkeypatch.chdir(checkout / "a")
    monkeypatch.delenv("PWD", raising=False)
    sandbox = resolve_config(config_path=ci, source_dir=Path("vendor")).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_ash_config_in_a_checkout_found_only_through_the_resolved_root(
    tmp_path, monkeypatch
):
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".ash").mkdir()
    rogue = checkout / ".ash" / "rogue.yaml"
    rogue.write_text(REPO_CONFIG)
    (checkout / "src" / ".ash").mkdir(parents=True)
    (checkout / "src" / ".ash" / ".ash.yaml").write_text("project_name: src\n")
    link = tmp_path / "link"
    _symlink(link, checkout / "src")
    monkeypatch.setenv("ASH_CONFIG", str(rogue))
    sandbox = resolve_config(source_dir=link).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []
