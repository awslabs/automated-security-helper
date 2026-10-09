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


def _ignored_keys(message: str) -> set:
    """The settings a confinement warning names, from its "Ignoring ... from" clause."""
    if not message.startswith("Ignoring ") or " from " not in message:
        return set()
    return {
        key.strip() for key in message[len("Ignoring ") :].split(" from ")[0].split(",")
    }


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path):
    # A basetemp inside a repository, or a home that is a checkout with TMPDIR
    # under it, would make every refusal here pass for the wrong reason.
    assert not sandbox_grants.in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


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
        _ignored_keys(message)
        == {"sandbox.network_scanners", "sandbox.extra_read_paths"}
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
    # `cd checkout/vendor && ash scan`: the operating system reports the physical
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


def _confined(sandbox) -> bool:
    return sandbox.network_scanners is None and sandbox.extra_read_paths == []


@pytest.mark.parametrize("spelling", ["..", "../other"])
def test_a_root_above_a_symlinked_cwd_counts_the_checkout(
    tmp_path, monkeypatch, spelling
):
    # From `cd checkout/vendor/sub`, the CLI turns `--source-dir ..` into an
    # absolute path under the physical working directory, outside the checkout.
    checkout, ci = _vendor_link_out(tmp_path)
    (tmp_path / "elsewhere" / "other").mkdir()
    monkeypatch.chdir(checkout / "vendor" / "sub")
    monkeypatch.setenv("PWD", str(checkout / "vendor" / "sub"))
    root = Path(spelling).absolute()
    assert _confined(resolve_config(config_path=ci, source_dir=root).sandbox)


def test_a_symlink_below_a_symlinked_cwd_counts_the_checkout(tmp_path, monkeypatch):
    checkout, ci = _vendor_link_out(tmp_path)
    far = tmp_path / "far"
    far.mkdir()
    _symlink(tmp_path / "elsewhere" / "x", far)
    monkeypatch.chdir(checkout / "vendor")
    monkeypatch.setenv("PWD", str(checkout / "vendor"))
    root = Path("x").absolute()
    assert _confined(resolve_config(config_path=ci, source_dir=root).sandbox)


def test_a_pwd_naming_another_directory_does_not_replace_the_given_names(
    tmp_path, monkeypatch
):
    # $PWD names the working directory through another path: it may add a name for
    # the scan root, but the root as given and as resolved stay.
    plain = tmp_path / "plain"
    (plain / "a").mkdir(parents=True)
    out = tmp_path / "out"
    out.mkdir()
    _symlink(plain / "a" / "vendor", out)
    other = tmp_path / "other"
    other.mkdir()
    _symlink(other / "link", plain / "a")
    monkeypatch.chdir(plain / "a")
    monkeypatch.setenv("PWD", str(other / "link"))
    for root in (Path("vendor"), Path("vendor").absolute()):
        names = sandbox_grants.scan_root_names(root)
        assert Path(os.path.abspath(root)) in names, root
        assert Path(os.path.realpath(root)) in names, root
        assert other / "link" / "vendor" in names, root


def test_a_fresh_pwd_does_not_replace_the_resolved_path(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".ash").mkdir()
    rogue = checkout / ".ash" / "rogue.yaml"
    rogue.write_text(REPO_CONFIG)
    (checkout / "src" / ".ash").mkdir(parents=True)
    (checkout / "src" / ".ash" / ".ash.yaml").write_text("project_name: src\n")
    work = tmp_path / "work"
    work.mkdir()
    _symlink(work / "link", checkout / "src")
    monkeypatch.chdir(work)
    monkeypatch.setenv("PWD", str(work))
    monkeypatch.setenv("ASH_CONFIG", str(rogue))
    for root in (Path("link"), Path("link").absolute()):
        assert _confined(resolve_config(source_dir=root).sandbox), root


def test_a_pwd_naming_a_deleted_directory_is_ignored(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("PWD", str(tmp_path / "gone"))
    assert sandbox_grants._logical_paths(Path(".")) == []
    assert Path(os.path.realpath(checkout)) in sandbox_grants.scan_root_names(Path("."))


# The checkout rule. A config file inside any git checkout cannot grant, however the
# scan root is named; outside every checkout, the scan root's own names decide.


def test_a_trusted_config_kept_in_its_own_checkout_cannot_grant(tmp_path, caplog):
    ops = tmp_path / "ops"
    (ops / ".git").mkdir(parents=True)
    operator = ops / "ash.yaml"
    operator.write_text(REPO_CONFIG)
    target = tmp_path / "target"
    target.mkdir()
    caplog.set_level("WARNING")
    sandbox = resolve_config(config_path=operator, source_dir=target).sandbox
    assert sandbox.mode == "bwrap"
    assert _confined(sandbox)
    messages = [record.getMessage() for record in caplog.records]
    assert any(
        _ignored_keys(message)
        == {"sandbox.network_scanners", "sandbox.extra_read_paths"}
        and "ash.yaml" in message
        and "--config-overrides" in message
        for message in messages
    ), messages


def test_a_config_outside_every_checkout_and_the_target_still_grants(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    operator = tmp_path / "etc" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(REPO_CONFIG)
    sandbox = resolve_config(config_path=operator, source_dir=target).sandbox
    assert sandbox.network_scanners == ["checkov"]
    assert sandbox.extra_read_paths == ["~"]


def test_an_override_still_grants_beside_a_checkout_config(tmp_path):
    ops = tmp_path / "ops"
    (ops / ".git").mkdir(parents=True)
    operator = ops / "ash.yaml"
    operator.write_text(REPO_CONFIG)
    sandbox = resolve_config(
        config_path=operator,
        source_dir=tmp_path,
        config_overrides=[
            "sandbox.network_scanners=[checkov]",
            "sandbox.read_path_scanners=[zizmor]",
            "sandbox.env_scanners=[zizmor]",
        ],
    ).sandbox
    assert sandbox.network_scanners == ["checkov"]
    assert sandbox.read_path_scanners == ["zizmor"]
    assert sandbox.env_scanners == ["zizmor"]


def test_a_checkout_config_cannot_grant_read_paths_or_environment(tmp_path, caplog):
    source = _repo(
        tmp_path,
        "project_name: x\nsandbox:\n  mode: bwrap\n"
        "  read_path_scanners: [zizmor]\n  env_scanners: [zizmor]\n",
    )
    (source / ".git").mkdir()
    caplog.set_level("WARNING")
    sandbox = resolve_config(source_dir=source).sandbox
    assert any(
        _ignored_keys(record.getMessage())
        == {"sandbox.read_path_scanners", "sandbox.env_scanners"}
        for record in caplog.records
    ), [record.getMessage() for record in caplog.records]
    assert sandbox.read_path_scanners == []
    assert sandbox.env_scanners == []


def test_a_checkout_config_found_only_by_its_own_name(tmp_path):
    # The config file's name is inside a checkout; its resolved path is not.
    ops = tmp_path / "ops"
    (ops / ".git").mkdir(parents=True)
    real = tmp_path / "real.yaml"
    real.write_text(REPO_CONFIG)
    _symlink(ops / "ash.yaml", real)
    target = tmp_path / "target"
    target.mkdir()
    sandbox = resolve_config(config_path=ops / "ash.yaml", source_dir=target).sandbox
    assert _confined(sandbox)


def test_a_target_outside_every_checkout_still_confines_its_own_config(tmp_path):
    # An extracted archive: no .git anywhere, so the scan root's names decide.
    extract = tmp_path / "pkg-1.0"
    (extract / ".ash").mkdir(parents=True)
    (extract / ".ash" / ".ash.yaml").write_text(REPO_CONFIG)
    assert _confined(resolve_config(source_dir=extract).sandbox)


def test_a_symlinked_target_outside_every_checkout_confines_its_config(
    tmp_path, monkeypatch
):
    # No .git anywhere. The scan root is a symlink to the extract, so its config is
    # inside the root only by the root's resolved name or by $PWD.
    extract = tmp_path / "pkg-1.0"
    (extract / ".ash").mkdir(parents=True)
    (extract / ".ash" / ".ash.yaml").write_text(REPO_CONFIG)
    link = tmp_path / "pkg"
    _symlink(link, extract)
    assert _confined(resolve_config(source_dir=link).sandbox)
    monkeypatch.chdir(link)
    monkeypatch.setenv("PWD", str(link))
    assert _confined(resolve_config(source_dir=Path.cwd()).sandbox)
    assert _confined(resolve_config(source_dir=Path(".")).sandbox)


def test_in_any_checkout_sees_git_files_and_dangling_links(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: /elsewhere\n")
    assert sandbox_grants.in_any_checkout(worktree / "a" / "ash.yaml")
    dangling = tmp_path / "dangling"
    dangling.mkdir()
    _symlink(dangling / ".git", tmp_path / "gone")
    assert sandbox_grants.in_any_checkout(dangling / "ash.yaml")
    assert not sandbox_grants.in_any_checkout(tmp_path / "plain" / "ash.yaml")
    # A name outside every checkout that resolves into one counts as inside: the
    # helper is public, and callers may pass a path as the operator spelled it.
    (tmp_path / "plain").mkdir()
    (worktree / "a").mkdir()
    (worktree / "a" / "ash.yaml").write_text("project_name: x\n")
    _symlink(tmp_path / "plain" / "into.yaml", worktree / "a" / "ash.yaml")
    assert sandbox_grants.in_any_checkout(tmp_path / "plain" / "into.yaml")


def test_a_settings_derived_read_path_is_not_granted_by_default(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    sandbox = resolve_config(source_dir=tmp_path / "t").sandbox
    results = tmp_path / "results"
    results.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    requirements = SandboxRequirements(
        read_paths=(str(rules),),
        cache_paths=(str(cache),),
        env_names=("ZIZMOR_GITHUB_TOKEN",),
        read_paths_require_grant=True,
        env_requires_grant=True,
    )

    def policy(**grants):
        return build_scanner_policy(
            "zizmor",
            requirements,
            argv0="/bin/true",
            source_dir=tmp_path,
            output_dir=tmp_path,
            results_dir=results,
            scan_target=None,
            cwd=None,
            offline=False,
            network_scanners=sandbox.network_scanners,
            **grants,
        )

    denied = policy()
    assert Path(os.path.realpath(rules)) not in [
        Path(os.path.realpath(p)) for p in denied.read_only
    ]
    assert "ZIZMOR_GITHUB_TOKEN" not in denied.env_names
    assert Path(os.path.realpath(cache)) not in [
        Path(os.path.realpath(p)) for p in denied.cache
    ]
    granted = policy(read_path_scanners=["zizmor"], env_scanners=["zizmor"])
    # A granted option path is still mounted only inside the source tree or an
    # extra_read_paths entry; rules lives in tmp_path, which is the source tree here.
    # Option-derived caches are never writable.
    assert Path(os.path.realpath(cache)) not in [
        Path(os.path.realpath(p)) for p in granted.cache
    ]
    assert Path(os.path.realpath(rules)) in [
        Path(os.path.realpath(p)) for p in granted.read_only
    ]
    assert "ZIZMOR_GITHUB_TOKEN" in granted.env_names


def test_the_confinement_refuses_to_compare_settings_with_themselves(tmp_path):
    sandbox = resolve_config(source_dir=tmp_path).sandbox
    with pytest.raises(ValueError):
        sandbox_grants.confine_sandbox_grants(sandbox, sandbox, [])


def test_read_and_environment_grants_reach_the_policy_of_a_real_spawn(
    tmp_path, monkeypatch, caplog
):
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
    target = tmp_path / "target"
    target.mkdir()
    # Inside the scanned tree: a granted option path is mounted only there or in an
    # extra_read_paths entry.
    rules = target / "rules"
    rules.mkdir()
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="zizmor"),
        sandbox_requirements=SandboxRequirements(
            read_paths=(str(rules),),
            env_names=("ZIZMOR_GITHUB_TOKEN",),
            read_paths_require_grant=True,
            env_requires_grant=True,
        ),
        results_dir=None,
    )

    def policy_for(overrides):
        config = resolve_config(
            source_dir=target,
            config_overrides=["sandbox.mode=bwrap", *overrides],
        )
        context = SimpleNamespace(
            config=config, source_dir=target, output_dir=tmp_path / "out"
        )
        scope = scope_module.scanner_sandbox_scope(plugin, context, target)
        with scope_module.sandbox_scope(scope):
            scope_module.prepare_spawn([sys.executable, "--version"], {}, None)
        return recorder.policies[-1]

    def reads(policy):
        return [Path(os.path.realpath(p)) for p in policy.read_only]

    caplog.set_level("WARNING")
    denied = policy_for([])
    assert Path(os.path.realpath(rules)) not in reads(denied)
    assert "ZIZMOR_GITHUB_TOKEN" not in denied.env_names
    messages = [record.getMessage() for record in caplog.records]
    assert any("sandbox.read_path_scanners" in m for m in messages), messages
    assert any("sandbox.env_scanners" in m for m in messages), messages

    granted = policy_for(
        ["sandbox.read_path_scanners=[zizmor]", "sandbox.env_scanners=[zizmor]"]
    )
    assert Path(os.path.realpath(rules)) in reads(granted)
    assert "ZIZMOR_GITHUB_TOKEN" in granted.env_names

    # Each list grants only its own kind of access, all the way to the spawn.
    read_only = policy_for(["sandbox.read_path_scanners=[zizmor]"])
    assert Path(os.path.realpath(rules)) in reads(read_only)
    assert "ZIZMOR_GITHUB_TOKEN" not in read_only.env_names
    env_only = policy_for(["sandbox.env_scanners=[zizmor]"])
    assert Path(os.path.realpath(rules)) not in reads(env_only)
    assert "ZIZMOR_GITHUB_TOKEN" in env_only.env_names


# Tenth review.


def test_a_config_symlinked_out_of_a_target_outside_every_checkout_is_inside(
    tmp_path,
):
    # No .git anywhere: the discovered config's own name is in the scan root, even
    # though the file it resolves to sits beside it.
    pkg = tmp_path / "pkg"
    (pkg / ".ash").mkdir(parents=True)
    data = tmp_path / "pkg-data" / "x.yaml"
    data.parent.mkdir()
    data.write_text(REPO_CONFIG)
    _symlink(pkg / ".ash" / ".ash.yaml", data)
    assert _confined(resolve_config(source_dir=pkg).sandbox)


def test_a_subdirectory_config_symlinked_elsewhere_in_the_repository_is_inside(
    tmp_path,
):
    repo = tmp_path / "repo"
    api = repo / "services" / "api"
    (api / ".ash").mkdir(parents=True)
    shared = repo / "shared" / "x.yaml"
    shared.parent.mkdir()
    shared.write_text(REPO_CONFIG)
    _symlink(api / ".ash" / ".ash.yaml", shared)
    assert _confined(resolve_config(source_dir=api).sandbox)


def test_the_workspace_plan_keeps_a_project_configs_own_name(tmp_path):
    import json

    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )
    from automated_security_helper.workspace.resolver import resolve_workspace

    workspace = tmp_path / "workspace"
    api = workspace / "api"
    (api / ".ash").mkdir(parents=True)
    (api / "app.py").write_text("x = 1\n")
    outside = tmp_path / "outside.yaml"
    outside.write_text(REPO_CONFIG)
    _symlink(api / ".ash" / ".ash.yaml", outside)
    definition = workspace / "ws.code-workspace"
    definition.write_text(json.dumps({"folders": [{"path": "api"}]}))
    plan = resolve_workspace(definition)
    (project,) = plan.projects
    assert Path(project.config_source).name == ".ash.yaml"
    sandbox = _project_config_with_policy(
        project, ProjectScanSettings(output_dir=tmp_path / "out")
    ).sandbox
    assert _confined(sandbox)


def test_an_extends_base_in_another_checkout_cannot_grant(tmp_path):
    # The root config is outside every checkout and the scan root; its base is in
    # someone's checkout elsewhere.
    # Bases must stay under the root config's directory, so the other checkout is
    # vendored there.
    other = tmp_path / "etc" / "vendor"
    (other / ".git").mkdir(parents=True)
    (other / "base.yaml").write_text(REPO_CONFIG)
    root = tmp_path / "etc" / "ash.yaml"
    root.write_text("project_name: x\nextends: vendor/base.yaml\n")
    target = tmp_path / "target"
    target.mkdir()
    sandbox = resolve_config(config_path=root, source_dir=target).sandbox
    assert _confined(sandbox)


def test_an_operator_config_named_inside_a_checkout_is_not_the_trusted_base(
    tmp_path,
):
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )

    ops = tmp_path / "ops"
    (ops / ".git").mkdir(parents=True)
    real = tmp_path / "elsewhere.yaml"
    real.write_text(TRUSTED_BWRAP)
    _symlink(ops / "operator.yaml", real)
    project = _workspace_project(tmp_path / "workspace", "project_name: api\n")
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", default_config_path=str(ops / "operator.yaml")
    )
    sandbox = _project_config_with_policy(project, settings).sandbox
    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners is None


def test_ash_config_named_inside_a_checkout_cannot_grant(tmp_path, monkeypatch):
    ops = tmp_path / "ops"
    (ops / ".git").mkdir(parents=True)
    real = tmp_path / "elsewhere.yaml"
    real.write_text(REPO_CONFIG)
    _symlink(ops / "ash.yaml", real)
    monkeypatch.setenv("ASH_CONFIG", str(ops / "ash.yaml"))
    target = tmp_path / "target"
    target.mkdir()
    assert _confined(resolve_config(source_dir=target).sandbox)
    # With a config of the target's own in the tree, ASH_CONFIG is the trusted
    # base, and its lexical name keeps it from granting there too.
    (target / ".ash").mkdir()
    (target / ".ash" / ".ash.yaml").write_text("project_name: t\n")
    assert _confined(resolve_config(source_dir=target).sandbox)


def _zizmor_policy(tmp_path, requirements, source_dir=None, **grants):
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    return build_scanner_policy(
        "zizmor",
        requirements,
        argv0="/bin/true",
        source_dir=source_dir or tmp_path,
        output_dir=tmp_path,
        results_dir=results,
        scan_target=None,
        cwd=None,
        offline=False,
        network_scanners=None,
        **grants,
    )


def test_read_and_environment_grants_are_independent(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    requirements = SandboxRequirements(
        read_paths=(str(rules),),
        env_prefixes=("ZIZMOR_",),
        env_names=("GH_TOKEN",),
        read_paths_require_grant=True,
        env_requires_grant=True,
    )
    rules_real = Path(os.path.realpath(rules))
    read_only = _zizmor_policy(tmp_path, requirements, read_path_scanners=["zizmor"])
    assert rules_real in [Path(os.path.realpath(p)) for p in read_only.read_only]
    assert "GH_TOKEN" not in read_only.env_names
    assert "ZIZMOR_" not in read_only.env_prefixes
    env_only = _zizmor_policy(tmp_path, requirements, env_scanners=["zizmor"])
    assert rules_real not in [Path(os.path.realpath(p)) for p in env_only.read_only]
    assert "GH_TOKEN" in env_only.env_names
    assert "ZIZMOR_" in env_only.env_prefixes


def test_a_granted_option_path_is_mounted_only_inside_trusted_roots(
    tmp_path, monkeypatch
):
    import shutil
    import socket
    import tempfile

    source = tmp_path / "src"
    (source / "rules").mkdir(parents=True)
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    company = tmp_path / "opt" / "company-rules"
    company.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _symlink(source / "escape", elsewhere)
    # A socket inside a trusted root, so only the socket check can refuse it. Bound
    # under a short temporary directory: a socket path has a platform length limit
    # (108 bytes on Linux) that a long basetemp would exceed.
    sockets = Path(tempfile.mkdtemp(prefix="ash-s-"))
    sock_path = sockets / "a.sock"
    listener = None
    if hasattr(socket, "AF_UNIX"):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(sock_path))
    try:
        requirements = SandboxRequirements(
            read_paths=(
                str(home),
                str(home / ".ssh"),
                str(source / "rules"),
                str(company),
                str(source / "escape"),
                str(sock_path),
            ),
            cache_paths=(str(source / "rules"),),
            read_paths_require_grant=True,
        )
        policy = _zizmor_policy(
            tmp_path,
            requirements,
            source_dir=source,
            read_path_scanners=["zizmor"],
            extra_read_paths=[str(company), str(sockets)],
        )
        mounted = [Path(os.path.realpath(p)) for p in policy.read_only]
        assert Path(os.path.realpath(source / "rules")) in mounted
        assert Path(os.path.realpath(company)) in mounted
        assert Path(os.path.realpath(home)) not in mounted
        assert Path(os.path.realpath(home / ".ssh")) not in mounted
        # Resolved before the check: a link inside the tree pointing out is outside.
        assert Path(os.path.realpath(elsewhere)) not in mounted
        assert Path(os.path.realpath(sock_path)) not in mounted
        # The resolved path is what the policy carries, not the spelling.
        assert str(source / "escape") not in [str(p) for p in policy.read_only]
        # Option-derived caches are never mounted, even inside the tree.
        assert Path(os.path.realpath(source / "rules")) not in [
            Path(os.path.realpath(p)) for p in policy.cache
        ]
    finally:
        if listener is not None:
            listener.close()
        shutil.rmtree(sockets, ignore_errors=True)


def test_a_scanner_renamed_by_a_config_file_is_not_sandboxed(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from pydantic import BaseModel

    from automated_security_helper.utils.sandbox import scope as scope_module
    from automated_security_helper.utils.sandbox.backends import SandboxUnavailable

    class MyScannerConfig(BaseModel):
        name: str = "my-scanner"

    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: None)
    config = resolve_config(
        source_dir=tmp_path, config_overrides=["sandbox.mode=bwrap"]
    )
    context = SimpleNamespace(
        config=config, source_dir=tmp_path, output_dir=tmp_path / "out"
    )
    renamed = SimpleNamespace(
        config=MyScannerConfig(name="grype"),
        sandbox_requirements=SandboxRequirements(network=True),
        results_dir=None,
    )
    with pytest.raises(SandboxUnavailable):
        scope_module.scanner_sandbox_scope(renamed, context, tmp_path)
    honest = SimpleNamespace(
        config=MyScannerConfig(),
        sandbox_requirements=SandboxRequirements(),
        results_dir=None,
    )
    assert scope_module.scanner_sandbox_scope(honest, context, tmp_path) is not None


def _detect_secrets(source: Path, overrides, baseline: Path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    config = resolve_config(
        source_dir=source,
        config_overrides=[
            f"scanners.detect-secrets.options.baseline_file={baseline}",
            *overrides,
        ],
    )
    context = PluginContext(
        source_dir=source,
        output_dir=source / "out",
        work_dir=source / "out" / "work",
        config=config,
    )
    return DetectSecretsScanner(
        context=context,
        config=config.get_plugin_config(
            plugin_type="scanner", plugin_name="detect-secrets"
        ),
    )


def test_a_baseline_outside_the_tree_is_not_read_under_the_sandbox(tmp_path, caplog):
    source = tmp_path / "src"
    source.mkdir()
    host = tmp_path / "host.json"
    host.write_text('{"results": {}, "plugins_used": [], "filters_used": []}')
    caplog.set_level("WARNING")
    scanner = _detect_secrets(source, ["sandbox.mode=bwrap"], host)
    assert scanner.config.options.baseline_file is None
    assert any("baseline" in r.getMessage() for r in caplog.records)
    granted = _detect_secrets(
        source,
        ["sandbox.mode=bwrap", "sandbox.read_path_scanners=[detect-secrets]"],
        host,
    )
    assert granted.config.options.baseline_file is not None
    unsandboxed = _detect_secrets(source, [], host)
    assert unsandboxed.config.options.baseline_file is not None
    inside = source / ".secrets.baseline"
    inside.write_text('{"results": {}, "plugins_used": [], "filters_used": []}')
    in_tree = _detect_secrets(source, ["sandbox.mode=bwrap"], inside)
    assert in_tree.config.options.baseline_file is not None


# Eleventh review.


def test_a_plugin_renamed_through_its_config_dict_is_not_sandboxed(
    tmp_path, monkeypatch
):
    # Built the way scan_phase builds a plugin: from the raw config dict. A name the
    # plugin's own config class rejects falls back to the generic config class.
    from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
        SnykCodeScanner,
    )
    from automated_security_helper.utils.sandbox import scope as scope_module
    from automated_security_helper.utils.sandbox.backends import SandboxUnavailable

    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: None)
    config = resolve_config(
        source_dir=tmp_path,
        config_overrides=["sandbox.mode=bwrap", "sandbox.network_scanners=[grype]"],
    )
    from automated_security_helper.base.plugin_context import PluginContext

    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=config,
    )
    renamed = SnykCodeScanner(
        context=context, config={"name": "grype", "enabled": True}
    )
    assert renamed.config.name == "grype"
    with pytest.raises(SandboxUnavailable):
        scope_module.scanner_sandbox_scope(renamed, context, tmp_path)
    honest = SnykCodeScanner(
        context=context, config={"name": "snyk-code", "enabled": True}
    )
    assert scope_module.scanner_sandbox_scope(honest, context, tmp_path) is not None


def test_a_scan_root_spelled_through_a_link_and_dot_dot_still_counts(tmp_path):
    # No .git. "top/link/../api" names data/api: the kernel follows link before the
    # "..", which a lexical fold of the path would not.
    data = tmp_path / "data"
    (data / "sub").mkdir(parents=True)
    (data / "api" / ".ash").mkdir(parents=True)
    (data / "x.yaml").write_text(REPO_CONFIG)
    _symlink(data / "api" / ".ash" / ".ash.yaml", data / "x.yaml")
    top = tmp_path / "top"
    top.mkdir()
    _symlink(top / "link", data / "sub")
    spelled = Path(f"{top}/link/../api")
    assert _confined(resolve_config(source_dir=spelled).sandbox)


def test_the_baseline_is_read_once_and_not_reopened_for_the_scan(tmp_path):
    import json

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    entry = {
        "type": "Secret Keyword",
        "filename": "original.py",
        "hashed_secret": "0" * 40,
        "is_verified": False,
        "line_number": 1,
    }
    baseline = source / ".secrets.baseline"
    baseline.write_text(json.dumps({"results": {"original.py": [entry]}}))
    config = DetectSecretsScannerConfig()
    config.options.baseline_file = baseline
    scanner = DetectSecretsScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "work",
            config=get_default_config(),
        ),
        config=config,
    )
    # Swap the checked file for a link to a different document before the scan.
    swapped = tmp_path / "swapped.json"
    swapped.write_text(
        json.dumps({"results": {"swapped.py": [dict(entry, filename="swapped.py")]}})
    )
    baseline.unlink()
    _symlink(baseline, swapped)
    scanner.scan(target=source, target_type="source")
    loaded = {str(name) for name in scanner._secrets_collection.files}
    assert "swapped.py" not in loaded


def test_option_path_containment_follows_windows_path_rules():
    from pathlib import PureWindowsPath

    from automated_security_helper.utils.sandbox.policy import _inside_any

    roots = [PureWindowsPath("C:/Work/Repo"), PureWindowsPath("D:/Company/Rules")]
    # Case-insensitive, as NTFS is.
    assert _inside_any(PureWindowsPath("c:/work/repo/rules/x.yml"), roots)
    assert _inside_any(PureWindowsPath("C:/WORK/REPO"), roots)
    assert _inside_any(PureWindowsPath("d:/company/rules/sub/a.yml"), roots)
    # Same tail on another drive is outside.
    assert not _inside_any(PureWindowsPath("E:/Work/Repo/rules"), roots)
    # A sibling sharing a prefix is outside.
    assert not _inside_any(PureWindowsPath("C:/Work/Repo-other/x"), roots)
    # A drive root is never inside a directory on it.
    assert not _inside_any(PureWindowsPath("C:/"), roots)


def test_option_paths_are_carried_resolved_and_contained_in_extra_entries(tmp_path):
    source = tmp_path / "src"
    (source / "rules").mkdir(parents=True)
    (source / "rules" / "r.yml").write_text("rules: []\n")
    _symlink(source / "rules-link", source / "rules")
    company = tmp_path / "opt" / "company"
    (company / "sub").mkdir(parents=True)
    (company / "sub" / "c.yml").write_text("rules: []\n")
    requirements = SandboxRequirements(
        read_paths=(str(source / "rules-link"), str(company / "sub" / "c.yml")),
        read_paths_require_grant=True,
    )
    policy = _zizmor_policy(
        tmp_path,
        requirements,
        source_dir=source,
        read_path_scanners=["zizmor"],
        extra_read_paths=[str(company)],
    )
    carried = [str(p) for p in policy.read_only]
    # The resolved path goes into the policy, not the link's spelling.
    assert str(Path(os.path.realpath(source / "rules"))) in carried
    assert str(source / "rules-link") not in carried
    # A file below an extra_read_paths entry counts as inside it.
    assert str(Path(os.path.realpath(company / "sub" / "c.yml"))) in carried


def test_a_config_named_through_an_alias_of_the_scan_root_is_inside(tmp_path):
    # No .git. The config is passed through an alias of the scan root, and is
    # itself a link out of it: only comparing files, not spellings, catches it.
    pkg = tmp_path / "pkg"
    (pkg / ".ash").mkdir(parents=True)
    outside = tmp_path / "outside.yaml"
    outside.write_text(REPO_CONFIG)
    _symlink(pkg / ".ash" / ".ash.yaml", outside)
    alias = tmp_path / "alias"
    _symlink(alias, pkg)
    sandbox = resolve_config(
        config_path=alias / ".ash" / ".ash.yaml", source_dir=pkg
    ).sandbox
    assert _confined(sandbox)


def test_a_baseline_in_the_tree_that_links_out_is_not_read(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    host = tmp_path / "host.json"
    host.write_text('{"results": {}, "plugins_used": [], "filters_used": []}')
    _symlink(source / ".secrets.baseline", host)
    scanner = _detect_secrets(
        source, ["sandbox.mode=bwrap"], source / ".secrets.baseline"
    )
    assert scanner.config.options.baseline_file is None


def test_a_plugin_whose_config_is_not_its_own_class_is_not_sandboxed(
    tmp_path, monkeypatch
):
    # Unreachable through validation today; kept so a fallback config class with
    # the plugin's own name cannot pass the identity check.
    from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
        SnykCodeScanner,
    )
    from automated_security_helper.utils.sandbox import scope as scope_module
    from automated_security_helper.utils.sandbox.backends import SandboxUnavailable

    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: None)
    config = resolve_config(
        source_dir=tmp_path, config_overrides=["sandbox.mode=bwrap"]
    )
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=config,
    )
    plugin = SnykCodeScanner.model_construct(
        context=context, config=ScannerPluginConfigBase(name="snyk-code")
    )
    with pytest.raises(SandboxUnavailable):
        scope_module.scanner_sandbox_scope(plugin, context, tmp_path)
