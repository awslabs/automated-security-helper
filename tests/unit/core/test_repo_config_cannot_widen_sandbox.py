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
