# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--providers``: a comma-separated permission boundary and preference order.

Only the listed providers may install anything this run, the first one that can
serve a command wins, a provider that cannot is skipped with its reason printed, and
when none can the tool is refused with every reason, nothing run and nothing
substituted. An unknown name is a usage error naming the known set.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.utils.download_utils import (
    create_pinned_tool_install_command,
)
from automated_security_helper.utils.rules_bundles import (
    create_rules_bundle_install_command,
)
from tests.unit.cli.dependencies_install_support import (
    CHECKOV_COMMAND,
    build_scene,
    run_install,
)

pytestmark = pytest.mark.unit


def test_an_unknown_provider_is_refused_listing_the_known_ones(tmp_path, monkeypatch):
    scene = build_scene(monkeypatch, tmp_path)

    run_install(scene, monkeypatch, tmp_path, "--providers", "uv,nosuch")

    assert scene.result.exit_code == 2, scene.text
    assert "Unknown provider(s) in --providers: nosuch" in scene.text, scene.text
    for known in ("uv", "pipx", "pip", "nix", "release-download", "apt", "brew"):
        assert known in scene.text, scene.text
    assert scene.calls == [], scene.calls


def test_an_empty_entry_is_a_usage_error(tmp_path, monkeypatch):
    scene = build_scene(monkeypatch, tmp_path)

    run_install(scene, monkeypatch, tmp_path, "--providers", "uv,,pipx")

    assert scene.result.exit_code == 2, scene.text
    assert "no empty entry" in scene.text, scene.text
    assert scene.calls == [], scene.calls


def test_pipx_refuses_a_version_range_naming_the_capability_and_runs_nothing(
    tmp_path, monkeypatch
):
    scene = build_scene(monkeypatch, tmp_path, find_on_path=lambda c: None)

    run_install(scene, monkeypatch, tmp_path, "--providers", "pipx")

    assert scene.result.exit_code == 1, scene.text
    assert scene.calls == [], scene.calls
    text = " ".join(scene.text.split())
    assert (
        "pipx does not support interpreter requests (an interpreter request given "
        "as a version range ('>=3.10,<3.14')" in text
    ), text
    assert "--providers pipx: no permitted provider can install checkov." in text
    assert "no provider outside the list was tried and none was substituted" in text
    assert "REFUSED BY PROVIDER" in text, text


def test_the_first_listed_provider_that_can_serve_wins_and_skips_are_said(
    tmp_path, monkeypatch
):
    scene = build_scene(monkeypatch, tmp_path, find_on_path=lambda c: f"/x/{c}")

    run_install(scene, monkeypatch, tmp_path, "--providers", "pipx,uv")

    assert scene.argvs == [CHECKOV_COMMAND], scene.calls
    assert "Skipped provider pipx for checkov" in scene.text, scene.text
    assert scene.result.exit_code == 0, scene.text


def test_a_listed_ecosystem_installs_from_its_facet_row_and_says_the_caveat(
    tmp_path, monkeypatch
):
    scene = build_scene(monkeypatch, tmp_path, find_on_path=lambda c: f"/x/{c}")

    run_install(scene, monkeypatch, tmp_path, "--providers", "brew")

    assert scene.argvs == [["brew", "install", "checkov"]], scene.calls
    assert "Homebrew installs the version its formula carries" in scene.text


def test_the_list_is_a_permission_boundary_a_pinned_install_is_not_run_under_uv_only(
    tmp_path, monkeypatch
):
    pinned = create_pinned_tool_install_command(
        "grype", "linux", "amd64", str(tmp_path / "bin")
    )
    scene = build_scene(
        monkeypatch,
        tmp_path,
        name="grype",
        command="grype",
        uv_managed=False,
        declared=[pinned],
        find_on_path=lambda c: None,
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "uv")

    assert scene.calls == [], scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert "uv does not support python tool installs" in " ".join(scene.text.split())


def test_release_download_listed_runs_the_pinned_install_as_declared(
    tmp_path, monkeypatch
):
    pinned = create_pinned_tool_install_command(
        "grype", "linux", "amd64", str(tmp_path / "bin")
    )
    scene = build_scene(
        monkeypatch,
        tmp_path,
        name="grype",
        command="grype",
        uv_managed=False,
        declared=[pinned],
        find_on_path=lambda c: f"/x/{c}",
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "release-download,brew")

    assert scene.argvs == [list(pinned.args)], scene.calls
    assert scene.result.exit_code == 0, scene.text


def test_a_declared_stub_provider_refuses_as_not_implemented(tmp_path, monkeypatch):
    scene = build_scene(monkeypatch, tmp_path, find_on_path=lambda c: None)

    run_install(scene, monkeypatch, tmp_path, "--providers", "cargo")

    assert scene.calls == [], scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert "cargo is not implemented" in " ".join(scene.text.split())


#: The rules bundle cfn-guard declares beside its binary.
_RULES_BUNDLE = "aws-guard-rules-registry"


def _cfn_guard_scene(tmp_path, monkeypatch, *, on_run=None):
    """A scene with cfn-guard's two declared commands, in their declared order.

    The pinned binary download, then the pinned rules-bundle install, as
    ``CfnGuardScanner.setup_custom_install_commands`` declares them. The
    already-present check answers "not present", so each command reaches the
    recorder whatever this host has installed; the recorder runs nothing, and
    nothing is downloaded.
    """
    pinned = create_pinned_tool_install_command(
        "cfn-guard", "linux", "amd64", str(tmp_path / "bin")
    )
    rules = create_rules_bundle_install_command(_RULES_BUNDLE)
    scene = build_scene(
        monkeypatch,
        tmp_path,
        name="cfn-guard",
        command="cfn-guard",
        uv_managed=False,
        declared=[pinned, rules],
        find_on_path=lambda c: f"/x/{c}",
        on_run=on_run,
    )
    monkeypatch.setattr(
        dependencies_module, "pinned_install_already_satisfied", lambda *_a, **_k: None
    )
    return scene, list(pinned.args), list(rules.args)


@pytest.mark.parametrize(
    "providers",
    ["release-download", "release-download,custom"],
    ids=["release-download", "release-download-then-custom"],
)
def test_release_download_runs_cfn_guards_rules_bundle_install_as_declared(
    tmp_path, monkeypatch, providers
):
    """The rules-bundle install is a pinned release download of its own.

    It runs as declared. It is not rebuilt from its tool's name as a second download
    of the cfn-guard binary, which left the bundle uninstalled while the run reported
    success. With custom listed after release-download the result is the same:
    release-download is tried first and serves both commands.
    """
    scene, pinned, rules = _cfn_guard_scene(tmp_path, monkeypatch)

    run_install(scene, monkeypatch, tmp_path, "--providers", providers)

    assert scene.argvs == [pinned, rules], scene.calls
    assert scene.result.exit_code == 0, scene.text


def test_release_download_fails_the_run_when_the_rules_bundle_install_fails(
    tmp_path, monkeypatch
):
    """A failed rules-bundle install fails the run: no "Installation Complete" and
    exit 0 while the bundle a scan of a template needs is absent."""
    rules_argv = list(create_rules_bundle_install_command(_RULES_BUNDLE).args)
    scene, _pinned, rules = _cfn_guard_scene(
        tmp_path, monkeypatch, on_run=lambda argv: 1 if argv == rules_argv else 0
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "release-download")

    assert rules in scene.argvs, scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert "Installation Complete" not in scene.text, scene.text


def test_without_providers_cfn_guards_two_commands_run_as_declared(
    tmp_path, monkeypatch
):
    """The default run is unchanged: each command is built by its own provider."""
    scene, pinned, rules = _cfn_guard_scene(tmp_path, monkeypatch)

    run_install(scene, monkeypatch, tmp_path)

    assert scene.argvs == [pinned, rules], scene.calls
    assert scene.result.exit_code == 0, scene.text
    assert "Skipped provider" not in scene.text, scene.text
