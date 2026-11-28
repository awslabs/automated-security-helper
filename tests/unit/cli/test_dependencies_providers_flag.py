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

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.utils import download_utils
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


#: A configured opengrep version other than the one ASH pins, so the scanner declares
#: commands of its own for it rather than the pinned download.
_UNPINNED_OPENGREP = "v2.1.0"


def _opengrep_refusal(test_plugin_context, target_platform, arch, sha256):
    """The one command opengrep declares for ``target_platform``/``arch``.

    Built by ``OpengrepScanner`` itself, from a configured version other than the
    pinned one and the digests in ``sha256``. Where none can be checked (no digest
    for the pair, or a 2.x version on windows/amd64, whose asset is a zip, with or
    without one) it is a refusal: it writes why to stderr and exits 1.
    """
    options = OpengrepScannerConfigOptions(version=_UNPINNED_OPENGREP, sha256=sha256)
    scanner = OpengrepScanner(
        context=test_plugin_context, config=OpengrepScannerConfig(options=options)
    )
    [command] = scanner.custom_install_commands[target_platform][arch]
    return command


def _refusal_scene(tmp_path, monkeypatch, refusal, *, tool, pinned_present=False):
    """A scene whose one plugin, for ``tool``, declares ``refusal`` and nothing else.

    The recorder answers the refusal with the exit code its child would give, 1, and
    any other command with 0. ``pinned_present`` stands for a verified copy of the
    pinned ``tool`` already on disk. Only the disk lookup behind the already-present
    check is answered, so the check still judges a command by its exact shape and
    answers None for anything but the pinned download itself.
    """
    argv = list(refusal.args)
    scene = build_scene(
        monkeypatch,
        tmp_path,
        name=tool,
        command=tool,
        uv_managed=False,
        declared=[refusal],
        find_on_path=lambda c: f"/x/{c}",
        on_run=lambda ran: 1 if ran == argv else 0,
    )
    present = download_utils.VerifiedPresentTool(
        tool=tool, version="pinned", path=tmp_path / "bin" / tool, sha256="0" * 64
    )
    monkeypatch.setattr(
        download_utils,
        "find_verified_pinned_executable",
        lambda *_a, **_k: present if pinned_present else None,
    )
    return scene, argv


@pytest.mark.parametrize(
    "target_platform,arch,sha256,pinned_present",
    [
        ("linux", "amd64", {}, False),
        ("linux", "amd64", {}, True),
        ("windows", "amd64", {"windows/amd64": "a" * 64}, False),
        ("windows", "amd64", {"windows/amd64": "a" * 64}, True),
    ],
    ids=[
        "unverified-version",
        "unverified-version-pinned-copy-present",
        "windows-zip-with-digest",
        "windows-zip-with-digest-pinned-copy-present",
    ],
)
def test_release_download_runs_opengreps_refusal_as_declared(
    tmp_path,
    monkeypatch,
    test_plugin_context,
    target_platform,
    arch,
    sha256,
    pinned_present,
):
    """opengrep's refusal of a version ASH cannot verify fails the run.

    It runs as declared, exits 1, and the row reads FAILED, whether or not a
    verified copy of the pinned opengrep is already on disk. It is not rebuilt from
    its tool's name as the download of ASH's pinned opengrep, which installed a
    version the configuration did not name, or skipped the pinned copy as already
    present, and read INSTALLED or VERIFIED PRESENT with exit 0. The windows/amd64
    case configures a digest, so a version-and-digest pin is refused too.
    """
    refusal = _opengrep_refusal(test_plugin_context, target_platform, arch, sha256)
    scene, argv = _refusal_scene(
        tmp_path, monkeypatch, refusal, tool="opengrep", pinned_present=pinned_present
    )

    run_install(scene, monkeypatch, tmp_path, "--providers", "release-download")

    assert scene.argvs == [argv], scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert "FAILED" in scene.text, scene.text
    assert "INSTALLED" not in scene.text, scene.text
    assert "VERIFIED PRESENT" not in scene.text, scene.text
    assert "Installation Complete" not in scene.text, scene.text


@pytest.mark.parametrize(
    "providers",
    [None, "release-download", "release-download,custom"],
    ids=["default", "release-download", "release-download-then-custom"],
)
def test_the_no_bin_directory_refusal_runs_as_declared_on_every_route(
    tmp_path, monkeypatch, providers
):
    """With no bin directory a pinned tool's command only refuses, on every route.

    ``ash dependencies install`` runs it, counts it as failed and shows why, by
    default and under release-download alike. It is not rebuilt as the pinned
    download into this run's bin directory. An install run sets its bin directory
    before it builds any plugin, so the refusal reaches the installer only from a
    plugin built without one.
    """
    refusal = download_utils.refusing_install_command(download_utils.NO_BIN_DIRECTORY)
    scene, argv = _refusal_scene(tmp_path, monkeypatch, refusal, tool="grype")
    flags = () if providers is None else ("--providers", providers)

    run_install(scene, monkeypatch, tmp_path, *flags)

    assert scene.argvs == [argv], scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert "FAILED" in scene.text, scene.text
    assert "Installation Complete" not in scene.text, scene.text


def test_release_download_still_refuses_a_command_of_a_tool_it_cannot_download(
    tmp_path, monkeypatch
):
    """A tool with no pinned download is not served, whatever its command does.

    cfn-nag declares the same refusal when it has no bin directory. release-download
    refuses it, as it refuses every command of a tool it has no pinned download for,
    and nothing runs.
    """
    refusal = download_utils.refusing_install_command(download_utils.NO_BIN_DIRECTORY)
    scene, _argv = _refusal_scene(tmp_path, monkeypatch, refusal, tool="cfn_nag_scan")

    run_install(scene, monkeypatch, tmp_path, "--providers", "release-download")

    assert scene.calls == [], scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert "REFUSED BY PROVIDER" in scene.text, scene.text
    assert "has no pinned release asset" in " ".join(scene.text.split()), scene.text


#: A plugin's own install command, run through the shell: the shape a plugin from
#: outside ASH may declare. The recorder runs nothing.
_OWN_SHELL_INSTALL = "curl -fsSL https://vendor.example/install.sh | sh"


def _own_command_scene(tmp_path, monkeypatch):
    """A scene whose one plugin, for gitleaks, declares a shell command of its own.

    gitleaks has a pinned release download on every platform pair ASH pins, so
    which provider serves the command does not depend on this host.
    """
    own = CustomCommand(args=[_OWN_SHELL_INSTALL], shell=True)
    scene = build_scene(
        monkeypatch,
        tmp_path,
        name="gitleaks",
        command="gitleaks",
        uv_managed=False,
        declared=[own],
        find_on_path=lambda c: f"/x/{c}",
    )
    return scene, list(own.args)


def test_release_download_refuses_a_plugins_own_shell_command(tmp_path, monkeypatch):
    """Only the listed providers may install anything.

    release-download installs ASH's pinned, digest-verified downloads. A plugin's
    own shell or download command is what the custom provider runs, so with only
    release-download listed it is refused, with a reason that names custom, and
    nothing runs.
    """
    scene, _own = _own_command_scene(tmp_path, monkeypatch)

    run_install(scene, monkeypatch, tmp_path, "--providers", "release-download")

    assert scene.calls == [], scene.calls
    assert scene.result.exit_code == 1, scene.text
    assert "REFUSED BY PROVIDER" in scene.text, scene.text
    text = " ".join(scene.text.split())
    assert "release-download does not support custom install commands" in text, text
    assert "list custom to run it as declared" in text, text


def test_with_custom_listed_a_plugins_own_shell_command_runs_through_custom(
    tmp_path, monkeypatch
):
    """With custom listed after release-download, custom runs the command.

    release-download is tried first and skipped with its reason; custom runs the
    command as declared, through the shell.
    """
    scene, own = _own_command_scene(tmp_path, monkeypatch)

    run_install(scene, monkeypatch, tmp_path, "--providers", "release-download,custom")

    assert scene.calls == [(own, True)], scene.calls
    text = " ".join(scene.text.split())
    assert "Skipped provider release-download for gitleaks:" in text, text
    assert "list custom to run it as declared" in text, text
    assert scene.result.exit_code == 0, scene.text
