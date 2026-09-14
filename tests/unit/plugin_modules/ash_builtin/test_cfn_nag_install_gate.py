# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-nag declares its gem install only where RubyGems is actually present.

Why this file exists. cfn-nag is the one scanner ASH provisions through a package
manager rather than a pinned binary download, so it is the only one whose install
command can be *missing its interpreter*. Declaring the command unconditionally
turned that into a much worse failure than an unavailable scanner:
``run_command`` catches ``FileNotFoundError`` and returns 1, a non-zero install
command fails the whole run, and so on any host without Ruby
``ash dependencies install`` exited non-zero for every plugin together, before any
scan. That is reached from ``Dockerfile:253`` and ``:328`` and from both
python-local branches of the scan action.

It was also inconsistent. npm-audit needs a Node runtime ASH does not install,
declares no command, and is reported as a constraint rather than a malfunction.
Same condition, opposite outcome, purely because one plugin declared a command that
could not work and the other declared none.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
)

GEM_PROBE = (
    "automated_security_helper.plugin_modules.ash_builtin.scanners."
    "cfn_nag_scanner.find_executable"
)


@pytest.fixture
def context(tmp_path: Path) -> PluginContext:
    output_dir = tmp_path / "out"
    return PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "converted",
        config=get_default_config(),
    )


def _commands(context, *, gem=None, compiler=None):
    """Build a scanner with `gem` and a C compiler each present or absent."""

    def probe(command):
        if command == "gem":
            return gem
        if command in ("cc", "gcc", "clang"):
            return compiler
        return f"/usr/bin/{command}"

    with patch(GEM_PROBE, side_effect=probe):
        scanner = CfnNagScanner(context=context)
    return scanner.get_installation_commands("linux", "amd64")


def test_no_gem_means_no_install_command(context):
    """Absent RubyGems must yield zero commands, not a command that fails.

    Zero commands is what routes cfn-nag to "no install path on this platform" in
    the installer's report -- named, alongside npm-audit, and not fatal to the rest
    of the run.
    """
    assert _commands(context, gem=None, compiler="/usr/bin/cc") == []


def test_no_compiler_means_no_install_command(context):
    """RubyGems alone is not enough: the closure needs a native build.

    This is the windows-latest case, and it is measured rather than predicted. With
    the gem command declared unconditionally the install reached
    "ERROR: Failed to build gem native extension", returned 1, and failed
    `ash dependencies install` for every scanner at once -- so a Windows job whose
    only command was the installer went red for a constraint that belongs to one
    scanner.
    """
    assert _commands(context, gem="/usr/bin/gem", compiler=None) == []


def test_gem_present_declares_the_pinned_install(context):
    """Positive control.

    Without it, the assertion above would pass just as well if cfn-nag had no
    install path at all, which is the state this whole change exists to end.
    """
    commands = _commands(context, gem="/usr/bin/gem", compiler="/usr/bin/cc")
    assert len(commands) == 1
    argv = commands[0]
    assert argv[:3] == ["gem", "install", "cfn-nag"]
    # --user-install because a stock Linux GEM_HOME is root-owned, and --bindir
    # because ASH looks on PATH and in ASH_BIN_PATH, not in a user gem bin.
    assert "--user-install" in argv
    assert "--bindir" in argv


def test_the_pinned_version_is_the_one_the_gemfile_declares(context):
    """One version, one source of truth.

    A gem version drifting from assets/Gemfile would mean the container and a local
    install run different cfn-nag builds while both look correct.
    """
    from automated_security_helper.utils.tool_downloads import CFN_NAG_GEM_VERSION

    gemfile = (
        Path(__file__).parents[4]
        / "automated_security_helper"
        / "assets"
        / "Gemfile"
    ).read_text(encoding="utf-8")
    assert f'"{CFN_NAG_GEM_VERSION}"' in gemfile, (
        f"CFN_NAG_GEM_VERSION is {CFN_NAG_GEM_VERSION} but assets/Gemfile pins "
        "something else"
    )
    assert CFN_NAG_GEM_VERSION in _commands(
        context, gem="/usr/bin/gem", compiler="/usr/bin/cc"
    )[0]
