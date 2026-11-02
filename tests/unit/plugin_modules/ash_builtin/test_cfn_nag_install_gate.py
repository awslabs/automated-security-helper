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

pytestmark = pytest.mark.unit

_SCANNER = (
    "automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner"
)
GEM_PROBE = f"{_SCANNER}.find_executable"
PLATFORM_PROBE = f"{_SCANNER}.platform.system"
HEADERS_PROBE = f"{_SCANNER}._ruby_headers_present"


@pytest.fixture
def context(tmp_path: Path) -> PluginContext:
    output_dir = tmp_path / "out"
    return PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "converted",
        config=get_default_config(),
    )


def _commands(context, *, gem=None, compiler=None, system="Linux", headers=True):
    """Build a scanner with `gem` and a C compiler each present or absent.

    ``headers`` pins the Ruby development-headers probe (``ruby.h`` beside the
    ``ruby`` on PATH), which otherwise reads the real filesystem of whatever host
    runs the tests: a Linux runner with a ruby but no ruby-dev package would declare
    no install command and fail every positive case here for a reason that is not
    the gate under test.

    ``system`` is pinned rather than inherited, and that is load-bearing rather than
    tidiness. The gate branches on the host platform: Windows keys on RI_DEVKIT and
    ignores the compiler entirely. Without this patch these tests asserted the POSIX
    branch while running on whatever the runner happened to be -- and `unit-test` runs
    on windows-latest across four Python versions. Measured with platform.system()
    forced to Windows and RI_DEVKIT unset: test_gem_present_declares_the_pinned_install
    failed with `assert 0 == 1` and test_the_pinned_version_... raised IndexError. With
    RI_DEVKIT set instead, test_no_compiler_means_no_install_command fails. At least
    one fails either way, so the break did not depend on the runner's environment.
    """

    def probe(command):
        if command == "gem":
            return gem
        if command in ("cc", "gcc", "clang"):
            return compiler
        return f"/usr/bin/{command}"

    with (
        patch(GEM_PROBE, side_effect=probe),
        patch(PLATFORM_PROBE, return_value=system),
        patch(HEADERS_PROBE, return_value=headers),
    ):
        scanner = CfnNagScanner(context=context)
    return scanner.get_installation_commands("linux", "amd64")


def test_missing_ruby_headers_on_linux_declare_no_install_command(context):
    """gem and a compiler present, ruby.h absent: psych's extension cannot build.

    A Linux host with ruby but no ruby-dev package passes the gem and compiler
    probes and then fails inside psych's extconf on the missing header, which would
    fail `ash dependencies install` for every scanner at once. The gate declares
    nothing instead, and its warning names the headers.
    """
    assert (
        _commands(context, gem="/usr/bin/gem", compiler="/usr/bin/cc", headers=False)
        == []
    )


def _headers_probe(tmp_path: Path, layout: str) -> bool:
    """``_ruby_headers_present`` against a fake ruby under ``tmp_path/prefix``.

    ``layout``: ``versioned`` (Debian: include/ruby-3.3.0/ruby.h), ``flat``
    (Fedora, RHEL, Amazon Linux: include/ruby.h), ``no-header`` (an include
    directory with no ruby.h: the dev package is missing) or ``shim`` (no include
    directory at all: a version manager's shim on PATH).
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cfn_nag_scanner,
    )

    prefix = tmp_path / "prefix"
    (prefix / "bin").mkdir(parents=True)
    ruby = prefix / "bin" / "ruby"
    ruby.write_text("#!/bin/sh\n", encoding="utf-8")
    if layout == "versioned":
        (prefix / "include" / "ruby-3.3.0").mkdir(parents=True)
        (prefix / "include" / "ruby-3.3.0" / "ruby.h").write_text("", encoding="utf-8")
    elif layout == "flat":
        (prefix / "include").mkdir()
        (prefix / "include" / "ruby.h").write_text("", encoding="utf-8")
    elif layout == "no-header":
        (prefix / "include").mkdir()
    # A system include directory that holds nothing, so only the prefix decides.
    system_include = tmp_path / "system-include"
    system_include.mkdir()
    with patch(GEM_PROBE, return_value=str(ruby)):
        return cfn_nag_scanner._ruby_headers_present(system_include=system_include)


@pytest.mark.parametrize(
    "layout, present",
    [
        pytest.param("versioned", True, id="debian-versioned-dir"),
        pytest.param("flat", True, id="fedora-flat-ruby-h"),
        pytest.param("no-header", False, id="dev-package-missing"),
        pytest.param("shim", True, id="version-manager-shim-undecided"),
    ],
)
def test_the_headers_probe_reads_both_layouts_and_is_undecided_for_a_shim(
    tmp_path, layout, present
):
    """At the base only ``include/ruby-*/ruby.h`` counted, so a Fedora-style
    ``include/ruby.h`` and an rbenv shim both read as headers missing and cfn-nag
    as having no install path on hosts where the install succeeds."""
    assert _headers_probe(tmp_path, layout) is present


def test_no_gem_means_no_install_command(context):
    """Absent RubyGems must yield zero commands, not a command that fails.

    Zero commands is what routes cfn-nag to "no install path on this platform" in
    the installer's report -- named, alongside npm-audit, and not fatal to the rest
    of the run.
    """
    assert _commands(context, gem=None, compiler="/usr/bin/cc") == []


def test_windows_without_a_devkit_declares_nothing(context, monkeypatch):
    """On Windows the marker is RI_DEVKIT, not a compiler on PATH.

    Measured, and it corrected a first attempt. Probing for cc/gcc/clang passed on
    windows-latest -- that image has a gcc reachable -- so the gem install ran anyway
    and still died with "Failed to build gem native extension", because Ruby's mkmf
    needs a toolchain matching its own x64-mingw-ucrt ABI rather than any gcc.
    RI_DEVKIT is what RubyInstaller's devkit and ruby/setup-ruby export, so it is the
    variable that actually tracks whether a gem can be built.
    """
    monkeypatch.delenv("RI_DEVKIT", raising=False)
    # A compiler IS reachable, which is exactly the windows-latest situation.
    assert (
        _commands(
            context,
            gem="C:/Ruby/bin/gem",
            compiler="C:/mingw/bin/gcc",
            system="Windows",
        )
        == []
    )

    monkeypatch.setenv("RI_DEVKIT", "C:/Ruby/msys64")
    assert (
        len(_commands(context, gem="C:/Ruby/bin/gem", compiler=None, system="Windows"))
        == 1
    )


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


def test_without_a_bin_directory_the_command_only_refuses(context, monkeypatch):
    """No absolute ASH_BIN_PATH and no usable home directory: no --bindir to give.

    The command says why and exits 1, rather than naming a directory under the
    working directory or the text "None".
    """
    from automated_security_helper.utils import download_utils

    monkeypatch.setattr(download_utils, "ASH_BIN_PATH", None)
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)

    commands = _commands(context, gem="/usr/bin/gem", compiler="/usr/bin/cc")

    assert len(commands) == 1
    assert commands[0][2] == "import sys; sys.exit(sys.argv[1])", commands[0]
    assert "--bin-path" in commands[0][3]


def test_the_pinned_version_is_the_one_the_gemfile_declares(context):
    """One version, one source of truth.

    A gem version drifting from assets/Gemfile would mean the container and a local
    install run different cfn-nag builds while both look correct.
    """
    from automated_security_helper.utils.tool_downloads import CFN_NAG_GEM_VERSION

    gemfile = (
        Path(__file__).parents[4] / "automated_security_helper" / "assets" / "Gemfile"
    ).read_text(encoding="utf-8")
    assert f'"{CFN_NAG_GEM_VERSION}"' in gemfile, (
        f"CFN_NAG_GEM_VERSION is {CFN_NAG_GEM_VERSION} but assets/Gemfile pins "
        "something else"
    )
    assert (
        CFN_NAG_GEM_VERSION
        in _commands(context, gem="/usr/bin/gem", compiler="/usr/bin/cc")[0]
    )
