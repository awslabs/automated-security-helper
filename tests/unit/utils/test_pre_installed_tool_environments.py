# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pre-installed tool check judges the environment the copy really has.

Each test pins one change in ``utils/pre_installed_tool.py``:

* a Nix program wrapped more than once is followed through every ``exec`` hop;
* the Nix metadata staging keeps one distribution per name, so two versions of
  one distribution on the closure's path list are not both handed to uv;
* the dry run passes ``--break-system-packages``, so a tool installed into an
  externally managed system interpreter can be judged;
* a copy installed in the user site is "unverifiable", not "unsatisfied";
* the validated form of the version constraint builds the requirement;
* the memo key carries the uv that judged, so a verdict made with one uv is
  not served to a caller passing another;
* the sandbox-refusal verdict carries a summary naming its cause.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import pre_installed_tool
from automated_security_helper.utils.pre_installed_tool import (
    _dry_run,
    _stage_nix_metadata,
    find_nix_python_environment,
    reset_pre_installed_tool_cache,
    verify_pre_installed_tool,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bits"),
]


@pytest.fixture(autouse=True)
def _fresh_verdicts():
    reset_pre_installed_tool_cache()
    yield
    reset_pre_installed_tool_cache()


def _executable(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _wrapped_program(tmp_path: Path) -> Path:
    """The script nixpkgs' wrapPythonPrograms writes: a shebang and the addsitedir line."""
    site = tmp_path / "store" / "site-packages"
    site.mkdir(parents=True)
    return _executable(
        tmp_path / "store" / ".checkov-wrapped",
        (
            f"#!{sys.executable}\n"
            f"import sys; import site; site.addsitedir(p, k), ['{site}']\n"
        ).encode(),
    )


class TestNixWrappersAreFollowedThroughEveryHop:
    def test_a_twice_wrapped_program_is_recognized(self, tmp_path):
        wrapped = _wrapped_program(tmp_path)
        inner = _executable(
            tmp_path / "store" / "bin" / ".checkov-wrapped-inner",
            f'#!/bin/sh\nexec -a "$0" "{wrapped}" "$@"\n'.encode(),
        )
        outer = _executable(
            tmp_path / "bin" / "checkov",
            f'#!/bin/sh\nexport FOO=1\nexec -a "$0" "{inner}" "$@"\n'.encode(),
        )
        found = find_nix_python_environment(str(outer))
        assert found is not None
        interpreter, site_dirs = found
        assert interpreter == sys.executable
        assert len(site_dirs) == 1

    def test_a_singly_wrapped_program_still_is(self, tmp_path):
        """The control."""
        wrapped = _wrapped_program(tmp_path)
        outer = _executable(
            tmp_path / "bin" / "checkov",
            f'#!/bin/sh\nexec -a "$0" "{wrapped}" "$@"\n'.encode(),
        )
        assert find_nix_python_environment(str(outer)) is not None

    def test_two_scripts_that_exec_each_other_end(self, tmp_path):
        first = tmp_path / "bin" / "a"
        second = tmp_path / "bin" / "b"
        _executable(first, f'#!/bin/sh\nexec -a "$0" "{second}" "$@"\n'.encode())
        _executable(second, f'#!/bin/sh\nexec -a "$0" "{first}" "$@"\n'.encode())
        assert find_nix_python_environment(str(first)) is None


class TestNixMetadataIsStagedOncePerDistribution:
    def test_two_versions_of_one_distribution_stage_the_first(self, tmp_path):
        first = tmp_path / "site-a"
        second = tmp_path / "site-b"
        for site, dist_info in (
            (first, "Foo_Bar-1.0.dist-info"),
            (second, "foo-bar-2.0.dist-info"),
        ):
            (site / dist_info).mkdir(parents=True)
            (site / dist_info / "METADATA").write_text("Name: foo-bar\n")
        target = tmp_path / "staged"
        target.mkdir()
        assert _stage_nix_metadata([str(first), str(second)], target) == 1
        assert [p.name for p in target.iterdir()] == ["Foo_Bar-1.0.dist-info"]

    def test_two_distributions_both_stage(self, tmp_path):
        """The control. Two distributions are two METADATA ``Name`` headers: the
        staging keys on the header, not the directory stem, so a control whose
        two headers both said ``x`` described one distribution twice."""
        site = tmp_path / "site"
        for name in ("a", "b"):
            dist_info = site / f"{name}-1.0.dist-info"
            dist_info.mkdir(parents=True)
            (dist_info / "METADATA").write_text(f"Name: {name}\n")
        target = tmp_path / "staged"
        target.mkdir()
        assert _stage_nix_metadata([str(site)], target) == 2

    def test_two_directories_naming_one_distribution_stage_once(self, tmp_path):
        """The shape the old control had: two dist-info directories whose
        METADATA both name ``x`` are one distribution under two stems."""
        site = tmp_path / "site"
        for stem in ("a-1.0.dist-info", "b-1.0.dist-info"):
            (site / stem).mkdir(parents=True)
            (site / stem / "METADATA").write_text("Name: x\n")
        target = tmp_path / "staged"
        target.mkdir()
        assert _stage_nix_metadata([str(site)], target) == 1


def test_the_dry_run_may_judge_an_externally_managed_interpreter(monkeypatch):
    seen: list = []

    def _run(command, timeout):
        seen.append(command)
        return pre_installed_tool._ProbeFailure("not run")

    monkeypatch.setattr(pre_installed_tool, "_run", _run)
    _dry_run("/opt/uv", "/usr/bin/python3", "bandit>=1")
    assert seen and "--break-system-packages" in seen[0]
    assert seen[0].index("--break-system-packages") < seen[0].index("--python")


class TestAUserSiteInstallIsUnverifiable:
    def test_the_copy_in_the_user_scripts_directory(self, tmp_path, monkeypatch):
        import sysconfig

        scripts = tmp_path / "user" / "bin"
        tool = _executable(
            scripts / "bandit", f"#!{sys.executable}\nprint('bandit 1.7.0')\n".encode()
        )
        real_get_path = sysconfig.get_path

        def _get_path(name, scheme=None, *args, **kwargs):
            if name == "scripts" and scheme and scheme.endswith("_user"):
                return str(scripts)
            if scheme is None:
                return real_get_path(name, *args, **kwargs)
            return real_get_path(name, scheme, *args, **kwargs)

        monkeypatch.setattr(sysconfig, "get_path", _get_path)
        # The --version probe answers; a dry run of uv must never be asked for.
        import subprocess  # nosec B404

        def _run(command, timeout):
            if command[0] == str(tool):
                return subprocess.CompletedProcess(command, 0, "bandit 1.7.0\n", "")
            pytest.fail(f"unexpected run: {command}")

        monkeypatch.setattr(pre_installed_tool, "_run", _run)
        verdict = verify_pre_installed_tool(
            str(tool), "bandit", ["sarif"], ">=1.7", uv_executable="/opt/uv"
        )
        assert verdict.status == "unverifiable"
        assert "user site" in verdict.detail
        assert verdict.summary


class TestTheRequirementAndTheMemo:
    def test_the_validated_constraint_builds_the_requirement(
        self, tmp_path, monkeypatch
    ):
        tool = _executable(
            tmp_path / "bin" / "bandit", f"#!{sys.executable}\nprint('1')\n".encode()
        )
        seen: list = []

        def _verify(executable, package, extras, constraint, requirement, uv, values):
            seen.append((constraint, requirement))
            return pre_installed_tool.PreInstalledToolVerdict(
                "satisfied", executable, requirement, ""
            )

        monkeypatch.setattr(pre_installed_tool, "_verify", _verify)
        verdict = verify_pre_installed_tool(
            str(tool), "bandit", None, ">= 1.7.0, ", uv_executable="/opt/uv"
        )
        assert seen == [(">=1.7.0", "bandit>=1.7.0")]
        assert verdict.requirement == "bandit>=1.7.0"

    def test_a_verdict_made_with_one_uv_is_not_served_for_another(
        self, tmp_path, monkeypatch
    ):
        tool = _executable(
            tmp_path / "bin" / "bandit", f"#!{sys.executable}\nprint('1')\n".encode()
        )
        probes: list = []

        def _verify(executable, package, extras, constraint, requirement, uv, values):
            probes.append(uv)
            return pre_installed_tool.PreInstalledToolVerdict(
                "satisfied", executable, requirement, ""
            )

        monkeypatch.setattr(pre_installed_tool, "_verify", _verify)
        verify_pre_installed_tool(str(tool), "bandit", uv_executable="/opt/uv-a")
        verify_pre_installed_tool(str(tool), "bandit", uv_executable="/opt/uv-b")
        verify_pre_installed_tool(str(tool), "bandit", uv_executable="/opt/uv-a")
        assert probes == ["/opt/uv-a", "/opt/uv-b"]


def test_the_sandbox_refusal_names_its_cause_in_the_summary(tmp_path, monkeypatch):
    from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

    tool = _executable(
        tmp_path / "bin" / "bandit", f"#!{sys.executable}\nprint('1')\n".encode()
    )

    def _verify(*args, **kwargs):
        raise SandboxUnavailable("the scope refused")

    monkeypatch.setattr(pre_installed_tool, "_verify", _verify)
    verdict = verify_pre_installed_tool(str(tool), "bandit", uv_executable="/opt/uv")
    assert verdict.status == "unverifiable"
    assert verdict.summary == "the scanner sandbox refused the check"
