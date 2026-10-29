# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_workspace_policy.py: the fixture and the child-run wrapper.

The script is its own gate; these tests pin the parts of it that a real scan
cannot show going wrong without a scanner on the host:

* the ceiling run suppresses a file the lax project's actionable count does not
  depend on, so a correct implementation of workspace suppressions cannot make
  the ceiling assertions fail;
* the scan child runs under a scrubbed environment, with a timeout, decoded as
  UTF-8;
* a failed positive control ends the run as a broken fixture, exit 3, before any
  policy verdict is printed;
* the recorded policy path is compared to the expected one as a file, not as
  text, so a temporary directory behind a symlink is not a failure.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def policy_script(script_loader):
    return script_loader("verify_workspace_policy")


class TestFixtureShape:
    def test_lax_has_a_second_source_file_carrying_the_same_finding(
        self, policy_script, tmp_path: Path
    ):
        policy_script.build_fixture(tmp_path)
        lax_sources = sorted(p.name for p in (tmp_path / "lax" / "src").iterdir())
        assert lax_sources == sorted(["runner.py", policy_script.LAX_SUPPRESSED_FILE])
        suppressed = tmp_path / "lax" / "src" / policy_script.LAX_SUPPRESSED_FILE
        assert suppressed.read_text(encoding="utf-8") == policy_script.LAX_SOURCE

    def test_the_suppressed_path_is_not_the_lax_projects_only_source(
        self, policy_script, tmp_path: Path
    ):
        """The ceiling assertions read runner.py; the policy must not suppress it."""
        policy_script.build_fixture(tmp_path)
        suppressed = tmp_path / policy_script.LAX_SUPPRESSED_WORKSPACE_PATH
        assert suppressed.is_file()
        assert suppressed.name != "runner.py"
        remaining = [p for p in (tmp_path / "lax" / "src").iterdir() if p != suppressed]
        assert remaining, "suppressing the file would leave lax with no finding"
        assert policy_script.LAX_SUPPRESSED_PROJECT_PATH == (
            "src/" + policy_script.LAX_SUPPRESSED_FILE
        )


class TestChildEnvironment:
    def test_ash_variables_are_dropped(self, policy_script):
        base = {
            "PATH": "/usr/bin",
            "ASH_CONFIG": "/elsewhere/ash.yaml",
            "ASH_EXCLUDED_SCANNERS": "bandit",
            "ASH_WORKSPACE_CONFIG": "/elsewhere/policy.yaml",
            "ASHY": "kept: not an ASH_ option",
        }
        env = policy_script.child_environment(base)
        assert not [key for key in env if key.startswith("ASH_")]
        assert env["PATH"] == "/usr/bin"
        assert env["ASHY"] == "kept: not an ASH_ option"
        assert env["PYTHONIOENCODING"] == "utf-8"
        assert env["PYTHONUTF8"] == "1"
        assert (
            Path(env["PYTHONPATH"]) == Path(policy_script.__file__).resolve().parents[1]
        )

    def test_run_ash_scrubs_the_environment_decodes_utf8_and_times_out(
        self, policy_script, tmp_path: Path, monkeypatch
    ):
        recorded: dict = {}

        def fake_run(argv, **kwargs):
            recorded["argv"] = argv
            recorded.update(kwargs)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setenv("ASH_EXCLUDED_SCANNERS", "bandit")
        monkeypatch.setattr(policy_script.subprocess, "run", fake_run)
        code, payload, output = policy_script.run_ash(
            tmp_path / "ws.code-workspace", tmp_path / "out", timeout=17.5
        )
        assert (code, payload, output) == (0, {}, "")
        assert "ASH_EXCLUDED_SCANNERS" not in recorded["env"]
        assert recorded["encoding"] == "utf-8"
        assert recorded["errors"] == "replace"
        assert recorded["timeout"] == 17.5
        assert "text" not in recorded


class TestSameFile:
    def test_a_symlinked_parent_still_names_the_same_file(
        self, policy_script, tmp_path: Path
    ):
        real = tmp_path / "real"
        real.mkdir()
        policy = real / "policy.yaml"
        policy.write_text("workspace: {}\n", encoding="utf-8")
        link = tmp_path / "link"
        try:
            os.symlink(real, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        recorded = (link / "policy.yaml").as_posix()
        assert recorded != policy.resolve().as_posix()
        assert policy_script.same_file(recorded, policy)

    def test_a_different_file_is_not_the_same(self, policy_script, tmp_path: Path):
        (tmp_path / "a.yaml").write_text("", encoding="utf-8")
        (tmp_path / "b.yaml").write_text("", encoding="utf-8")
        assert not policy_script.same_file(
            (tmp_path / "a.yaml").as_posix(), tmp_path / "b.yaml"
        )
        assert not policy_script.same_file(None, tmp_path / "b.yaml")


def _payload(**projects):
    return {
        "projects": [dict(project=name, **fields) for name, fields in projects.items()]
    }


@pytest.fixture
def scratch_under_tmp(policy_script, tmp_path: Path, monkeypatch):
    """main() makes its scratch directory under tmp_path, not the system tmp."""

    def mkdtemp(prefix: str = "") -> str:
        scratch = tmp_path / f"{prefix}scratch"
        scratch.mkdir()
        return str(scratch)

    monkeypatch.setattr(policy_script.tempfile, "mkdtemp", mkdtemp)
    return tmp_path


class TestFailedControlStopsTheRun:
    def test_a_lax_project_with_no_findings_is_a_broken_fixture(
        self, policy_script, scratch_under_tmp, monkeypatch, capsys
    ):
        calls: list[Path] = []

        def fake_run_ash(workspace, output_dir, policy=None, timeout=None):
            calls.append(output_dir)
            return (
                0,
                _payload(
                    lax={"finding_count": 0, "actionable_finding_count": 0},
                    strict={"finding_count": 1, "actionable_finding_count": 1},
                    iac={"finding_count": 1, "actionable_finding_count": 1},
                ),
                "",
            )

        monkeypatch.setattr(policy_script, "run_ash", fake_run_ash)
        assert policy_script.main([]) == 3
        out = capsys.readouterr().out
        assert "FIXTURE BROKEN" in out
        assert "ceiling tightens" not in out
        assert [p.name for p in calls] == ["out-a"]

    def test_a_timed_out_scan_is_reported_not_hung(
        self, policy_script, scratch_under_tmp, monkeypatch, capsys
    ):
        def fake_run_ash(workspace, output_dir, policy=None, timeout=None):
            raise subprocess.TimeoutExpired(
                cmd=["ash"], timeout=timeout, output=b"partial", stderr=None
            )

        monkeypatch.setattr(policy_script, "run_ash", fake_run_ash)
        assert policy_script.main(["--timeout", "5"]) == 3
        out = capsys.readouterr().out
        assert "did not finish within 5 seconds" in out
        assert "partial" in out
