"""Tests for Nix mode.

The properties worth pinning here are the ones whose failure is silent. A forwarded
argument that gets dropped, a recursion guard that is set but never read, or a fallback to
local mode when Nix is absent all produce a scan that looks like it worked. Each of those
gets an explicit test rather than being left to an end-to-end run to notice.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_nix import (
    ASH_IN_NIX_ENV_VAR,
    ASH_NIX_FLAKE_REF_ENV_VAR,
    build_nix_command,
    resolve_flake_ref,
    rewrite_mode_args,
    run_ash_nix,
)


class TestRunModeEnum:
    def test_nix_is_a_run_mode(self):
        assert RunMode.nix.value == "nix"

    def test_nix_round_trips_through_its_value(self):
        # Config files carry the string, so a mismatch here would make `mode: nix` in a
        # config silently fail to select the mode.
        assert RunMode("nix") is RunMode.nix


class TestRewriteModeArgs:
    def test_two_token_form_becomes_local(self):
        assert rewrite_mode_args(["scan", "--mode", "nix"]) == [
            "scan",
            "--mode",
            "local",
        ]

    def test_equals_form_becomes_local(self):
        assert rewrite_mode_args(["scan", "--mode=nix"]) == ["scan", "--mode=local"]

    def test_absent_mode_is_appended(self):
        # Nix mode can be selected by config file, leaving no --mode in argv. Without the
        # appended flag the inner scan would read that same config, select nix again and
        # recurse.
        assert rewrite_mode_args(["scan"]) == ["scan", "--mode", "local"]

    def test_other_arguments_survive_verbatim(self):
        # This is the whole reason argv is forwarded rather than rebuilt from parsed
        # options: a rebuild drops whatever it forgets to handle.
        argv = [
            "scan",
            "--source-dir",
            "/src",
            "--output-dir",
            "/out",
            "--mode",
            "nix",
            "--scanners",
            "bandit",
            "--debug",
        ]
        result = rewrite_mode_args(argv)
        assert result == [
            "scan",
            "--source-dir",
            "/src",
            "--output-dir",
            "/out",
            "--mode",
            "local",
            "--scanners",
            "bandit",
            "--debug",
        ]

    def test_mode_value_is_not_mistaken_for_a_flag(self):
        # The two-token branch skips the token after --mode. If that skip were missing the
        # stale value would remain and the inner scan would get "--mode local nix".
        assert "nix" not in rewrite_mode_args(["scan", "--mode", "nix", "--quiet"])


class TestResolveFlakeRef:
    def test_explicit_argument_wins_over_environment(self, monkeypatch):
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "github:someone/else")
        assert resolve_flake_ref("path:/explicit") == "path:/explicit"

    def test_environment_override_is_honored(self, monkeypatch):
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "github:someone/else")
        assert resolve_flake_ref() == "github:someone/else"

    def test_source_checkout_resolves_to_a_path_ref(self, monkeypatch, tmp_path):
        monkeypatch.delenv(ASH_NIX_FLAKE_REF_ENV_VAR, raising=False)
        (tmp_path / "flake.nix").write_text("{}")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix._repo_flake_dir",
            lambda: tmp_path,
        )
        # `path:` matters: a bare path is read as a git tree, so uncommitted edits to
        # flake.nix would be silently ignored.
        assert resolve_flake_ref() == f"path:{tmp_path}"

    def test_falls_back_to_the_published_repo_at_this_version(self, monkeypatch):
        monkeypatch.delenv(ASH_NIX_FLAKE_REF_ENV_VAR, raising=False)
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix._repo_flake_dir",
            lambda: None,
        )
        ref = resolve_flake_ref()
        assert ref.startswith("github:awslabs/automated-security-helper/v")

    def test_fallback_is_version_pinned_not_a_branch(self, monkeypatch):
        # An unpinned ref would make the scanner set unreproducible, which defeats the
        # reason for using a flake at all.
        monkeypatch.delenv(ASH_NIX_FLAKE_REF_ENV_VAR, raising=False)
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix._repo_flake_dir",
            lambda: None,
        )
        from automated_security_helper import __version__

        assert resolve_flake_ref().endswith(f"/v{__version__}")


class TestBuildNixCommand:
    def test_enables_experimental_features_before_the_subcommand(self):
        cmd = build_nix_command("path:/repo", ["scan"], "/usr/bin/nix")
        assert cmd[0] == "/usr/bin/nix"
        assert cmd[1] == "--extra-experimental-features"
        assert "nix-command" in cmd[2] and "flakes" in cmd[2]
        # Both features are off by default on a stock multi-user install, so omitting this
        # makes every first run fail with "experimental Nix feature ... is disabled".
        assert cmd.index("--extra-experimental-features") < cmd.index("develop")

    def test_runs_ash_inside_the_shell_with_the_forwarded_args(self):
        cmd = build_nix_command("path:/repo", ["scan", "--mode", "local"], "nix")
        assert cmd[-4:] == ["ash", "scan", "--mode", "local"]
        assert "--command" in cmd
        assert cmd[cmd.index("--command") + 1] == "ash"

    def test_flake_ref_is_passed_to_develop(self):
        cmd = build_nix_command("github:owner/repo/v1", ["scan"], "nix")
        assert cmd[cmd.index("develop") + 1] == "github:owner/repo/v1"


class TestRunAshNix:
    def test_missing_nix_raises_and_does_not_fall_back(self, monkeypatch):
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: None,
        )
        with pytest.raises(RuntimeError) as excinfo:
            run_ash_nix(argv=["scan"])
        message = str(excinfo.value)
        # The message must say Nix is missing AND that no fallback happened. A silent
        # downgrade to local mode is the exact failure this mode exists to prevent, so the
        # error has to rule it out explicitly rather than just reporting a missing binary.
        assert "not found on PATH" in message
        assert "will not fall back" in message

    def test_recursion_guard_refuses_a_nested_run(self, monkeypatch):
        monkeypatch.setenv(ASH_IN_NIX_ENV_VAR, "1")
        with pytest.raises(RuntimeError, match="already running inside a Nix shell"):
            run_ash_nix(argv=["scan"])

    def test_recursion_guard_accepts_the_documented_truthy_values(self, monkeypatch):
        for value in ["YES", "yes", "1", "TRUE", "true"]:
            monkeypatch.setenv(ASH_IN_NIX_ENV_VAR, value)
            with pytest.raises(RuntimeError, match="already running inside a Nix shell"):
                run_ash_nix(argv=["scan"])

    def test_child_environment_carries_the_guard_and_offline_flag(self, monkeypatch):
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )

        captured = {}

        def fake_run(cmd, env=None, check=None, text=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.subprocess.run",
            fake_run,
        )

        run_ash_nix(argv=["scan", "--mode", "nix"])

        # The guard is what stops the inner run re-entering Nix mode.
        assert captured["env"][ASH_IN_NIX_ENV_VAR] == "1"
        # Without this the scanners that prefer `uv tool install` fetch their own copies
        # and shadow the pinned ones, so the report would describe versions the flake
        # never supplied.
        assert captured["env"]["ASH_OFFLINE"] == "YES"
        # And the inner invocation must be a local scan, not another nix one.
        assert "--mode" in captured["cmd"]
        assert captured["cmd"][captured["cmd"].index("--mode") + 1] == "local"

    def test_nonzero_exit_is_returned_rather_than_raised(self, monkeypatch):
        # A scan that finds something exits non-zero by design. Raising here would turn a
        # working scan into an error.
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.subprocess.run",
            lambda cmd, env=None, check=None, text=None: subprocess.CompletedProcess(
                cmd, 2
            ),
        )
        result = run_ash_nix(argv=["scan"])
        assert result.returncode == 2

    def test_debug_prints_the_assembled_command(self, monkeypatch, capsys):
        # Small, but this is the one thing a user reaches for when Nix mode misbehaves:
        # without the full command echoed, an adopter cannot reproduce the invocation by
        # hand to see what the shell did.
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.subprocess.run",
            lambda cmd, env=None, check=None, text=None: subprocess.CompletedProcess(
                cmd, 0
            ),
        )

        run_ash_nix(argv=["scan"], debug=True)

        printed = capsys.readouterr().out
        assert "develop" in printed
        assert "path:/repo" in printed

    def test_argv_defaults_to_the_process_arguments(self, monkeypatch):
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )
        monkeypatch.setattr(sys, "argv", ["ash", "scan", "--quiet", "--mode", "nix"])

        captured = {}

        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.subprocess.run",
            lambda cmd, env=None, check=None, text=None: captured.update(cmd=cmd)
            or subprocess.CompletedProcess(cmd, 0),
        )

        run_ash_nix()
        # sys.argv[0] is the executable and must not be forwarded as a scan argument.
        assert "ash" == captured["cmd"][captured["cmd"].index("--command") + 1]
        assert "--quiet" in captured["cmd"]


class TestRepoFlakeDir:
    def test_finds_the_flake_in_this_checkout(self):
        # These tests run from a source checkout, which is the case the path: branch
        # exists to serve, so this asserts the parents[2] arithmetic is right. Getting it
        # wrong would send every developer run at the remote flake instead of their edits.
        from automated_security_helper.interactions.run_ash_nix import _repo_flake_dir

        found = _repo_flake_dir()
        assert found is not None, "expected to find flake.nix at the repository root"
        assert (Path(found) / "flake.nix").is_file()
