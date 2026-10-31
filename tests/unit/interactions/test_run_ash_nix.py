"""Tests for Nix mode.

The properties worth pinning here are the ones whose failure is silent. A forwarded
argument that gets dropped, a recursion guard that is set but never read, or a fallback to
local mode when Nix is absent all produce a scan that looks like it worked. Each of those
gets an explicit test rather than being left to an end-to-end run to notice.
"""

import os
import subprocess
import sys
import types
from pathlib import Path
from urllib.parse import quote

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_nix import (
    ASH_IN_NIX_ENV_VAR,
    ASH_NIX_FLAKE_REF_ENV_VAR,
    OUTER_PYTHONPATH_ENV_VAR,
    build_nix_command,
    resolve_flake_ref,
    rewrite_mode_args,
    run_ash_nix,
    shown_flake_ref,
)


@pytest.mark.unit
class TestRunModeEnum:
    def test_nix_is_a_run_mode(self):
        assert RunMode.nix.value == "nix"

    def test_nix_round_trips_through_its_value(self):
        # Config files carry the string, so a mismatch here would make `mode: nix` in a
        # config silently fail to select the mode.
        assert RunMode("nix") is RunMode.nix


@pytest.mark.unit
class TestRewriteModeArgs:
    def test_two_token_form_becomes_local(self):
        assert rewrite_mode_args(["scan", "--mode", "nix"]) == [
            "scan",
            "--mode",
            "local",
            "--no-show-summary",
        ]

    def test_equals_form_becomes_local(self):
        assert rewrite_mode_args(["scan", "--mode=nix"]) == [
            "scan",
            "--mode=local",
            "--no-show-summary",
        ]

    def test_absent_mode_is_appended(self):
        # Nix mode can be selected by config file, leaving no --mode in argv. Without the
        # appended flag the inner scan would read that same config, select nix again and
        # recurse.
        assert rewrite_mode_args(["scan"]) == [
            "scan",
            "--mode",
            "local",
            "--no-show-summary",
        ]

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
            "--no-show-summary",
        ]

    def test_mode_value_is_not_mistaken_for_a_flag(self):
        # The two-token branch skips the token after --mode. If that skip were missing the
        # stale value would remain and the inner scan would get "--mode local nix".
        assert "nix" not in rewrite_mode_args(["scan", "--mode", "nix", "--quiet"])

    def test_the_inner_scan_prints_no_summary_of_its_own(self):
        # The outer process prints the metrics table and the exit-code legend from the
        # results it reads back, as container mode's does; without this switch the
        # inner scan printed both too and a nix run showed every table twice.
        assert (
            rewrite_mode_args(["scan", "--mode", "nix"]).count("--no-show-summary") == 1
        )
        # Given once already (a library caller's --no-show-summary): not doubled.
        assert (
            rewrite_mode_args(["scan", "--no-show-summary"]).count("--no-show-summary")
            == 1
        )
        # Asked for explicitly: still the outer process's to print. The later of the
        # two spellings wins inside the shell, so the other one is dropped.
        rewritten = rewrite_mode_args(["scan", "--show-summary"])
        assert "--show-summary" not in rewritten
        assert "--no-show-summary" in rewritten

    def test_arguments_after_a_double_dash_are_forwarded_verbatim(self):
        # Everything after a bare `--` is positional, however it is spelled, so a
        # `--mode` there is a value and is neither rewritten nor dropped.
        assert rewrite_mode_args(["scan", "--mode", "nix", "--", "--mode", "x"]) == [
            "scan",
            "--mode",
            "local",
            "--no-show-summary",
            "--",
            "--mode",
            "x",
        ]

    def test_the_local_mode_goes_before_a_double_dash(self):
        # Appended after `--` the switch would be a positional argument, and the inner
        # scan would inherit nix mode from the config and recurse.
        assert rewrite_mode_args(["scan", "--", "target"]) == [
            "scan",
            "--mode",
            "local",
            "--no-show-summary",
            "--",
            "target",
        ]


@pytest.mark.unit
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
        # flake.nix would be silently ignored. The path is percent-encoded as a URL
        # path (below); an ordinary directory name is its own encoding.
        assert resolve_flake_ref() == "path:" + quote(str(tmp_path), safe="/")

    def test_a_checkout_under_a_url_delimiter_is_percent_encoded(
        self, monkeypatch, tmp_path
    ):
        # A `path:` reference is a URL to nix: `#` starts the attribute, `?` the query,
        # and a space is no URL character, so a checkout under a directory named with
        # any of them was misparsed and the shell never opened.
        monkeypatch.delenv(ASH_NIX_FLAKE_REF_ENV_VAR, raising=False)
        checkout = tmp_path / "a #1?b c"
        checkout.mkdir()
        (checkout / "flake.nix").write_text("{}")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix._repo_flake_dir",
            lambda: checkout,
        )

        ref = resolve_flake_ref()

        assert ref.startswith("path:")
        assert "#" not in ref and "?" not in ref and " " not in ref
        assert ref.endswith("/a%20%231%3Fb%20c")

    def test_falls_back_to_the_published_repo_at_this_version(self, monkeypatch):
        monkeypatch.delenv(ASH_NIX_FLAKE_REF_ENV_VAR, raising=False)
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix._repo_flake_dir",
            lambda: None,
        )
        ref = resolve_flake_ref()
        # The repository name is interpolated rather than written inline, and not for
        # style. tests/unit/test_agent_plugin_ash_version.py walks every file in the tree
        # for install references, and it now reads the flake form --
        # `github:<owner>/<repo>/v<version>` -- alongside the `@v` forms, because the
        # installation guide's ASH_NIX_FLAKE_REF override had gone two minor releases
        # stale while every `@v`-anchored mechanism reported the tree clean. The prefix
        # asserted here ends at `/v` with nothing after it, which that walk's loose pin
        # reader classifies as a truncated ref -- one that resolves to nothing -- so
        # written contiguously this assertion is reported as a real defect in the tree.
        #
        # Interpolation rather than a mid-word implicit concatenation: `ruff format` joins
        # adjacent string literals when the result fits the line length, so a split here
        # comes back from the formatter contiguous again. Measured, not assumed.
        #
        # The asserted value is unchanged either way.
        repo = "automated-security-helper"
        assert ref.startswith(f"github:awslabs/{repo}/v")

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


@pytest.mark.unit
class TestShownFlakeRef:
    """The flake reference as the INFO line and the debug command line show it."""

    @pytest.mark.parametrize(
        "ref",
        [
            "path:/repo",
            "github:owner/repo/v1",
            "git+https://host/repo?ref=main",
            "flake-ref",
        ],
    )
    def test_a_reference_without_userinfo_is_shown_as_it_is(self, ref):
        assert shown_flake_ref(ref) == ref

    def test_a_urls_userinfo_is_not_shown(self):
        # A token an operator put in ASH_NIX_FLAKE_REF so nix can fetch the flake is a
        # credential; the line reaches the console and ash.log in the output directory.
        shown = shown_flake_ref("git+https://alice:token-1@host/org/repo?ref=main")
        assert "token-1" not in shown
        assert "alice" not in shown
        assert shown == "git+https://<userinfo>@host/org/repo?ref=main"

    def test_a_token_alone_before_the_host_is_not_shown(self):
        assert shown_flake_ref("git+https://token-1@host/repo") == (
            "git+https://<userinfo>@host/repo"
        )

    @pytest.mark.parametrize(
        "ref, shown",
        [
            pytest.param(
                "git+https://host/org/repo?private_token=hunter2",
                "git+https://host/org/repo?private_token=<hidden>",
                id="private-token",
            ),
            pytest.param(
                "git+https://host/repo?ref=main&access_token=hunter2&rev=abc",
                "git+https://host/repo?ref=main&access_token=<hidden>&rev=abc",
                id="access-token-between-others",
            ),
            pytest.param(
                "git+https://alice:hunter2@host/repo?API_KEY=hunter2",
                "git+https://<userinfo>@host/repo?API_KEY=<hidden>",
                id="userinfo-and-query",
            ),
        ],
    )
    def test_a_query_value_named_for_a_credential_is_not_shown(self, ref, shown):
        # The userinfo is not the only place a URL flake reference carries a token:
        # a git host's API takes one as a query parameter.
        assert shown_flake_ref(ref) == shown
        assert "hunter2" not in shown_flake_ref(ref)

    def test_a_query_of_ordinary_parameters_is_shown_as_it_is(self):
        ref = "git+https://host/repo?ref=main&rev=0123abc&dir=sub"
        assert shown_flake_ref(ref) == ref

    def test_an_at_sign_after_the_authority_is_left_alone(self):
        # Only the authority holds userinfo; a `@` in the path or query is data.
        ref = "github:owner/repo?ref=release@2"
        assert shown_flake_ref(ref) == ref


class TestBuildNixCommand:
    @pytest.mark.unit
    def test_enables_experimental_features_before_the_subcommand(self):
        cmd = build_nix_command("path:/repo", ["scan"], "/usr/bin/nix")
        assert cmd[0] == "/usr/bin/nix"
        assert cmd[1] == "--extra-experimental-features"
        assert "nix-command" in cmd[2] and "flakes" in cmd[2]
        # Both features are off by default on a stock multi-user install, so omitting this
        # makes every first run fail with "experimental Nix feature ... is disabled".
        assert cmd.index("--extra-experimental-features") < cmd.index("develop")

    @pytest.mark.unit
    def test_runs_this_ash_inside_the_shell_with_the_forwarded_args(self):
        """The inner scan is the interpreter running now, started by absolute path."""
        cmd = build_nix_command("path:/repo", ["scan", "--mode", "local"], "nix")
        inner = cmd[cmd.index("--command") + 1 :]
        assert inner[0] == sys.executable
        assert Path(inner[0]).is_absolute()
        code = inner.index("-c")
        # -P, where Python has it, is the only option before -c.
        assert inner[1:code] == (["-P"] if sys.version_info >= (3, 11) else [])
        assert "automated_security_helper.cli.entrypoint" in inner[code + 1]
        assert inner[code + 2 :] == ["scan", "--mode", "local"]

    @pytest.mark.integration
    def test_the_inner_command_runs_this_ash_and_not_one_in_the_scanned_tree(
        self, tmp_path
    ):
        """-c puts the working directory, the scanned tree, first on sys.path."""
        from automated_security_helper.interactions.run_ash_nix import _this_ash
        from tests.utils.helpers import REPO_ROOT

        planted = tmp_path / "automated_security_helper"
        planted.mkdir()
        (planted / "__init__.py").write_text(
            "raise SystemExit('imported from the scanned tree')\n", encoding="utf-8"
        )
        env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))

        completed = subprocess.run(  # nosec B603 - the command under test
            [*_this_ash(), "--version"],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert "imported from the scanned tree" not in completed.stderr
        assert completed.returncode == 0, completed.stderr[-2000:]


#: The inner command as it was: `-c`, with nothing dropping the working directory.
_OLD_INNER_COMMAND = [
    sys.executable,
    "-c",
    (
        "import sys; sys.argv[0] = 'ash'; "
        "from automated_security_helper.cli.entrypoint import main; main()"
    ),
]


def _plant_ash(directory: Path, marker: Path) -> None:
    """An ``automated_security_helper`` package in ``directory`` that records its import."""
    init = directory / "automated_security_helper" / "__init__.py"
    init.parent.mkdir(parents=True)
    init.write_text(
        f"open({str(marker)!r}, 'a', encoding='utf-8').write('planted\\n')\n",
        encoding="utf-8",
    )


def _run_in(argv, cwd: Path) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONSAFEPATH"}
    return subprocess.run(
        [*argv, "--version"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


class TestTheInnerScanImportsNothingFromTheScanDirectory:
    """``nix develop --command`` starts the inner scan in the scan's directory.

    Under ``-c`` Python puts that directory first on ``sys.path`` (as ``''``), and
    the inner command's first import is ``automated_security_helper``, so a package of
    that name in the scanned repository ran in place of ASH. The directory stays as
    it is; the inner command drops the entry instead, and adds ``-P`` where Python
    has it.
    """

    @pytest.mark.integration
    def test_control_the_old_inner_command_imports_the_planted_package(self, tmp_path):
        marker = tmp_path / "IMPORTED"
        _plant_ash(tmp_path / "repo", marker)
        _run_in(_OLD_INNER_COMMAND, tmp_path / "repo")
        assert marker.read_text(encoding="utf-8") == "planted\n"

    @pytest.mark.integration
    def test_the_inner_command_runs_the_installed_ash(self, tmp_path):
        from automated_security_helper.interactions.run_ash_nix import _this_ash

        marker = tmp_path / "IMPORTED"
        _plant_ash(tmp_path / "repo", marker)
        result = _run_in(_this_ash(), tmp_path / "repo")
        assert not marker.exists(), marker.read_text(encoding="utf-8")
        assert result.returncode == 0, result.stderr

    @pytest.mark.integration
    def test_without_p_the_code_alone_drops_the_entry(self, tmp_path):
        """Python 3.10 has no -P, so the -c source has to be enough on its own."""
        from automated_security_helper.interactions.run_ash_nix import _this_ash

        argv = [arg for arg in _this_ash() if arg != "-P"]
        marker = tmp_path / "IMPORTED"
        _plant_ash(tmp_path / "repo", marker)
        result = _run_in(argv, tmp_path / "repo")
        assert not marker.exists(), marker.read_text(encoding="utf-8")
        assert result.returncode == 0, result.stderr

    @pytest.mark.unit
    def test_flake_ref_is_passed_to_develop(self):
        cmd = build_nix_command("github:owner/repo/v1", ["scan"], "nix")
        assert cmd[cmd.index("develop") + 1] == "github:owner/repo/v1"


class TestTheInnerCommandRestoresTheOperatorsPythonPath:
    """Inside the shell PYTHONPATH is unset (flake.nix), so an ASH or a plugin module
    importable only through the operator's PYTHONPATH could not import. The inner
    command puts those directories back on ``sys.path``, ahead of the installed
    packages as PYTHONPATH's are, from OUTER_PYTHONPATH_ENV_VAR."""

    @pytest.mark.integration
    def test_a_directory_the_operator_named_is_importable_again(self, tmp_path):
        from automated_security_helper.interactions.run_ash_nix import _this_ash

        marker = tmp_path / "IMPORTED"
        _plant_ash(tmp_path / "named", marker)
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("PYTHONSAFEPATH", "PYTHONPATH")
        }
        env[OUTER_PYTHONPATH_ENV_VAR] = str(tmp_path / "named")

        subprocess.run(
            [*_this_ash(), "--version"],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )

        # The planted package was imported in place of the installed ASH: the named
        # directory came first on sys.path, as a PYTHONPATH entry would.
        assert marker.exists()
        assert marker.read_text(encoding="utf-8") == "planted\n"

    @pytest.mark.integration
    def test_without_the_variable_the_installed_ash_runs(self, tmp_path):
        from automated_security_helper.interactions.run_ash_nix import _this_ash

        marker = tmp_path / "IMPORTED"
        _plant_ash(tmp_path / "named", marker)
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("PYTHONSAFEPATH", "PYTHONPATH", OUTER_PYTHONPATH_ENV_VAR)
        }

        result = subprocess.run(
            [*_this_ash(), "--version"],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )

        assert not marker.exists()
        assert result.returncode == 0, result.stderr


class _EnteredShell:
    """Stands in for ``run_ash_nix._enter_shell``, the one call that starts ``nix``.

    ``run_ash_nix`` decides the flake reference, rewrites the arguments, builds the
    command and the child's environment, and hands the command and the environment
    to ``_enter_shell``. The cells that use this are about those decisions, so the
    call is replaced by a recorder and nothing is started: whether a ``nix`` is
    installed where they run changes no result. What ``_enter_shell`` does with the
    command is pinned where it happens (``TestEnterShell``, the launcher cells, and
    the stand-in ``nix`` of the signal cells).

    The module's own name is replaced, not ``subprocess.run`` or ``Popen``: those
    are every caller's (see ``_restore_process_wide_tool_state`` in
    tests/conftest.py).
    """

    def __init__(self) -> None:
        self.returncode = 0
        self.cmd = None
        self.env = None

    def __call__(self, cmd, env):
        self.cmd = cmd
        self.env = env
        return subprocess.CompletedProcess(cmd, self.returncode)


@pytest.fixture
def entered_shell(monkeypatch) -> _EnteredShell:
    shell = _EnteredShell()
    monkeypatch.setattr(
        "automated_security_helper.interactions.run_ash_nix._enter_shell", shell
    )
    return shell


@pytest.mark.unit
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
            with pytest.raises(
                RuntimeError, match="already running inside a Nix shell"
            ):
                run_ash_nix(argv=["scan"])

    def test_child_environment_carries_the_guard_and_offline_flag(
        self, monkeypatch, entered_shell
    ):
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )

        run_ash_nix(argv=["scan", "--mode", "nix"])

        # The guard is what stops the inner run re-entering Nix mode.
        assert entered_shell.env[ASH_IN_NIX_ENV_VAR] == "1"
        # Without this the scanners that prefer `uv tool install` fetch their own copies
        # and shadow the pinned ones, so the report would describe versions the flake
        # never supplied.
        assert entered_shell.env["ASH_OFFLINE"] == "YES"
        # And the inner invocation must be a local scan, not another nix one.
        assert "--mode" in entered_shell.cmd
        assert entered_shell.cmd[entered_shell.cmd.index("--mode") + 1] == "local"
        # The shell's standard input is set where it is started: TestEnterShell.

    def test_child_environment_carries_the_outer_run_id(
        self, monkeypatch, entered_shell
    ):
        """The inner run writes it into its results file (utils/inner_run_outcome.py)."""
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )

        run_ash_nix(
            argv=["scan"],
            outer_run_id="0123456789abcdef0123456789abcdef",  # pragma: allowlist secret
        )

        assert entered_shell.env["ASH_OUTER_RUN_ID"] == (
            "0123456789abcdef0123456789abcdef"
        )

    def test_nonzero_exit_is_returned_rather_than_raised(
        self, monkeypatch, entered_shell
    ):
        # A scan that finds something exits non-zero by design. Raising here would turn a
        # working scan into an error.
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )
        entered_shell.returncode = 2

        result = run_ash_nix(argv=["scan"])

        assert result.returncode == 2

    def test_debug_prints_the_assembled_command(
        self, monkeypatch, capsys, entered_shell
    ):
        # Small, but this is the one thing a user reaches for when Nix mode misbehaves:
        # without the full command echoed, an adopter cannot reproduce the invocation by
        # hand to see what the shell did.
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )

        run_ash_nix(argv=["scan"], debug=True)

        printed = capsys.readouterr().out
        assert "develop" in printed
        assert "path:/repo" in printed

    def test_argv_defaults_to_the_process_arguments(self, monkeypatch, entered_shell):
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )
        monkeypatch.setattr(sys, "argv", ["ash", "scan", "--quiet", "--mode", "nix"])

        run_ash_nix()

        # sys.argv[0] is the executable and must not be forwarded as a scan argument.
        inner = entered_shell.cmd[entered_shell.cmd.index("--command") + 1 :]
        assert inner[0] == sys.executable
        assert "ash" not in inner
        assert "--quiet" in entered_shell.cmd

    def test_the_shell_gets_a_path_without_the_scanned_trees_entries(
        self, monkeypatch, tmp_path, entered_shell
    ):
        """As every other child does; nix develop prepends its own packages to it."""
        from automated_security_helper.utils import subprocess_utils
        from automated_security_helper.utils.subprocess_utils import scanning_tree

        repo = tmp_path / "repo"
        (repo / ".venv" / "bin").mkdir(parents=True)
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        # A child's PATH keeps only anchored entries, and "/usr/bin" has no drive
        # letter on Windows, so the system entry is built with abspath.
        system = os.path.abspath("/usr/bin")
        monkeypatch.setenv(
            "PATH", os.pathsep.join([str(repo / ".venv" / "bin"), system])
        )
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )
        subprocess_utils.clear_find_executable_cache()

        with scanning_tree(repo):
            run_ash_nix(argv=["scan"])

        assert entered_shell.env["PATH"] == "/usr/bin"
        assert entered_shell.env[ASH_IN_NIX_ENV_VAR] == "1"

    def test_the_flake_reference_is_logged_without_its_userinfo(
        self, monkeypatch, capsys, entered_shell
    ):
        """The INFO line and the debug command line reach the console and ash.log."""
        from automated_security_helper.interactions import run_ash_nix as module

        logged = []
        recorder = types.SimpleNamespace(
            info=lambda message, *a, **k: logged.append(message),
            debug=lambda message, *a, **k: logged.append(message),
            warning=lambda message, *a, **k: logged.append(message),
        )
        monkeypatch.setattr(module, "ASH_LOGGER", recorder)
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(
            ASH_NIX_FLAKE_REF_ENV_VAR, "git+https://user:token-1@host/org/repo"
        )
        monkeypatch.setattr(module, "find_executable", lambda _: "/usr/bin/nix")

        run_ash_nix(argv=["scan"], debug=True)

        printed = capsys.readouterr().out
        assert "token-1" not in printed, printed
        assert "token-1" not in "\n".join(logged), logged
        assert "git+https://<userinfo>@host/org/repo" in printed
        assert any(
            "Entering Nix shell from flake: git+https://<userinfo>@" in m
            for m in logged
        )
        # The shell is given the reference as the operator wrote it.
        assert "git+https://user:token-1@host/org/repo" in entered_shell.cmd

    def test_the_operators_pythonpath_is_handed_to_the_inner_command(
        self, monkeypatch, entered_shell
    ):
        """The flake's shell hook unsets PYTHONPATH; the inner command puts the
        operator's own entries back from this variable (flake.nix, _this_ash)."""
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )
        entries = os.pathsep.join(["/opt/ash-src", "/opt/plugins"])
        monkeypatch.setenv("PYTHONPATH", entries)

        run_ash_nix(argv=["scan"])

        assert entered_shell.env[OUTER_PYTHONPATH_ENV_VAR] == entries
        code = entered_shell.cmd[entered_shell.cmd.index("-c") + 1]
        assert OUTER_PYTHONPATH_ENV_VAR in code
        assert "sys.path[:0]" in code
        # No path of this host in the command: it is one fixed string.
        assert "/opt/ash-src" not in code

    def test_no_pythonpath_means_no_hand_over(self, monkeypatch, entered_shell):
        monkeypatch.delenv(ASH_IN_NIX_ENV_VAR, raising=False)
        monkeypatch.delenv("PYTHONPATH", raising=False)
        monkeypatch.setenv(ASH_NIX_FLAKE_REF_ENV_VAR, "path:/repo")
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.find_executable",
            lambda _: "/usr/bin/nix",
        )

        run_ash_nix(argv=["scan"])

        assert OUTER_PYTHONPATH_ENV_VAR not in entered_shell.env


@pytest.mark.integration
class TestEnterShell:
    def test_the_shell_gets_an_empty_standard_input(self, monkeypatch):
        """Neither ``nix`` nor the scanners it starts read this process's input.

        ``run_ash_nix`` hands the command to ``_enter_shell``, which starts it, so
        the standard input is set there. The cell starts a harmless child of this
        interpreter in place of ``nix`` and records what ``Popen`` was given.
        """
        real_popen = subprocess.Popen
        given = {}

        def popen_recording_its_arguments(cmd, **kwargs):
            given.update(kwargs)
            return real_popen([sys.executable, "-c", "raise SystemExit(0)"], **kwargs)

        # The module's own name for the standard library, as test_executable_lookup.py
        # does for subprocess_utils: Popen is replaced for this module alone.
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_nix.subprocess",
            types.SimpleNamespace(
                Popen=popen_recording_its_arguments,
                DEVNULL=subprocess.DEVNULL,
                CompletedProcess=subprocess.CompletedProcess,
            ),
        )
        from automated_security_helper.interactions.run_ash_nix import _enter_shell

        result = _enter_shell(["nix", "develop"], env={})

        assert result.returncode == 0
        assert given.get("stdin") is subprocess.DEVNULL


@pytest.mark.unit
class TestRepoFlakeDir:
    def test_finds_the_flake_in_this_checkout(self):
        # These tests run from a source checkout, which is the case the path: branch
        # exists to serve, so this asserts the parents[2] arithmetic is right. Getting it
        # wrong would send every developer run at the remote flake instead of their edits.
        from automated_security_helper.interactions.run_ash_nix import _repo_flake_dir

        found = _repo_flake_dir()
        assert found is not None, "expected to find flake.nix at the repository root"
        assert (Path(found) / "flake.nix").is_file()

    def test_a_flake_beside_site_packages_is_not_this_repository(
        self, monkeypatch, tmp_path
    ):
        # In a packaged install the parents[2] arithmetic lands on the environment's
        # site-packages directory. A flake.nix left there by something else must not
        # replace the published, version-pinned toolchain: only a checkout, which
        # ships pyproject.toml beside flake.nix, is this repository.
        from automated_security_helper.interactions import run_ash_nix

        site = tmp_path / "site-packages"
        module = site / "automated_security_helper" / "interactions" / "run_ash_nix.py"
        module.parent.mkdir(parents=True)
        module.write_text("", encoding="utf-8")
        (site / "flake.nix").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(run_ash_nix, "__file__", str(module))

        assert run_ash_nix._repo_flake_dir() is None

        (site / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        assert run_ash_nix._repo_flake_dir() == site.resolve()
