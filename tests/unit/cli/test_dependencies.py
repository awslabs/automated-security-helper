"""Tests for cli/dependencies.py — covers get_platform, get_architecture, run_command, install."""

from unittest.mock import patch, MagicMock

from automated_security_helper.cli.dependencies import (
    get_platform,
    get_architecture,
    run_command,
    dependencies_app,
)


class TestGetPlatform:
    """Tests for get_platform."""

    def test_linux(self):
        with patch("platform.system", return_value="Linux"):
            assert get_platform() == "linux"

    def test_darwin(self):
        with patch("platform.system", return_value="Darwin"):
            assert get_platform() == "darwin"

    def test_windows(self):
        with patch("platform.system", return_value="Windows"):
            assert get_platform() == "windows"

    def test_unknown(self):
        with patch("platform.system", return_value="FreeBSD"):
            assert get_platform() == "unknown"


class TestGetArchitecture:
    """Tests for get_architecture."""

    def test_x86_64(self):
        with patch("platform.machine", return_value="x86_64"):
            assert get_architecture() == "amd64"

    def test_amd64(self):
        with patch("platform.machine", return_value="amd64"):
            assert get_architecture() == "amd64"

    def test_aarch64(self):
        with patch("platform.machine", return_value="aarch64"):
            assert get_architecture() == "arm64"

    def test_arm64(self):
        with patch("platform.machine", return_value="arm64"):
            assert get_architecture() == "arm64"

    def test_unknown_arch(self):
        with patch("platform.machine", return_value="s390x"):
            assert get_architecture() == "unknown"


class TestRunCommand:
    """Tests for run_command."""

    def test_successful_command(self):
        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command"
        ) as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = "output"
            mock_result.stderr = ""
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            result = run_command(["echo", "hello"])
            assert result == 0

    def test_failed_command(self):
        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command"
        ) as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_result.stderr = "error"
            mock_result.returncode = 1
            mock_run.return_value = mock_result

            result = run_command(["false"])
            assert result == 1

    def test_exception_returns_1(self):
        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command",
            side_effect=RuntimeError("boom"),
        ):
            result = run_command(["bad-command"])
            assert result == 1


class TestInstallDependencies:
    """Tests for the install command via typer runner."""

    def test_install_command_exists(self):
        """Verify the install command is registered."""
        from typer.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(dependencies_app, ["install", "--help"])
        assert result.exit_code == 0
        assert "Install dependencies" in result.output


class TestInstallHonorsConfiguredToolVersion:
    """`dependencies install` installs the version the resolved config names.

    The image build pins bandit, checkov and semgrep by passing
    `--config-overrides scanners.<tool>.options.tool_version===<version>` (from
    `install-pinned-tool --uv-tool-pins`). The scanners were constructed from the
    context alone, without their own config section, so each one fell back to its
    class default range and `uv tool install` took whatever PyPI had that day. The
    license entry recorded the pinned version and the build failed when the two
    disagreed.
    """

    def _installed_argvs(self, tmp_path, monkeypatch, overrides):
        from typer.testing import CliRunner

        monkeypatch.chdir(tmp_path)
        captured = []

        def fake_run(cmd, shell=False):
            captured.append(list(cmd))
            return 0

        args = ["--tool", "semgrep", "--bin-path", str(tmp_path / "bin")]
        for override in overrides:
            args += ["--config-overrides", override]
        with patch(
            "automated_security_helper.cli.dependencies.run_command",
            side_effect=fake_run,
        ):
            result = CliRunner().invoke(dependencies_app, args)
        assert result.exit_code == 0, result.output
        return [" ".join(c) for c in captured]

    def test_pinned_tool_version_reaches_the_install_command(
        self, tmp_path, monkeypatch
    ):
        argvs = self._installed_argvs(
            tmp_path,
            monkeypatch,
            ["scanners.semgrep.options.tool_version===1.179.0"],
        )
        assert any("semgrep==1.179.0" in a for a in argvs), argvs

    def test_without_a_pin_the_default_range_is_used(self, tmp_path, monkeypatch):
        argvs = self._installed_argvs(tmp_path, monkeypatch, [])
        assert argvs, "no install command was issued for semgrep"
        assert not any("semgrep==" in a for a in argvs), argvs
