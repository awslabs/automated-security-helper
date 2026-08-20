"""Tests for rendering plugin dependencies into install commands.

These exist because the failure mode they pin is silent. ``PluginDependency.version``
used to be rendered as ``f"{name}=={version}"`` for anything that was not the
literal string ``"latest"``, so a plugin declaring a supported *range* produced
``ferret-scan==>=0.1.0,<2.0.0`` -- which pip cannot parse. Nothing raised: the
range simply never reached an installer, callers installed the package by hand,
and CI resolved whatever release was newest at the moment the job ran.

That is not a hypothetical. ferret-scan 2.3.3 was published at
2026-08-20T21:14:59Z, three major versions above the range its ASH plugin
declares as supported. Jobs whose install step ran after that timestamp picked it
up, its new API_KEY_OR_SECRET detector matched ``session: Optional[Session]`` in
a generated Pydantic schema, and three unrelated merge-queue branches went red
inside eight minutes with no source change on any of them.
"""

import sys

import pytest

from automated_security_helper.base.plugin_base import (
    PluginBase,
    PluginDependency,
    pep440_requirement,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import PackageManager


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()

    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


class ConcretePlugin(PluginBase):
    """Minimal concrete implementation for testing."""

    def validate_plugin_dependencies(self) -> bool:
        return True


def _plugin_with_dependency(plugin_context, dep: PluginDependency) -> ConcretePlugin:
    return ConcretePlugin(
        context=plugin_context,
        dependencies={"linux": {"amd64": [dep]}},
    )


class TestPep440Requirement:
    """The three ways a declared version is interpreted."""

    def test_latest_emits_no_constraint(self):
        """``latest`` is the documented way to say "resolver's choice"."""
        assert pep440_requirement("ferret-scan", "latest") == "ferret-scan"

    def test_bare_version_is_pinned_exactly(self):
        """A bare version keeps the historical ``==`` behaviour."""
        assert pep440_requirement("ferret-scan", "1.10.0") == "ferret-scan==1.10.0"

    @pytest.mark.parametrize(
        "constraint",
        [
            ">=0.1.0,<2.0.0",
            ">=1.0.0",
            "<2.0.0",
            "==1.10.0",
            "!=1.9.0",
            "~=1.10.0",
        ],
    )
    def test_specifier_is_passed_through_verbatim(self, constraint):
        """A specifier must not have a second operator glued in front of it."""
        rendered = pep440_requirement("ferret-scan", constraint)
        assert rendered == f"ferret-scan{constraint}"
        assert "==>" not in rendered
        assert "==<" not in rendered

    def test_the_regression_shape_is_parseable(self):
        """The exact string that used to be produced was invalid; this one is not."""
        rendered = pep440_requirement("ferret-scan", ">=0.1.0,<2.0.0")
        assert rendered == "ferret-scan>=0.1.0,<2.0.0"

        # Prove it, rather than asserting a shape and hoping. packaging is a
        # transitive dependency of the build stack, so skip instead of failing
        # if it is genuinely unavailable.
        packaging_requirements = pytest.importorskip("packaging.requirements")
        parsed = packaging_requirements.Requirement(rendered)
        assert parsed.name == "ferret-scan"
        assert "1.10.0" in parsed.specifier
        assert "2.3.3" not in parsed.specifier


class TestGetInstallationCommandsRendersRanges:
    """The renderer is the thing an installer actually calls."""

    def test_pip_dependency_carries_the_range(self, plugin_context):
        plugin = _plugin_with_dependency(
            plugin_context,
            PluginDependency(
                name="ferret-scan",
                version=">=0.1.0,<2.0.0",
                package_manager=PackageManager.PIP,
            ),
        )
        commands = plugin.get_installation_commands("linux", "amd64")
        assert [
            sys.executable,
            "-m",
            "pip",
            "install",
            "ferret-scan>=0.1.0,<2.0.0",
        ] in commands

    def test_uv_dependency_carries_the_range(self, plugin_context):
        plugin = _plugin_with_dependency(
            plugin_context,
            PluginDependency(
                name="ferret-scan",
                version=">=0.1.0,<2.0.0",
                package_manager=PackageManager.UV,
            ),
        )
        commands = plugin.get_installation_commands("linux", "amd64")
        assert [
            "uv",
            "tool",
            "install",
            "ferret-scan>=0.1.0,<2.0.0",
        ] in commands

    def test_exact_pin_behaviour_is_unchanged(self, plugin_context):
        """Existing declarations must render exactly as they did before."""
        plugin = _plugin_with_dependency(
            plugin_context,
            PluginDependency(
                name="bandit",
                version="1.7.5",
                package_manager=PackageManager.PIP,
            ),
        )
        commands = plugin.get_installation_commands("linux", "amd64")
        assert [sys.executable, "-m", "pip", "install", "bandit==1.7.5"] in commands

    def test_latest_stays_unconstrained(self, plugin_context):
        plugin = _plugin_with_dependency(
            plugin_context,
            PluginDependency(
                name="bandit",
                version="latest",
                package_manager=PackageManager.PIP,
            ),
        )
        commands = plugin.get_installation_commands("linux", "amd64")
        assert [sys.executable, "-m", "pip", "install", "bandit"] in commands

    def test_non_pep440_managers_are_left_alone(self, plugin_context):
        """apt/npm/brew spell ranges differently; translating them would guess."""
        plugin = _plugin_with_dependency(
            plugin_context,
            PluginDependency(
                name="trivy",
                version="0.50.0",
                package_manager=PackageManager.APT,
            ),
        )
        commands = plugin.get_installation_commands("linux", "amd64")
        assert ["apt-get", "install", "-y", "trivy=0.50.0"] in commands
