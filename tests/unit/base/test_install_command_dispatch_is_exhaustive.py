"""Tests that every PackageManager member has a decided install rendering.

Why this exists: ``PluginBase.get_installation_commands`` dispatched over
``PackageManager`` with an ``if``/``elif`` chain that covered eight of the ten
members and ended without an ``else``. ``PackageManager.CONDA`` had no branch --
it appeared exactly once in the whole repository, at its own declaration -- so a
plugin declaring ``package_manager: conda`` produced an empty command list.

Nothing raised and nothing warned. ``ashx dependencies install`` printed
"Installing dependencies for ..." with no command under it, and its verdict only
fails a run when *nothing at all* was attempted and a needed tool is still
missing, so a plugin declaring one pip dependency alongside one conda dependency
installed half of what it declared and the tally said it had finished. The conda
dependency's absence then surfaced at scan time as a scanner reported MISSING,
which names neither the dependency nor the manager.

The prevention rule is the derived set. ``_UNRENDERED_PACKAGE_MANAGERS`` is
computed as ``PackageManager`` minus the rendered members minus the members that
deliberately render nothing, so a member added to the enum without a decision
lands in it and fails ``test_no_package_manager_is_unrendered`` -- rather than
reaching ``get_installation_commands`` and raising only for whoever happens to
run that one plugin.

Out of scope, deliberately: chocolatey's ``--version`` flag shares an argv
element with the package name, which is wrong but preserved verbatim, and no
range translation is attempted for any non-pip manager (see
``pep440_requirement``).
"""

import pytest

from automated_security_helper.base.plugin_base import (
    PluginBase,
    PluginDependency,
)
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import PackageManager
from automated_security_helper.core.exceptions import ToolNotProvisionableError

AshConfig.model_rebuild()


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir, output_dir=output_dir, work_dir=work_dir
    )


def _dispatch_names():
    """Import the dispatch internals lazily.

    Deliberately not a module-level import: on a tree without the fix these names
    do not exist, and importing them at module scope would turn every test here
    into one collection error. Kept lazy so the behavioural tests below fail on
    their own assertions instead -- an empty command list for a declared conda
    dependency -- which is the symptom, not a missing symbol.
    """
    from automated_security_helper.base import plugin_base

    return (
        plugin_base._INSTALL_COMMAND_BUILDERS,
        plugin_base._NO_INSTALL_COMMAND_PACKAGE_MANAGERS,
        plugin_base._UNRENDERED_PACKAGE_MANAGERS,
    )


def _no_command_members():
    return _dispatch_names()[1]


def _plugin_with(context, *deps: PluginDependency) -> PluginBase:
    plugin = PluginBase(context=context)
    plugin.config = PluginConfigBase(name="dispatch-probe")
    plugin.dependencies = {"linux": {"amd64": list(deps)}}
    return plugin


class TestEveryMemberIsDecided:
    """The enum and the dispatch cannot drift apart."""

    def test_no_package_manager_is_unrendered(self):
        """Every PackageManager member either renders a command or is listed as not.

        This is the gate. A member added to ``PackageManager`` without either a
        builder or an entry in ``_NO_INSTALL_COMMAND_PACKAGE_MANAGERS`` shows up
        here by name.
        """
        _, _, unrendered = _dispatch_names()

        assert unrendered == frozenset(), (
            "PackageManager members with no install rendering decided: "
            + ", ".join(sorted(m.value for m in unrendered))
        )

    def test_the_two_sets_do_not_overlap(self):
        """A member cannot both render a command and be declared to render none."""
        builders, no_command, _ = _dispatch_names()

        assert frozenset(builders) & no_command == frozenset()

    @pytest.mark.parametrize("member", sorted(PackageManager, key=lambda m: m.value))
    def test_every_member_yields_a_command_or_is_a_declared_no_op(
        self, member, plugin_context
    ):
        """No member silently produces an empty list.

        Parametrised over the enum rather than over a hand-written list of names,
        so the case that was missing -- conda -- could not have been omitted from
        the test the way it was omitted from the dispatch.
        """
        plugin = _plugin_with(
            plugin_context,
            PluginDependency(
                name="probe-tool", version="1.2.3", package_manager=member
            ),
        )

        commands = plugin.get_installation_commands("linux", "amd64")

        if member in {PackageManager.URL, PackageManager.CUSTOM}:
            # The two members whose commands live in custom_install_commands. Named
            # here rather than read from the module so this test still expresses the
            # expectation on a tree that has no such set.
            assert commands == []
        else:
            assert len(commands) == 1
            assert commands[0], "an empty argv is not a command"
            assert "probe-tool" in " ".join(commands[0])


class TestCondaSpecifically:
    """conda is the member the dispatch forgot."""

    def test_conda_dependency_yields_a_conda_install_command(self, plugin_context):
        plugin = _plugin_with(
            plugin_context,
            PluginDependency(
                name="conda-tool",
                version="1.2.3",
                package_manager=PackageManager.CONDA,
            ),
        )

        assert plugin.get_installation_commands("linux", "amd64") == [
            ["conda", "install", "-y", "conda-tool=1.2.3"]
        ]

    def test_conda_latest_is_unpinned(self, plugin_context):
        """ "latest" means no constraint, matching apt/npm/brew/yum."""
        plugin = _plugin_with(
            plugin_context,
            PluginDependency(name="conda-tool", package_manager=PackageManager.CONDA),
        )

        assert plugin.get_installation_commands("linux", "amd64") == [
            ["conda", "install", "-y", "conda-tool"]
        ]

    def test_a_conda_dependency_alongside_pip_is_not_dropped(self, plugin_context):
        """The partial-install case: the pip command alone used to be the whole list."""
        plugin = _plugin_with(
            plugin_context,
            PluginDependency(
                name="pip-side", version="1.0.0", package_manager=PackageManager.PIP
            ),
            PluginDependency(
                name="conda-side", version="2.0.0", package_manager=PackageManager.CONDA
            ),
        )

        commands = plugin.get_installation_commands("linux", "amd64")

        assert len(commands) == 2
        assert commands[1] == ["conda", "install", "-y", "conda-side=2.0.0"]


class TestAnUndecidedMemberIsRefused:
    """A member with no rendering fails loudly and names itself."""

    def test_unhandled_member_raises_naming_the_member_and_the_dependency(
        self, plugin_context, monkeypatch
    ):
        """Simulates a PackageManager member added without a builder.

        CONDA stands in for the hypothetical new member by having its builder
        removed, which is the exact state the enum was in before this change.
        """
        builders = dict(_dispatch_names()[0])
        del builders[PackageManager.CONDA]
        monkeypatch.setattr(
            "automated_security_helper.base.plugin_base._INSTALL_COMMAND_BUILDERS",
            builders,
        )

        plugin = _plugin_with(
            plugin_context,
            PluginDependency(
                name="conda-tool",
                version="1.2.3",
                package_manager=PackageManager.CONDA,
            ),
        )

        with pytest.raises(ToolNotProvisionableError) as excinfo:
            plugin.get_installation_commands("linux", "amd64")

        message = str(excinfo.value)
        assert "conda" in message
        assert "conda-tool" in message

    def test_a_value_that_is_not_a_member_at_all_raises(self, plugin_context):
        """A plugin that bypassed pydantic validation still fails loudly."""
        plugin = PluginBase(context=plugin_context)
        plugin.config = PluginConfigBase(name="dispatch-probe")
        plugin.dependencies = {
            "linux": {
                "amd64": [
                    PluginDependency.model_construct(
                        name="probe-tool", version="1.0.0", package_manager="nixpkgs"
                    )
                ]
            }
        }

        with pytest.raises(ValueError, match="nixpkgs"):
            plugin.get_installation_commands("linux", "amd64")
