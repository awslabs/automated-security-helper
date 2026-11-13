# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv mixin checks the ``--from`` spec it hands to the dependency probe.

``_uv_probe_from_spec`` is the spec the dependency checks pass to
``get_uv_tool_command``: ``_uv_from_spec`` passed through ``checked_requirement``
with the package named, as ``run_tool`` checks the spec the scan itself runs
under. A spec the run would refuse is logged in the plugin's fixed words, with
nothing of the spec in the line, and the probe runs bare instead of handing uv a
path, a URL or a marker.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin

pytestmark = pytest.mark.unit


class FakePlugin(UVToolMixin):
    """The attributes the mixin reads from PluginBase, and nothing else."""

    def __init__(self, **kwargs):
        self.command = kwargs.get("command", "bandit")
        self.use_uv_tool = True
        self.uv_tool_package_name = kwargs.get("uv_tool_package_name", None)
        self.uv_tool_install_commands = []
        self.extras = kwargs.get("extras", None)
        self.constraint = kwargs.get("constraint", None)
        self.logged: list[tuple[str, int]] = []

    def _plugin_log(self, message, level=logging.INFO, **kwargs):
        self.logged.append((message, level))

    def _get_tool_package_extras(self):
        return self.extras

    def _get_tool_version_constraint(self):
        return self.constraint

    def _get_tool_with_dependencies(self):
        return None


class TestTheProbeSpecIsChecked:
    def test_the_scans_spec_passes_through_as_built(self):
        plugin = FakePlugin(
            command="bandit", extras=["sarif", "toml"], constraint=">=1.7.0,<2.0.0"
        )
        assert plugin._uv_probe_from_spec() == "bandit[sarif,toml]>=1.7.0,<2.0.0"
        assert plugin.logged == []

    def test_a_package_named_apart_from_the_command_passes(self):
        plugin = FakePlugin(
            command="jupyter-nbconvert", uv_tool_package_name="nbconvert"
        )
        assert plugin._uv_probe_from_spec() == "nbconvert"

    def test_no_from_spec_stays_none(self):
        """The scan passes no ``--from`` either, so the probe must not invent one."""
        assert FakePlugin(command="bandit")._uv_probe_from_spec() is None

    @pytest.mark.parametrize(
        ("constraint", "leak"),
        [
            pytest.param(" @ file:///srv/other", "file:///srv/other", id="url"),
            pytest.param(">=1; sys_platform != 'x'", "sys_platform", id="marker"),
            pytest.param("2", "bandit2", id="glued-digit-names-another-package"),
        ],
    )
    def test_a_spec_the_run_would_refuse_is_not_handed_to_the_probe(
        self, constraint, leak
    ):
        """Fails at the base: there was no check, so the spec reached uv as built."""
        plugin = FakePlugin(command="bandit", constraint=constraint)
        assert plugin._uv_from_spec() == f"bandit{constraint}", (
            "premise: the spec is built from the constraint as given"
        )

        assert plugin._uv_probe_from_spec() is None

        ((message, level),) = plugin.logged
        assert level == logging.WARNING
        assert message.startswith("bandit: Refusing to pass the --from spec for bandit")
        assert leak not in message
