# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config named for another plugin does not build this plugin, subclass or not.

``plugin_config.config_validated_by_declared_model`` refuses a config of another
class that names another plugin. It used to check the name only after it had
returned early for an instance of the plugin's own config class, so a subclass
of that class which declared another plugin's name as its default still built
the plugin, and the plugin took the ``enabled`` it set. The name is checked
first now, whatever the class of the config.

When the plugin declares no name of its own there is nothing to compare, and the
other config's name is not written into the plugin's config: before the name
check existed it was dropped, and it is dropped again.

No cell calls AWS: boto3's Session is a stand-in that fails a cell that reaches
it, and no cell writes a file.
"""

from typing import Optional, Union
from unittest.mock import MagicMock

import boto3
import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.base.plugin_config import (
    PluginConfigBase,
    config_validated_by_declared_model,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
    CloudWatchLogsReporterConfig,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
    S3ReporterConfig,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
    SecurityHubReporterConfig,
)

pytestmark = pytest.mark.unit

REPORTERS = [
    (SecurityHubReporter, SecurityHubReporterConfig),
    (S3Reporter, S3ReporterConfig),
    (CloudWatchLogsReporter, CloudWatchLogsReporterConfig),
]
#: Each reporter with a subclass of its own config that is named for each other
#: reporter.
PAIRS = [
    (reporter, config, other_config.model_fields["name"].default)
    for reporter, config in REPORTERS
    for _, other_config in REPORTERS
    if other_config is not config
]


@pytest.fixture(autouse=True)
def no_aws(monkeypatch):
    """No cell may build a real AWS session."""
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))
    monkeypatch.setattr(boto3, "Session", session)
    return session


def _context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=AshConfig(project_name="fixture-project"),
    )


def _subclass_named(config_class, name):
    """A subclass of *config_class* that declares *name* as its default, as a
    plugin's config class declares its own."""
    return type(
        f"Named{config_class.__name__}",
        (config_class,),
        {"__annotations__": {"name": str}, "name": name},
    )


@pytest.mark.parametrize(
    ("reporter_class", "config_class", "other_name"),
    PAIRS,
    ids=[f"{r.__name__}<-{c.__name__}-named-{n}" for r, c, n in PAIRS],
)
def test_a_subclass_of_the_plugins_own_config_named_for_another_plugin_is_refused(
    tmp_path, no_aws, reporter_class, config_class, other_name
):
    given = _subclass_named(config_class, other_name)(enabled=True)
    # The control: the object is an instance of this plugin's own config class,
    # it is enabled, and it names another plugin.
    assert isinstance(given, config_class)
    assert given.enabled is True and given.name == other_name

    with pytest.raises(ValidationError) as raised:
        reporter_class(context=_context(tmp_path), config=given)

    no_aws.assert_not_called()
    assert "not this plugin's name" in str(raised.value)
    assert repr(other_name) in str(raised.value)


@pytest.mark.parametrize(
    ("reporter_class", "config_class"),
    REPORTERS,
    ids=[r.__name__ for r, _ in REPORTERS],
)
def test_a_subclass_of_the_plugins_own_config_with_its_name_still_builds_it(
    tmp_path, no_aws, reporter_class, config_class
):
    """The control: a subclass that keeps the plugin's own name builds the
    plugin, as does the plugin's own class."""
    own_name = config_class.model_fields["name"].default
    same = _subclass_named(config_class, own_name)(enabled=True)

    from_subclass = reporter_class(context=_context(tmp_path), config=same)
    from_own = reporter_class(
        context=_context(tmp_path), config=config_class(enabled=True)
    )

    assert from_subclass.config.enabled is True and from_own.config.enabled is True
    no_aws.assert_not_called()


class _OwnConfig(PluginConfigBase):
    """A plugin's config class that declares no name of its own."""


class _OtherConfig(PluginConfigBase):
    name: Optional[str] = "other-plugin"


class _PluginWithoutAName(BaseModel):
    config: Union[_OwnConfig, PluginConfigBase, None] = None


def test_a_plugin_without_a_declared_name_does_not_take_the_other_configs_name():
    """The plugin declares no name, so there is nothing to compare and nothing
    to refuse. The enabled flag the other config set is read, and its name stays
    out of the plugin's config."""
    given = _OtherConfig(enabled=False)
    assert given.name == "other-plugin"

    built = config_validated_by_declared_model(
        _PluginWithoutAName, PluginConfigBase, given, lambda value: value
    )

    assert isinstance(built, _OwnConfig), built
    assert built.enabled is False
    assert built.name is None, built.name


def test_a_plugin_without_a_declared_name_keeps_a_name_its_own_dump_set():
    """The control: the name is dropped only because the plugin has none to
    compare it with; a plain mapping is validated as it was given."""
    built = config_validated_by_declared_model(
        _PluginWithoutAName,
        PluginConfigBase,
        {"enabled": False, "name": "given-by-mapping"},
        lambda value: value,
    )

    assert isinstance(built, _OwnConfig)
    assert built.name == "given-by-mapping"
