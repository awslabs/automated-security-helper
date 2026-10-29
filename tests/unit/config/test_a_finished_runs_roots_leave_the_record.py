# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run's derived roots leave the configuration's record when the run ends.

``forget_derived_roots`` removes one run's roots and nothing else: the unscoped
record and every other run's roots stay, so a run that is still going keeps
refusing under its own directories.
"""

from types import SimpleNamespace

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import (
    derived_roots_scope,
    forget_derived_roots,
    record_derived_roots,
    refused_derived_product,
)

pytestmark = pytest.mark.unit


def _refused(path, source, config):
    return refused_derived_product(
        path, source_dir=source, key="config_file", config=config
    )


@pytest.fixture
def source(tmp_path):
    directory = tmp_path.resolve() / "src"
    directory.mkdir()
    return directory


def _record(config, run, directory):
    directory.mkdir()
    with derived_roots_scope(run):
        record_derived_roots(config, directory)
    return directory / "x.yaml"


def test_forgetting_a_run_stops_refusing_under_its_roots(tmp_path, source):
    config = AshConfig()
    first = _record(config, "first", tmp_path.resolve() / "out1")
    assert _refused(first, source, config) is True

    forget_derived_roots(config, "first")

    assert _refused(first, source, config) is False
    assert config._run_derived_roots == {}


def test_forgetting_a_run_keeps_every_other_runs_roots(tmp_path, source):
    config = AshConfig()
    first = _record(config, "first", tmp_path.resolve() / "out1")
    second = _record(config, "second", tmp_path.resolve() / "out2")

    forget_derived_roots(config, "first")

    assert _refused(first, source, config) is False
    assert _refused(second, source, config) is True
    with derived_roots_scope("second"):
        assert _refused(second, source, config) is True


def test_forgetting_a_run_keeps_the_unscoped_record(tmp_path, source):
    config = AshConfig()
    unscoped = tmp_path.resolve() / "out0"
    unscoped.mkdir()
    record_derived_roots(config, unscoped)
    _record(config, "first", tmp_path.resolve() / "out1")

    forget_derived_roots(config, "first")

    assert _refused(unscoped / "x.yaml", source, config) is True


def test_forgetting_replaces_the_mapping_instead_of_changing_it(tmp_path):
    """A config copy shares the mapping object; forgetting must not change it."""
    config = AshConfig()
    _record(config, "first", tmp_path.resolve() / "out1")
    held = config._run_derived_roots

    forget_derived_roots(config, "first")

    assert "first" in held
    assert config._run_derived_roots is not held


def test_forgetting_a_run_that_was_never_recorded_changes_nothing(tmp_path):
    config = AshConfig()
    _record(config, "first", tmp_path.resolve() / "out1")
    held = config._run_derived_roots

    forget_derived_roots(config, "never-recorded")

    assert config._run_derived_roots is held


@pytest.mark.parametrize("stand_in", [None, object(), SimpleNamespace()])
def test_forgetting_on_a_config_that_holds_no_record_does_nothing(stand_in):
    forget_derived_roots(stand_in, "first")
