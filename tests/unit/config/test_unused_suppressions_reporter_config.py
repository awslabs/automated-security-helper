# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unused-suppressions reporter is a declared ReporterConfigSegment field.

Why this file exists
--------------------
Before the field was declared, the reporter's config reached it only through the
segment's ``extra="allow"``. It ran, and ``get_plugin_config`` found it under
either spelling, but it was missing from the published AshConfig.json schema and
nothing validated its options until the reporter itself did.

What holds for every aliased plugin field (both spellings, both keys at once,
``--config-overrides``, rejecting a bad ``enabled``) is in
test_aliased_plugin_config_spellings.py, which covers this field with the rest.
This file covers what is specific to this reporter:

* Its own option is validated at load. That is a behavior change: such a config
  used to load, and the reporter failed later.
* A config that does not mention the reporter gets the reporter's own defaults,
  as it did before.
* No committed config becomes invalid.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporterConfig,
)

# Every spelling a caller uses to look the reporter up. report_phase passes the
# lowercased class name; cli/report.py passes the --output-format value; the
# others are the config key in each spelling.
LOOKUP_NAMES = [
    "unused-suppressions",
    "unused_suppressions",
    "UnusedSuppressionsReporter",
    "unusedsuppressionsreporter",
]


def _load(tmp_path: Path, yaml_text: str) -> AshConfig:
    path = tmp_path / ".ash.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return AshConfig.from_file(path)


def _resolved(config: AshConfig) -> dict:
    """The settings every lookup name resolves to, asserted to be one value."""
    found = {name: config.get_plugin_config("reporter", name) for name in LOOKUP_NAMES}
    values = list(found.values())
    assert all(v == values[0] for v in values), f"lookups disagree: {found}"
    assert values[0] is not None, f"no lookup found the reporter: {found}"
    return UnusedSuppressionsReporterConfig.model_validate(values[0]).model_dump()


@pytest.mark.parametrize("key", ["unused-suppressions", "unused_suppressions"])
def test_its_output_format_option_is_validated_at_load(tmp_path, key):
    """Before the field was declared, this config loaded and the value sat
    unvalidated in the segment's extras until the reporter was built."""
    with pytest.raises(ValidationError) as excinfo:
        _load(
            tmp_path,
            f"""
project_name: probe
reporters:
  {key}:
    options:
      output_format: 5
""",
        )
    assert "reporters.unused-suppressions.options.output_format" in str(excinfo.value)


@pytest.mark.parametrize("key", ["unused-suppressions", "unused_suppressions"])
def test_a_valid_output_format_reaches_every_lookup(tmp_path, key):
    config = _load(
        tmp_path,
        f"""
project_name: probe
reporters:
  {key}:
    options:
      output_format: json
""",
    )
    assert _resolved(config)["options"]["output_format"] == "json"


def test_a_config_that_does_not_mention_it_gets_the_reporter_defaults(tmp_path):
    """Same effective settings as before the field existed.

    Before, no lookup found anything and the reporter fell back to its own
    ``UnusedSuppressionsReporterConfig()``. Now every lookup finds the field's
    default, which is that same object.
    """
    config = _load(tmp_path, "project_name: probe\n")
    assert _resolved(config) == UnusedSuppressionsReporterConfig().model_dump()
    assert config.reporters.unused_suppressions.enabled is True
    assert config.reporters.unused_suppressions.options.output_format == "both"


REPO_ROOT = Path(__file__).resolve().parents[3]


# Listed rather than globbed: a glob under the repository root can descend into
# another xdist worker's scratch tree (see tests/unit/test_repo_walkers_skip_scratch.py).
SHIPPED_CONFIGS = [
    ".ash/.ash.yaml",
    ".ash/.ash_community_plugins.yaml",
    ".ash/.ash_no_ignore.yaml",
    "examples/ash_plugins_example/.ash/.ash.yaml",
]


@pytest.mark.parametrize("relpath", SHIPPED_CONFIGS)
def test_shipped_configs_still_load(relpath):
    """No committed config becomes invalid under the stricter load."""
    config = AshConfig.from_file(REPO_ROOT / relpath)
    _resolved(config)
