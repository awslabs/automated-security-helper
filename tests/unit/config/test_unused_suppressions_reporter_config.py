# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unused-suppressions reporter is a declared ReporterConfigSegment field.

Why this file exists
--------------------
Before the field was declared, the reporter's config reached it only through the
segment's ``extra="allow"``. It ran, and ``get_plugin_config`` found it under
either spelling, but it was missing from the published AshConfig.json schema and
nothing validated its options until the reporter itself did.

Declaring it changes three things that a config author can observe, and each is
pinned here:

* Both spellings a config might use today, ``unused-suppressions`` and
  ``unused_suppressions``, still load and resolve to the same settings under
  every name ``get_plugin_config`` is asked for. Without the segment's
  before-validator, the underscore key would land in the extras while the field
  kept its defaults, and two lookups would disagree.
* A bad option value is rejected when the config loads. That is a behavior
  change: such a config used to load, and the reporter failed later.
* A config that does not mention the reporter gets the reporter's own defaults,
  as it did before.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError
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
def test_either_spelling_loads_validates_and_resolves_the_same(tmp_path, key):
    config = _load(
        tmp_path,
        f"""
project_name: probe
reporters:
  {key}:
    enabled: false
    options:
      output_format: json
""",
    )
    field = config.reporters.unused_suppressions
    assert isinstance(field, UnusedSuppressionsReporterConfig)
    assert field.enabled is False
    assert field.options.output_format == "json"
    # One copy of the settings, in the field: nothing left behind in the extras
    # for a lookup to find instead.
    assert not (config.reporters.__pydantic_extra__ or {})
    resolved = _resolved(config)
    assert resolved["enabled"] is False
    assert resolved["options"]["output_format"] == "json"


def test_both_spellings_merge_with_the_hyphenated_key_winning(tmp_path):
    config = _load(
        tmp_path,
        """
project_name: probe
reporters:
  unused_suppressions:
    enabled: false
    options:
      output_format: markdown
  unused-suppressions:
    options:
      output_format: json
""",
    )
    resolved = _resolved(config)
    # output_format is set by both, and the documented spelling wins.
    assert resolved["options"]["output_format"] == "json"
    # enabled is set only under the underscore key, and is kept.
    assert resolved["enabled"] is False
    assert not (config.reporters.__pydantic_extra__ or {})


def test_an_override_keeps_the_rest_of_the_file_settings(tmp_path):
    """apply_config_overrides round-trips the config through model_dump().

    That dump is keyed by field name, so the file's settings come back as
    ``unused_suppressions`` while an override written as documented adds
    ``unused-suppressions`` with only the overridden key. Keeping just one of
    the two would silently revert either the override or the file.
    """
    config = _load(
        tmp_path,
        """
project_name: probe
reporters:
  unused-suppressions:
    enabled: false
""",
    )
    overridden = apply_config_overrides(
        config, ["reporters.unused-suppressions.options.output_format=json"]
    )
    resolved = _resolved(overridden)
    assert resolved["options"]["output_format"] == "json"
    assert resolved["enabled"] is False


def test_an_override_with_no_touch_to_the_reporter_keeps_its_settings(tmp_path):
    config = _load(
        tmp_path,
        """
project_name: probe
reporters:
  unused-suppressions:
    enabled: false
    options:
      output_format: markdown
""",
    )
    overridden = apply_config_overrides(config, ["fail_on_findings=false"])
    resolved = _resolved(overridden)
    assert resolved["enabled"] is False
    assert resolved["options"]["output_format"] == "markdown"


@pytest.mark.parametrize("key", ["unused-suppressions", "unused_suppressions"])
@pytest.mark.parametrize(
    "body, bad_path",
    [
        ("enabled: not-a-bool", "reporters.unused-suppressions.enabled"),
        (
            "options:\n      output_format: 5",
            "reporters.unused-suppressions.options.output_format",
        ),
    ],
)
def test_an_invalid_option_is_rejected_when_the_config_loads(
    tmp_path, key, body, bad_path
):
    """The validation gain, and the behavior change that comes with it.

    Before the field was declared, both of these configs loaded: the values sat
    unvalidated in the segment's extras until the reporter was built. Now the
    load itself fails, and names the offending path.
    """
    with pytest.raises(ValidationError) as excinfo:
        _load(
            tmp_path,
            f"""
project_name: probe
reporters:
  {key}:
    {body}
""",
        )
    assert bad_path in str(excinfo.value)


def test_an_invalid_override_is_rejected(tmp_path):
    config = _load(tmp_path, "project_name: probe\n")
    with pytest.raises(ASHConfigValidationError):
        apply_config_overrides(
            config, ["reporters.unused-suppressions.enabled=not-a-bool"]
        )


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


def test_lint_still_steers_to_the_hyphen_and_says_what_happens(tmp_path):
    """The underscore spelling is still a lint warning, with an accurate reason.

    The generic message says a snake-form key lands in the extras and the
    built-in keeps its defaults. For this key that is no longer true, so the
    message must not claim it.
    """
    from automated_security_helper.config.config_linter import (
        ConfigLinter,
        LintCategory,
    )

    path = tmp_path / ".ash.yaml"
    path.write_text(
        "project_name: t\nreporters:\n  unused_suppressions:\n    enabled: false\n",
        encoding="utf-8",
    )
    issues = [
        i
        for i in ConfigLinter.lint(path).issues
        if i.category == LintCategory.LEGACY_NAME_VARIANT
    ]
    assert len(issues) == 1
    assert "'unused-suppressions'" in issues[0].message
    assert "ASH reads it as 'unused-suppressions'" in issues[0].message
    assert "keeps its default config" not in issues[0].message


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
