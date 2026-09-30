# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A declared plugin field reads the same under its alias and its field name.

Why this file exists
--------------------
Several built-in plugins are declared with a hyphenated alias that differs from
the Python field name: ``gitlab-sast`` / ``gitlab_sast``, ``cdk-nag`` /
``cdk_nag`` and so on. The config segments do not set ``populate_by_name``, so
before the shared before-validator, a key written with the field name landed in
the segment's ``extra="allow"`` bucket, unvalidated, while the declared field
kept its defaults. Two things went wrong from there:

* Lookups disagreed. ``get_plugin_config`` by the alias returned the defaults,
  while the runtime lookup by class name could reach the extras copy. For a
  scanner, the runtime lookup got the defaults, so ``cdk_nag: {enabled: false}``
  did not disable the scanner.
* ``--config-overrides`` reverted settings. ``apply_config_overrides``
  round-trips through ``model_dump()``, which is keyed by field name, so the
  file's settings came back as ``gitlab_sast`` while an override written as
  documented added ``gitlab-sast`` holding only the overridden key.

Every case is parametrized over the aliased fields read from the segments'
``model_fields``, not a list written here, so a newly aliased plugin is covered
without editing this file.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import (
    AshConfig,
    ConverterConfigSegment,
    ReporterConfigSegment,
    ScannerConfigSegment,
)
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError

SEGMENTS = {
    "scanners": ("scanner", ScannerConfigSegment),
    "reporters": ("reporter", ReporterConfigSegment),
    "converters": ("converter", ConverterConfigSegment),
}


def _aliased_fields():
    cases = []
    for segment, (plugin_type, segment_cls) in SEGMENTS.items():
        for field_name, info in segment_cls.model_fields.items():
            if info.alias and info.alias != field_name:
                cases.append(
                    pytest.param(
                        segment,
                        plugin_type,
                        field_name,
                        info.alias,
                        info.annotation,
                        id=f"{segment}.{info.alias}",
                    )
                )
    return cases


ALIASED = _aliased_fields()


def test_the_parametrization_is_not_empty():
    """Guards the derivation: an empty list would make every test below vacuous."""
    ids = {p.id for p in ALIASED}
    for expected in (
        "reporters.gitlab-sast",
        "reporters.flat-json",
        "reporters.github-ghas",
        "reporters.gitlab-cyclonedx",
        "reporters.unused-suppressions",
        "scanners.cdk-nag",
    ):
        assert expected in ids, sorted(ids)


def _runtime_lookup_name(plugin_type: str, config_cls: type) -> str:
    """The name the scan and report phases look this plugin up by.

    Both pass ``plugin_class.__name__.lower()``, so find the registered plugin
    class whose ``config`` field is this config class.
    """
    import typing

    import automated_security_helper.plugin_modules.ash_builtin  # noqa: F401
    import automated_security_helper.plugin_modules.ash_builtin.reporters  # noqa: F401
    import automated_security_helper.plugin_modules.ash_builtin.scanners  # noqa: F401
    from automated_security_helper.plugins import ash_plugin_manager

    for cls in ash_plugin_manager.plugin_modules(plugin_type):
        annotation = cls.model_fields["config"].annotation
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if (args[0] if args else annotation) is config_cls:
            return cls.__name__.lower()
    raise AssertionError(f"no registered {plugin_type} uses {config_cls.__name__}")


def _load(tmp_path: Path, yaml_text: str) -> AshConfig:
    path = tmp_path / ".ash.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return AshConfig.from_file(path)


def _resolved(config, plugin_type, field_name, alias, config_cls) -> dict:
    """What the alias and field-name lookups resolve to, asserted to be one value.

    The runtime lookup by class name is checked separately, in
    test_the_runtime_lookup_finds_the_same_settings, because one plugin misses
    it for a reason unrelated to spelling.
    """
    names = [alias, field_name]
    found = {n: config.get_plugin_config(plugin_type, n) for n in names}
    values = list(found.values())
    assert values[0] is not None, f"no lookup found the plugin: {found}"
    assert all(v == values[0] for v in values), f"lookups disagree: {found}"
    return config_cls.model_validate(values[0]).model_dump()


@pytest.mark.parametrize("spelling", ["alias", "field_name"])
@pytest.mark.parametrize("segment, plugin_type, field_name, alias, config_cls", ALIASED)
def test_either_spelling_loads_and_resolves_the_same(
    tmp_path, segment, plugin_type, field_name, alias, config_cls, spelling
):
    key = alias if spelling == "alias" else field_name
    config = _load(
        tmp_path,
        f"""
project_name: probe
{segment}:
  {key}:
    enabled: false
    options:
      probe_marker: from-the-file
""",
    )
    field = getattr(getattr(config, segment), field_name)
    assert isinstance(field, config_cls)
    assert field.enabled is False
    # One copy of the settings, in the field: nothing left in the extras for a
    # lookup to find instead.
    assert not (getattr(config, segment).__pydantic_extra__ or {})
    resolved = _resolved(config, plugin_type, field_name, alias, config_cls)
    assert resolved["enabled"] is False
    assert resolved["options"]["probe_marker"] == "from-the-file"


def _runtime_lookup_cases():
    cases = []
    for param in ALIASED:
        if param.id == "reporters.github-ghas":
            # GHASReporter's lowercased class name, "ghasreporter", reduces to
            # "ghas", and the key "github-ghas" reduces to "githubghas", so
            # get_plugin_config never matches them and the reporter always runs
            # with its defaults. That is a name-reduction defect in
            # get_plugin_config, not the alias split this file covers. strict,
            # so the fix turns this red and the mark has to come off.
            param = pytest.param(
                *param.values,
                id=param.id,
                marks=pytest.mark.xfail(
                    strict=True,
                    reason="get_plugin_config cannot match GHASReporter to github-ghas",
                ),
            )
        cases.append(param)
    return cases


@pytest.mark.parametrize("spelling", ["alias", "field_name"])
@pytest.mark.parametrize(
    "segment, plugin_type, field_name, alias, config_cls", _runtime_lookup_cases()
)
def test_the_runtime_lookup_finds_the_same_settings(
    tmp_path, segment, plugin_type, field_name, alias, config_cls, spelling
):
    """The scan and report phases look plugins up by lowercased class name."""
    key = alias if spelling == "alias" else field_name
    config = _load(
        tmp_path,
        f"""
project_name: probe
{segment}:
  {key}:
    enabled: false
""",
    )
    expected = _resolved(config, plugin_type, field_name, alias, config_cls)
    runtime = config.get_plugin_config(
        plugin_type, _runtime_lookup_name(plugin_type, config_cls)
    )
    assert runtime is not None, "the runtime lookup found nothing"
    assert config_cls.model_validate(runtime).model_dump() == expected


@pytest.mark.parametrize("segment, plugin_type, field_name, alias, config_cls", ALIASED)
def test_both_spellings_merge_with_the_alias_winning(
    tmp_path, segment, plugin_type, field_name, alias, config_cls
):
    config = _load(
        tmp_path,
        f"""
project_name: probe
{segment}:
  {field_name}:
    enabled: false
    options:
      probe_marker: field-name
  {alias}:
    options:
      probe_marker: alias
""",
    )
    resolved = _resolved(config, plugin_type, field_name, alias, config_cls)
    # Set by both: the documented spelling wins.
    assert resolved["options"]["probe_marker"] == "alias"
    # Set only under the field name: kept.
    assert resolved["enabled"] is False
    assert not (getattr(config, segment).__pydantic_extra__ or {})


@pytest.mark.parametrize("spelling", ["alias", "field_name"])
@pytest.mark.parametrize("segment, plugin_type, field_name, alias, config_cls", ALIASED)
def test_an_override_keeps_the_rest_of_the_file_settings(
    tmp_path, segment, plugin_type, field_name, alias, config_cls, spelling
):
    """The file's settings survive an override of another key, and vice versa."""
    key = alias if spelling == "alias" else field_name
    config = _load(
        tmp_path,
        f"""
project_name: probe
{segment}:
  {key}:
    enabled: false
""",
    )
    overridden = apply_config_overrides(
        config, [f"{segment}.{alias}.options.probe_marker=from-the-override"]
    )
    resolved = _resolved(overridden, plugin_type, field_name, alias, config_cls)
    assert resolved["options"]["probe_marker"] == "from-the-override"
    assert resolved["enabled"] is False


@pytest.mark.parametrize("segment, plugin_type, field_name, alias, config_cls", ALIASED)
def test_an_unrelated_override_keeps_the_settings(
    tmp_path, segment, plugin_type, field_name, alias, config_cls
):
    config = _load(
        tmp_path,
        f"""
project_name: probe
{segment}:
  {field_name}:
    enabled: false
""",
    )
    overridden = apply_config_overrides(config, ["fail_on_findings=false"])
    resolved = _resolved(overridden, plugin_type, field_name, alias, config_cls)
    assert resolved["enabled"] is False


@pytest.mark.parametrize("spelling", ["alias", "field_name"])
@pytest.mark.parametrize("segment, plugin_type, field_name, alias, config_cls", ALIASED)
def test_an_invalid_value_is_rejected_when_the_config_loads(
    tmp_path, segment, plugin_type, field_name, alias, config_cls, spelling
):
    """Under the field-name spelling this is a behavior change.

    That spelling used to land unvalidated in the extras, so the config loaded
    and the bad value was ignored (or failed later, when the plugin was built).
    """
    key = alias if spelling == "alias" else field_name
    with pytest.raises(ValidationError) as excinfo:
        _load(
            tmp_path,
            f"""
project_name: probe
{segment}:
  {key}:
    enabled: not-a-bool
""",
        )
    assert f"{segment}.{alias}.enabled" in str(excinfo.value)


@pytest.mark.parametrize("segment, plugin_type, field_name, alias, config_cls", ALIASED)
def test_an_invalid_override_is_rejected(
    tmp_path, segment, plugin_type, field_name, alias, config_cls
):
    config = _load(tmp_path, "project_name: probe\n")
    with pytest.raises(ASHConfigValidationError):
        apply_config_overrides(config, [f"{segment}.{field_name}.enabled=not-a-bool"])


@pytest.mark.parametrize("segment, plugin_type, field_name, alias, config_cls", ALIASED)
def test_lint_still_steers_to_the_alias_and_says_what_happens(
    tmp_path, segment, plugin_type, field_name, alias, config_cls
):
    """The field-name spelling is still a lint warning, with an accurate reason.

    The linter used to say that spelling lands in the extras and the built-in
    keeps its defaults. That is no longer true for any aliased field.
    """
    from automated_security_helper.config.config_linter import (
        ConfigLinter,
        LintCategory,
    )

    path = tmp_path / ".ash.yaml"
    path.write_text(
        f"project_name: t\n{segment}:\n  {field_name}:\n    enabled: false\n",
        encoding="utf-8",
    )
    issues = [
        i
        for i in ConfigLinter.lint(path).issues
        if i.category == LintCategory.LEGACY_NAME_VARIANT
    ]
    assert len(issues) == 1
    assert f"ASH reads it as {alias!r}" in issues[0].message
    assert "keeps its default config" not in issues[0].message
