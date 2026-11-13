# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A section of a configuration, printed on its own, shows no value it read from
the environment, and neither does a plugin built from one.

A configuration's repr redacts what its files read through ``${VAR}``. A
section of it printed without the configuration around it, as a traceback with
locals (show_debug_locals) prints a frame that holds ``config.global_settings``
or an ignore-path entry, and a plugin, which runs with a section of its own
built from the configuration (ReportPhase builds each reporter that way), have
the same values in their fields. Each prints them as <value>; a literal value
stays readable.
"""

import inspect
from io import StringIO
from typing import Any, Iterator, Literal, Set, Type, get_args

import pytest
from pydantic import BaseModel
from rich.console import Console
from rich.traceback import Traceback

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.runtime_patch import apply_runtime_patch
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)
from automated_security_helper.utils.error_text import config_environment_values
from automated_security_helper.utils.redacted_model import NO_RICH_REPR

pytestmark = pytest.mark.unit

#: Values the file reads from the environment: an ignore path's reason (a
#: section's nested list), a scanner option (a section a plugin module's
#: scanner reads), and a reporter option.
REASON_CANARY = "zzsectionreason-6114"
NOTE_CANARY = "zzsectionnote-2087"
BUCKET_CANARY = "zzsectionbucket-9350"
CANARIES = (REASON_CANARY, NOTE_CANARY, BUCKET_CANARY)
#: Written literally beside them; redaction must not touch it.
LITERAL_PATH = "vendor/**"

WRITTEN = (
    "project_name: readable-section-project\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    f"    - path: {LITERAL_PATH}\n"
    "      reason: !ENV ${ASH_ZS_REASON}\n"
    "scanners:\n"
    "  zz-section-scanner:\n"
    "    enabled: true\n"
    "    options:\n"
    "      note: !ENV ${ASH_ZS_NOTE}\n"
    "reporters:\n"
    "  s3:\n"
    "    enabled: true\n"
    "    options:\n"
    "      bucket_name: !ENV ${ASH_ZS_BUCKET}\n"
)


class ZzSectionScannerOptions(ScannerOptionsBase):
    note: str = ""


class ZzSectionScannerConfig(ScannerPluginConfigBase):
    name: Literal["zz-section-scanner"] = "zz-section-scanner"
    options: ZzSectionScannerOptions = ZzSectionScannerOptions()


class ZzSectionScanner(ScannerPluginBase[ZzSectionScannerConfig]):
    """A scanner a plugin module could bring: never run, only built and printed."""

    def model_post_init(self, context: Any) -> None:
        super().model_post_init(context)
        # A value copied out of the section into a field of the plugin's own,
        # as plugins describe themselves from their options.
        self.tool_description = "notes: " + self.config.options.note

    def validate_plugin_dependencies(self) -> bool:
        return True

    def scan(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    def _execute_scan(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_ZS_REASON", REASON_CANARY)
    monkeypatch.setenv("ASH_ZS_NOTE", NOTE_CANARY)
    monkeypatch.setenv("ASH_ZS_BUCKET", BUCKET_CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "operator" / ".ash.yaml"
    path.parent.mkdir()
    path.write_text(WRITTEN, encoding="utf-8")
    return path


def _knows_its_values(config: AshConfig) -> AshConfig:
    """Controls: the config read each value and knows it read it."""
    if not set(config_environment_values(config)) >= set(CANARIES):
        raise RuntimeError("control: the config does not know the values it read")
    if not all(canary in config.model_dump_json() for canary in CANARIES):
        raise RuntimeError("control: a value is not in the config's fields")
    return config


@pytest.fixture
def config(config_file):
    _, loaded = resolve_config_module.load_config_file_for_run(config_file)
    return _knows_its_values(loaded)


def _shows_no_value(text: str) -> None:
    for canary in CANARIES:
        assert canary not in text, f"the env-read value {canary} prints as written"


def _traceback_text(local_value: Any) -> str:
    def failing(held):
        raise ValueError("the error whose traceback shows the frame's locals")

    try:
        failing(local_value)
    except ValueError:
        rendered = Traceback(show_locals=True, width=300)
    console = Console(
        file=StringIO(), width=300, force_terminal=False, color_system=None
    )
    console.print(rendered)
    return console.file.getvalue()


SECTIONS = {
    "global-settings": lambda c: c.global_settings,
    "ignore-path-entry": lambda c: c.global_settings.ignore_paths[0],
    "ignore-paths-list": lambda c: c.global_settings.ignore_paths,
    "scanners-section": lambda c: c.scanners,
    "reporters-section": lambda c: c.reporters,
}


@pytest.mark.parametrize("part", sorted(SECTIONS))
def test_a_section_printed_on_its_own_shows_no_environment_value(config, part):
    _shows_no_value(repr(SECTIONS[part](config)))
    _shows_no_value(str(SECTIONS[part](config)))


@pytest.mark.parametrize("part", sorted(SECTIONS))
def test_a_traceback_with_a_section_local_shows_no_environment_value(config, part):
    _shows_no_value(_traceback_text(SECTIONS[part](config)))


def test_a_section_keeps_a_literal_value_readable(config):
    text = repr(config.global_settings.ignore_paths[0])
    assert LITERAL_PATH in text, text
    assert "<value>" in text, text


def _s3_reporter(config, tmp_path) -> S3Reporter:
    """Built as ReportPhase builds each reporter: its section from the config."""
    context = PluginContext(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", config=config
    )
    plugin = S3Reporter(context=context, config=reporter_section(config, S3Reporter))
    if plugin.config.options.bucket_name != BUCKET_CANARY:
        raise RuntimeError("control: the reporter does not hold the value")
    return plugin


def _scanner(config, tmp_path) -> ZzSectionScanner:
    """Built as the scan builds a plugin module's scanner: its section from the
    config's scanners segment, validated by the plugin."""
    context = PluginContext(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", config=config
    )
    section = config.get_plugin_config(
        plugin_type="scanner", plugin_name="zz-section-scanner"
    )
    plugin = ZzSectionScanner(context=context, config=section)
    if plugin.config.options.note != NOTE_CANARY:
        raise RuntimeError("control: the scanner does not hold the value")
    return plugin


PLUGINS = {"reporter": _s3_reporter, "scanner": _scanner}


@pytest.mark.parametrize("kind", sorted(PLUGINS))
def test_a_plugin_built_from_the_config_shows_no_environment_value(
    config, tmp_path, kind
):
    plugin = PLUGINS[kind](config, tmp_path)
    _shows_no_value(repr(plugin))
    _shows_no_value(_traceback_text(plugin))
    # As ReportPhase holds its reporters: a list of them, a frame local.
    _shows_no_value(_traceback_text([plugin]))


@pytest.mark.parametrize("kind", sorted(PLUGINS))
def test_a_plugins_own_section_printed_on_its_own_shows_no_environment_value(
    config, tmp_path, kind
):
    plugin = PLUGINS[kind](config, tmp_path)
    _shows_no_value(repr(plugin.config))
    _shows_no_value(_traceback_text(plugin.config))


def test_a_section_assigned_after_the_load_shows_no_environment_value(config):
    rebuilt = type(config.global_settings).model_validate(
        config.global_settings.model_dump()
    )
    config.global_settings = rebuilt
    _shows_no_value(repr(config.global_settings))


def test_a_copy_with_a_new_section_shows_no_environment_value(config):
    rebuilt = type(config.global_settings).model_validate(
        config.global_settings.model_dump()
    )
    copied = config.model_copy(update={"global_settings": rebuilt})
    _shows_no_value(repr(copied.global_settings))


def test_the_sections_of_a_config_resolved_with_overrides_show_no_environment_value(
    config_file, tmp_path
):
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    resolved = resolve_config_module.resolve_config(
        config_path=config_file,
        source_dir=scanned,
        config_overrides=["fail_on_findings=false"],
    )
    _knows_its_values(resolved)
    if resolved.fail_on_findings is not False:
        raise RuntimeError("control: the override did not apply")
    for part in sorted(SECTIONS):
        _shows_no_value(repr(SECTIONS[part](resolved)))


def test_rich_finds_no_field_by_field_repr_to_call(config, tmp_path):
    """Rich prints a model through its __rich_repr__ when it has one, and
    pydantic gives every model one that yields each field's raw value. A
    redacted model has none, so Rich prints its repr; that holds by the model's
    own answer, not by Rich swallowing an error it raises."""
    held = [SECTIONS[part](config) for part in sorted(SECTIONS)]
    held += [config, PLUGINS["reporter"](config, tmp_path)]
    held += [PLUGINS["scanner"](config, tmp_path)]
    offered = [type(item).__name__ for item in held if hasattr(item, "__rich_repr__")]
    assert offered == [], offered


def test_the_sections_of_a_config_a_runtime_patch_rebuilt_show_no_environment_value(
    config,
):
    """An MCP client's patch rebuilds the config from its dump and gives the new
    one the base's recorded values all at once (config/runtime_patch.py)."""
    allowlist = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/project_name"], denied_paths=[]
    )
    patched = apply_runtime_patch(
        config,
        [{"op": "replace", "path": "/project_name", "value": "renamed"}],
        allowlist=allowlist,
    )
    _knows_its_values(patched)
    if patched.project_name != "renamed":
        raise RuntimeError("control: the patch did not apply")
    for part in sorted(SECTIONS):
        _shows_no_value(repr(SECTIONS[part](patched)))


def test_a_section_given_a_new_entry_shows_no_environment_value(config):
    """An entry put into a section's field takes the section's values."""
    entry = IgnorePathWithReason(path="other/**", reason=REASON_CANARY)
    config.global_settings.ignore_paths = [entry]
    _shows_no_value(repr(config.global_settings.ignore_paths[0]))


def test_an_entry_a_sections_copy_puts_in_shows_no_environment_value(config):
    """An entry given to a section's ``model_copy(update=...)`` was never put
    in a config, so the copy carries this section's values into it, as the
    config's own copy does for a section passed in ``update``."""
    entry = IgnorePathWithReason(path="other/**", reason=REASON_CANARY)
    copied = config.global_settings.model_copy(update={"ignore_paths": [entry]})
    if copied.ignore_paths[0].reason != REASON_CANARY:
        raise RuntimeError("control: the update did not apply")
    _shows_no_value(repr(copied.ignore_paths[0]))
    _shows_no_value(str(copied.ignore_paths[0]))


def test_an_entry_appended_in_place_is_carried_when_the_field_is_assigned(config):
    """A list's ``append`` tells the section nothing, so the appended entry
    carries no values until the field is assigned -- the documented remedy
    (RedactedSection's docstring). The docstring names the whole in-place
    write class, not just append: insert, extend, item and slice assignment,
    and dict-key writes all bypass the section the same way. The section's own
    text redacts either way, because the section redacts with its own record."""
    from automated_security_helper.utils import redacted_model

    documented = redacted_model.RedactedSection.__doc__ or ""
    assert "written in place" in documented, (
        "the in-place write limit is not documented"
    )
    for named in ("insert", "extend", "slice", "dict key", "Assigning the field"):
        assert named in documented, (
            f"the documented in-place write class does not name {named!r}"
        )
    entry = IgnorePathWithReason(path="other/**", reason=REASON_CANARY)
    config.global_settings.ignore_paths.append(entry)
    if REASON_CANARY not in repr(entry):
        raise RuntimeError("control: an appended entry is expected to carry nothing")
    _shows_no_value(repr(config.global_settings))
    config.global_settings.ignore_paths = config.global_settings.ignore_paths
    _shows_no_value(repr(config.global_settings.ignore_paths[-1]))


def test_a_sections_record_leaves_unknown_comparisons_to_the_other_side(config):
    """The record answers equality only for another record; anything else is
    left to the other side (NotImplemented), so a stand-in that equals
    anything, as unittest.mock.ANY is, equals a record from either side."""
    from unittest import mock

    record = config.global_settings._environment_record
    assert (record == mock.ANY) is True
    assert (mock.ANY == record) is True
    assert record == type(record)()
    assert (record == object()) is False


def test_a_config_built_without_a_file_redacts_its_sections_too(monkeypatch):
    """Every config records the reporter defaults read from the environment,
    however it is built, and its sections redact with them."""
    monkeypatch.setenv("ASH_S3_BUCKET_NAME", BUCKET_CANARY)
    built = AshConfig(
        project_name="built",
        global_settings={"ignore_paths": [{"path": "x/**", "reason": BUCKET_CANARY}]},
    )
    if BUCKET_CANARY not in config_environment_values(built):
        raise RuntimeError("control: the config did not record the reporter default")
    _shows_no_value(repr(built.global_settings.ignore_paths[0]))


def test_a_section_that_carries_values_equals_one_that_does_not(config, monkeypatch):
    """The values are not part of a section's value: a section equals its
    rebuilt copy, and one equal to its default still drops out of a dump that
    leaves out defaults."""
    rebuilt = type(config.global_settings).model_validate(
        config.global_settings.model_dump()
    )
    assert rebuilt == config.global_settings
    monkeypatch.setenv("ASH_S3_BUCKET_NAME", BUCKET_CANARY)
    built = AshConfig(project_name="built")
    if BUCKET_CANARY not in config_environment_values(built):
        raise RuntimeError("control: the config did not record the reporter default")
    assert "global_settings" not in built.model_dump(exclude_defaults=True)


def _model_types(annotation: Any) -> Iterator[Type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
    for argument in get_args(annotation):
        yield from _model_types(argument)


def _reachable_models() -> Set[Type[BaseModel]]:
    """Every model type a configuration's fields can hold, a plugin section's
    included; a plugin's own fields (its context) are not a section."""
    found: Set[Type[BaseModel]] = set()
    pending = [AshConfig]
    while pending:
        model = pending.pop()
        if model in found:
            continue
        found.add(model)
        if issubclass(model, PluginBase):
            continue
        annotations = [info.annotation for info in model.model_fields.values()]
        extra = getattr(model, "__annotations__", {}).get("__pydantic_extra__")
        if extra is not None:
            annotations.append(extra)
        for annotation in annotations:
            pending.extend(_model_types(annotation))
    return found


def test_every_model_a_config_holds_prints_redacted():
    """Structural: each model type a configuration can hold redacts its own
    repr and str, and gives Rich no field-by-field repr around it."""
    reachable = _reachable_models()
    if len(reachable) < 10 or ScannerPluginConfigBase not in reachable:
        raise RuntimeError(("control: the walk missed the sections", reachable))
    unredacted = sorted(
        model.__name__
        for model in reachable
        if model.__repr_str__ is BaseModel.__repr_str__
        or inspect.getattr_static(model, "__rich_repr__", None) is not NO_RICH_REPR
    )
    assert unredacted == [], unredacted
