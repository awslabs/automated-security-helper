# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The run's plugin failure record shows an env-read value on no surface.

The record lives on the PluginContext, so it has every surface the context
has: the dumps (excluded, and pinned here so removing the exclusion fails),
pydantic's repr (which shows excluded fields too) and the recorded texts. For
an entry the config read from the environment, the resolved module path IS
the variable's value: the record is keyed by it but stays out of repr and
every dump, and the refusal prints only the shown label -- the error's kind
alone for a masked name, while a literal name keeps its full, readable error
text.
"""

from __future__ import annotations

import json
import sys

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugins.loader import (
    PluginLoadFailure,
    PluginModuleImportError,
    load_plugins,
)

pytestmark = pytest.mark.unit

SENTINEL = "recsentinel_ash_plugins"
#: The env-read value: a module that does not exist, so the error quotes it.
VALUE = "recval_ash_plugins"
#: Exists; its import error quotes its own name.
SELF_QUOTING = "recself_ash_plugins"
#: Named literally in the file; imports a missing dependency.
LITERAL = "reclit_ash_plugins"
LITERAL_DEP = "reclitdep_for_record"


def _context(tmp_path, config=None):
    from automated_security_helper.config.ash_config import AshConfig

    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=config if config is not None else AshConfig(),
    )


DUMPS = {
    "model_dump": lambda m: json.dumps(m.model_dump(), default=str),
    "model_dump-json-mode": lambda m: json.dumps(m.model_dump(mode="json")),
    "model_dump_json": lambda m: m.model_dump_json(),
    "model_dump-by-alias": lambda m: json.dumps(
        m.model_dump(by_alias=True), default=str
    ),
    "model_dump-exclude-none": lambda m: json.dumps(
        m.model_dump(exclude_none=True), default=str
    ),
}


@pytest.mark.parametrize("dump", list(DUMPS))
def test_a_context_dump_never_holds_the_record(tmp_path, dump):
    context = _context(tmp_path)
    context.plugin_load_record[SENTINEL] = PluginLoadFailure(
        recorded="ModuleNotFoundError: x " + SENTINEL, kind="ModuleNotFoundError"
    )
    assert SENTINEL in context.plugin_load_record, "control: the record holds it"
    text = DUMPS[dump](context)
    assert "plugin_load_record" not in text, text[:2000]
    assert SENTINEL not in text, text[:2000]


@pytest.mark.parametrize("dump", list(DUMPS))
def test_a_model_carrying_a_context_never_dumps_its_record(tmp_path, dump):
    """ScanResultsContainer.raw_results is declared ``Any``, so it admits a
    scanner and with it the PluginContext. BuildConfig.custom_scanners used to
    be the carrier but is refused at construction (next cell); this declared
    field is the path that remains from a results model to a context."""
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    context = _context(tmp_path)
    context.plugin_load_record[SENTINEL] = PluginLoadFailure(
        recorded="ImportError: " + SENTINEL, kind="ImportError"
    )
    scanner = DetectSecretsScanner(context=context)
    container = ScanResultsContainer(scanner_name="probe", raw_results=scanner)
    assert container.raw_results.context.plugin_load_record, (
        "control: the carried record is set"
    )
    text = DUMPS[dump](container)
    assert '"work_dir"' in text, (
        "control: the dump walked the carried context, so it could have shown "
        "the record: " + text[:2000]
    )
    assert SENTINEL not in text, text[:2000]


@pytest.mark.parametrize("dump", list(DUMPS))
def test_the_aggregated_results_carrying_a_scanner_never_dump_its_record(
    tmp_path, dump
):
    """The scan copies a container whose raw_results is neither SARIF nor
    CycloneDX into AshAggregatedResults.additional_reports as the object itself
    (ScanResultProcessor.process_container's last branch), and that model is
    the one written to disk. Built here the way that branch builds it."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    context = _context(tmp_path)
    context.plugin_load_record[SENTINEL] = PluginLoadFailure(
        recorded="ImportError: " + SENTINEL, kind="ImportError"
    )
    scanner = DetectSecretsScanner(context=context)
    aggregated = AshAggregatedResults()
    aggregated.additional_reports = {"probe": {"source": {"raw_results": scanner}}}
    assert scanner.context.plugin_load_record, "control: the carried record is set"
    text = DUMPS[dump](aggregated)
    assert '"work_dir"' in text, (
        "control: the dump walked the carried context, so it could have shown "
        "the record: " + text[:2000]
    )
    assert SENTINEL not in text, text[:2000]


def test_the_custom_scanner_refusal_surfaces_none_of_the_record(tmp_path):
    """BuildConfig.custom_scanners, the config-side path to a PluginContext, is
    refused at construction, so there is no dump to check there. This cell
    pins that the refusal itself surfaces none of the record text. The error
    carries the refused entry as each entry's ``input``, so the surfaces that
    walk the scanner are the entry's repr (which depends on the field's
    ``repr=False``) and the error's ``json()`` (which serializes the input and
    depends on ``exclude=True``). The error's str and repr only hold a cut
    ``input_value=``, so they are checked too but cannot fail on a lost pin;
    the CHANGELOG describes consumers quoting ``errors()`` and ``json()``."""
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import BuildConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    context = _context(tmp_path)
    context.plugin_load_record[SENTINEL] = PluginLoadFailure(
        recorded="ImportError: " + SENTINEL, kind="ImportError"
    )
    scanner = DetectSecretsScanner(context=context)
    assert SENTINEL in scanner.context.plugin_load_record, (
        "control: the carried record is set"
    )
    with pytest.raises(ValidationError) as caught:
        BuildConfig(custom_scanners=[scanner])
    assert "custom_scanners is not supported" in str(caught.value)
    assert SENTINEL not in str(caught.value)
    assert SENTINEL not in repr(caught.value)
    errors = caught.value.errors()
    assert errors, "control: the refusal carries error entries"
    for err in errors:
        assert SENTINEL not in str(err.get("loc"))
        assert SENTINEL not in str(err.get("msg"))
        assert SENTINEL not in str(err.get("type"))
        shown = repr(err["input"])
        assert str(context.work_dir) in shown, (
            "control: the repr walked the carried context: " + shown[:2000]
        )
        assert SENTINEL not in shown, shown[:2000]
    as_json = caught.value.json()
    assert str(context.work_dir) in as_json, (
        "control: json() serialized the carried context: " + as_json[:2000]
    )
    assert SENTINEL not in as_json, as_json[:2000]


def test_a_build_config_without_entries_holds_no_context():
    """The refusal leaves the empty default as the only state, so a config
    model has no field through which a context could be carried."""
    from automated_security_helper.config.ash_config import BuildConfig

    assert BuildConfig().custom_scanners == []


@pytest.mark.parametrize("route", ["assignment", "model_construct"])
@pytest.mark.parametrize("dump", list(DUMPS))
def test_a_build_config_forced_to_hold_a_context_never_dumps_its_record(
    tmp_path, dump, route
):
    """The refusal runs in validation, and neither route below validates:
    BuildConfig sets no validate_assignment, and model_construct skips
    validation by design. A config that holds a scanner anyway therefore still
    reaches every dump, so the record's exclusion is pinned on this carrier
    too, not only on the models that declare a field for a scanner."""
    from automated_security_helper.config.ash_config import BuildConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    context = _context(tmp_path)
    context.plugin_load_record[SENTINEL] = PluginLoadFailure(
        recorded="ImportError: " + SENTINEL, kind="ImportError"
    )
    scanner = DetectSecretsScanner(context=context)
    if route == "assignment":
        build = BuildConfig()
        build.custom_scanners = [scanner]
    else:
        build = BuildConfig.model_construct(custom_scanners=[scanner])
    assert build.custom_scanners[0].context.plugin_load_record, (
        "control: the carried record is set"
    )
    text = DUMPS[dump](build)
    assert '"work_dir"' in text, (
        "control: the dump walked the carried context, so it could have shown "
        "the record: " + text[:2000]
    )
    assert SENTINEL not in text, text[:2000]


@pytest.fixture
def env_read_failing(tmp_path, monkeypatch):
    modules = tmp_path / "modules"
    (modules / SELF_QUOTING).mkdir(parents=True)
    (modules / SELF_QUOTING / "__init__.py").write_text(
        f"from {SELF_QUOTING} import does_not_exist  # noqa: F401\n", encoding="utf-8"
    )
    (modules / LITERAL).mkdir(parents=True)
    (modules / LITERAL / "__init__.py").write_text(
        f"import {LITERAL_DEP}  # noqa: F401\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(modules))
    for name in (SELF_QUOTING, LITERAL, VALUE):
        monkeypatch.delitem(sys.modules, name, raising=False)
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path / "src")
    (tmp_path / "cfg").mkdir()
    yield tmp_path
    for name in (SELF_QUOTING, LITERAL, VALUE):
        sys.modules.pop(name, None)


def _refused(tmp_path, entry, monkeypatch, value=None):
    if value is not None:
        monkeypatch.setenv("ASH_RECPROBE", value)
    config_file = tmp_path / "cfg" / "ash.yaml"
    config_file.write_text(
        f"project_name: probe\nash_plugin_modules:\n  - {entry}\n", encoding="utf-8"
    )
    context = _context(tmp_path, resolve_config(config_path=str(config_file)))
    with pytest.raises(PluginModuleImportError) as caught:
        load_plugins(plugin_context=context)
    return context, str(caught.value)


@pytest.mark.parametrize(
    "value,kind",
    [(VALUE, "ModuleNotFoundError"), (SELF_QUOTING, "ImportError")],
    ids=["missing", "self-quoting"],
)
def test_the_recorded_text_holds_no_env_value(
    env_read_failing, monkeypatch, value, kind
):
    context, _ = _refused(env_read_failing, "${ASH_RECPROBE}", monkeypatch, value)
    assert context.plugin_load_record, "control: the failure was recorded"
    texts = [failure.recorded for failure in context.plugin_load_record.values()]
    assert all(value not in text for text in texts), texts
    assert all(f.kind == kind for f in context.plugin_load_record.values())


@pytest.mark.parametrize(
    "value", [VALUE, SELF_QUOTING], ids=["missing", "self-quoting"]
)
def test_each_failing_module_keeps_its_own_record_entry(
    env_read_failing, monkeypatch, value
):
    """The record is keyed by the module path, one entry per real module:
    keying by the shown form made every env-read entry share the one
    '<value>' key. The keys reach no surface -- the dump and repr cells here
    pin that -- and the refusal prints shown labels, never keys."""
    context, refusal = _refused(env_read_failing, "${ASH_RECPROBE}", monkeypatch, value)
    assert list(context.plugin_load_record) == [value], list(context.plugin_load_record)
    assert value not in refusal, refusal


@pytest.mark.parametrize(
    "value", [VALUE, SELF_QUOTING], ids=["missing", "self-quoting"]
)
def test_the_contexts_repr_never_shows_the_record(env_read_failing, monkeypatch, value):
    """pydantic's repr shows every field, exclude=True ones too, so the record
    is also repr=False, and with the config's own repr redacting its env-read
    values the WHOLE repr(PluginContext) is value-free -- not only the
    record's contribution."""
    context, _ = _refused(env_read_failing, "${ASH_RECPROBE}", monkeypatch, value)
    assert context.plugin_load_record, "control: the failure was recorded"
    shown = repr(context)
    assert "plugin_load_record" not in shown, "the context's repr shows the record"
    assert value not in shown, "the context's repr shows the env value"
    # The recorded texts stay value-free; the keys are the module paths by
    # design and reach no surface (the field is out of repr and every dump,
    # and a configured failure refuses the run before
    # metadata.plugin_load_errors is written).
    recorded = " ".join(
        failure.recorded for failure in context.plugin_load_record.values()
    )
    assert value not in recorded, recorded


@pytest.mark.parametrize(
    "value,kind",
    [(VALUE, "ModuleNotFoundError"), (SELF_QUOTING, "ImportError")],
    ids=["missing", "self-quoting"],
)
def test_the_masked_refusal_names_the_right_kind(
    env_read_failing, monkeypatch, value, kind
):
    """The masked arm's wording itself, not only the value's absence: without
    it, the record-time redaction alone would keep these green."""
    _, refusal = _refused(env_read_failing, "${ASH_RECPROBE}", monkeypatch, value)
    assert f"'<value>' ({kind}, whose text is not shown" in refusal, refusal
    assert value not in refusal, refusal


def test_a_literal_name_and_its_error_stay_readable(env_read_failing, monkeypatch):
    """Redaction costs a literal name nothing: its refusal keeps the module
    name and the error's own words."""
    _, refusal = _refused(
        env_read_failing, LITERAL, monkeypatch, value="recprobe_unrelated_value"
    )
    assert (
        f"'{LITERAL}' (ModuleNotFoundError: No module named '{LITERAL_DEP}')" in refusal
    ), refusal
    assert "REDACTED" not in refusal, refusal


#: A second env-read entry beside the first: importable, so only one fails.
GOOD = "recgood_ash_plugins"


@pytest.fixture
def two_env_entries(env_read_failing, monkeypatch):
    """Two entries, each read from its own variable; returns the refusing run."""
    modules = env_read_failing / "modules"
    (modules / GOOD).mkdir()
    (modules / GOOD / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.delitem(sys.modules, GOOD, raising=False)

    def refuse(first, second):
        monkeypatch.setenv("ASH_RECPROBE_A", first)
        monkeypatch.setenv("ASH_RECPROBE_B", second)
        config_file = env_read_failing / "cfg" / "ash.yaml"
        config_file.write_text(
            "project_name: probe\nash_plugin_modules:\n"
            "  - ${ASH_RECPROBE_A}\n  - ${ASH_RECPROBE_B}\n",
            encoding="utf-8",
        )
        context = _context(
            env_read_failing, resolve_config(config_path=str(config_file))
        )
        with pytest.raises(PluginModuleImportError) as caught:
            load_plugins(plugin_context=context)
        return context, str(caught.value)

    yield refuse
    sys.modules.pop(GOOD, None)


def test_one_failure_of_two_env_read_entries_is_named_once(two_env_entries):
    """Two env-read entries sharing one '<value>' key reported the importable
    one as failed beside the one that failed."""
    context, refusal = two_env_entries(GOOD, VALUE)
    assert context.plugin_load_record, "control: the failure was recorded"
    assert refusal.count("'<value>' (") == 1, refusal


def test_two_env_read_failures_keep_both_kinds(two_env_entries):
    """Two env-read failures sharing one key kept only the last one, and the
    refusal said its kind twice."""
    context, refusal = two_env_entries(SELF_QUOTING, VALUE)
    assert context.plugin_load_record, "control: the failures were recorded"
    kinds = sorted(failure.kind for failure in context.plugin_load_record.values())
    assert kinds == ["ImportError", "ModuleNotFoundError"], (kinds, refusal)
