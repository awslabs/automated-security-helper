# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failure's redaction needles cover every masked module of its load.

A failing import's text can quote modules OTHER than the failing one: a
piece's body imports a sibling piece of the same environment value, or a
literal module imports a masked piece's missing submodule. Needles built
from the failing module alone leave the quoted neighbor in clear -- in the
DEBUG traceback, the recorded text, the WARNING line (a literal module's
label is not masked, so its error text is shown), the exit-3 refusal, and
the plugin list's console output at the default level. The loader computes
the masked forms of the WHOLE load once and redacts every failure with
them, literal modules included.

A dotted env-read entry adds its proper dotted prefixes: a missing
top-level package ("No module named 'pkg'") or a raising parent package
(frame ".../pkg/__init__.py") quotes the top-level name alone, which the
full dotted, "/" and "\\" forms never match. Two bounds keep the prefixes
from blanking readable text: a prefix shorter than the word-band floor is
not a needle, and a prefix equal to a namespace root the plugin-namespace
rule names ("automated_security_helper", "ash_plugins") stays readable --
the rule's own text is public, and ASH's own frames quote it.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import pytest

from automated_security_helper.utils.log import ASH_LOGGER

TRACEBACK = "failure traceback"
RAISES = "raise RuntimeError('module body refuses')\n"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.records: List[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def sink():
    handler = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(1)
    yield handler
    ASH_LOGGER.removeHandler(handler)
    ASH_LOGGER.setLevel(level)


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("ASH_PLUGIN_MODULES", "ASH_CONFIG", "ASH_SOURCE_DIR"):
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "needle-site"
    root.mkdir()
    for name in [m for m in sys.modules if m.startswith("ndl")]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if m.startswith("ndl")]:
        sys.modules.pop(name, None)


def _plant(root: Path, files: Dict[str, str]) -> None:
    for relative, body in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def _config_file(path: Path, entries: Sequence[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"  - {entry}\n" for entry in entries)
    path.write_text(
        f"project_name: demo\nash_plugin_modules:\n{body}", encoding="utf-8"
    )
    return path


def _engine_load(tmp_path: Path, entries: Sequence[str], sink: _Sink):
    """The scan engine's own loader call: the config's names, labels and
    values, then the refusal a configured failure raises. The returned
    sources are every surface a failure's text reaches."""
    from automated_security_helper.config.plugin_module_trust import (
        config_module_names,
        split_plugin_modules,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugins.loader import (
        PluginModuleImportError,
        load_additional_plugin_modules,
        refuse_failed_plugin_imports,
    )
    from automated_security_helper.utils.error_text import config_environment_values

    cfg = _config_file(tmp_path / "needle-config" / "cfg.yaml", entries)
    config = resolve_config(config_path=str(cfg))
    names = split_plugin_modules(list(config.ash_plugin_modules))
    shown = config_module_names(config) or None
    record: Dict[str, Any] = {}
    load_additional_plugin_modules(
        names, shown=shown, record=record, values=config_environment_values(config)
    )
    refusal = ""
    try:
        refuse_failed_plugin_imports(names, record, shown=shown)
    except PluginModuleImportError as error:
        refusal = str(error)
    sources = {
        f"log{i}:{r.levelname}:{r.filename}:{r.lineno}": r.getMessage()
        for i, r in enumerate(sink.records)
    }
    # The record's keys are module paths by design and reach no surface; its
    # texts feed the run metadata and a literal label's refusal.
    sources["record-texts"] = repr([f.recorded for f in record.values()])
    sources["refusal"] = refusal
    return names, record, shown, sources


def _holding(sources: Dict[str, str], names: Sequence[str]) -> Dict[str, str]:
    """Each source that holds a name, its lines with the names as tokens, so
    an assertion message cannot itself print a masked value."""
    held = {}
    for where, body in sources.items():
        if not any(name in body for name in names):
            continue
        lines = [line for line in body.splitlines() if any(n in line for n in names)]
        shown = " || ".join(lines)
        for index, name in sorted(enumerate(names), key=lambda p: -len(p[1])):
            shown = shown.replace(name, f"[[NAME-{index}]]")
        held[where] = shown[:500]
    return held


#: files, environment, entries, the env-read names that must not show.
CROSS: Dict[str, Tuple[Dict[str, str], Dict[str, str], List[str], Tuple[str, ...]]] = {
    "pair-sibling-body-raises": (
        {
            "ndlxa_ash_plugins/__init__.py": "import ndlxb_ash_plugins\n",
            "ndlxb_ash_plugins/__init__.py": RAISES,
        },
        {"ASH_NDL_XPAIR": "ndlxa_ash_plugins,ndlxb_ash_plugins"},
        ["${ASH_NDL_XPAIR}"],
        ("ndlxa_ash_plugins", "ndlxb_ash_plugins"),
    ),
    "pair-sibling-missing-sub": (
        {
            "ndlya_ash_plugins/__init__.py": "import ndlyb_ash_plugins.ndlnosub\n",
            "ndlyb_ash_plugins/__init__.py": "",
        },
        {"ASH_NDL_YPAIR": "ndlya_ash_plugins,ndlyb_ash_plugins"},
        ["${ASH_NDL_YPAIR}"],
        ("ndlya_ash_plugins", "ndlyb_ash_plugins"),
    ),
    "literal-imports-env-piece": (
        {
            "ndlza_ash_plugins/__init__.py": "",
            "ndlzb_ash_plugins/__init__.py": "",
            "ndlzl_ash_plugins/__init__.py": "import ndlzb_ash_plugins.ndlnosub\n",
        },
        {"ASH_NDL_ZPAIR": "ndlza_ash_plugins,ndlzb_ash_plugins"},
        ["${ASH_NDL_ZPAIR}", "ndlzl_ash_plugins"],
        ("ndlza_ash_plugins", "ndlzb_ash_plugins"),
    ),
    # The control: a one-piece value is the run's whole value already, so the
    # literal importer's text was hidden before the load-wide needles existed.
    "control-literal-imports-single-value": (
        {
            "ndlwb_ash_plugins/__init__.py": "",
            "ndlwl_ash_plugins/__init__.py": "import ndlwb_ash_plugins.ndlnosub\n",
        },
        {"ASH_NDL_WONE": "ndlwb_ash_plugins"},
        ["${ASH_NDL_WONE}", "ndlwl_ash_plugins"],
        ("ndlwb_ash_plugins",),
    ),
}


@pytest.mark.parametrize("shape", sorted(CROSS))
def test_a_failure_hides_the_masked_piece_it_quotes(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, shape: str
):
    files, env, entries, hidden = CROSS[shape]
    _plant(site, files)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    names, record, shown, sources = _engine_load(tmp_path, entries, sink)
    if not record:
        raise RuntimeError(("premise: an import failed", names))
    if not all((shown or {}).get(n, n) != n for n in hidden):
        raise RuntimeError(("premise: every env-read name is masked", shown))
    if not any(TRACEBACK in b for b in sources.values()):
        raise RuntimeError("premise: the DEBUG traceback was logged")
    held = _holding(sources, hidden)
    assert not held, held


def test_plugin_list_hides_the_env_piece_a_literal_module_imports(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """The literal-importer shape through ``ash plugin list`` with no
    ``--debug``: the refusal and the WARNING print at the default level, so
    this leak reaches the console of every run, not only a debug one."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    files, env, entries, hidden = CROSS["literal-imports-env-piece"]
    _plant(site, files)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    cfg = _config_file(tmp_path / "needle-cli" / "cfg.yaml", entries)
    project = tmp_path / "needle-proj"
    project.mkdir()
    monkeypatch.chdir(project)
    result = CliRunner().invoke(app, ["plugin", "list", "--config", str(cfg)])
    if result.exit_code != 3:
        raise RuntimeError(("premise: the listing was refused", result.exit_code))
    sources = {"output": result.output or ""}
    for i, r in enumerate(sink.records):
        if r.levelno >= logging.INFO:
            sources[f"log{i}:{r.levelname}:{r.filename}:{r.lineno}"] = r.getMessage()
    held = _holding(sources, hidden)
    assert not held, held


#: files, the entry's value, whether it is read from the environment.
DOTTED: Dict[str, Tuple[Dict[str, str], str, bool]] = {
    "env-top-missing": ({}, "ndlmiss_ash_plugins.ndlmisssub", True),
    "env-parent-raises": (
        {
            "ndlpar_ash_plugins/__init__.py": RAISES,
            "ndlpar_ash_plugins/ndlparsub/__init__.py": "",
        },
        "ndlpar_ash_plugins.ndlparsub",
        True,
    ),
    # The leaf raising puts ".../top/sub/__init__.py" in the frame: the "/"
    # form of the FULL path is the one needle that covers the sub segment,
    # since the top-level prefix needle ends before it.
    "control-env-leaf-raises": (
        {
            "ndlleaf_ash_plugins/__init__.py": "",
            "ndlleaf_ash_plugins/ndlleafsub/__init__.py": RAISES,
        },
        "ndlleaf_ash_plugins.ndlleafsub",
        True,
    ),
    # The control: a literal entry's failure text does quote the top level.
    "control-literal-top-missing": ({}, "ndlmissl_ash_plugins.ndlmisslsub", False),
}


@pytest.mark.parametrize("shape", sorted(DOTTED))
def test_an_env_dotted_entrys_prefix_is_hidden(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, shape: str
):
    files, value, from_env = DOTTED[shape]
    _plant(site, files)
    if from_env:
        monkeypatch.setenv("ASH_NDL_DOT", value)
        entries = ["${ASH_NDL_DOT}"]
    else:
        entries = [value]
    names, record, shown, sources = _engine_load(tmp_path, entries, sink)
    if names != [value] or sorted(record) != [value]:
        raise RuntimeError(("premise: the entry failed", names, sorted(record)))
    top, sub = value.split(".")
    # The sub segment on its own too: a needle that hides only the head of
    # ".../top/sub/__init__.py" leaves the sub segment readable beside the
    # redaction marker, which still names a piece of the value.
    forms = (value, value.replace(".", "/"), top, sub)
    held = _holding(sources, forms)
    if not from_env:
        # NAME-2 is the top-level name standing alone.
        assert any("[[NAME-2]]" in h for h in held.values()), held
        return
    assert not held, held


def test_a_namespace_root_prefix_stays_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """The must-not-flag control: an env-read entry under the documented
    namespace root fails with "No module named 'ash_plugins'", and the root
    is public text (the namespace rule's own words name it), so it is never
    a needle: the recorded text keeps it readable while the entry's own
    dotted forms stay hidden."""
    monkeypatch.setenv("ASH_NDL_ROOT", "ash_plugins.ndlrootmissing")
    names, record, shown, sources = _engine_load(tmp_path, ["${ASH_NDL_ROOT}"], sink)
    if sorted(record) != ["ash_plugins.ndlrootmissing"]:
        raise RuntimeError(("premise: the entry failed", sorted(record)))
    assert "ash_plugins" in sources["record-texts"], sources["record-texts"][:400]
    held = _holding(
        sources, ("ash_plugins.ndlrootmissing", "ash_plugins/ndlrootmissing")
    )
    assert not held, held
