# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked name spelled like the load's own vocabulary keeps frames readable.

At the real redacting surfaces -- the loader's DEBUG traceback, the record,
the WARNING line and the refusal -- a masked module whose segment is named
like the import machinery's own text ("import_module") blanked the frames
every failing load prints: `, in import_module` became `, in <value>`, and
the blanking itself told a reader what the segment is called. The
module-form needles now carry a frame exemption for ASH's and importlib's
own frame lines, so that text survives, while the same segment stays hidden
wherever a message quotes it outside those frames.

The distribution needle's variant pattern is measured here too: a failure
quoting the masked name in another PEP 503 separator spelling
("Segtop.Ash_Plugins" for the masked "segtop_ash_plugins") printed it in
clear, because only the canonical hyphen literal was a needle. A name that
does not normalize to the masked one segment for segment stays readable.

The fixtures are the segment-spelling suite's
(test_a_masked_modules_segments_are_hidden_in_every_spelling): a planted
sys.path site, the scan engine's own loader call, and sources that cover
every surface a failure's text reaches.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

import pytest

from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

TRACEBACK = "failure traceback"
RAISES_FROM_FILE = (
    "import pathlib\n"
    "raise RuntimeError((pathlib.Path(__file__).parent / 'msg.txt')"
    ".read_text(encoding='utf-8'))\n"
)

T = "segtop_ash_plugins"
LIT = "seglit_ash_plugins"
VOCAB = f"{T}.import_module"


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


def _ours(name: str) -> bool:
    return name in ("ash_plugins", "ab") or name.startswith(
        ("seg", "ash_plugins.", "ab.")
    )


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("ASH_PLUGIN_MODULES", "ASH_CONFIG", "ASH_SOURCE_DIR"):
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "frame-site"
    root.mkdir()
    for name in [m for m in sys.modules if _ours(m)]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if _ours(m)]:
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
    """The scan engine's own loader call, as the segment-spelling suite runs
    it: the config's names, labels and values, then the refusal a configured
    failure raises. The returned sources are every surface a failure's text
    reaches."""
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

    cfg = _config_file(tmp_path / "frame-config" / "cfg.yaml", entries)
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
    sources["record-texts"] = repr([f.recorded for f in record.values()])
    sources["refusal"] = refusal
    return names, record, shown, sources


def _holding(sources: Dict[str, str], names: Sequence[str]) -> Dict[str, str]:
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


def test_the_import_machinerys_frames_survive_a_masked_vocabulary_segment(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Must-flag: a masked entry whose segment is named import_module fails
    to import; the DEBUG traceback keeps the loader's own call text and the
    importlib frame's own function name, while the entry's top level stays
    hidden on every surface."""
    monkeypatch.setenv("ASH_STANDIN_VOCAB", VOCAB)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_STANDIN_VOCAB}"], sink
    )
    if names != [VOCAB] or sorted(record) != [VOCAB]:
        raise RuntimeError(("premise: the entry failed", names, sorted(record)))
    if (shown or {}).get(VOCAB, VOCAB) == VOCAB:
        raise RuntimeError(("premise: the entry is masked", shown))
    debug = "\n".join(
        b for w, b in sources.items() if ":DEBUG:" in w and TRACEBACK in b
    )
    if not debug:
        raise RuntimeError("premise: the DEBUG traceback was logged")
    assert "importlib.import_module(module_path)" in debug, debug[-500:]
    assert ", in import_module" in debug, debug[-500:]
    held = _holding(sources, (T,))
    assert not held, held


def test_the_vocabulary_segment_stays_hidden_outside_the_machinery_frames(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Must-not-flag: the same masked segment quoted by another module's own
    message is still hidden -- the exemption is the frame lines', not the
    word's."""
    _plant(
        site,
        {
            f"{LIT}/__init__.py": RAISES_FROM_FILE,
            f"{LIT}/msg.txt": "cannot use import_module here",
        },
    )
    monkeypatch.setenv("ASH_STANDIN_VOCAB", VOCAB)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_STANDIN_VOCAB}", LIT], sink
    )
    if sorted(record) != sorted([VOCAB, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    assert "cannot use <value> here" in record[LIT].recorded, record[LIT].recorded[:300]


def test_a_separator_variant_quoted_by_a_failure_is_hidden(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Must-flag: a failure quoting the masked name in another PEP 503
    separator spelling is hidden on every surface, as the canonical and raw
    spellings already are."""
    variant = "Segtop.Ash_Plugins"
    _plant(
        site,
        {
            f"{LIT}/__init__.py": RAISES_FROM_FILE,
            f"{LIT}/msg.txt": (
                f"No package metadata was found for {variant} "
                f"(from {variant}-1.0.dist-info)"
            ),
        },
    )
    monkeypatch.setenv("ASH_STANDIN_DIST", T)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_STANDIN_DIST}", LIT], sink
    )
    if sorted(record) != sorted([T, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    if (shown or {}).get(T, T) == T or (shown or {}).get(LIT) != LIT:
        raise RuntimeError(("premise: the value masked, the literal shown", shown))
    held = _holding(sources, (variant,))
    assert not held, held
    assert "<value>" in sources["record-texts"], sources["record-texts"][:300]


def test_a_name_that_does_not_normalize_to_the_masked_one_stays_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Must-not-flag: a name that does not normalize to the masked one
    segment for segment (here a missing separator) is another package's text
    and prints."""
    unrelated = "segtopash.plugins"
    _plant(
        site,
        {
            f"{LIT}/__init__.py": RAISES_FROM_FILE,
            f"{LIT}/msg.txt": f"{unrelated} is an unrelated package",
        },
    )
    monkeypatch.setenv("ASH_STANDIN_DIST", T)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_STANDIN_DIST}", LIT], sink
    )
    if sorted(record) != sorted([T, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    assert f"{unrelated} is an unrelated package" in record[LIT].recorded, record[
        LIT
    ].recorded[:300]
