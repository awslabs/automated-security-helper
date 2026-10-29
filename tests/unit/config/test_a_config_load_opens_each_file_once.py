# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each config file is read once per load, counted at the interpreter.

The one-read contract (the as-written view parses the text the resolution
read) is measured here with an audit hook on ``open``, so every module's read
counts whatever name it imported the reader under. A spy on one module's
binding misses a read made through another module's own import, and two such
reads are exactly the swap window the contract closes.

Two opens are not a second read. A base is opened first so the grant is asked
about the file the descriptor holds (``open_config_for_judgment``); nothing is
read from that descriptor, so the hook does not count it. And a file a caller
had already read, handed in through the ``reads`` and ``texts`` caches, is read
again held to the identity the chain walk vetted and compared with the cached
text, which refuses a file replaced in between. A read after a file's first is
therefore allowed only when it is held to an identity; the hook records any
other as ``unheld_rereads``, the swap window itself.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

_ACTIVE: dict = {"opens": None}

#: The function that opens a base so the grant is asked about the file the
#: descriptor holds. Nothing is read from that descriptor.
_JUDGMENT_OPEN = "open_config_for_judgment"

#: The function every held read goes through, and the argument that holds it.
_HELD_READ = "read_config_bytes"


class _Opens(list):
    """The names of the files read, in order.

    ``unheld_rereads`` names each read of a file already read that was not held
    to an identity (``read_config_bytes(expect=...)``): a second read through
    any name of the reader, which can see a file other than the one the first
    saw.
    """

    def __init__(self) -> None:
        super().__init__()
        self.unheld_rereads: list = []


def _hook(event, args):
    collector = _ACTIVE["opens"]
    if collector is None or event != "open" or not args:
        return
    target = args[0]
    if isinstance(target, int):
        return
    try:
        name = os.path.basename(os.fsdecode(target))
    except Exception:
        return
    mode = args[1] if len(args) > 1 else None
    if not name.startswith("readonce-") or (mode is not None and "w" in str(mode)):
        return
    caller = sys._getframe(1)
    if caller.f_code.co_name == _JUDGMENT_OPEN:
        return
    held = (
        caller.f_code.co_name == _HELD_READ
        and caller.f_locals.get("expect") is not None
    )
    if name in collector and not held:
        collector.unheld_rereads.append(name)
    collector.append(name)


sys.addaudithook(_hook)


@pytest.fixture
def opens():
    _ACTIVE["opens"] = _Opens()
    try:
        yield _ACTIVE["opens"]
    finally:
        _ACTIVE["opens"] = None


@pytest.fixture
def chain(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    folder = tmp_path / "cfg"
    folder.mkdir()
    (folder / "readonce-base.yaml").write_text("project_name: base\n", encoding="utf-8")
    top = folder / "readonce-top.yaml"
    top.write_text("extends: readonce-base.yaml\nproject_name: top\n", encoding="utf-8")
    operator = tmp_path / "readonce-operator.yaml"
    operator.write_text("project_name: op\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    monkeypatch.chdir(src)
    return top, operator


def _counts(names):
    return {n: names.count(n) for n in sorted(set(names))}


def test_validate_opens_each_file_once(chain, opens, monkeypatch):
    top, operator = chain
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    result = CliRunner().invoke(app, ["config", "validate", "--config", str(top)])
    counts = _counts(opens)
    assert result.exit_code == 0, result.output
    assert set(counts) == {
        "readonce-top.yaml",
        "readonce-base.yaml",
        "readonce-operator.yaml",
    }, counts
    # The check reads each file and the run load that follows reads the cached
    # ones again, held to the identity it vetted (so a file replaced in between
    # is refused). Every read after a file's first must be one of those.
    assert opens.unheld_rereads == [], (opens.unheld_rereads, counts)


def test_the_scan_load_opens_each_file_once(chain, opens):
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    top, _ = chain
    load_config_file_for_run(top)
    counts = _counts(opens)
    assert set(counts) == {"readonce-top.yaml", "readonce-base.yaml"}, counts
    assert all(n == 1 for n in counts.values()), counts


def test_the_stock_reader_opens_each_file_once(chain, opens):
    from automated_security_helper.config.config_sources import resolve_config_document

    top, _ = chain
    resolve_config_document(top, confine_to=top.parent)
    counts = _counts(opens)
    assert all(n == 1 for n in counts.values()) and len(counts) == 2, counts


def test_a_file_swapped_after_its_read_is_recorded_as_read(tmp_path, monkeypatch):
    """The base reads an environment value; right after that read the file on
    disk is replaced with a literal. The record (the references) and the
    results record describe the text the resolution read: the reference is
    kept, and the value is not written as text."""
    from automated_security_helper.config import config_sources, resolve_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    value = "c5-swap-needle-55"
    monkeypatch.setenv("ASH_TEST_SWAP_A", value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    folder = tmp_path / "cfg"
    folder.mkdir()
    base = folder / "readonce-swap-base.yaml"
    base.write_text("project_name: ${ASH_TEST_SWAP_A}\n", encoding="utf-8")
    top = folder / "readonce-swap-top.yaml"
    top.write_text("extends: readonce-swap-base.yaml\n", encoding="utf-8")
    swapped = []

    def wrap(module):
        real = module.read_config_text

        def read(p, *a, **k):
            text = real(p, *a, **k)
            if os.path.basename(str(p)) == "readonce-swap-base.yaml" and not swapped:
                base.write_text("project_name: lit-swapped\n", encoding="utf-8")
                swapped.append(True)
            return text

        monkeypatch.setattr(module, "read_config_text", read)

    for module in (config_sources, resolve_config):
        if hasattr(module, "read_config_text"):
            wrap(module)
    _, config = resolve_config.load_config_file_for_run(top)
    record = AshAggregatedResults(ash_config=config).model_dump(mode="json")
    written = [r.written for r in config._environment_references]
    assert swapped, "control: the swap never happened; the cell measured nothing"
    assert config.project_name == value
    assert "${ASH_TEST_SWAP_A}" in written, written
    assert value not in str(record["ash_config"]), record["ash_config"].get(
        "project_name"
    )


@pytest.mark.parametrize("hand_in_texts", [True, False])
def test_a_callers_reader_and_its_cache(chain, opens, hand_in_texts):
    """A caller's own reader keeps its text and hands the mapping in: the
    as-written view is parsed from it, and each file is read once. Without the
    mapping the call is refused before any file is read: the view would
    record nothing for any file, so a value read from the environment would
    be resolved into the data and never redacted."""
    from automated_security_helper.config.config_sources import (
        parse_config_text,
        read_config_text,
        resolve_config_document,
    )

    top, _ = chain
    texts: dict = {}

    def reader(path):
        text = read_config_text(path)
        texts[Path(path).resolve()] = text
        return parse_config_text(path, text)

    if not hand_in_texts:
        with pytest.raises(TypeError, match="texts"):
            resolve_config_document(
                top, confine_to=top.parent, reader=reader, texts=None
            )
        assert _counts(opens) == {}, opens
        return
    resolve_config_document(
        top,
        confine_to=top.parent,
        reader=reader,
        texts=texts,
    )
    counts = _counts(opens)
    assert all(n == 1 for n in counts.values()) and len(counts) == 2, counts


def test_the_fold_display_never_rereads_the_file(tmp_path):
    """With no held text the refused key is shown ``<value>``; the file on
    disk (here one whose text names the key literally, as a swapped file
    could) is never read for it."""
    from automated_security_helper.config import config_sources

    path = tmp_path / "readonce-swapped.yaml"
    path.write_text(
        "reporters:\n  zq-literal-key:\n    enabled: true\n", encoding="utf-8"
    )
    data = {"reporters": {"zq-literal-key": {"enabled": True}}}
    shown = config_sources._shown_fold_key("zq-literal-key", path, data, None)
    assert shown == config_sources.ENVIRONMENT_VALUE_SHOWN, shown


def test_the_reference_view_with_no_held_text_reads_no_disk(tmp_path, opens):
    """_file_references with no held text is refused and opens nothing:
    reading the file again could pair a swapped text against data the load
    parsed earlier, and recording nothing would leave the file's environment
    reads resolved into the data with no reference recorded anywhere."""
    from automated_security_helper.config.config_sources import (
        _file_references,
        read_config_file,
    )

    path = tmp_path / "readonce-held.yaml"
    path.write_text("project_name: ${ASH_READONCE_VAR}\n", encoding="utf-8")
    data = {"project_name": "resolved"}
    with pytest.raises(TypeError, match="held no text|no held text"):
        _file_references(path, data, read_config_file, None)
    assert _counts(opens) == {}, opens


def test_the_stock_reader_holds_its_text_under_the_path_it_resolved(
    tmp_path, monkeypatch
):
    """The stock reader keeps each file's text under the path the resolution
    resolved, the key it looks the text up by. Kept under a second resolve
    taken at read time, a root symlink retargeted in between left the text
    under one path and the lookup under another, and the stock reader's own
    read was refused as a caller's reader that had not filled its cache.

    The link is retargeted to a second name for the same file (a hard link), so
    the identity the walk vetted still holds at the open and only the path
    differs: a read of a different file is refused by that identity
    (``read_config_bytes``, ``ConfigFileChangedError``; the control below), so
    it cannot reach the lookup this test pins."""
    from automated_security_helper.config import config_sources

    first = tmp_path / "first.yaml"
    first.write_text("project_name: first\n", encoding="utf-8")
    second = tmp_path / "second.yaml"
    os.link(first, second)
    link = tmp_path / "ash.yaml"
    link.symlink_to(first)
    real_read = config_sources.read_config_text
    retargeted: list = []

    def retarget_then_read(path, *args, **kwargs):
        if Path(path) == link and not retargeted:
            link.unlink()
            link.symlink_to(second)
            retargeted.append(True)
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "read_config_text", retarget_then_read)
    document = config_sources.resolve_config_document(link, confine_to=tmp_path)
    assert retargeted == [True], "control: the link was never retargeted"
    assert document.data["project_name"] == "first", document.data


def test_control_a_link_retargeted_to_another_file_is_refused(tmp_path, monkeypatch):
    """The read holds the file to the identity the walk vetted, so a root symlink
    retargeted to a different file between the check and the open is refused
    rather than read (``read_config_bytes``)."""
    from automated_security_helper.config import config_sources

    first = tmp_path / "first.yaml"
    first.write_text("project_name: first\n", encoding="utf-8")
    second = tmp_path / "second.yaml"
    second.write_text("project_name: second\n", encoding="utf-8")
    link = tmp_path / "ash.yaml"
    link.symlink_to(first)
    real_read = config_sources.read_config_text
    retargeted: list = []

    def retarget_then_read(path, *args, **kwargs):
        if Path(path) == link and not retargeted:
            link.unlink()
            link.symlink_to(second)
            retargeted.append(True)
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "read_config_text", retarget_then_read)
    with pytest.raises(config_sources.ConfigFileChangedError):
        config_sources.resolve_config_document(link, confine_to=tmp_path)
    assert retargeted == [True], "control: the link was never retargeted"


def test_control_a_judgment_descriptor_is_not_a_read(chain, opens):
    """The descriptor a base is judged on is opened and never read from, so the
    counter leaves it out; without this the tests above could pass by counting
    nothing at all."""
    from automated_security_helper.config.config_sources import (
        open_config_for_judgment,
    )

    top, _ = chain
    held = open_config_for_judgment(top)
    assert held is not None, "control: nothing was opened; the test measured nothing"
    held.close()
    assert _counts(opens) == {}, opens
    assert opens.unheld_rereads == [], opens.unheld_rereads


def test_control_a_second_read_without_an_identity_is_flagged(chain, opens):
    """Whatever name the second read goes through (the reader, or a plain
    ``Path.read_text`` in another module), a read after the first that is not
    held to an identity is the swap window, and the counter says so."""
    from automated_security_helper.config.config_sources import (
        file_identity,
        read_config_text,
    )

    top, _ = chain
    read_config_text(top, expect=file_identity(top))
    top.read_text(encoding="utf-8")
    assert _counts(opens) == {"readonce-top.yaml": 2}, opens
    assert opens.unheld_rereads == ["readonce-top.yaml"], opens.unheld_rereads


def test_control_a_second_read_held_to_an_identity_is_allowed(chain, opens):
    from automated_security_helper.config.config_sources import (
        file_identity,
        read_config_text,
    )

    top, _ = chain
    identity = file_identity(top)
    read_config_text(top, expect=identity)
    read_config_text(top, expect=identity)
    assert _counts(opens) == {"readonce-top.yaml": 2}, opens
    assert opens.unheld_rereads == [], opens.unheld_rereads
