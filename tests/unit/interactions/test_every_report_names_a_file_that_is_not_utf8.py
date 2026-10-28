# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every bundled report names a file whose name is not UTF-8, from a scan and from ``ash report``.

A result records such a name in the record form, the surrogate as the six characters
``\\udcNN``. One scan with every bundled reporter enabled, over a file named so that
holds a finding, must write each report, and each must name the file:

- decoded as its format reads it (JSON, YAML, XML), a report holds no lone
  surrogate, which a writer that escapes the surrogate itself would leave;
- it names the file as often as the same report names a plain file of the same
  shape, a backslash and five letters where the escape is: in the record form
  where a machine reads it, and with the backslash doubled where a human report
  shows it on one line, because the record form reads as an escape there.

The same holds for each report ``ash report`` renders again from the saved results.

These cells are a regression guard: they pin outputs that were already right
before the record-form range, so they hold green across it. A source root whose
own name is not UTF-8 cannot sharpen them, because such a root is refused before
any scanner runs (test_a_source_dir_that_is_not_utf8_is_refused.py pins the
refusal), and no other input reaches the project name or an absolute URI with a
name the record form would change.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from tests.utils import undecodable_names as names
from tests.utils.undecodable_names import ODD_BYTES

# Every test here plants a file whose name is not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

#: A plain file name of RECORDED's shape. A report writes the two alike, so its
#: count of this one is the yardstick for RECORDED's.
SAME_SHAPE = "secr\\vdce9t.py"
#: Any surrogate code point.
_SURROGATE = re.compile("[\ud800-\udfff]")


def _reporter_names() -> List[str]:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS

    probe = PluginContext(source_dir=Path.cwd(), output_dir=Path.cwd())
    return sorted(reporter(context=probe).config.name for reporter in ASH_REPORTERS)


def _config(tmp_path: Path, reporters: List[str]) -> Path:
    config = tmp_path / "every-reporter.yaml"
    config.write_text(
        "reporters:\n"
        + "".join(f"  {name}:\n    enabled: true\n" for name in reporters),
        encoding="utf-8",
    )
    return config


def _scanned(tmp_path: Path, label: str, name: bytes) -> Tuple[Path, Dict[str, str]]:
    reporters = _reporter_names()
    source = names.make_tree(tmp_path / label, {name: names.secret_source()})
    output = tmp_path / f"{label}-out"
    ran = names.scan(
        tmp_path,
        source,
        output,
        "--config",
        str(_config(tmp_path, reporters)),
        "--output-formats",
        ",".join(reporters),
    )
    assert names.results_file(output).is_file(), ran
    return output, names.reports(output)


def _name_runs(text: str, tail: str) -> List[int]:
    """Backslash-run lengths at each naming of the file in *text*: the record
    form's naming carries one backslash, the shown (one-line) form two, and a
    markdown context escapes each of those again for odd and plain alike."""
    return sorted(len(m.group(1)) for m in re.finditer(r"secr(\\+)" + tail, text))


def _conforms(name: str, odd_runs: List[int], plain_runs: List[int]) -> bool:
    """Does the odd report name the file as the plain one does, with every
    shown sink doubling the record form's backslash? The record form reads as
    an escape, so the one-line form shows it with the backslash doubled:

    - the markdown and text summaries show every naming that way, so each odd
      run is its plain run doubled;
    - the HTML report shows the findings table that way and embeds the record
      form as data (the finding's code element and the copy attribute), so the
      naming count matches, every naming is the record or the doubled form,
      and the table's naming is the doubled one;
    - every other report is machine-read and holds the record form unchanged.
    """
    if name in ("ash.summary.md", "ash.summary.txt"):
        return odd_runs == sorted(2 * run for run in plain_runs)
    if name == "ash.html":
        return (
            len(odd_runs) == len(plain_runs)
            and set(plain_runs) == {1}
            and set(odd_runs) <= {1, 2}
            and 2 in odd_runs
        )
    return odd_runs == plain_runs


def _compare(odd: Dict[str, str], plain: Dict[str, str]) -> None:
    assert sorted(odd) == sorted(plain)
    decoded = {name: names.report_text(name, odd[name]) for name in odd}
    holding = sorted(name for name, text in decoded.items() if _SURROGATE.search(text))
    assert holding == [], holding
    counts = {
        name: (
            _name_runs(decoded[name], r"udce9t\.py"),
            _name_runs(names.report_text(name, plain[name]), r"vdce9t\.py"),
        )
        for name in plain
    }
    differ = {name: runs for name, runs in counts.items() if not _conforms(name, *runs)}
    assert differ == {}, differ
    assert sum(len(want) for _, want in counts.values()) > 0, counts


def test_every_report_of_a_scan_names_the_file(tmp_path):
    _, odd = _scanned(tmp_path, "odd", ODD_BYTES)
    _, plain = _scanned(tmp_path, "plain", SAME_SHAPE.encode("utf-8"))

    # One report or more from each bundled reporter.
    assert len(odd) >= len(_reporter_names()), sorted(odd)
    _compare(odd, plain)


def _extensions() -> Dict[str, str]:
    """Each bundled reporter's name, to the file name a scan writes its report to."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS

    probe = PluginContext(source_dir=Path.cwd(), output_dir=Path.cwd())
    configs = [reporter(context=probe).config for reporter in ASH_REPORTERS]
    return {config.name: f"ash.{config.extension}" for config in configs}


def test_every_report_ash_report_renders_names_the_file(tmp_path):
    """ash report writes the report to stdout, as UTF-8; each is read from there under
    the file name the scan gives it, so its format is decoded the same way."""
    odd_out, _ = _scanned(tmp_path, "odd", ODD_BYTES)
    plain_out, _ = _scanned(tmp_path, "plain", SAME_SHAPE.encode("utf-8"))

    rendered: Dict[str, Dict[str, str]] = {"odd": {}, "plain": {}}
    for reporter, file_name in sorted(_extensions().items()):
        for label, output in (("odd", odd_out), ("plain", plain_out)):
            ran = names.report_of(tmp_path, output, reporter)
            assert ran.code == 0, (reporter, label, ran)
            rendered[label][file_name] = ran.stdout_bytes.decode("utf-8")

    _compare(rendered["odd"], rendered["plain"])
