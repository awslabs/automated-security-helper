# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs-example runner compares an output sample with the output of its block.

A text block marked ``<!-- doctest: output -->`` shows what the run block above it
prints. The runner runs the block, normalizes both texts (ANSI codes, Rich's box
drawing, durations and timestamps, the session's paths, runs of whitespace), and
requires every line of the sample other than ``...`` to appear in the output, in
order. These tests plant a sample the output contradicts, with a matching control
beside it, using trivial commands so the file runs in a few seconds.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FENCE = "```"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = _load("_ash_docs_runner", HERE / "docs_runner.py")
checks = runner.load_docs_checks()


def _run(tmp_path: Path, text: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "page.md"
    path.write_text(text, encoding="utf-8")
    page = checks.parse_page(path, tmp_path)
    scratch = tmp_path / "sessions"
    scratch.mkdir()
    return runner.PageRunner(page, scratch).run()


def _page(command: str, sample: str, marker: str = "") -> str:
    above = f"{marker}\n" if marker else ""
    return (
        f"# Page\n\n{above}{FENCE}bash\n{command}\n{FENCE}\n\n"
        f"<!-- doctest: output -->\n{FENCE}text\n{sample}\n{FENCE}\n"
    )


def test_a_sample_the_output_contains_passes(tmp_path):
    results = _run(
        tmp_path,
        _page(
            "printf 'Scanning %s\\n' \"$PWD\"\nprintf '\\033[1mPASSED\\033[0m in 1.25s\\n'\n"
            "echo 'Exit code: 0'",
            "Scanning .\n...\nPASSED in 3.40s\nExit code: 0",
        ),
    )
    assert [r.lang for r in results] == ["bash", "text"]
    assert all(r.ok for r in results), runner.failure_report(results)


def test_a_sample_line_the_output_lacks_fails_with_its_line(tmp_path):
    results = _run(tmp_path, _page("echo '1 actionable'", "2 actionable"))
    run, sample = results
    assert run.ok
    assert not sample.ok
    report = sample.report()
    assert "page.md:9" in report, report
    assert "'2 actionable' is not in the output of the block at line 3" in report, (
        report
    )
    assert "1 actionable" in report, "the output tail is not in the report"


def test_a_sample_whose_lines_are_out_of_order_fails(tmp_path):
    results = _run(tmp_path, _page("echo first; echo second", "second\nfirst"))
    assert not results[1].ok
    assert "'first' is not in the output" in results[1].report()


def test_a_sample_after_a_failing_block_is_still_compared(tmp_path):
    results = _run(
        tmp_path,
        _page("echo partial; exit 3", "partial", "<!-- doctest: run expect-exit=3 -->"),
    )
    assert all(r.ok for r in results), runner.failure_report(results)
    results = _run(
        tmp_path / "again",
        _page(
            "echo partial; exit 3", "complete", "<!-- doctest: run expect-exit=3 -->"
        ),
    )
    assert results[0].ok and not results[1].ok


def test_the_session_paths_in_the_output_are_normalized(tmp_path):
    """The project directory reads as relative paths and HOME as ~, whatever the
    temporary directory the session ran in."""
    results = _run(
        tmp_path,
        _page(
            'mkdir -p out && echo "wrote $PWD/out/ash.sarif" && echo "cache in $HOME/.cache"',
            "wrote out/ash.sarif\ncache in ~/.cache",
        ),
    )
    assert [r.lang for r in results] == ["bash", "text"]
    assert all(r.ok for r in results), runner.failure_report(results)


def test_the_output_is_rendered_at_a_fixed_width(tmp_path):
    results = _run(tmp_path, _page('echo "columns=$COLUMNS"', "columns=100"))
    assert [r.lang for r in results] == ["bash", "text"]
    assert all(r.ok for r in results), runner.failure_report(results)


def test_a_python_blocks_output_is_compared_too(tmp_path):
    text = (
        f"# Page\n\n{FENCE}python\nprint('from python')\n{FENCE}\n\n"
        f"<!-- doctest: output -->\n{FENCE}text\nfrom python\n{FENCE}\n\n"
        f"{FENCE}python\nprint('again')\n{FENCE}\n\n"
        f"<!-- doctest: output -->\n{FENCE}text\nnot printed\n{FENCE}\n"
    )
    results = _run(tmp_path, text)
    assert [r.ok for r in results] == [True, True, True, False], runner.failure_report(
        results
    )


def test_unmarked_text_blocks_are_not_compared(tmp_path):
    text = (
        f"# Page\n\n{FENCE}bash\necho one\n{FENCE}\n\n{FENCE}text\nanything\n{FENCE}\n"
    )
    results = _run(tmp_path, text)
    assert [r.lang for r in results] == ["bash"]


def test_a_sample_after_a_block_that_does_not_run_is_not_compared_but_reported(
    tmp_path,
):
    """Nothing produces output to compare it with, so the runner leaves it alone, and
    the marker check reports the marker instead of letting it pass unchecked."""
    text = (
        f'# Page\n\n<!-- doctest: illustrative reason="needs Docker" -->\n'
        f"{FENCE}bash\ndocker ps\n{FENCE}\n\n"
        f"<!-- doctest: output -->\n{FENCE}text\nCONTAINER ID\n{FENCE}\n\n"
        f"{FENCE}bash\necho runs\n{FENCE}\n"
    )
    results = _run(tmp_path, text)
    assert [r.lang for r in results] == ["bash"]
    assert results[0].command.strip() == "echo runs"
    findings = checks.check_markers([tmp_path / "page.md"], tmp_path)
    assert [(f.line, f.message[:38]) for f in findings] == [
        (8, "marked output but follows no run block")
    ], findings


def test_the_runner_compares_the_samples_the_marker_check_accepts(tmp_path):
    """The runner and the checks read one definition of an output sample."""
    text = (
        _page("echo one", "one")
        + f"\n{FENCE}python\nprint('two')\n{FENCE}\n\n"
        + f"<!-- doctest: output -->\n{FENCE}text\ntwo\n{FENCE}\n\n"
        + f"<!-- doctest: output -->\n{FENCE}text\nthree\n{FENCE}\n"
    )
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "page.md"
    path.write_text(text, encoding="utf-8")
    page = checks.parse_page(path, tmp_path)
    compared = runner.compared_samples(page)
    assert compared == checks.output_samples(page)
    assert sorted(
        block.fence_line for block in page.blocks if id(block) in compared
    ) == [
        8,
        17,
    ]
