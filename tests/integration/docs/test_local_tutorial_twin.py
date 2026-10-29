# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""getting-started/local.md's tutorial, run offline with bandit as its only scanner.

The tutorial's scans run every scanner, which downloads databases and rules, so its
scan steps are illustrative and the docs runner never runs them. Nothing then held the
page's central claims to the code: that the project of step 4 has findings, that the
suppression of step 7 takes one of them away, and that the fix of step 9 makes the
scan pass. This test runs a twin of steps 4 to 9 through the docs runner. The
project, the suppression and the fix are the page's own blocks, read from the page;
only each scan is narrowed to ``ash --scanners bandit --offline``, which needs nothing
but bandit. bandit is the scanner the page's findings come from.

Each scan must exit with the code the page prints below it (``exit code: N``), and
print the page's ``Exiting due to N actionable findings`` line where it shows one.
``ash report`` in step 6 must exit 0 and name the rule the page suppresses next.

bandit has to be where a docs session finds tools (docs_runner.session_path): the
interpreter's bin directory, a directory ASH installs tools into for the invoking user
(ASH's bin directory, uv's tool bin directory), or /usr/local/bin, /usr/bin or /bin,
with the sarif and toml extras the bandit scanner requires offline.
``ash dependencies install --tool bandit`` installs it that way. When it is not there,
this fails and says so; without the extras, the scans show bandit MISSING and exit 1.
It does not skip: a skip would be a green run that ran nothing.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
PAGE = Path("docs/content/getting-started/local.md")
FENCE = "```"
TWIN_SCAN = "ash --scanners bandit --offline"
SCAN_TIMEOUT_S = 300


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


def _docs_root(config) -> Path:
    value = config.getoption("--docs-root", default=None)
    return Path(value).resolve() if value else REPO_ROOT


def _steps(page) -> dict[int, list]:
    """The page's blocks under each numbered step heading (``## 5. Run the scan``)."""
    headings = sorted(
        (line, int(match.group(1)))
        for line, text in page.prose
        if (match := re.match(r"^##\s+(\d+)\.\s", text))
    )
    steps: dict[int, list] = {}
    for block in page.blocks:
        number = None
        for line, step in headings:
            if line < block.fence_line:
                number = step
        if number is not None:
            steps.setdefault(number, []).append(block)
    return steps


def _scan_and_sample(blocks, step: int):
    """The step's ``ash`` scan block and the output sample after it."""
    for index, block in enumerate(blocks):
        if block.lang == "bash" and re.search(r"^ash\s*$", block.body, re.MULTILINE):
            # The first sample after the scan that says how it exits: step 5 shows a
            # narrower scan's table before the full scan's output.
            sample = next(
                (
                    b
                    for b in blocks[index + 1 :]
                    if b.lang == "text"
                    and re.search(r"^exit code: \d+$", b.body, re.MULTILINE)
                ),
                None,
            )
            assert sample is not None, f"step {step} shows no output for its scan"
            return block, sample.body
    raise AssertionError(f"step {step} of {PAGE} has no `ash` scan block")


def _expected_exit(sample: str, step: int) -> str:
    found = re.findall(r"^exit code: (\d+)$", sample, re.MULTILINE)
    assert len(found) == 1, f"step {step}'s sample does not say which code it exits"
    return found[0]


def _heredoc_file(body: str) -> tuple[str, str]:
    """(name, content) of the file a ``cat > name <<'EOF'`` block writes."""
    match = re.search(
        r"^cat > (\S+) <<'EOF'\n(.*?)\nEOF$", body, re.MULTILINE | re.DOTALL
    )
    assert match, "step 4 no longer writes its project file with a here-document"
    return match.group(1), match.group(2)


def _replace_function(source: str, replacement: str) -> str:
    """source with the top-level function replacement defines swapped for it."""
    name = re.match(r"\s*def (\w+)\(", replacement)
    assert name, "step 9's block is not a function definition"
    pattern = re.compile(
        rf"^def {name.group(1)}\(.*?(?=^\S|\Z)", re.MULTILINE | re.DOTALL
    )
    assert pattern.search(source), f"step 4's project has no {name.group(1)}()"
    return pattern.sub(replacement.strip("\n") + "\n", source, count=1)


def _twin(page) -> tuple[str, list[tuple[str, str]]]:
    """The twin page, and (expected exit, required output) for each block it runs."""
    steps = _steps(page)
    for step in (4, 5, 6, 7, 8, 9):
        assert steps.get(step), f"{PAGE} has no blocks under step {step}"
    project = next(b for b in steps[4] if b.lang == "bash")
    name, source = _heredoc_file(project.body)
    config = next(b for b in steps[7] if b.lang in ("yaml", "yml"))
    fix = next(b for b in steps[9] if b.lang == "python")
    report = next(b for b in steps[6] if b.body.strip() == "ash report")
    report_sample = next(b.body for b in steps[6] if b.lang == "text")
    rule = re.search(r"Rule ID: (\S+)", report_sample)
    assert rule, "step 6's sample names no rule"

    parts: list[str] = []
    expectations: list[tuple[str, str]] = []

    def run(body: str, expected: str, output: str) -> None:
        parts.append(
            f"<!-- doctest: run expect-exit={expected} timeout={SCAN_TIMEOUT_S} -->\n"
            f"{FENCE}bash\n{body}\n{FENCE}\n"
        )
        expectations.append((expected, output))

    def scan(step: int) -> None:
        _block, sample = _scan_and_sample(steps[step], step)
        actionable = re.search(r"Exiting due to \d+ actionable findings", sample)
        run(
            TWIN_SCAN,
            _expected_exit(sample, step),
            actionable.group(0) if actionable else "",
        )

    run(project.body, "0", "")
    scan(5)
    run(report.body, "0", rule.group(1))
    run(f"mkdir -p .ash\ncat > .ash/.ash.yaml <<'EOF'\n{config.body}\nEOF", "0", "")
    scan(8)
    fixed = _replace_function(source, fix.body)
    run(f"cat > {name} <<'EOF'\n{fixed.rstrip()}\nEOF", "0", "")
    scan(9)
    return "# Twin of the local tutorial\n\n" + "\n".join(parts), expectations


def test_the_local_tutorial_holds_with_bandit_offline(tmp_path, request):
    session_path = runner.session_path()
    bandit = shutil.which("bandit", path=session_path)
    if bandit is None:
        pytest.fail(
            "bandit is not installed where a docs session looks for tools "
            f"({session_path}), so the local tutorial's twin cannot run. Install it "
            "with `ash dependencies install --tool bandit`, or into this environment "
            "with the extras ASH's bandit scanner requires (`uv pip install "
            "'bandit[sarif,toml]'`); the integration-test job must install it before "
            "the docs examples step.",
            pytrace=False,
        )
    docs_root = _docs_root(request.config)
    page = checks.parse_page(docs_root / PAGE, docs_root)
    text, expectations = _twin(page)
    twin_path = tmp_path / "local-twin.md"
    twin_path.write_text(text, encoding="utf-8")
    twin = checks.parse_page(twin_path, tmp_path)
    scratch = tmp_path / "sessions"
    scratch.mkdir()
    results = runner.PageRunner(twin, scratch, docs_root=docs_root).run()
    assert len(results) == len(expectations), runner.failure_report(results)
    missing = [
        f"{result.page}:{result.line}: {result.command!r} did not print {output!r}; "
        f"its output ends:\n{result.output[-1500:]}"
        for result, (_expected, output) in zip(results, expectations)
        if result.ok and output not in result.output
    ]
    if missing or not all(result.ok for result in results):
        pytest.fail(
            "\n\n".join([runner.failure_report(results), *missing]), pytrace=False
        )
