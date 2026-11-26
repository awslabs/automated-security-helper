# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The local tutorial's journey, run offline with bandit as its only scanner.

The tutorial's scans run every scanner, which downloads databases and rules, so its
scan steps are illustrative and the docs runner never runs them. Nothing then held the
page's central claims to the code: that the project of step 4 has findings, that the
suppression of step 7 takes one of them away, and that the fix of step 9 makes the
scan pass. This test runs a twin of steps 4 to 9 through the docs runner. The
project, the suppression and the fix are the journey's own blocks; only each scan is
narrowed to the journey's ``twin.scan`` (``ash --scanners bandit --offline``), which
needs nothing but bandit. bandit is the scanner the page's findings come from.

The page is a render of ``docs/journeys/getting-started-local.journey.yaml``
(``scripts/generate_journey_pages.py``), and that file's ``twin:`` fields are what
this test reads: each scan step's exit code and actionable-finding count, the rule
the report names, the config the suppression writes, the function the fix replaces.
The renderer refuses a journey whose samples contradict those fields, and the
freshness gate fails a page that is not the render, so the page cannot say one thing
while this test checks another. The test used to recover the same facts by parsing the
rendered page with regular expressions.

Each scan must exit with the code the journey states, and print its ``Exiting due to
N actionable findings`` line where it states a count. ``ashx results report`` in
step 6 must exit 0 and name the rule the page suppresses next.

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
import os
import posixpath
import shlex
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="the docs job has no Windows runner and the windows-latest legs "
        "install no scanner tools, so bandit is MISSING there and every scan of "
        "the twin exits 1 (test_docs_runner_can_fail.py skips the same way)",
    ),
]

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
JOURNEY = Path("docs/journeys/getting-started-local.journey.yaml")
#: The page this twin runs, named as the other journey twins name theirs, which is how
#: tests/unit/docs/test_every_page_is_doctested.py finds the page a twin covers.
PAGE = "docs/content/getting-started/local.md"
FENCE = "```"
#: The twin steps of the local tutorial, in page order. A journey that loses one has
#: stopped holding a claim the page makes.
TWIN_STEPS = ["project", "scan", "report", "save", "scan", "fix", "scan"]


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
journeys = _load(
    "_ash_journey_pages", REPO_ROOT / "scripts" / "generate_journey_pages.py"
)


def _docs_root(config) -> Path:
    value = config.getoption("--docs-root", default=None)
    return Path(value).resolve() if value else REPO_ROOT


def _twin(journey: dict) -> tuple[str, list[tuple[str, str]]]:
    """The twin page, and (expected exit, required output) for each block it runs."""
    twin = journey["twin"]
    steps = [
        segment["block"]
        for segment in journey["body"]
        if "block" in segment and "twin" in segment["block"]
    ]
    assert [step["twin"]["kind"] for step in steps] == TWIN_STEPS, (
        f"{JOURNEY} no longer has the steps of the local tutorial's twin, {TWIN_STEPS}"
    )
    project = next(step for step in steps if step["twin"]["kind"] == "project")
    name, source = journeys.heredoc_file(journeys.block_body(project))

    parts: list[str] = []
    expectations: list[tuple[str, str]] = []

    def run(body: str, expected: str, output: str) -> None:
        parts.append(
            f"<!-- doctest: run expect-exit={expected} timeout={twin['timeout']} -->\n"
            f"{FENCE}bash\n{body}\n{FENCE}\n"
        )
        expectations.append((expected, output))

    for step in steps:
        claim = step["twin"]
        body = journeys.block_body(step)
        if claim["kind"] == "project":
            run(body, "0", "")
        elif claim["kind"] == "scan":
            actionable = claim.get("actionable")
            run(
                twin["scan"],
                claim["exit"],
                f"Exiting due to {actionable} actionable findings"
                if actionable is not None
                else "",
            )
        elif claim["kind"] == "report":
            run(body, "0", claim["rule-id"])
        elif claim["kind"] == "save":
            directory = shlex.quote(posixpath.dirname(claim["path"]) or ".")
            run(
                f"mkdir -p {directory}\n"
                f"cat > {shlex.quote(claim['path'])} <<'EOF'\n{body}\nEOF",
                "0",
                "",
            )
        else:
            fixed = journeys.replace_function(source, body)
            run(f"cat > {shlex.quote(name)} <<'EOF'\n{fixed.rstrip()}\nEOF", "0", "")
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
    assert (docs_root / PAGE).is_file(), f"{PAGE} is the page this twin covers"
    journey = journeys.load_journey(docs_root / JOURNEY)
    text, expectations = _twin(journey)
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
