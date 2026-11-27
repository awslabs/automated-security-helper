# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""getting-started/ci.md's tutorial: the part of its arc that runs on one machine.

The page adds a GitHub Actions workflow and walks a pull request through it. That half
needs GitHub: a repository with Actions enabled, a pull request, a runner, the reusable
workflow at ``v3.8.0``, and code scanning. None of it runs here, and no step of this
twin pretends to: the workflow file of step 1, the comment, the JUnit check and the
code scanning upload of steps 2 and 4 are checked by the docs checks that read the
page (the ``config kind=github-actions`` blocks) and not by running them.

What does run here is what the workflow's scan job does on the repository: ASH on the
checked-out tree, and its exit code. The page says three things about it, and the twin
holds each to the code:

- step 5: a file whose ``subprocess`` call passes ``shell=True`` fails the scan with
  exit code 2, and bandit is the scanner that fails;
- step 3: the ``.ashrc.yaml`` the page adds to the root of the branch is a config ASH
  accepts, and with ``severity_threshold: HIGH`` that finding, which is HIGH, still
  fails the scan;
- step 5: "Delete the file and push again, and the checks pass, provided ``main`` itself
  had no actionable findings".

The page's ``main`` is a repository with code in it. The twin gives its tree one clean
Python file, ``hello.py``, which stands for that code: a tree that holds nothing bandit
can scan ends with exit 1 ("no scanner ran"), not with the pass the page describes.
The ``ash_demo.py`` file and the ``.ashrc.yaml`` are the page's own blocks, read from
the page; the scan is narrowed to ``ash scan fs --only-scanners bandit --offline``,
which needs nothing but bandit. Like the local tutorial's twin, it fails, and does not
skip, when bandit is missing.

Not run: the zizmor check of step 1 (a ``uses:`` line that names a tag is
``zizmor/unpinned-uses`` at HIGH until it is pinned to a commit). zizmor is not among
the tools the integration tier is guaranteed to have, and a twin that skipped when it
was absent would be a green run that ran nothing.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


jt = _load("_ash_journey_twin", Path(__file__).resolve().parent / "journey_twin.py")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="the docs job has no Windows runner and the windows-latest legs "
        "install no scanner tools, so bandit is MISSING there and every scan of "
        "the twin exits 1 (test_docs_runner_can_fail.py skips the same way)",
    ),
]

PAGE = "docs/content/getting-started/ci.md"


def test_the_ci_tutorials_scan_fails_on_the_shell_call_and_passes_without_it(
    tmp_path, request
):
    jt.require_bandit()
    root = jt.docs_root(request.config)
    page = jt.parse_page(PAGE, root)

    demo = jt.only_block(jt.blocks_under(page, r"5\."), "shell=True", lang="python")
    gate = jt.only_block(
        jt.blocks_under(page, r"3\."), "severity_threshold: HIGH", lang="yaml"
    )

    twin = jt.Twin("the CI tutorial")
    twin.run("printf 'print(\"hello\")\\n' > hello.py")
    twin.run(jt.BANDIT_SCAN, absent=("Exiting due to",))
    twin.run(f"cat > ash_demo.py <<'EOF'\n{demo.body}\nEOF")
    twin.run(
        jt.BANDIT_SCAN,
        code=2,
        prints=("bandit", "FAILED", "Exiting due to 1 actionable findings"),
    )
    twin.run(f"cat > .ashrc.yaml <<'EOF'\n{gate.body}\nEOF")
    twin.run("ash config validate", prints=("Configuration is valid!",))
    twin.run(
        jt.BANDIT_SCAN,
        code=2,
        prints=("FAILED", "Exiting due to 1 actionable findings"),
    )
    twin.run("rm ash_demo.py")
    twin.run(jt.BANDIT_SCAN, absent=("Exiting due to",))
    twin.execute(tmp_path, root)
