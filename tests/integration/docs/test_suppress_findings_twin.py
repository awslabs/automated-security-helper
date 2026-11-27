# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""how-to/suppress-findings.md: the scan goes red, the suppression turns it green, and
the page's account of what each way of suppressing leaves in the results.

The page's runnable blocks run in test_docs_examples.py, each held to the exit code it
is marked with. Nothing there reads what a scan wrote, and nothing there shows the
arc: a finding, then the suppression that takes it out of the verdict, then the
suppression that stops working. This twin runs those blocks in an order that does, on
the page's own fixture project (one detect-secrets finding, ``SECRET-SECRET-KEYWORD``
in ``app.py``, which ASH reports with no network and no extra tool), and then reads the
findings each scan wrote:

- red: the page's suppression command, with its ``--config-overrides`` taken away,
  exits 2 with the finding open;
- green: the page's suppression command exits 0, and the finding is still in the
  results, marked suppressed, with the reason the suppression gave. That is the page's
  first sentence: "A suppression keeps the finding in the results, marked suppressed,
  with your reason";
- an ignore path for ``app.py`` (the page's expired ignore path without its
  ``expires``) exits 0 and leaves no finding of ``app.py`` in the results at all, which
  is the page's other sentence: "An ignore path drops findings in a path from the
  results entirely";
- the page's misspelled ``ruleId`` exits 3 and prints the refusal the page quotes
  (``Unknown key 'ruleId' (did you mean 'rule_id'?)``); its expired suppression and
  its expired ignore path exit 2, and the expired suppression prints the line naming
  the entry;
- the page's ``vendor/`` run passes, and ``--ignore-suppressions`` exits 2 again.

``--config-overrides`` is what the page uses to try a suppression before writing it into
the file, so it is what the twin runs. The ``.ashrc.yaml`` entries of the page's first
YAML block name ``src/deploy.py`` and ``tests/**``, files this project does not have, so
the twin does not write them; their fields are held by the options table's own check
against the model (``<!-- doctest: options of=global_settings.suppressions -->``).
"""

from __future__ import annotations

import importlib.util
import os
import re
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
        reason="the docs runner is documented POSIX-only (docs_runner.py:41-47)",
    ),
]

PAGE = "docs/content/how-to/suppress-findings.md"
RULE = "SECRET-SECRET-KEYWORD"
OVERRIDE = re.compile(r"\s*\\\n\s*--config-overrides '[^']*'")


def _the_finding(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f["rule_id"] == RULE and f["file_path"] == "app.py"]


def test_a_suppression_turns_the_scan_green_and_leaves_the_finding_marked(
    tmp_path, request
):
    root = jt.docs_root(request.config)
    page = jt.parse_page(PAGE, root)
    blocks = [b for b in page.blocks if b.lang == "bash"]

    suppress = jt.only_block(
        blocks,
        'suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD"',
        without=(
            "ruleId",
            "expires",
            "--ignore-suppressions",
            "ignore_paths",
            "vendor",
        ),
    )
    misspelled = jt.only_block(blocks, '"ruleId"')
    expired = jt.only_block(
        blocks, "suppressions+=", '"expires": "2020-01-01"', without=("ruleId",)
    )
    expired_ignore = jt.only_block(blocks, "ignore_paths+=", '"expires": "2020-01-01"')
    vendor = jt.only_block(blocks, "mkdir -p vendor")
    everything = jt.only_block(blocks, "--ignore-suppressions")

    unsuppressed = OVERRIDE.sub("", suppress.body)
    assert unsuppressed != suppress.body and "--config-overrides" not in unsuppressed
    ignored = expired_ignore.body.replace(', "expires": "2020-01-01"', "")
    assert ignored != expired_ignore.body

    reason = re.search(r'"reason": "([^"]+)"', suppress.body)
    assert reason, "the page's suppression no longer gives a reason"
    prose = " ".join(" ".join(t for _l, t in page.prose).split())
    unknown_key = re.search(
        r"`(Unknown key 'ruleId' \(did you mean 'rule_id'\?\))`", prose
    )
    assert unknown_key, "the page no longer quotes the unknown-key warning"
    sample = jt.only_block(
        [b for b in page.blocks if b.lang == "text"], "expired on 2020-01-01"
    )
    named = re.search(r"Suppression of rule .*? expired on 2020-01-01\.", sample.body)
    assert named, "the page's sample no longer names the expired suppression"
    expired_line = named.group(0)

    twin = jt.Twin("the suppress-findings page", fixture="sample-project")
    twin.run(unsuppressed, code=2, prints=("actionable findings",))
    twin.run(jt.capture_scan("red"))
    twin.run(suppress.body, code=jt.block_exit(suppress), absent=("Exiting due to",))
    twin.run(jt.capture_scan("suppressed"))
    twin.run(ignored, absent=("Exiting due to",))
    twin.run(jt.capture_scan("ignored"))
    twin.run(
        misspelled.body,
        code=jt.block_exit(misspelled),
        prints=(unknown_key.group(1),),
    )
    twin.run(expired.body, code=jt.block_exit(expired), prints=(expired_line,))
    twin.run(expired_ignore.body, code=jt.block_exit(expired_ignore))
    twin.run(vendor.body, code=jt.block_exit(vendor))
    twin.run(everything.body, code=jt.block_exit(everything))
    session = twin.execute(tmp_path, root)

    open_finding = _the_finding(jt.findings(session, "red"))
    assert [f["is_suppressed"] for f in open_finding] == [False], open_finding

    kept = _the_finding(jt.findings(session, "suppressed"))
    assert [f["is_suppressed"] for f in kept] == [True], kept
    assert reason.group(1) in kept[0]["suppression_justification"]

    dropped = jt.findings(session, "ignored")
    assert [f for f in dropped if f["file_path"] == "app.py"] == [], dropped
