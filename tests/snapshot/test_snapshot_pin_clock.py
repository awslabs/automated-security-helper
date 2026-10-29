# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``pin_clock``'s id counter is the test's own, whatever ran before it.

The config loader's client-supplied check
(``config_sources.refuse_environment_in_a_delivered_file``) imports
``automated_security_helper.cli.mcp.sandbox`` on first use, and that import
chain (``cli.mcp`` -> ``mcp.server`` -> ``opentelemetry``) calls ``uuid.uuid4``
at module level: ``opentelemetry.context`` builds three context keys with it,
and ``opentelemetry.baggage`` and ``opentelemetry.trace.propagation`` one each.
On a fresh process -- the first test on an xdist worker, or a file run on its
own -- that first use happens inside ``pin_clock``'s counter window, so the
model built afterwards gets report id ``...006`` where the committed snapshot
holds ``...001``. Which test pays the draws depends on what ran earlier in the
process, which is exactly what a pinned id must not depend on.

Each cell runs in a child interpreter, a fresh process with nothing imported
yet, rather than this worker with modules taken out of ``sys.modules``: what a
first import draws depends on everything the process has not imported, not
only on the trees a test knows to remove.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - a fresh interpreter is the property under test
import sys

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.integration

#: Runs ``sys.argv[1]`` (one of the scenarios below) in a fresh interpreter and
#: prints what it found as JSON on the last line.
DRIVER = """
import json, sys, uuid
from pathlib import Path

import pytest

from tests.snapshot.support.fixture_model import fixture_config, pin_clock

def pinned_index(drawn):
    # pin_clock's n-th id is uuid.UUID(int=n, version=4); 0 for any other.
    return next(
        (n for n in range(1, 100) if drawn == uuid.UUID(int=n, version=4)), 0
    )


outcome = {"premise": "opentelemetry" not in sys.modules}
monkeypatch = pytest.MonkeyPatch()
scenario = sys.argv[1]
if scenario == "first-config-load":
    pin_clock(monkeypatch)
    fixture_config()
    outcome["first"] = pinned_index(uuid.uuid4())
elif scenario == "module-drawing-at-import":
    # A module no one has imported, which draws an id while it loads.
    module_dir = Path(sys.argv[2])
    (module_dir / "draws_at_import.py").write_text(
        "import uuid\\nDRAWN = uuid.uuid4()\\n", encoding="utf-8"
    )
    sys.path.insert(0, str(module_dir))
    pin_clock(monkeypatch)
    import draws_at_import  # noqa: F401
    outcome["first"] = pinned_index(uuid.uuid4())
elif scenario == "the-tests-own-draws":
    pin_clock(monkeypatch)
    outcome["draws"] = [pinned_index(uuid.uuid4()), pinned_index(uuid.uuid4())]
monkeypatch.undo()
print(json.dumps(outcome))
"""


def _run(scenario: str, *args: str, cwd) -> dict:
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [sys.executable, "-I", "-c", importing_this_checkout(DRIVER), scenario, *args],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=cwd,
    )
    assert completed.returncode == 0, completed.stderr[-3000:]
    outcome = json.loads(completed.stdout.strip().splitlines()[-1])
    assert outcome["premise"], (
        "the child had imported opentelemetry before the scenario ran, so it "
        "is not the fresh process the cell is about"
    )
    return outcome


def test_a_fresh_process_s_first_config_load_does_not_consume_pinned_ids(tmp_path):
    """After ``pin_clock`` and a first config load, the next id is still 1."""
    outcome = _run("first-config-load", cwd=tmp_path)
    assert outcome["first"] == 1, (
        "the config loader's first import consumed pinned ids: the test's own "
        f"first draw is id {outcome['first']}"
    )


def test_a_module_that_draws_while_it_loads_does_not_consume_pinned_ids(tmp_path):
    """Any module imported for the first time inside the window, not only the
    config loader's chain: an id drawn while a module loads is not the test's,
    so it comes from the real ``uuid4``."""
    outcome = _run("module-drawing-at-import", str(tmp_path), cwd=tmp_path)
    assert outcome["first"] == 1, (
        "a module's import-time draw consumed a pinned id: the test's own first "
        f"draw is id {outcome['first']}"
    )


def test_the_test_s_own_draws_are_pinned(tmp_path):
    """The control: what the code under test draws comes from the counter."""
    outcome = _run("the-tests-own-draws", cwd=tmp_path)
    assert outcome["draws"] == [1, 2], outcome["draws"]
