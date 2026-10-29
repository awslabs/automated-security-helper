# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A CI e2e leg has the tools its tests drive, and says so by name when it does not.

The e2e tests run the product the way an operator does: the ``ash`` CLI as a child
process, the MCP server as a child process, a docs page's commands in a shell. A
runner that lacks one of the programs they start does not fail those tests; most of
them skip, and a leg that skips everything exits 0 and reads green. This module is the
leg-level assertion for the tools a leg is provisioned with today, so the loss of one
fails the leg by name instead of thinning it out.

What an e2e leg is provisioned with, from .github/workflows/ash-unified-ci.yml
(``e2e-test-linux``, ``-macos``, ``-windows``) and the ``setup-ash`` and
``run-unit-tests`` actions: uv and a Python from ``setup-ash`` with ``install-ash`` off,
then ``uv sync --extra cdk --extra symbols`` and ``uv run pytest -m e2e``. That puts
three console scripts in the environment's own scripts directory: ``ash``,
``cfn-lint`` and ``detect-secrets``. The runner image supplies ``git``, ``bash`` and
``node``, and ``setup-ash`` supplies ``uv``.

The console scripts are looked up in the running interpreter's scripts directory and
not on PATH, so the check does not depend on how the leg's PATH was built. The system
tools are looked up on PATH.

Not asserted here: the third-party scanner binaries (grype, trivy, syft, semgrep,
opengrep, checkov, bandit, gitleaks, actionlint, zizmor, cfn-guard, ferret-scan and the
rest) and the container runtimes. No step of the e2e jobs installs them today, and the
e2e tests that need one skip when it is absent (``_why_it_cannot_run`` in
tests/integration/scanners/test_links_leaving_the_tree_reach_no_output.py is the
nearest thing to a shared skip; there is no fixture shared by all e2e modules).
Provisioning them is a separate CI change. Until it lands, the executed-test floor in
tests/utils/sharding.py (``fail_a_tier_run_that_executed_no_test``) is what makes an
e2e leg that ran nothing fail.

The check applies to a CI tier run only, as ``sharding.is_ci_tier_run`` in
tests/utils/sharding.py defines it, the same test the executed-test floor uses. On a
developer's machine it skips and names the tools.
"""

from __future__ import annotations

import shutil
import sys
import sysconfig
from pathlib import Path
from typing import Optional, Sequence

import pytest

from tests.utils import sharding

pytestmark = pytest.mark.e2e

#: Console scripts of this checkout's environment, found beside the interpreter.
ENVIRONMENT_SCRIPTS = ("ash", "cfn-lint", "detect-secrets")
#: Programs the runner image or ``setup-ash`` puts on PATH.
SYSTEM_TOOLS = ("git", "bash", "node", "uv")


def _missing(names: Sequence[str], search_path: Optional[str]) -> list[str]:
    """The names ``shutil.which`` does not find; ``search_path=None`` means PATH."""
    return [name for name in names if shutil.which(name, path=search_path) is None]


def test_the_e2e_runner_has_the_tools_its_tests_drive(request):
    # The control comes first and runs everywhere: the lookup must be able to find a
    # program that is there and to miss one that is not, or the assertion below proves
    # nothing in either direction.
    interpreter = Path(sys.executable)
    assert _missing([interpreter.name], str(interpreter.parent)) == []
    assert _missing(["no-such-tool-7c41e2"], None) == ["no-such-tool-7c41e2"]

    wanted = ", ".join((*ENVIRONMENT_SCRIPTS, *SYSTEM_TOOLS))
    if not sharding.is_ci_tier_run(request.config):
        pytest.skip(
            "not a CI tier run (sharding.is_ci_tier_run is false); "
            f"on a CI e2e leg this asserts that {wanted} are found"
        )

    scripts_directory = sysconfig.get_path("scripts")
    missing_scripts = _missing(ENVIRONMENT_SCRIPTS, scripts_directory)
    missing_system = _missing(SYSTEM_TOOLS, None)
    assert not (missing_scripts or missing_system), (
        "this e2e leg lacks tools its tests drive. "
        f"Missing from the environment's scripts directory ({scripts_directory}): "
        f"{', '.join(missing_scripts) or 'none'}. "
        f"Missing from PATH: {', '.join(missing_system) or 'none'}. "
        f"All required: {wanted}"
    )
