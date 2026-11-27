"""``automated_security_helper.cli.container`` imports first, and without the root CLI.

``ash container build`` is registered lazily: ``cli/main.py`` names the command's
module by path (``_LAZY_SUBCOMMANDS``) and imports it only when the command is looked
up. The module took its help text from ``cli/main.py``, so importing it first ran the
whole root CLI module for one string, and an eager registration in ``cli/main.py``
(``from automated_security_helper.cli.container import container_app``) would have
made the two modules import each other. The text now lives in ``cli/help_text.py``,
which neither module imports back.

Both rows run a fresh interpreter. A pytest process has imported the root module long
before any test runs, and an import cycle shows only when the command module is the
first one a process imports (a plugin, a shell completion that walks the commands, a
test file run alone).
"""

from __future__ import annotations

import subprocess  # nosec B404 - fixed argv, sys.executable, no shell
import sys

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.unit

#: The command module imported first, then whether the root CLI module came with it.
_PROBE = """
import sys

import automated_security_helper.cli.container

root_imported = "automated_security_helper.cli.main" in sys.modules
print("ROOT_MODULE_IMPORTED=" + str(root_imported))
"""


@pytest.fixture(scope="module")
def first_import() -> subprocess.CompletedProcess[str]:
    """What a fresh interpreter reports after importing the command module first."""
    return subprocess.run(  # nosec B603 - fixed argv, no shell
        [sys.executable, "-c", importing_this_checkout(_PROBE)],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_the_container_module_imports_first_in_a_fresh_interpreter(first_import):
    assert first_import.returncode == 0, first_import.stderr


def test_the_container_module_does_not_import_the_root_cli_module(first_import):
    assert first_import.returncode == 0, first_import.stderr
    assert "ROOT_MODULE_IMPORTED=False" in first_import.stdout.splitlines(), (
        "importing cli/container.py ran cli/main.py: the command module reads "
        "something from the root CLI module. stdout:\n" + first_import.stdout
    )
