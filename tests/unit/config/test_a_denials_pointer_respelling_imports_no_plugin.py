"""A denial's respelling of a pointer imports no plugin module.

A runtime-override denial is matched through ``canonical_segments``, which
reads a pointer, or a denial's pattern, along the model and writes each old
spelling on the way as the canonical one, so a denial in a key's old spelling
still meets a write in its canonical one. Importing a plugin module registers
the plugins it defines, so that reading must import none. That holds through
the section of a scanner ASH ships whose manifest gives no typed section
(guarddog's): the fold and lint read such a section as the scanner's own config
class, which imports its module, and matching a denial does not.

The test watches a fresh interpreter's modules, so it starts a child Python and
is an integration test: it runs with ``--run-integration``.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.integration


def test_respelling_a_pointer_through_guarddogs_section_imports_no_plugin(
    tmp_path: Path,
) -> None:
    """A denial respells a pointer through guarddog's section and imports nothing.

    guarddog's manifest gives no typed section, and the walk that reads its
    section as the scanner's own config class imports the scanner's module.
    The fold and lint take that walk; a denial's respelling of the pointer
    (canonical_segments) does not, so matching a denial imports no plugin
    module, as building the plugin keys does not
    (``test_building_the_keys_imports_no_plugin_module`` in test_runtime_patch.py).
    The old spelling is respelled all the same: past a key the walk does not
    know, every old spelling is read as its canonical one.
    """
    # AshConfig is imported before the modules are counted: canonical_segments
    # imports it on its first call.
    code = (
        "import json, sys\n"
        "from automated_security_helper.plugins.loader import load_internal_plugins\n"
        "from automated_security_helper.config.ash_config import AshConfig\n"
        "from automated_security_helper.config import spellings\n"
        "load_internal_plugins()\n"
        "def loaded():\n"
        "    return sorted(m for m in sys.modules if 'plugin_modules.ash_' in m)\n"
        "before = loaded()\n"
        "assert not [m for m in before if 'guarddog' in m], before\n"
        "pointer = ['scanners', 'guarddog', 'options', 'excluded_paths']\n"
        "segments = spellings.canonical_segments([*pointer, '0', 'expiration'])\n"
        "assert loaded() == before, sorted(set(loaded()) - set(before))\n"
        "print(json.dumps(segments))\n"
    )
    result = subprocess.run(  # nosec B603 - fixed argv: this interpreter, literal probe
        [sys.executable, "-c", importing_this_checkout(code)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    segments = json.loads(result.stdout.strip().splitlines()[-1])
    assert segments == [
        "scanners",
        "guarddog",
        "options",
        "excluded_paths",
        "0",
        "expires",
    ]
