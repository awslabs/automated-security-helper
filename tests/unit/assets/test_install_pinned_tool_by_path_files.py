"""The files install-pinned-tool.py loads by path load with no package installed.

The installer runs before ASH is installed: in the image build, and in CI steps that
call it from a checkout with the system interpreter. So ``load_pins`` does not import
the few package files it needs. It loads each one by path and registers it under its
dotted name, with bare stand-ins for the parent packages, so that ``tool_downloads``
can import the two files loaded before it. An import of any other part of the package
finds nothing: the package is not installed and the stand-ins have no search path.

That is a rule on each of those files. At module level it may import the standard
library and the files loaded before it, and nothing else. A module-level import of
``utils/short_reason`` in ``core/exceptions.py`` broke it without any test noticing:
every in-process test stayed green because the package is importable inside a test,
and the first failure was the installer step of a CI job, ``ModuleNotFoundError: No
module named 'automated_security_helper.utils'``.

The tests start a child interpreter with ``-I -S`` in a directory outside the
checkout, so that it cannot import the package, and they check four things:

* The child cannot import the package. Without that, a load that needs the package
  would pass here for the wrong reason.
* Every file the installer loads by path loads. The list is the installer's own: the
  child wraps the installer's loader and runs ``load_pins``, so a file added to
  ``load_pins`` later is checked with no edit to this file. A file that fails is
  recorded and the run goes on, so one run names every file that is broken.
* ``load_pins`` runs once as it is, unwrapped, and returns the pins.
* The check can fail. In a scratch copy of the listed files, one file at a time ends
  in a module-level import of the package, and the run must report that file. In a
  tree where a listed file already fails on its own this cannot tell the planted
  import from the real one; the second test is the one that fails then.

They start a process, so they are integration tests; the unit tier starts none.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE = "automated_security_helper"
PACKAGE_ROOT = REPO_ROOT / PACKAGE
SCRIPT = PACKAGE_ROOT / "assets" / "install-pinned-tool.py"

#: The line added at the end of one scratch copy. It imports a module of the package
#: that is none of the files the installer loads, as a module-level import does.
_PLANTED_IMPORT = f"\nimport {PACKAGE}.utils.short_reason  # planted by the test\n"

#: What the child runs. Its code names no module of the package: the name to look for
#: is an argument. ``mode`` is one of
#:
#: - "importable": report whether the package can be imported, and stop;
#: - "each": run load_pins with the installer's loader wrapped, so that every file it
#:   asks for is attempted and a failure is recorded where it would have been raised;
#: - "plain": run load_pins as it is.
_PROBE = """
import importlib.util
import json
import sys
import types
from pathlib import Path

installer_file, package_root, mode, package = sys.argv[1:5]
report = {"importable": importlib.util.find_spec(package) is not None}
if mode != "importable" and not report["importable"]:
    spec = importlib.util.spec_from_file_location("pins_loader", installer_file)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    asked, failed = [], []
    real_load = loader._load_by_path

    def attempt(name, path):
        asked.append(str(path))
        try:
            return real_load(name, path)
        except Exception as error:
            reason = type(error).__name__ + ": " + str(error)
            failed.append({"file": str(path), "error": reason})
            return types.ModuleType(name)

    if mode == "each":
        loader._load_by_path = attempt
    loaded = loader.load_pins(Path(package_root))
    report.update(asked=asked, failed=failed, loaded=loaded.__name__)
print(json.dumps(report))
"""


def _run_probe(package_root: Path, mode: str, cwd: Path) -> dict[str, Any]:
    """The probe's report, from a child interpreter that cannot import the package."""
    result = subprocess.run(  # nosec B603 - fixed interpreter, script and probe
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            _PROBE,
            str(SCRIPT),
            str(package_root),
            mode,
            PACKAGE,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=cwd,
    )
    if result.returncode != 0:
        pytest.fail(
            f"the probe exited {result.returncode} in its {mode!r} run over "
            f"{package_root}:\n{result.stderr}"
        )
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["importable"] is False, (
        f"the probe interpreter can import {PACKAGE}, so a load that needs it would "
        "pass here for the wrong reason"
    )
    return report


def _failures(failed: list[dict[str, str]], root: Path) -> str:
    """What to tell a reader whose change made a by-path file need the package."""
    listing = "\n".join(
        f"  {Path(entry['file']).relative_to(root).as_posix()}: {entry['error']}"
        for entry in failed
    )
    return (
        "install-pinned-tool.py loads these files by path before the package is "
        "installed, so at module level each may import the standard library and the "
        "files loaded before it, and nothing else. These did not load on an "
        f"interpreter that cannot import {PACKAGE}; the first is the cause, and any "
        f"after it may follow from it:\n{listing}\n"
        "Move the import of any other part of the package into the function that "
        "uses it."
    )


class TestTheByPathFilesLoadOnABareInterpreter:
    def test_the_probe_interpreter_cannot_import_the_package(self, tmp_path):
        # Importable here and hidden there: the flags are what let the other tests
        # prove anything.
        assert importlib.util.find_spec(PACKAGE) is not None

        report = _run_probe(PACKAGE_ROOT, "importable", tmp_path)

        assert report == {"importable": False}

    def test_every_file_loaded_by_path_loads_without_the_package(self, tmp_path):
        report = _run_probe(PACKAGE_ROOT, "each", tmp_path)

        assert report["asked"], (
            "load_pins asked to load no file by path, so nothing was checked. If the "
            "installer's loader was renamed or replaced, update _PROBE to match."
        )
        assert not report["failed"], _failures(report["failed"], PACKAGE_ROOT)

    def test_load_pins_returns_the_pins_without_the_package(self, tmp_path):
        report = _run_probe(PACKAGE_ROOT, "plain", tmp_path)

        assert report["loaded"] == f"{PACKAGE}.utils.tool_downloads"

    def test_a_listed_file_that_imports_the_package_is_reported(self, tmp_path):
        asked = _run_probe(PACKAGE_ROOT, "each", tmp_path)["asked"]
        listed = [Path(path).relative_to(PACKAGE_ROOT) for path in asked]
        assert listed, "the installer listed no file, so there is nothing to plant in"

        for number, planted in enumerate(listed):
            root = tmp_path / f"scratch-{number}"
            for relative in listed:
                text = (PACKAGE_ROOT / relative).read_text(encoding="utf-8")
                copy = root / relative
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_text(
                    text + _PLANTED_IMPORT if relative == planted else text,
                    encoding="utf-8",
                )

            failed = _run_probe(root, "each", tmp_path)["failed"]

            reported = [
                entry for entry in failed if Path(entry["file"]) == root / planted
            ]
            assert reported, (
                f"a copy of {planted.as_posix()} that imports {PACKAGE} at module "
                "level was not reported as failing, so this check cannot fail for "
                f"it:\n{_failures(failed, root)}"
            )
            assert PACKAGE in reported[0]["error"], reported[0]["error"]
