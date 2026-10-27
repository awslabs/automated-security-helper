# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On Python 3.10, a non-editable ASH install's hints name its own source.

Why this file exists
--------------------
The reinstall and extra hints find ASH's distribution with
``packages_distributions()``. The standard library's version of it on Python 3.10
reads only ``top_level.txt``, and hatchling writes none, so on 3.10 every
non-editable install (a wheel, ``pip install git+...``, ``uv tool install``, uvx)
went unfound. The hints then fell back to the release tag, which on a build
between releases names an older tree and, for the symbols extra, a tag that does
not define the extra. The unit suite cannot see this: its 3.10 run is an editable
install, which the second discovery strategy finds by path.

What it does
------------
It builds a wheel shaped like hatchling's (METADATA, WHEEL and RECORD, no
``top_level.txt``) from the package under test and its real metadata, installs it
into a fresh Python 3.10 environment without dependencies, then installs only the
packages the hint code imports, at the versions this environment has, plus tomli,
which the package's import chain needs on 3.10 alone, at the constraint ASH's own
metadata declares for it. The ``direct_url.json`` the installer wrote is replaced
by the one uv writes for a git install, so the hints must name that commit.

Needs uv and a Python 3.10 that uv can find or download; it fails, rather than
skipping, when either is missing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from importlib.metadata import distribution, version
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

import automated_security_helper

pytestmark = pytest.mark.slow

COMMIT = "0123456789abcdef0123456789abcdef01234567"
GIT_RECORD = {
    "url": "https://github.com/awslabs/automated-security-helper.git",
    "vcs_info": {"vcs": "git", "commit_id": COMMIT, "requested_revision": COMMIT},
}
#: What ``automated_security_helper.utils.ash_install`` imports outside the
#: standard library, installed at the versions this environment has.
IMPORTED_DEPENDENCIES = ("rich", "importlib-metadata")
#: What the package's import chain needs on 3.10 and this environment, on a newer
#: Python, does not install: version_management reads pyproject.toml with tomli
#: below 3.11 (tomllib from 3.11), and pyproject.toml declares tomli under a
#: python_full_version marker, so ``version("tomli")`` has no answer here.
#: Installed at the requirement ASH's own metadata declares for 3.10 instead.
DECLARED_DEPENDENCIES = ("tomli",)

PROBE = """
import json
from automated_security_helper.utils import ash_install
print(json.dumps({
    "reinstall": ash_install.ash_reinstall_command(),
    "symbols": ash_install.extra_install_command("symbols"),
}))
"""


def _uv(*args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [sys.executable, "-m", "uv", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"uv {' '.join(args)} failed:\n{result.stderr}"
    return result


def _record_line(arcname: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"{arcname},sha256={digest.decode()},{len(data)}"


def _build_wheel(dest: Path) -> Path:
    """A wheel of the package under test, laid out the way hatchling lays it out."""
    dist = distribution("automated-security-helper")
    name_version = f"automated_security_helper-{dist.version}"
    dist_info = f"{name_version}.dist-info"
    wheel = dest / f"{name_version}-py3-none-any.whl"
    package = Path(automated_security_helper.__file__).resolve().parent
    entries = {
        f"automated_security_helper/{path.relative_to(package).as_posix()}": path.read_bytes()
        for path in sorted(package.rglob("*.py"))
        if "__pycache__" not in path.parts
    }
    entries[f"{dist_info}/METADATA"] = dist.read_text("METADATA").encode()
    entries[f"{dist_info}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: hatchling\nRoot-Is-Purelib: true\n"
        b"Tag: py3-none-any\n"
    )
    record = [_record_line(arcname, data) for arcname, data in entries.items()]
    record.append(f"{dist_info}/RECORD,,")
    entries[f"{dist_info}/RECORD"] = ("\n".join(record) + "\n").encode()
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
        for arcname, data in entries.items():
            archive.writestr(arcname, data)
    return wheel


#: The environment the 3.10 install is for, as its markers see it: the base
#: install of ASH (no extra) on Python 3.10.
_PYTHON_310_ENVIRONMENT = {
    "python_version": "3.10",
    "python_full_version": "3.10.0",
    "extra": "",
}


def _declared_requirement(name: str) -> str:
    """The version constraint ASH's own metadata declares for ``name`` on 3.10.

    Each ``Requires-Dist`` entry is parsed, its name compared in canonical form
    (so ``tomli-w`` is not ``tomli``), and its marker evaluated for the 3.10
    environment, so an entry of an extra, or of another Python, is not the one
    installed. The marker itself is dropped from what is returned: the install
    is for the 3.10 environment, where it holds, and the constraint is what pins.
    """
    wanted = canonicalize_name(name)
    for entry in distribution("automated-security-helper").requires or ():
        requirement = Requirement(entry)
        if canonicalize_name(requirement.name) != wanted:
            continue
        if requirement.marker is not None and not requirement.marker.evaluate(
            _PYTHON_310_ENVIRONMENT
        ):
            continue
        requirement.marker = None
        return str(requirement)
    raise AssertionError(
        f"ASH's metadata declares no dependency named {name} for Python 3.10"
    )


def _run(python: Path, *args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        [str(python), *args], capture_output=True, text=True, cwd=cwd, check=False
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_a_git_install_on_python_310_is_reinstalled_from_its_commit(tmp_path):
    wheel = _build_wheel(tmp_path)
    venv = tmp_path / "venv310"
    _uv("venv", "--python", "3.10", str(venv))
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    _uv("pip", "install", "--python", str(python), "--no-deps", str(wheel))
    _uv(
        "pip",
        "install",
        "--python",
        str(python),
        *(f"{name}=={version(name)}" for name in IMPORTED_DEPENDENCIES),
        *(_declared_requirement(name) for name in DECLARED_DEPENDENCIES),
    )
    assert _run(python, "-c", "import sys; print(sys.version_info[:2])") == "(3, 10)"

    site = Path(
        _run(python, "-c", "import sysconfig; print(sysconfig.get_path('purelib'))")
    )
    dist_infos = list(site.glob("automated_security_helper-*.dist-info"))
    assert len(dist_infos) == 1, dist_infos
    assert not (dist_infos[0] / "top_level.txt").exists()
    (dist_infos[0] / "direct_url.json").write_text(
        json.dumps(GIT_RECORD), encoding="utf-8"
    )

    hints = json.loads(_run(python, "-I", "-c", PROBE, cwd=tmp_path).splitlines()[-1])

    assert f"git+{GIT_RECORD['url']}@{COMMIT}" in hints["reinstall"], hints
    assert "@v" not in hints["reinstall"], hints
    assert "tree-sitter" in hints["symbols"], hints
    assert "automated-security-helper" not in hints["symbols"], hints
