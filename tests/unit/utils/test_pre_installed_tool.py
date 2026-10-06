# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``verify_pre_installed_tool`` against a real venv and the real uv, offline.

The venv is made with the stdlib ``venv`` module and populated with hand-written
``.dist-info`` metadata, so the real ``uv pip install --dry-run --offline
--no-cache`` decides without a network or a cache. That is the point of these
tests: they check uv's actual verdicts on extras, environment markers and
version constraints, which is what the scanner selection relies on.
"""

import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from automated_security_helper.utils import pre_installed_tool
from automated_security_helper.utils.pre_installed_tool import (
    build_requirement,
    find_tool_interpreter,
    reset_pre_installed_tool_cache,
    verify_pre_installed_tool,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="writes a POSIX console script; a Windows venv needs an .exe launcher",
)

# uv is a runtime dependency of ASH, so its absence is a failure, not a skip.
UV = shutil.which("uv") or "uv"
# makeWrapper names bash by absolute path; so do these fixtures.
BASH = shutil.which("bash") or "/bin/bash"


@pytest.fixture(autouse=True)
def _fresh_cache():
    reset_pre_installed_tool_cache()
    yield
    reset_pre_installed_tool_cache()


def _add_dist(site_packages: Path, name: str, version: str, requires=()):
    dist = site_packages / f"{name.replace('-', '_')}-{version}.dist-info"
    dist.mkdir()
    lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    extras = sorted(
        {r.split('extra == "')[1].split('"')[0] for r in requires if "extra ==" in r}
    )
    lines += [f"Provides-Extra: {e}" for e in extras]
    lines += [f"Requires-Dist: {r}" for r in requires]
    (dist / "METADATA").write_text("\n".join(lines) + "\n")
    (dist / "INSTALLER").write_text("test\n")
    (dist / "RECORD").write_text("")


@pytest.fixture
def tool_env(tmp_path):
    """A venv providing ``faketool`` 1.9.4 with a ``sarif`` and a ``toml`` extra."""
    root = tmp_path / "tool-venv"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(root)
    site_packages = next(root.glob("lib/python*/site-packages"))
    _add_dist(
        site_packages,
        "faketool",
        "1.9.4",
        requires=[
            'sarif-om>=1.0.4; extra == "sarif"',
            # Excluded by its marker on every supported Python; uv must agree.
            'tomli>=1.1.0; python_version < "3.0" and extra == "toml"',
        ],
    )
    script = root / "bin" / "faketool"
    script.write_text(f"#!{root / 'bin' / 'python'}\nprint('faketool 1.9.4')\n")
    script.chmod(0o755)
    return root, site_packages, script


def test_satisfied_when_the_environment_has_every_extra(tool_env):
    _, site_packages, script = tool_env
    _add_dist(site_packages, "sarif-om", "1.0.4")

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif", "toml"], ">=1.7.0,<2.0.0", uv_executable=UV
    )

    assert verdict.status == "satisfied", verdict.detail


def test_missing_extra_is_named(tool_env):
    _, _, script = tool_env

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif", "toml"], ">=1.7.0,<2.0.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied"
    assert verdict.missing_extras == ("sarif",)
    assert "missing extra: sarif" in verdict.detail


def test_version_outside_the_constraint_is_named(tool_env):
    _, site_packages, script = tool_env
    _add_dist(site_packages, "sarif-om", "1.0.4")

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif"], ">=2.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied"
    assert verdict.missing_extras == ()
    assert "does not satisfy '>=2.0'" in verdict.detail


def test_symlinked_entry_point_resolves_to_its_venv(tool_env, tmp_path):
    """``uv tool install`` puts a symlink in ~/.local/bin; follow it to the venv."""
    root, site_packages, script = tool_env
    _add_dist(site_packages, "sarif-om", "1.0.4")
    bin_dir = tmp_path / "local-bin"
    bin_dir.mkdir()
    (bin_dir / "faketool").symlink_to(script)

    assert find_tool_interpreter(str(bin_dir / "faketool")) == str(
        root / "bin" / "python"
    )
    verdict = verify_pre_installed_tool(
        str(bin_dir / "faketool"), "faketool", ["sarif"], None, uv_executable=UV
    )
    assert verdict.status == "satisfied", verdict.detail


def test_a_binary_that_does_not_run_is_unsatisfied(tmp_path):
    broken = tmp_path / "faketool"
    broken.write_text("#!/bin/sh\necho boom >&2\nexit 3\n")
    broken.chmod(0o755)

    verdict = verify_pre_installed_tool(str(broken), "faketool", ["sarif"], None)

    assert verdict.status == "unsatisfied"
    assert "exited 3" in verdict.detail and "boom" in verdict.detail


def test_a_tool_with_no_python_environment_is_unverifiable(tmp_path):
    native = tmp_path / "faketool"
    native.write_text("#!/bin/sh\necho 1.0\n")
    native.chmod(0o755)

    verdict = verify_pre_installed_tool(str(native), "faketool", ["sarif"], None)

    assert verdict.status == "unverifiable"


def test_a_missing_path_is_unverifiable(tmp_path):
    verdict = verify_pre_installed_tool(str(tmp_path / "nope"), "faketool")
    assert verdict.status == "unverifiable"


def test_uv_errors_unrelated_to_resolution_are_unverifiable(tool_env, monkeypatch):
    """A dry run that fails for another reason says nothing about the extras."""
    _, _, script = tool_env
    real_run = subprocess.run

    def fake_run(argv, *args, **kwargs):
        if Path(argv[0]).name == "uv":
            return subprocess.CompletedProcess(
                argv, 2, "", "error: interpreter broke\n"
            )
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(pre_installed_tool.subprocess, "run", fake_run)

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif"], None, uv_executable=UV
    )

    assert verdict.status == "unverifiable"


def test_verdicts_are_memoized(tool_env, monkeypatch):
    _, _, script = tool_env
    first = verify_pre_installed_tool(
        str(script), "faketool", ["sarif"], None, uv_executable=UV
    )

    def no_subprocess(*args, **kwargs):
        raise AssertionError("a memoized verdict must not re-probe")

    monkeypatch.setattr(pre_installed_tool.subprocess, "run", no_subprocess)
    assert (
        verify_pre_installed_tool(
            str(script), "faketool", ["sarif"], None, uv_executable=UV
        )
        == first
    )


def test_build_requirement_matches_the_uv_from_spec():
    assert build_requirement("bandit", ["sarif", "toml"], ">=1.7.0,<2.0.0") == (
        "bandit[sarif,toml]>=1.7.0,<2.0.0"
    )
    assert (
        build_requirement("checkov", None, ">=3.2.0,<4.0.0") == "checkov>=3.2.0,<4.0.0"
    )
    assert build_requirement("semgrep", [], None) == "semgrep"


# --- nixpkgs-wrapped programs -------------------------------------------------
#
# The layouts below copy what nixpkgs builds for a Python application (checked
# against checkov 3.3.9, bandit 1.9.4 and semgrep 1.172.0 from the flake):
# bin/<tool> is a makeWrapper bash script that execs bin/.<tool>-wrapped, whose
# shebang is a BARE interpreter and whose second or third line puts the
# closure on sys.path with site.addsitedir. The interpreter here is a fresh
# venv's python, so like Nix's it has nothing installed of its own.


def _nix_store_path(store: Path, name: str, dists) -> str:
    site_packages = store / name / "lib" / "python3" / "site-packages"
    site_packages.mkdir(parents=True)
    for dist_name, version, requires in dists:
        _add_dist(site_packages, dist_name, version, requires)
    return str(site_packages)


def _nix_program(tmp_path, tool, version, closure, *, make_wrapper=True):
    """A Nix-shaped ``tool``. ``closure`` is ``[(store_name, [(dist, ver, reqs)])]``."""
    interpreter_root = tmp_path / "nix-python"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(interpreter_root)
    interpreter = interpreter_root / "bin" / "python"

    store = tmp_path / "store"
    site_dirs = [_nix_store_path(store, name, dists) for name, dists in closure]
    bin_dir = store / f"{tool}-{version}" / "bin"
    bin_dir.mkdir(parents=True)

    sitedir_list = ",".join(f"'{d}'" for d in site_dirs)
    wrapped = bin_dir / (f".{tool}-wrapped" if make_wrapper else tool)
    wrapped.write_text(
        f"#!{interpreter}\n"
        "# -*- coding: utf-8 -*-\n"
        f"import sys;import site;import functools;sys.argv[0] = '{bin_dir / tool}';"
        f"functools.reduce(lambda k, p: site.addsitedir(p, k), [{sitedir_list}], "
        "site._init_pathinfo());\n"
        f"print('{tool} {version}')\n"
    )
    wrapped.chmod(0o755)
    if make_wrapper:
        wrapper = bin_dir / tool
        wrapper.write_text(
            f"#! {BASH} -e\n"
            "export PYTHONNOUSERSITE='true'\n"
            f'exec -a "$0" "{wrapped}"  "$@" \n'
        )
        wrapper.chmod(0o755)
    return bin_dir / tool, str(interpreter), site_dirs


CHECKOV_CLOSURE = [
    ("checkov", [("checkov", "3.3.9", ["pyyaml>=6"])]),
    ("pyyaml", [("pyyaml", "6.0.2", [])]),
]


def test_a_nix_wrapped_program_is_verified_against_its_closure(tmp_path):
    """Before: 'could not locate the Python environment', so uv ran a PyPI build."""
    program, interpreter, site_dirs = _nix_program(
        tmp_path, "checkov", "3.3.9", CHECKOV_CLOSURE
    )

    assert pre_installed_tool.find_nix_python_environment(str(program)) == (
        interpreter,
        tuple(site_dirs),
    )
    verdict = verify_pre_installed_tool(
        str(program), "checkov", None, ">=3.2.0,<4.0.0", uv_executable=UV
    )

    assert verdict.status == "satisfied", verdict.detail
    assert verdict.from_nix is True


def test_a_nix_wrapped_program_that_is_too_old_names_the_version(tmp_path):
    program, _, _ = _nix_program(tmp_path, "checkov", "3.3.9", CHECKOV_CLOSURE)

    verdict = verify_pre_installed_tool(
        str(program), "checkov", None, ">=3.4.0,<4.0.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied"
    assert verdict.from_nix is True
    assert "Nix environment" in verdict.detail
    assert "installed checkov does not satisfy '>=3.4.0,<4.0.0'" in verdict.detail


def test_a_nix_closure_missing_an_extra_names_the_extra(tmp_path):
    """nixpkgs' bandit omits the sarif extra the scan's --format sarif needs."""
    program, _, _ = _nix_program(
        tmp_path,
        "bandit",
        "1.9.4",
        [("bandit", [("bandit", "1.9.4", ['sarif-om>=1.0.4; extra == "sarif"'])])],
    )

    verdict = verify_pre_installed_tool(
        str(program), "bandit", ["sarif"], ">=1.7.0,<2.0.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied"
    assert verdict.missing_extras == ("sarif",)
    assert "does not satisfy '>=1.7.0,<2.0.0'" not in verdict.detail


def test_a_gap_deeper_in_a_nix_closure_is_not_called_a_version_mismatch(tmp_path):
    """nixpkgs' semgrep requires pyjwt[crypto] but ships pyjwt without cryptography."""
    program, _, _ = _nix_program(
        tmp_path,
        "semgrep",
        "1.172.0",
        [
            ("semgrep", [("semgrep", "1.172.0", ["pyjwt[crypto]>=2.13"])]),
            (
                "pyjwt",
                [("pyjwt", "2.13.0", ['cryptography>=3.4.0; extra == "crypto"'])],
            ),
        ],
    )

    verdict = verify_pre_installed_tool(
        str(program), "semgrep", None, ">=1.125.0,<2.0.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied"
    assert "does not satisfy '>=1.125.0,<2.0.0'" not in verdict.detail
    assert "because cryptography was not found" in verdict.detail
    assert "\x1b[" not in verdict.detail


def test_a_nix_wrapped_script_installed_without_make_wrapper(tmp_path):
    """No makeWrapper arguments: bin/<tool> is the python script itself."""
    program, interpreter, _ = _nix_program(
        tmp_path, "checkov", "3.3.9", CHECKOV_CLOSURE, make_wrapper=False
    )

    # The shebang names a bare interpreter, which is what the venv path would
    # have used, and whose empty environment satisfies nothing.
    assert find_tool_interpreter(str(program)) == interpreter
    verdict = verify_pre_installed_tool(
        str(program), "checkov", None, ">=3.2.0,<4.0.0", uv_executable=UV
    )

    assert verdict.status == "satisfied", verdict.detail
    assert verdict.from_nix is True


def test_a_venv_tool_is_not_mistaken_for_a_nix_program(tool_env):
    _, _, script = tool_env

    assert pre_installed_tool.find_nix_python_environment(str(script)) is None
