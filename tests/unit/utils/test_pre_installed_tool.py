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

from automated_security_helper.utils import pre_installed_tool, subprocess_utils
from automated_security_helper.utils.pre_installed_tool import (
    build_requirement,
    find_tool_interpreter,
    reset_pre_installed_tool_cache,
    verify_pre_installed_tool,
)
from automated_security_helper.utils.uv_tool_runner import bundled_uv_executable

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="writes a POSIX console script; a Windows venv needs an .exe launcher",
)

# uv is a runtime dependency of ASH, so its absence is a failure, not a skip. The uv
# installed with ASH first, as ASH looks it up (``find_uv_or_none``), rather than
# whichever one the PATH of the run holds.
UV = bundled_uv_executable() or shutil.which("uv") or "uv"
#: The tests that run that uv. The unit tests' tool guard (tests/unit/conftest.py)
#: would answer for it; uv's own verdict is what they check.
real_uv = pytest.mark.runs_real_tools(
    reason="uv's own dry-run verdicts on extras, markers and constraints"
)
# makeWrapper names bash by absolute path; so do these fixtures.
BASH = shutil.which("bash") or "/bin/bash"


@pytest.fixture(autouse=True)
def _uv_is_on_path():
    """Fail each test with one clear reason when uv is missing, rather than a dozen
    unrelated-looking errors from inside the checks. Not a skip: a runner without
    uv cannot run ASH, and these tests must not pass quietly there."""
    if shutil.which("uv") is None:
        pytest.fail(
            "uv is not on PATH. These tests run the real uv, which ASH needs at "
            "run time; install uv to run them."
        )


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


@pytest.mark.integration
@real_uv
def test_satisfied_when_the_environment_has_every_extra(tool_env):
    _, site_packages, script = tool_env
    _add_dist(site_packages, "sarif-om", "1.0.4")

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif", "toml"], ">=1.7.0,<2.0.0", uv_executable=UV
    )

    assert verdict.status == "satisfied", verdict.detail


@pytest.mark.integration
@real_uv
def test_missing_extra_is_named(tool_env):
    _, _, script = tool_env

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif", "toml"], ">=1.7.0,<2.0.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied"
    assert verdict.missing_extras == ("sarif",)
    assert "missing extra: sarif" in verdict.detail
    assert "missing extra: sarif" in verdict.summary


@pytest.mark.integration
@real_uv
def test_version_outside_the_constraint_is_named(tool_env):
    _, site_packages, script = tool_env
    _add_dist(site_packages, "sarif-om", "1.0.4")

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif"], ">=2.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied"
    assert verdict.missing_extras == ()
    assert "does not satisfy '>=2.0'" in verdict.detail


@pytest.mark.integration
@real_uv
@pytest.mark.parametrize(
    "name, value",
    [
        ("COLUMNS", "10"),
        ("COLUMNS", "20"),
        ("FORCE_COLOR", "1"),
        ("CLICOLOR_FORCE", "1"),
        ("TTY_COMPATIBLE", "1"),
    ],
)
def test_the_verdict_does_not_follow_the_callers_terminal(
    tool_env, monkeypatch, name, value
):
    """uv wraps its resolver error at the caller's COLUMNS, and colors it under
    FORCE_COLOR or CLICOLOR_FORCE, though its output is a pipe. At COLUMNS=20 "No
    solution found when resolving" came back split across lines, and a requirement
    the environment does not meet read "unverifiable"."""
    _, site_packages, script = tool_env
    _add_dist(site_packages, "sarif-om", "1.0.4")
    monkeypatch.setenv(name, value)

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif"], ">=2.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied", verdict.detail
    assert "does not satisfy '>=2.0'" in verdict.detail
    assert "\x1b" not in verdict.detail


@pytest.mark.integration
@real_uv
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


@pytest.mark.integration
def test_a_binary_that_does_not_run_is_unsatisfied(tmp_path):
    broken = tmp_path / "faketool"
    broken.write_text("#!/bin/sh\necho boom >&2\nexit 3\n")
    broken.chmod(0o755)

    verdict = verify_pre_installed_tool(str(broken), "faketool", ["sarif"], None)

    assert verdict.status == "unsatisfied"
    assert "exited 3" in verdict.detail and "boom" in verdict.detail


@pytest.mark.unit
def test_the_probe_excerpt_hides_a_respelled_env_read_version(tmp_path, monkeypatch):
    """The failed --version probe's excerpt gets the UV layer, not the
    neutral one: a pre-installed copy of a uv-managed tool can print an
    env-read version in another spelling ("9.9.9-RC777" as "9.9.9rc777"),
    which the neutral layer's as-written match misses, and the excerpt is
    redacted BEFORE its 500-character cut."""
    executable = tmp_path / "faketool"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        pre_installed_tool,
        "_run",
        lambda command, timeout: subprocess.CompletedProcess(
            command, 2, "", "faketool resolver pinned 9.9.9rc777 at startup"
        ),
    )

    verdict = verify_pre_installed_tool(
        str(executable),
        "faketool",
        ["sarif"],
        "==9.9.9-RC777",
        values=("9.9.9-RC777",),
    )

    assert verdict.status == "unsatisfied"
    assert "exited 2" in verdict.detail, verdict.detail
    assert "9.9.9rc777" not in verdict.detail, verdict.detail
    assert "9.9.9" not in verdict.detail, verdict.detail


@pytest.mark.integration
def test_a_tool_with_no_python_environment_is_unverifiable(tmp_path):
    native = tmp_path / "faketool"
    native.write_text("#!/bin/sh\necho 1.0\n")
    native.chmod(0o755)

    verdict = verify_pre_installed_tool(str(native), "faketool", ["sarif"], None)

    assert verdict.status == "unverifiable"


@pytest.mark.unit
@pytest.mark.parametrize("status", ["satisfied", "unsatisfied"])
def test_a_verdict_carries_the_version_its_probe_answered(
    tmp_path, monkeypatch, status
):
    """The ``--version`` probe the verification runs answers with the copy's
    version; the verdict keeps its first line, as uv's own probe reads a tool's
    version, so a caller running this copy reports the version that runs."""
    # A file that exists: the verdict is memoized by its mtime. Nothing runs it.
    executable = tmp_path / "jupyter-nbconvert"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        pre_installed_tool,
        "_run",
        lambda command, timeout: subprocess.CompletedProcess(
            command, 0, "7.16.0\nmore output\n", ""
        ),
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_nix_python_environment", lambda executable: None
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_tool_interpreter", lambda executable: "/env/python"
    )
    monkeypatch.setattr(pre_installed_tool, "_dry_run", lambda *a, **k: (status, ""))

    verdict = verify_pre_installed_tool(
        str(executable),
        "nbconvert",
        [],
        ">=7.16.0",
        uv_executable="/env/bin/uv",
    )

    # The control: the stubbed dry run decided the verdict.
    assert verdict.status == status
    assert getattr(verdict, "version", None) == "7.16.0"


@pytest.mark.unit
def test_the_version_hides_a_value_spanning_its_first_line_cut(tmp_path, monkeypatch):
    """The version the verdict carries is the probe answer's first line, and
    that cut rewrites an env-read value's line break before the downstream
    whole-spelling redaction can match it: the first half of the value rode
    out as the version. The probe's stdout is redacted whole with the
    caller's values before the first line is taken."""
    value = "Zq7Kx9LmLeak\nPw4Nv2RtTail"
    executable = tmp_path / "jupyter-nbconvert"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        pre_installed_tool,
        "_run",
        lambda command, timeout: subprocess.CompletedProcess(
            command, 0, f"7.16.0 {value} end\nmore output\n", ""
        ),
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_nix_python_environment", lambda executable: None
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_tool_interpreter", lambda executable: "/env/python"
    )
    monkeypatch.setattr(
        pre_installed_tool, "_dry_run", lambda *a, **k: ("satisfied", "")
    )

    verdict = verify_pre_installed_tool(
        str(executable),
        "nbconvert",
        [],
        ">=7.16.0",
        uv_executable="/env/bin/uv",
        values=(value,),
    )

    version = getattr(verdict, "version", None) or ""
    # The controls: the probe's own words around the value survive.
    assert "7.16.0" in version, version
    assert "Zq7Kx9LmLeak" not in version, version
    assert "Pw4Nv2RtTail" not in version, version


@pytest.mark.unit
def test_the_version_hides_a_respelled_env_read_version(tmp_path, monkeypatch):
    """The successful probe's answer gets the same uv layer as the failed
    one: the probed copy can be a uv-managed tool's, and it can print an
    env-read version in another spelling ("9.9.9-RC777" as "9.9.9rc777"),
    which the neutral as-written match misses -- so the respelled form rode
    out as the carried version while the failed branch hid it."""
    executable = tmp_path / "jupyter-nbconvert"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        pre_installed_tool,
        "_run",
        lambda command, timeout: subprocess.CompletedProcess(
            command, 0, "9.9.9rc777\nmore output\n", ""
        ),
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_nix_python_environment", lambda executable: None
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_tool_interpreter", lambda executable: "/env/python"
    )
    monkeypatch.setattr(
        pre_installed_tool, "_dry_run", lambda *a, **k: ("satisfied", "")
    )

    verdict = verify_pre_installed_tool(
        str(executable),
        "nbconvert",
        [],
        "==9.9.9-RC777",
        uv_executable="/env/bin/uv",
        values=("9.9.9-RC777",),
    )

    version = getattr(verdict, "version", None) or ""
    assert "9.9.9rc777" not in version, version
    assert "9.9.9" not in version, version


@pytest.mark.unit
def test_a_value_the_probe_never_printed_leaves_the_version_as_answered(
    tmp_path, monkeypatch
):
    """The control for the spanning cell: redacting with a value the probe's
    answer does not hold changes nothing, so the verdict still carries the
    version that runs."""
    executable = tmp_path / "jupyter-nbconvert"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        pre_installed_tool,
        "_run",
        lambda command, timeout: subprocess.CompletedProcess(
            command, 0, "7.16.0\nmore output\n", ""
        ),
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_nix_python_environment", lambda executable: None
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_tool_interpreter", lambda executable: "/env/python"
    )
    monkeypatch.setattr(
        pre_installed_tool, "_dry_run", lambda *a, **k: ("satisfied", "")
    )

    verdict = verify_pre_installed_tool(
        str(executable),
        "nbconvert",
        [],
        ">=7.16.0",
        uv_executable="/env/bin/uv",
        values=("UnrelatedValueTheToolNeverPrinted",),
    )

    assert getattr(verdict, "version", None) == "7.16.0"


@pytest.mark.unit
def test_a_missing_path_is_unverifiable(tmp_path):
    verdict = verify_pre_installed_tool(str(tmp_path / "nope"), "faketool")
    assert verdict.status == "unverifiable"


@pytest.mark.integration
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

    # verify_pre_installed_tool starts its probes through ASH's plain runner.
    monkeypatch.setattr(subprocess_utils, "_run_plain", fake_run)

    verdict = verify_pre_installed_tool(
        str(script), "faketool", ["sarif"], None, uv_executable=UV
    )

    assert verdict.status == "unverifiable"


@pytest.mark.integration
@real_uv
def test_verdicts_are_memoized(tool_env, monkeypatch):
    _, _, script = tool_env
    first = verify_pre_installed_tool(
        str(script), "faketool", ["sarif"], None, uv_executable=UV
    )

    def no_subprocess(*args, **kwargs):
        raise AssertionError("a memoized verdict must not re-probe")

    monkeypatch.setattr(subprocess_utils, "_run_plain", no_subprocess)
    assert (
        verify_pre_installed_tool(
            str(script), "faketool", ["sarif"], None, uv_executable=UV
        )
        == first
    )


@pytest.mark.unit
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


@pytest.mark.integration
@real_uv
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


@pytest.mark.integration
@real_uv
def test_a_nix_wrapped_program_that_is_too_old_names_the_version(tmp_path):
    program, _, _ = _nix_program(tmp_path, "checkov", "3.3.9", CHECKOV_CLOSURE)

    verdict = verify_pre_installed_tool(
        str(program), "checkov", None, ">=3.4.0,<4.0.0", uv_executable=UV
    )

    assert verdict.status == "unsatisfied"
    assert verdict.from_nix is True
    assert "Nix environment" in verdict.detail
    assert "installed checkov does not satisfy '>=3.4.0,<4.0.0'" in verdict.detail


@pytest.mark.integration
@real_uv
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


@pytest.mark.integration
@real_uv
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


@pytest.mark.integration
@real_uv
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


@pytest.mark.unit
def test_a_venv_tool_is_not_mistaken_for_a_nix_program(tool_env):
    _, _, script = tool_env

    assert pre_installed_tool.find_nix_python_environment(str(script)) is None


@pytest.mark.integration
@real_uv
class TestACheckTheSandboxRefusedIsNotRemembered:
    """A check the scanner sandbox refused never ran, so it has no verdict to keep.

    Verdicts are memoized for the whole process. A check made under a scope that
    refuses every spawn (a scanner that cannot be sandboxed as requested) is not
    remembered, so a later check of the same tool, in another scope or a later scan
    of the process, runs and decides.
    """

    def test_the_refused_check_is_unverifiable_and_says_why(self, tool_env):
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )

        _, site_packages, script = tool_env
        _add_dist(site_packages, "sarif-om", "1.0.4")

        with sandbox_scope(RefusingScope("faketool", "no sandbox backend here")):
            refused = verify_pre_installed_tool(
                str(script), "faketool", ["sarif"], None, uv_executable=UV
            )

        assert refused.status == "unverifiable"
        assert "no sandbox backend here" in refused.detail, refused.detail

    def test_a_later_check_runs_and_decides(self, tool_env):
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )

        _, site_packages, script = tool_env
        _add_dist(site_packages, "sarif-om", "1.0.4")
        with sandbox_scope(RefusingScope("faketool", "no sandbox backend here")):
            verify_pre_installed_tool(
                str(script), "faketool", ["sarif"], None, uv_executable=UV
            )

        later = verify_pre_installed_tool(
            str(script), "faketool", ["sarif"], None, uv_executable=UV
        )

        assert later.status == "satisfied", later.detail

    def test_a_refused_dry_run_is_not_remembered_either(self, tool_env, monkeypatch):
        """The version probe ran; the sandbox refused only the uv dry run."""
        from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

        _, site_packages, script = tool_env
        _add_dist(site_packages, "sarif-om", "1.0.4")
        real_spawn = pre_installed_tool.spawn_run

        def refuse_uv(argv, *args, **kwargs):
            if Path(argv[0]).name == "uv":
                raise SandboxUnavailable("the backend cannot plan uv here")
            return real_spawn(argv, *args, **kwargs)

        monkeypatch.setattr(pre_installed_tool, "spawn_run", refuse_uv)
        refused = verify_pre_installed_tool(
            str(script), "faketool", ["sarif"], None, uv_executable=UV
        )
        monkeypatch.setattr(pre_installed_tool, "spawn_run", real_spawn)
        later = verify_pre_installed_tool(
            str(script), "faketool", ["sarif"], None, uv_executable=UV
        )

        assert refused.status == "unverifiable"
        assert "the backend cannot plan uv here" in refused.detail, refused.detail
        assert later.status == "satisfied", later.detail


@pytest.mark.integration
def test_a_probe_failures_summary_names_no_path_and_no_tool_output(tmp_path):
    """``summary`` reaches recorded reasons (the jupyter converter's), so it
    carries the category and the exit code only; the copy's path and the
    probe's own words stay in ``detail`` for the log."""
    tool = tmp_path / "failing-tool"
    tool.write_text(f'#!{BASH}\necho "CARRIED-VALUE $0" >&2\nexit 7\n')
    tool.chmod(0o755)

    verdict = verify_pre_installed_tool(str(tool), "nbconvert", [], "==7.0.0")

    assert verdict.status == "unsatisfied"
    # The log's detail still names the copy and quotes the probe (controls).
    assert str(tool) in verdict.detail, verdict.detail
    assert "CARRIED-VALUE" in verdict.detail, verdict.detail
    assert "exited 7" in verdict.summary, verdict.summary
    assert str(tool) not in verdict.summary, verdict.summary
    assert "CARRIED-VALUE" not in verdict.summary, verdict.summary


@pytest.mark.integration
def test_a_version_mismatch_summary_names_no_interpreter_and_no_constraint(tmp_path):
    """The judged verdict's summary says the version constraint is not met
    without quoting the constraint (it can be read from the environment) or
    the interpreter's path; ``detail`` keeps both for the log."""
    uv = tmp_path / "uv"
    uv.write_text(f'#!{BASH}\necho "No solution found when resolving" >&2\nexit 1\n')
    uv.chmod(0o755)
    requirement = build_requirement("nbconvert", [], "==999.0.0")

    verdict = pre_installed_tool._judge(
        str(tmp_path / "jupyter-nbconvert"),
        "nbconvert",
        [],
        "==999.0.0",
        requirement,
        str(uv),
        sys.executable,
        None,
        f"its environment ({sys.executable})",
        values=(),
    )

    assert verdict.status == "unsatisfied"
    # The log's detail still names the environment and the constraint.
    assert sys.executable in verdict.detail, verdict.detail
    assert "999.0.0" in verdict.detail, verdict.detail
    assert "version constraint" in verdict.summary, verdict.summary
    assert sys.executable not in verdict.summary, verdict.summary
    assert "999" not in verdict.summary, verdict.summary


@pytest.mark.unit
def test_the_judges_values_parameter_cannot_be_passed_positionally():
    """The judge's redaction values are a required keyword: a positional
    eleventh argument raises at the call, so a new caller cannot silently
    hand the values to the wrong slot or run the judge with redaction off.
    The TypeError comes from the signature, so no probe ever starts."""
    with pytest.raises(TypeError):
        pre_installed_tool._judge(
            "faketool",
            "fakepkg",
            [],
            None,
            "fakepkg",
            "/nonexistent/uv",
            "/nonexistent/python",
            None,
            "its environment (/nonexistent/python)",
            None,
            (),
        )


@pytest.mark.integration
def test_a_probe_excerpt_hides_a_value_straddling_its_cut(tmp_path):
    """The probe's stderr is redacted BEFORE the excerpt's 500-character cut.

    The 492 filler characters put the cut inside the value: cut first, the
    excerpt would keep the fragment ``EDGE-SEC``, which the downstream
    whole-spelling redaction cannot match.
    """
    value = "EDGE-SECRET-7731"
    broken = tmp_path / "faketool"
    broken.write_text(
        "#!/bin/sh\necho '" + "x" * 492 + value + " and more' >&2\nexit 3\n"
    )
    broken.chmod(0o755)

    verdict = verify_pre_installed_tool(
        str(broken), "faketool", ["sarif"], None, values=[value]
    )

    assert verdict.status == "unsatisfied"
    assert "exited 3" in verdict.detail, verdict.detail
    assert value not in verdict.detail, verdict.detail
    assert "EDGE-SEC" not in verdict.detail, verdict.detail


@pytest.mark.integration
def test_a_generator_of_values_reaches_the_verify_whole(tmp_path, monkeypatch):
    """``values`` is consumed once: the memo key's ``tuple(values)`` used to
    drain a generator, so ``_verify`` got an empty set, cached an unredacted
    probe excerpt under a key that says it was redacted, and served it to
    every later caller with the same values."""
    received = []
    real_verify = pre_installed_tool._verify

    def _recording_verify(*args):
        received.append(args[-1])
        return real_verify(*args)

    monkeypatch.setattr(pre_installed_tool, "_verify", _recording_verify)
    value = "EDGE-SECRET-4482"
    broken = tmp_path / "faketool"
    broken.write_text("#!/bin/sh\necho 'uses " + value + "' >&2\nexit 3\n")
    broken.chmod(0o755)

    verdict = verify_pre_installed_tool(
        str(broken), "faketool", None, None, values=(v for v in (value,))
    )

    assert received == [(value,)], received
    assert value not in verdict.detail, verdict.detail


def _first_cause_adaptive(output, values, requirement, package):
    """Call ``_first_cause`` however the tree under test spells it.

    On a tree without the values threading the one-argument form runs, so
    these cells go red on the hidden-value assert -- the leak itself --
    never on a TypeError that would only prove the signature changed."""
    import inspect

    if "values" in inspect.signature(pre_installed_tool._first_cause).parameters:
        return pre_installed_tool._first_cause(output, values, requirement, package)
    return pre_installed_tool._first_cause(output)


@pytest.mark.unit
def test_the_cause_is_redacted_before_its_lines_are_flowed():
    """uv wraps long clauses at the terminal's width, so an env-read value can
    span the wrap. ``_first_cause`` flowed the RAW lines into one text (every
    line break became a space) before any redaction layer saw them, so the
    value's flowed spelling no longer matched its whole spelling and the
    fragments printed in the verdict detail. The cause text is redacted first,
    with the uv input layer ``_verify``'s own excerpt uses, and unwrapped
    after."""
    value = "Zq7Kx9Lm\nPw4Nv2Rt"
    output = (
        "  x No solution found when resolving dependencies:\n"
        f"  `-> Because faketool depends on {value} and you require faketool,\n"
        "      we can conclude that your requirements are unsatisfiable.\n"
    )

    reason = _first_cause_adaptive(output, (value,), "faketool==1.0", "faketool")

    assert reason.startswith("because "), reason
    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in reason, (part, reason)


@pytest.mark.unit
def test_the_cause_hides_a_value_uv_wrapped_with_an_indent():
    """uv wraps a long clause at a SPACE and indents the continuation line.
    The raw-text redaction cannot match the value across "\\n      ", and the
    flow (every whitespace run becomes one space) then REBUILDS the value's
    exact spelling after the only redaction pass had run, so it printed in
    clear. Before the one redaction pass runs, each value's whitespace
    respelling is normalized back to the value's own spelling, so the
    whole-spelling match sees it."""
    value = "Zq7Kx9Lm Pw4Nv2Rt"
    output = (
        "  x No solution found when resolving dependencies:\n"
        "  `-> Because faketool depends on Zq7Kx9Lm\n"
        "      Pw4Nv2Rt and you require faketool,\n"
        "      we can conclude that your requirements are unsatisfiable.\n"
    )

    reason = _first_cause_adaptive(output, (value,), "faketool==1.0", "faketool")

    assert reason.startswith("because "), reason
    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in reason, (part, reason)


@pytest.mark.unit
def test_the_fallback_hides_a_value_uv_wrapped_with_an_indent():
    """The first-line fallback reads the redacted lines too: a value whose
    first half ends the first line must not ride out in it."""
    value = "Zq7Kx9Lm Pw4Nv2Rt"
    output = "error: failed to read metadata near Zq7Kx9Lm\n      Pw4Nv2Rt here\n"

    reason = _first_cause_adaptive(output, (value,), "faketool==1.0", "faketool")

    assert "failed to read metadata" in reason, reason
    assert "Zq7Kx9Lm" not in reason, reason


@pytest.mark.unit
def test_the_hidden_argument_marker_survives_the_glyph_strip():
    """The tree glyphs uv draws are stripped from line edges; a both-edges
    strip AFTER the redaction ate the closing ">" of a line-ending
    "<argument N not shown>" marker (the strip set holds ">"), so the marker
    printed broken. The strip takes only a glyph PREFIX and trailing
    whitespace, so a placeholder at a line end keeps its ">".

    The input is hidden through the layer's substring arm: the env-read
    value sits GLUED inside the requirement's name, where the value layer's
    boundary match cannot reach it, so the whole input is replaced by the
    marker -- the one provenance-checked route that puts a marker at a line
    end (a value the layer matches at a boundary is rewritten before the
    input token is looked for, so that token never matches)."""
    value = "Zq7Kx9Lm"
    requirement = "pkgZq7Kx9Lm==1.0"
    output = (
        "  x No solution found when resolving dependencies:\n"
        f"  `-> Because you require {requirement}\n"
        "      and it was yanked, we can conclude that your requirements"
        " are unsatisfiable.\n"
    )

    reason = _first_cause_adaptive(output, (value,), requirement, "pkgZq7Kx9Lm")

    assert "<argument" in reason, reason
    assert "not shown>" in reason, reason
    assert requirement not in reason, reason


@pytest.mark.unit
def test_the_cause_is_still_unwrapped_with_no_values():
    """Control: with nothing env-read the extraction is unchanged."""
    output = (
        "  x No solution found when resolving dependencies:\n"
        "  `-> Because there is no version of faketool and you require faketool,\n"
        "      we can conclude that your requirements are unsatisfiable.\n"
    )

    reason = _first_cause_adaptive(output, (), "faketool==1.0", "faketool")

    assert reason == (
        "because there is no version of faketool and you require faketool"
    ), reason


@pytest.mark.unit
def test_the_fallback_first_line_is_taken_from_the_redacted_text():
    """When uv's output has no "Because" clause, ``_first_cause`` answers
    with the output's first line. That line has to come from the redacted
    text: answering the raw first line prints the env-read value as the
    whole cause, with every layer bypassed."""
    value = "Zq7Kx9LmSecretValue"
    output = f"error: failed to read metadata near {value} here\nmore output\n"

    reason = _first_cause_adaptive(output, (value,), "faketool==1.0", "faketool")

    # The control: the line's own words survive.
    assert "failed to read metadata" in reason, reason
    assert value not in reason, reason


@pytest.mark.unit
def test_the_fallback_is_the_first_line_with_no_values():
    """Control for the fallback pin: with nothing env-read the first line is
    answered as uv printed it."""
    output = "error: failed to read metadata here\nmore output\n"

    reason = _first_cause_adaptive(output, (), "faketool==1.0", "faketool")

    assert reason == "error: failed to read metadata here", reason


def _uv_tree(lines):
    """uv's tree: the clause's first line behind its ASCII glyph, continuation
    lines indented six spaces, as the cells above write it inline."""
    first, *rest = lines
    return (
        "  x No solution found when resolving dependencies:\n"
        f"  `-> {first}\n" + "".join(f"      {line}\n" for line in rest)
    )


_TAIL = (
    "and you require faketool, we can conclude that your requirements are "
    "unsatisfiable."
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "value, lines, core",
    [
        pytest.param(
            "-Zq7Kx9LmPw4Nv2Rt",
            ["Because faketool depends on", f"-Zq7Kx9LmPw4Nv2Rt {_TAIL}"],
            "Zq7Kx9LmPw4Nv2Rt",
            id="leading-dash-at-line-start",
        ),
        pytest.param(
            "Zq7Kx9LmPw4Nv2Rt-",
            ["Because faketool depends on Zq7Kx9LmPw4Nv2Rt-", _TAIL],
            "Zq7Kx9LmPw4Nv2Rt",
            id="trailing-dash-at-line-end",
        ),
        pytest.param(
            "Zq7Kx9LmPw4Nv2Rt\x0c",
            [f"Because faketool depends on Zq7Kx9LmPw4Nv2Rt\x0c {_TAIL}"],
            "Zq7Kx9LmPw4Nv2Rt",
            id="trailing-ff-mid-line",
        ),
        pytest.param(
            "Zq7Kx9LmPw4Nv2Rt",
            ["Because faketool depends on", f"Zq7Kx9LmPw4Nv2Rt {_TAIL}"],
            "Zq7Kx9LmPw4Nv2Rt",
            id="control-plain-value-at-line-start",
        ),
    ],
)
def test_the_cause_hides_a_value_at_a_line_edge(value, lines, core):
    """A glyph strip that runs on the RAW line edges before the one redaction
    pass respells a value whose own first or last character is in the strip
    set and sits at a line edge ("-" starts or ends base64url tokens), and a
    value ending in a separator ``splitlines`` honors (FF) loses it the same
    way, so the whole-spelling match missed and the value printed in the
    cause. The raw text is redacted first; only a glyph PREFIX and trailing
    whitespace are stripped after, when no value is left to respell."""
    output = _uv_tree(lines)
    assert value in output, "premise: the raw text holds the value whole"

    reason = _first_cause_adaptive(output, (value,), "faketool==1.0", "faketool")

    assert reason.startswith("because "), reason
    assert core not in reason, reason


@pytest.mark.unit
@pytest.mark.parametrize(
    "value, lines",
    [
        pytest.param(
            "Zq7Kx9Lm -Pw4Nv2Rt",
            ["Because faketool depends on Zq7Kx9Lm", f"-Pw4Nv2Rt {_TAIL}"],
            id="wrap-before-dash-word",
        ),
        pytest.param(
            "Zq7Kx9Lm- Pw4Nv2Rt",
            ["Because faketool depends on Zq7Kx9Lm-", f"Pw4Nv2Rt {_TAIL}"],
            id="wrap-after-dash-word",
        ),
        pytest.param(
            "Zq7Kx9Lm xPw4Nv2Rt",
            ["Because faketool depends on Zq7Kx9Lm", f"xPw4Nv2Rt {_TAIL}"],
            id="control-wrap-before-plain-word",
        ),
    ],
)
def test_the_cause_hides_a_value_wrapped_beside_a_strip_character(value, lines):
    """The whitespace-respelling normalization matched the value's words
    against the already-stripped text, so a wrap landing beside "-", ">",
    "|", "`" or a tree glyph lost that character before the words were looked
    for, and the normalization missed. It runs on the raw text now, where
    every word still spells itself."""
    reason = _first_cause_adaptive(
        _uv_tree(lines), (value,), "faketool==1.0", "faketool"
    )

    assert reason.startswith("because "), reason
    assert "Zq7Kx9Lm" not in reason and "Pw4Nv2Rt" not in reason, reason


@pytest.mark.unit
@pytest.mark.parametrize(
    "value, lines",
    [
        # The text-mode decode's spelling of a CR/CRLF value: the text holds LF.
        pytest.param(
            "Zq7Kx9Lm\r\nPw4Nv2Rt",
            ["Because faketool depends on Zq7Kx9Lm", f"Pw4Nv2Rt {_TAIL}"],
            id="crlf-value-lf-text",
        ),
        pytest.param(
            "Zq7Kx9Lm\rPw4Nv2Rt",
            ["Because faketool depends on Zq7Kx9Lm", f"Pw4Nv2Rt {_TAIL}"],
            id="cr-value-lf-text",
        ),
        pytest.param(
            "Zq7Kx9Lm\x0cPw4Nv2Rt",
            [f"Because faketool depends on Zq7Kx9Lm\x0cPw4Nv2Rt {_TAIL}"],
            id="inner-ff",
        ),
        pytest.param(
            "Zq7Kx9Lm Pw4Nv2Rt",
            [f"Because faketool depends on Zq7Kx9Lm Pw4Nv2Rt {_TAIL}"],
            id="inner-u2028",
        ),
    ],
)
def test_a_whitespace_respelled_value_is_hidden_in_the_cause(value, lines):
    """The normalization covers every whitespace respelling, not only the
    space-at-a-wrap case the committed cells above pin: a CR or CRLF value the
    text-mode decode turned into LF, and a value whose own separator is FF or
    U+2028 (which ``splitlines`` honors and a wrap can respell)."""
    reason = _first_cause_adaptive(
        _uv_tree(lines), (value,), "faketool==1.0", "faketool"
    )

    assert reason.startswith("because "), reason
    assert "Zq7Kx9Lm" not in reason and "Pw4Nv2Rt" not in reason, reason


def _dry_run_children(tmp_path, monkeypatch, stderr_text):
    """A fake tool and a fake uv (python stand-ins, no real uv): the uv writes
    *stderr_text* bytes and exits 1, so the dry run reads it through the real
    text-mode decode."""
    data = stderr_text.encode("utf-8").hex()
    tool = tmp_path / "faketool"
    tool.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write('1.0.0')\n")
    tool.chmod(0o755)
    uv = tmp_path / "fake-uv-dry"
    uv.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"sys.stderr.buffer.write(bytes.fromhex('{data}'))\nsys.exit(1)\n"
    )
    uv.chmod(0o755)
    monkeypatch.setattr(
        pre_installed_tool, "find_nix_python_environment", lambda executable: None
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_tool_interpreter", lambda executable: "/env/python"
    )
    return tool, uv


@pytest.mark.integration
def test_a_crlf_value_from_a_real_dry_run_is_hidden(tmp_path, monkeypatch):
    """End to end through the real text-mode decode: a multi-word value whose
    own separator is CRLF reaches the cause as LF, the normalization restores
    its spelling, and the verdict detail hides it. This pins the closure the
    in-memory crlf cell above describes on the production read path."""
    value = "Zq7Kx9Lm\r\nPw4Nv2Rt"
    stderr_text = (
        "  x No solution found when resolving dependencies:\n"
        f"  `-> Because faketool depends on {value} {_TAIL}\n"
    )
    tool, uv = _dry_run_children(tmp_path, monkeypatch, stderr_text)

    verdict = verify_pre_installed_tool(
        str(tool), "faketool", [], None, uv_executable=str(uv), values=(value,)
    )

    assert verdict.status == "unsatisfied", verdict
    assert "Zq7Kx9Lm" not in verdict.detail, verdict.detail
    assert "Pw4Nv2Rt" not in verdict.detail, verdict.detail


def _probed(monkeypatch, dry_run_returncode, dry_run_output):
    """The verdict without children: ``--version`` answers, every dry run
    answers *dry_run_output* on stderr with *dry_run_returncode*."""

    def fake_run(command, timeout):
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(command, 0, "1.0.0\n", "")
        return subprocess.CompletedProcess(
            command, dry_run_returncode, "", dry_run_output
        )

    monkeypatch.setattr(pre_installed_tool, "_run", fake_run)
    monkeypatch.setattr(
        pre_installed_tool, "find_nix_python_environment", lambda executable: None
    )
    monkeypatch.setattr(
        pre_installed_tool, "find_tool_interpreter", lambda executable: "/env/python"
    )


@pytest.mark.unit
def test_the_unverifiable_verdict_detail_hides_a_wrapped_value(tmp_path, monkeypatch):
    """An answer that is neither satisfied nor unsatisfied returns uv's own
    output as the verdict detail, never through the cause extraction, and
    that detail reaches the dependency reason and the through-uv log line.
    It takes the same redaction, with uv's wrap normalized, before it is
    returned -- the memo's contract that the cached detail embeds the
    redaction covers this arm too."""
    value = "Zq7Kx9Lm Pw4Nv2Rt"
    tool = tmp_path / "faketool"
    tool.write_text("", encoding="utf-8")
    _probed(
        monkeypatch,
        2,
        "error: failed to inspect the environment near Zq7Kx9Lm\n"
        "      Pw4Nv2Rt while reading metadata\n",
    )

    verdict = verify_pre_installed_tool(
        str(tool), "faketool", [], None, uv_executable="/env/bin/uv", values=(value,)
    )

    assert verdict.status == "unverifiable", verdict
    assert "Zq7Kx9Lm" not in verdict.detail, verdict.detail
    assert "Pw4Nv2Rt" not in verdict.detail, verdict.detail


@pytest.mark.unit
def test_the_unsatisfied_verdict_detail_hides_a_wrapped_value(tmp_path, monkeypatch):
    """The control for the cell above: the unsatisfied arm's detail goes
    through the cause extraction, which already redacts."""
    value = "Zq7Kx9Lm Pw4Nv2Rt"
    tool = tmp_path / "faketool"
    tool.write_text("", encoding="utf-8")
    _probed(
        monkeypatch,
        1,
        _uv_tree(["Because faketool depends on Zq7Kx9Lm", f"Pw4Nv2Rt {_TAIL}"]),
    )

    verdict = verify_pre_installed_tool(
        str(tool), "faketool", [], None, uv_executable="/env/bin/uv", values=(value,)
    )

    assert verdict.status == "unsatisfied", verdict
    assert "Zq7Kx9Lm" not in verdict.detail, verdict.detail
    assert "Pw4Nv2Rt" not in verdict.detail, verdict.detail
