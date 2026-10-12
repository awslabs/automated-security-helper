# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container legs' license check, exercised on a directory tree instead of an image.

.github/scripts/third_party_image_probe.py runs inside the built image in CI. Here
it runs against a tree under tmp_path laid out like one, so each way it can say no
is shown to say no without a container runtime. Every negative case is one
mutation of a tree the positive case passes on.

Skipped on Windows: the probe only ever runs in the Linux image, and the fixtures
rely on POSIX modes.
"""

import hashlib
import importlib.util
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / ".github" / "scripts"

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="the probe runs only inside the Linux image"
)


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = _load("_third_party_image_probe", "third_party_image_probe.py")
host = _load(
    "_assert_image_third_party_licenses", "assert-image-third-party-licenses.py"
)

ELF = b"\x7fELF" + b"\0" * 60
LICENSE = b"license text\n"
NOTICE = b"notice text\n"


def _tree(tmp_path: Path) -> dict:
    """A doc dir, a PATH and a dpkg database for one tool, ``demo``, plus a python."""
    doc = tmp_path / "doc"
    (doc / "demo").mkdir(parents=True)
    (doc / "demo" / "LICENSE").write_bytes(LICENSE)
    (doc / "demo" / "NOTICE").write_bytes(NOTICE)
    (doc / "demo" / "SOURCE").write_text("demo v1\nCommit: " + "a" * 40 + "\n")
    (doc / "index.json").write_text('{"tools": [{"tool": "demo"}]}')

    local_bin = tmp_path / "usr-local-bin"
    system_bin = tmp_path / "usr-bin"
    local_bin.mkdir()
    system_bin.mkdir()
    for directory, name in [
        (local_bin, "demo"),
        (local_bin, "python3.12"),
        (system_bin, "ls"),
    ]:
        (directory / name).write_bytes(ELF)
        (directory / name).chmod(0o755)
    (local_bin / "python3").symlink_to(local_bin / "python3.12")
    (local_bin / "a-script").write_text("#!/bin/sh\n")
    (local_bin / "a-script").chmod(0o755)

    python_license = tmp_path / "lib" / "python3.12" / "LICENSE.txt"
    python_license.parent.mkdir(parents=True)
    python_license.write_text("PSF\n")

    dpkg = tmp_path / "dpkg-info"
    dpkg.mkdir()
    (dpkg / "coreutils.list").write_text(f"/.\n{system_bin}/ls\n")

    return {
        "doc_dir": str(doc),
        "search_dirs": [str(local_bin), str(system_bin)],
        "dpkg_info_dir": str(dpkg),
        "site_dirs": [str(tmp_path / "site-packages")],
        "exempt": {
            r"python3\.[0-9]+": str(tmp_path / "lib" / "{name}" / "LICENSE.txt")
        },
        "tools": [
            {
                "tool": "demo",
                "commit": "a" * 40,
                "executables": ["demo"],
                "files": [
                    {"name": "LICENSE", "sha256": None},
                    {"name": "NOTICE", "sha256": hashlib.sha256(NOTICE).hexdigest()},
                ],
            }
        ],
    }


def _problems(spec: dict) -> list:
    return probe.probe(spec)["problems"]


def test_a_complete_tree_passes(tmp_path):
    spec = _tree(tmp_path)
    result = probe.probe(spec)
    assert result["problems"] == []
    accounted = "\n".join(result["accounted"])
    assert "demo: demo" in accounted
    assert "exempt, covered by" in accounted, "the python exemption must be exercised"


def test_an_unregistered_binary_on_path_fails_by_name(tmp_path):
    """The direction the build-time check cannot see: a binary that reached the
    image without ever touching the license table."""
    spec = _tree(tmp_path)
    smuggled = Path(spec["search_dirs"][0]) / "newscanner"
    smuggled.write_bytes(ELF)
    smuggled.chmod(0o755)
    problems = _problems(spec)
    assert len(problems) == 1 and "newscanner" in problems[0], problems


def test_a_debian_owned_binary_is_accepted_and_only_because_dpkg_owns_it(tmp_path):
    spec = _tree(tmp_path)
    Path(spec["dpkg_info_dir"], "coreutils.list").write_text("/.\n")
    problems = _problems(spec)
    assert any(
        p.endswith("Add an entry for it in utils/tool_downloads.py.") and "/ls " in p
        for p in problems
    ), problems


def test_an_exemption_whose_license_is_missing_fails(tmp_path):
    spec = _tree(tmp_path)
    Path(spec["exempt"][r"python3\.[0-9]+"].format(name="python3.12")).unlink()
    assert any("exempt on" in p for p in _problems(spec))


def test_a_symlinked_binary_is_counted_once(tmp_path):
    spec = _tree(tmp_path)
    accounted = probe.probe(spec)["accounted"]
    assert sum("covered by" in line for line in accounted) == 1, accounted


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda d: (d / "demo" / "LICENSE").unlink(), "LICENSE is missing"),
        (lambda d: (d / "demo" / "NOTICE").write_bytes(b"other\n"), "pinned SHA256"),
        (lambda d: (d / "demo" / "NOTICE").chmod(0o600), "not readable by every user"),
        (lambda d: (d / "demo" / "SOURCE").write_text("demo\n"), "does not name"),
        (lambda d: (d / "index.json").write_text('{"tools": []}'), "not listed"),
        (lambda d: (d / "index.json").unlink(), "index.json is missing"),
    ],
)
def test_each_missing_piece_fails(tmp_path, mutate, needle):
    spec = _tree(tmp_path)
    mutate(Path(spec["doc_dir"]))
    problems = _problems(spec)
    assert any(needle in p for p in problems), problems


def test_a_binary_a_python_distribution_installed_is_accepted(tmp_path):
    """/usr/local/bin/uv in the image comes from the uv wheel, whose dist-info
    RECORD lists it and whose license files sit beside that RECORD."""
    spec = _tree(tmp_path)
    wheel_bin = Path(spec["search_dirs"][0]) / "fromwheel"
    wheel_bin.write_bytes(ELF)
    wheel_bin.chmod(0o755)
    dist = tmp_path / "site-packages" / "fromwheel-1.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "RECORD").write_text("../usr-local-bin/fromwheel,sha256=x,64\n")
    result = probe.probe(spec)
    assert result["problems"] == []
    assert any("installed by a Python distribution" in a for a in result["accounted"])


def test_a_record_naming_another_file_does_not_cover_this_one(tmp_path):
    spec = _tree(tmp_path)
    smuggled = Path(spec["search_dirs"][0]) / "fromwheel"
    smuggled.write_bytes(ELF)
    smuggled.chmod(0o755)
    dist = tmp_path / "site-packages" / "other-1.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "RECORD").write_text("../usr-local-bin/somethingelse,sha256=x,64\n")
    assert any("fromwheel" in p for p in _problems(spec))


def test_a_directory_other_users_cannot_list_fails(tmp_path):
    spec = _tree(tmp_path)
    (Path(spec["doc_dir"]) / "demo").chmod(0o700)
    try:
        assert any("cannot be listed by every user" in p for p in _problems(spec))
    finally:
        (Path(spec["doc_dir"]) / "demo").chmod(0o755)


@pytest.mark.parametrize("mode", [0o700, 0o754])
def test_a_doc_root_other_users_cannot_traverse_fails(tmp_path, mode):
    """0o754 is readable but not searchable by others: listing works, opening
    the files inside does not."""
    spec = _tree(tmp_path)
    Path(spec["doc_dir"]).chmod(mode)
    try:
        assert any(
            p.startswith(spec["doc_dir"]) and "cannot be listed" in p
            for p in _problems(spec)
        )
    finally:
        Path(spec["doc_dir"]).chmod(0o755)


def test_only_the_first_executable_is_required(tmp_path):
    spec = _tree(tmp_path)
    spec["tools"][0]["executables"] = ["demo", "demo-helper"]
    assert _problems(spec) == []
    spec["tools"][0]["executables"] = ["demo-helper", "demo"]
    assert any("demo-helper is not on PATH" in p for p in _problems(spec))


@pytest.mark.parametrize(
    "path,alias",
    [("/bin/ls", "/usr/bin/ls"), ("/usr/bin/ls", "/bin/ls")],
)
def test_merged_usr_spellings_are_both_tried(path, alias):
    """dpkg may record /bin/ls for a file reached as /usr/bin/ls, or the reverse."""
    assert alias in probe._aliases(path)


def test_an_executable_missing_from_path_fails(tmp_path):
    spec = _tree(tmp_path)
    (Path(spec["search_dirs"][0]) / "demo").unlink()
    assert any("demo is not on PATH" in p for p in _problems(spec))


class TestTheHostSpec:
    def test_it_covers_every_license_entry(self):
        from automated_security_helper.utils.tool_downloads import (
            THIRD_PARTY_DOC_DIR,
            THIRD_PARTY_LICENSES,
        )

        spec = host.build_spec(host._load_pins())
        assert spec["doc_dir"] == THIRD_PARTY_DOC_DIR
        assert [t["tool"] for t in spec["tools"]] == sorted(THIRD_PARTY_LICENSES)
        uv = next(t for t in spec["tools"] if t["tool"] == "uv")
        assert uv["executables"] == ["uv", "uvx"]

    def test_the_python_exemption_matches_the_base_image_interpreter(self):
        """The base image's python3.12 is the only non-Debian ELF ASH did not put
        there; a Dependabot base bump to 3.13 must still match."""
        import re

        (pattern,) = host.EXEMPT
        assert re.fullmatch(pattern, "python3.12")
        assert re.fullmatch(pattern, "python3.13")
        assert not re.fullmatch(pattern, "python3-config")


class TestTheHostScript:
    """main() is the CI verdict; a regression that always returns 0 must fail here."""

    @staticmethod
    def _run(monkeypatch, *, returncode=0, stdout="", wrapper=""):
        import subprocess

        seen = {}

        def fake_run(command, **kwargs):
            seen["command"] = command
            seen["input"] = kwargs.get("input")
            return subprocess.CompletedProcess(command, returncode, stdout, "boom")

        monkeypatch.setattr(host.subprocess, "run", fake_run)
        monkeypatch.setenv("OCI_RUNNER_WRAPPER", wrapper)
        rc = host.main(["--runner", "podman", "--image", "img:tag"])
        return rc, seen

    def test_a_clean_verdict_passes(self, monkeypatch):
        rc, seen = self._run(monkeypatch, stdout='{"problems": [], "accounted": []}')
        assert rc == 0
        assert seen["command"][:7] == [
            "podman",
            "run",
            "--rm",
            "-i",
            "--entrypoint",
            "python3",
            "img:tag",
        ]
        assert '"tool": "trivy"' in seen["input"]

    def test_a_problem_fails(self, monkeypatch):
        rc, _ = self._run(
            monkeypatch, stdout='{"problems": ["x is missing"], "accounted": []}'
        )
        assert rc == 1

    def test_a_probe_that_did_not_run_fails(self, monkeypatch):
        rc, _ = self._run(monkeypatch, returncode=125)
        assert rc == 1

    def test_the_wrapper_goes_first(self, monkeypatch):
        _, seen = self._run(
            monkeypatch, stdout='{"problems": [], "accounted": []}', wrapper="sudo"
        )
        assert seen["command"][:2] == ["sudo", "podman"]


class TestTheCheckIsWiredIntoCi:
    """Deleting the CI step would otherwise fail nothing."""

    @staticmethod
    def _steps(relative: str) -> list:
        import yaml

        data = yaml.safe_load((REPO_ROOT / relative).read_text(encoding="utf-8"))
        return [
            step
            for step in data["runs"]["steps"]
            if "assert-image-third-party-licenses.py" in str(step.get("run", ""))
        ]

    def test_the_scan_test_action_runs_it_on_the_container_legs(self):
        (step,) = self._steps(".github/actions/run-scan-test/action.yml")
        assert step["if"] == "inputs.method == 'python-container'"

    def test_the_container_runtime_action_runs_it(self):
        (step,) = self._steps(".github/actions/validate-container/action.yml")
        assert "${RUNTIME}" in step["run"]


def _uv_tool_env(tmp_path: Path, record_names: str) -> Path:
    """A uv tool environment holding a compiled executable, linked onto PATH."""
    venv = tmp_path / "uv-tools" / "ziz"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/local/bin\n")
    exe = venv / "bin" / "ziz"
    exe.write_bytes(ELF)
    exe.chmod(0o755)
    dist = venv / "lib" / "python3.12" / "site-packages" / "ziz-1.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "RECORD").write_text(record_names)
    return exe


def test_a_compiled_executable_from_a_uv_tool_environment_is_accepted(tmp_path):
    """zizmor: an ELF in a uv tool's own venv, listed by that venv's RECORD."""
    spec = _tree(tmp_path)
    exe = _uv_tool_env(tmp_path, "../../../bin/ziz,sha256=x,64\n")
    (Path(spec["search_dirs"][0]) / "ziz").symlink_to(exe)
    result = probe.probe(spec)
    assert result["problems"] == []
    assert any("installed by a Python distribution" in a for a in result["accounted"])


def test_a_uv_tool_environment_record_must_name_the_executable(tmp_path):
    spec = _tree(tmp_path)
    exe = _uv_tool_env(tmp_path, "../../../bin/other,sha256=x,64\n")
    (Path(spec["search_dirs"][0]) / "ziz").symlink_to(exe)
    assert any("ziz is an executable on PATH" in p for p in _problems(spec))


def test_a_bin_dir_that_is_not_a_virtualenv_is_not_consulted(tmp_path):
    spec = _tree(tmp_path)
    exe = _uv_tool_env(tmp_path, "../../../bin/ziz,sha256=x,64\n")
    (exe.parent.parent / "pyvenv.cfg").unlink()
    (Path(spec["search_dirs"][0]) / "ziz").symlink_to(exe)
    assert any("ziz is an executable on PATH" in p for p in _problems(spec))


def test_an_entry_with_no_executables_needs_none_on_path(tmp_path):
    """A probed entry (a library in a uv tool environment) is not on PATH."""
    spec = _tree(tmp_path)
    spec["tools"][0]["executables"] = []
    (Path(spec["search_dirs"][0]) / "demo").unlink()
    assert _problems(spec) == []


def test_the_host_spec_lists_no_executables_for_probed_entries():
    from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

    spec = host.build_spec(host._load_pins())
    by_tool = {t["tool"]: t for t in spec["tools"]}
    for tool, entry in THIRD_PARTY_LICENSES.items():
        if entry.version_probe:
            assert by_tool[tool]["executables"] == [], tool
        else:
            assert by_tool[tool]["executables"], tool
