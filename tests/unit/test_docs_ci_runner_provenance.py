# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ASH a pipeline installed, read from the installed distribution itself.

WHY THIS EXISTS
---------------
ASH's version is a static string, so ``ash --version`` reads the same for the release
and for the pull request, and ``pip install --quiet`` prints nothing about where it
installed from. What does record it is the distribution's PEP 610 ``direct_url.json``,
which the rewrites print, between fixed markers, right after each install. This is
tests/integration/docs/ci_runners/provenance.py reading it back:

* a wheel install passes only when ``url`` is the wheel the run built, as the installer
  saw it, and ``archive_info`` records that wheel's sha256 (pip records the hash given
  in the URL; it strips the fragment from ``url``);
* a git install passes only when ``vcs_info`` is git at the head commit, and ``url`` is
  the base repository;
* anything else fails: an editable install of a checkout, another file, another commit,
  another repository, a missing direct_url.json, or no markers at all.

The markers are read out of the runners' logs as they are written, including act's
``--json`` lines, whose output text is the ``msg`` of each entry.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import warnings
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"
HEAD = "0123456789abcdef0123456789abcdef01234567"
REPOSITORY = "awslabs/automated-security-helper"
SHA256 = "d" * 64
WHEEL = PurePosixPath("/ash-wheel/automated_security_helper-0-py3-none-any.whl")
#: The file URIs the checks compare with, written out rather than computed by the code
#: under test (file_uri has a test of its own).
WHEEL_URI = "file:///ash-wheel/automated_security_helper-0-py3-none-any.whl"
OTHER_WHEEL_URI = "file:///opt/dist/other.whl"


def _module(stem: str):
    if PACKAGE not in sys.modules:
        init = CI_RUNNERS / "__init__.py"
        if not init.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/__init__.py")
        spec = importlib.util.spec_from_file_location(
            PACKAGE, init, submodule_search_locations=[str(CI_RUNNERS)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    if not (CI_RUNNERS / f"{stem}.py").is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{stem}.py")
    return importlib.import_module(f"{PACKAGE}.{stem}")


def _api(name: str):
    module = _module("provenance")
    if not hasattr(module, name):
        pytest.fail(
            f"tests/integration/docs/ci_runners/provenance.py defines no {name}"
        )
    return getattr(module, name)


WHEEL_INSTALL = {
    "url": WHEEL_URI,
    "archive_info": {"hash": f"sha256={SHA256}", "hashes": {"sha256": SHA256}},
}
GIT_INSTALL = {
    "url": f"https://github.com/{REPOSITORY}.git",
    "vcs_info": {"vcs": "git", "commit_id": HEAD, "requested_revision": HEAD},
}


def _markers() -> tuple[str, str]:
    begin, end = _api("PROVENANCE_BEGIN"), _api("PROVENANCE_END")
    for marker in (begin, end):
        assert (
            isinstance(marker, str) and marker and not any(c.isspace() for c in marker)
        )
    assert begin != end and begin not in end and end not in begin
    return begin, end


# ---------------------------------------------------------------------------
# Reading the markers out of a log
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_direct_url_files_are_read_from_a_plain_prefixed_log():
    begin, end = _markers()
    log = "\n".join(
        [
            "build_1  | installing",
            f"build_1  | {begin}",
            f"build_1  | {json.dumps(WHEEL_INSTALL)}",
            f"build_1  | {end}",
            f"\x1b[36mbuild_1  |\x1b[0m {begin}\r",
            "\x1b[36mbuild_1  |\x1b[0m no direct_url.json for automated-security-helper\r",
            f"\x1b[36mbuild_1  |\x1b[0m {end}\r",
        ]
    )
    assert _api("direct_urls_in_log")(log) == [WHEEL_INSTALL, None], (
        "one entry per marker pair; a pair around anything but a JSON object is None"
    )


@pytest.mark.unit
def test_direct_url_files_are_read_from_act_json_lines():
    begin, end = _markers()

    def line(msg: str) -> str:
        return json.dumps(
            {
                "job": "ash",
                "jobID": "ash",
                "level": "info",
                "msg": msg,
                "raw_output": True,
            }
        )

    log = "\n".join(
        [
            line(f"  | {begin}"),
            line(f"  | {json.dumps(GIT_INSTALL)}"),
            line(f"  | {end}"),
        ]
    )
    assert _api("direct_urls_in_log")(log) == [GIT_INSTALL]


@pytest.mark.unit
def test_a_log_without_markers_has_no_direct_url_files():
    assert _api("direct_urls_in_log")("installed\nscanned\n") == []


# ---------------------------------------------------------------------------
# A wheel install
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_wheel_the_run_built_passes():
    check = _api("wheel_provenance_problems")
    assert check(WHEEL_INSTALL, wheel=WHEEL, sha256=SHA256) == []
    hashes_only = {
        "url": WHEEL_URI,
        "archive_info": {"hashes": {"sha256": SHA256}},
    }
    assert check(hashes_only, wheel=WHEEL, sha256=SHA256) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "direct_url",
    [
        None,
        {**WHEEL_INSTALL, "url": OTHER_WHEEL_URI},
        {**WHEEL_INSTALL, "archive_info": {"hashes": {"sha256": "0" * 64}}},
        {**WHEEL_INSTALL, "archive_info": {}},
        {"url": "file:///work/repo", "dir_info": {"editable": True}},
        GIT_INSTALL,
        {
            "url": "https://files.pythonhosted.org/packages/x/"
            "automated_security_helper-0.0.0-py3-none-any.whl",
            "archive_info": {"hashes": {"sha256": SHA256}},
        },
    ],
    ids=[
        "no direct_url.json",
        "another file",
        "another hash",
        "no hash recorded",
        "editable checkout",
        "a git install",
        "an index",
    ],
)
def test_anything_but_that_wheel_fails(direct_url):
    problems = _api("wheel_provenance_problems")(direct_url, wheel=WHEEL, sha256=SHA256)
    assert problems and all(isinstance(p, str) for p in problems)


# ---------------------------------------------------------------------------
# A git install
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_head_commit_of_the_base_repository_passes():
    check = _api("git_provenance_problems")
    assert check(GIT_INSTALL, head_sha=HEAD, repository=REPOSITORY) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "direct_url",
    [
        None,
        {**GIT_INSTALL, "vcs_info": {**GIT_INSTALL["vcs_info"], "commit_id": "f" * 40}},
        {
            **GIT_INSTALL,
            "url": "https://github.com/someone/automated-security-helper.git",
        },
        {**GIT_INSTALL, "vcs_info": {**GIT_INSTALL["vcs_info"], "vcs": "hg"}},
        WHEEL_INSTALL,
        {"url": "file:///work/repo", "dir_info": {"editable": True}},
    ],
    ids=[
        "no direct_url.json",
        "another commit",
        "a fork",
        "not git",
        "a wheel",
        "editable",
    ],
)
def test_anything_but_that_commit_fails(direct_url):
    problems = _api("git_provenance_problems")(
        direct_url, head_sha=HEAD, repository=REPOSITORY
    )
    assert problems and all(isinstance(p, str) for p in problems)


# ---------------------------------------------------------------------------
# What uv records, and the repository URL without .git
# ---------------------------------------------------------------------------

#: What ``uv tool install "<spec> @ <wheel URI>#sha256=<hex>"`` records: the URL as
#: given, fragment and all, and no hash of its own (uv does not check the fragment).
UV_WHEEL_INSTALL = {"url": WHEEL_URI + "#sha256=" + SHA256, "archive_info": {}}


@pytest.mark.unit
def test_a_uv_install_of_the_wheel_the_run_built_passes():
    check = _api("wheel_provenance_problems")
    assert check(UV_WHEEL_INSTALL, wheel=WHEEL, sha256=SHA256) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "direct_url",
    [
        {**UV_WHEEL_INSTALL, "url": WHEEL_URI + "#sha256=" + "0" * 64},
        {**UV_WHEEL_INSTALL, "url": OTHER_WHEEL_URI + "#sha256=" + SHA256},
        {**UV_WHEEL_INSTALL, "archive_info": {"hashes": {"sha256": "0" * 64}}},
        {**UV_WHEEL_INSTALL, "archive_info": {"hashes": {"sha256": SHA256}}},
        {**UV_WHEEL_INSTALL, "url": UV_WHEEL_INSTALL["url"] + "&subdirectory=x"},
        {**UV_WHEEL_INSTALL, "url": WHEEL_URI + "#md5=" + "0" * 32},
        {"url": UV_WHEEL_INSTALL["url"]},
        {**UV_WHEEL_INSTALL, "dir_info": {"editable": True}},
    ],
    ids=[
        "the fragment names another hash",
        "the fragment on another file",
        "the fragment and a different recorded hash",
        "the fragment and a recorded hash",
        "more after the fragment's hash",
        "a fragment of another algorithm",
        "no archive_info",
        "a directory",
    ],
)
def test_a_uv_shaped_record_of_anything_else_fails(direct_url):
    problems = _api("wheel_provenance_problems")(direct_url, wheel=WHEEL, sha256=SHA256)
    assert problems and all(isinstance(p, str) for p in problems)


@pytest.mark.unit
def test_the_base_repository_passes_with_or_without_dot_git():
    check = _api("git_provenance_problems")
    bare = {**GIT_INSTALL, "url": f"https://github.com/{REPOSITORY}"}
    assert check(bare, head_sha=HEAD, repository=REPOSITORY) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "url",
    [
        f"https://github.com/{REPOSITORY}/",
        f"https://github.com/{REPOSITORY}.git/",
        f"git+https://github.com/{REPOSITORY}.git",
        f"http://github.com/{REPOSITORY}.git",
        f"https://github.com/{REPOSITORY}-fork",
    ],
)
def test_another_spelling_of_the_repository_url_fails(url):
    problems = _api("git_provenance_problems")(
        {**GIT_INSTALL, "url": url}, head_sha=HEAD, repository=REPOSITORY
    )
    assert problems


@pytest.mark.unit
@pytest.mark.parametrize(
    "path,expected",
    [
        (WHEEL, WHEEL_URI),
        (PurePosixPath("/tmp/a b/c%d/x.whl"), "file:///tmp/a%20b/c%25d/x.whl"),
        (PureWindowsPath("C:/Users/a b/x.whl"), "file:///C:/Users/a%20b/x.whl"),
        (PureWindowsPath("c:\\dist\\x.whl"), "file:///c:/dist/x.whl"),
        (
            PureWindowsPath("//server/share/dist/x.whl"),
            "file://server/share/dist/x.whl",
        ),
    ],
    ids=[
        "a POSIX path",
        "a POSIX path to quote",
        "a Windows drive path to quote",
        "a Windows drive path with backslashes",
        "a Windows share",
    ],
)
def test_the_wheel_file_uri_is_the_one_pathlib_writes_without_its_deprecation(
    path, expected
):
    """The strings ``PurePath.as_uri()`` gives, which is deprecated from 3.14."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert _api("file_uri")(path) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "path",
    [PurePosixPath("dist/x.whl"), PureWindowsPath("C:dist/x.whl")],
    ids=["a relative POSIX path", "a Windows path relative to a drive"],
)
def test_a_relative_path_has_no_file_uri(path):
    with pytest.raises(ValueError):
        _api("file_uri")(path)


# ---------------------------------------------------------------------------
# A command a runner echoes is not a print
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_an_echoed_print_command_is_not_a_print():
    begin, end = _markers()
    command = _api("direct_url_print_command")("/opt/ash/bin/python")
    assert begin in command and end in command
    log = "\n".join(
        [
            f"ash-scan $ {command}",
            f"+ {command}",
            f"+ echo {begin}",
            f"+ echo {end}",
            f"[Container] 2026/01/01 00:00:00.000000 Running command echo {begin}",
            f"text with {begin} and then {end} inside it",
            f"ash-scan > {begin}",
            f"ash-scan > {json.dumps(WHEEL_INSTALL)}",
            f"ash-scan > {end}",
        ]
    )
    assert _api("direct_urls_in_log")(log) == [WHEEL_INSTALL], (
        "only the line that is the marker after a runner's prefix counts"
    )


# ---------------------------------------------------------------------------
# The print program, run against a distribution it finds
# ---------------------------------------------------------------------------


def _venv_with(tmp_path: Path, versions: dict[str, dict | None]) -> Path:
    """A virtual environment holding fake automated-security-helper distributions."""
    venv = tmp_path / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv)],
        check=True,
        capture_output=True,
    )
    bindir = venv / ("Scripts" if sys.platform == "win32" else "bin")
    python = bindir / ("python.exe" if sys.platform == "win32" else "python")
    site = Path(
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    for version, direct_url in versions.items():
        info = site / f"automated_security_helper-{version}.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: automated-security-helper\n"
            f"Version: {version}\n",
            encoding="utf-8",
        )
        if direct_url is not None:
            (info / "direct_url.json").write_text(
                json.dumps(direct_url), encoding="utf-8"
            )
    return python


def _environment() -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "")}
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


@pytest.mark.integration
@pytest.mark.parametrize(
    "versions,expected",
    [
        ({"0.0.0": WHEEL_INSTALL}, [WHEEL_INSTALL]),
        ({"0.0.0": UV_WHEEL_INSTALL}, [UV_WHEEL_INSTALL]),
        ({"0.0.0": None}, [None]),
        ({"0.0.0": WHEEL_INSTALL, "0.0.1": WHEEL_INSTALL}, [None]),
    ],
    ids=["pip's record", "uv's record", "no direct_url.json", "two installed"],
)
def test_the_print_program_prints_the_one_installed_distribution_s_record(
    tmp_path, versions, expected
):
    python = _venv_with(tmp_path, versions)
    done = subprocess.run(
        [str(python), "-I", "-c", _api("PRINT_PROGRAM")],
        env=_environment(),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert _api("direct_urls_in_log")(done.stdout) == expected


@pytest.mark.integration
@pytest.mark.skipif(
    sys.platform == "win32", reason="the runners run on Linux; the command is for sh"
)
def test_the_print_command_runs_the_program_in_a_shell(tmp_path):
    python = _venv_with(tmp_path, {"0.0.0": WHEEL_INSTALL})
    command = _api("direct_url_print_command")(shlex.quote(str(python)))
    assert _api("PRINT_PROGRAM") in command
    done = subprocess.run(
        ["sh", "-c", command],
        env=_environment(),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert _api("direct_urls_in_log")(done.stdout) == [WHEEL_INSTALL]
    missing = _api("direct_url_print_command")(shlex.quote(str(tmp_path / "missing")))
    done = subprocess.run(
        ["sh", "-c", missing],
        env=_environment(),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, "the print never fails the pipeline it is in"
    assert _api("direct_urls_in_log")(done.stdout) == []


@pytest.mark.unit
@pytest.mark.parametrize("name", ["PRINT_PROGRAM", "BUILT_PRINT_PROGRAM"])
def test_a_print_program_fits_every_quoting_it_is_written_into(name):
    """One line a shell's single quotes, a Groovy ''' string and YAML all keep as is."""
    program = _api(name)
    assert isinstance(program, str) and program
    for text in ("\n", "\\", "'", ": ", " #"):
        assert text not in program, f"{name} holds {text!r}"


# ---------------------------------------------------------------------------
# The image the run built from the checkout
# ---------------------------------------------------------------------------
#
# The image's Dockerfile builds a wheel from the checkout and installs it with
# ``uv pip install --system``, then deletes it. That install records no commit and no
# hash, and its direct_url.json (when there is one) names only a local file, as the
# release image's does. What an image built from the pull request holds, and a release
# image does not, is the pull request's files. So the print records, on one short line,
# how many files the installed distribution lists under automated_security_helper/ and
# a digest of their paths and sha256s, and the sha256 of its METADATA (version,
# dependencies, description) and entry_points.txt. The check passes only when all of
# those are the ones of the wheel the run built from the same checkout. The
# build-generated ASH_INSTALLED_REVISION is left out of both, since it holds whatever
# the build could read for a branch name.

REVISION = "automated_security_helper/assets/ASH_INSTALLED_REVISION"
WHEEL_NAME = "automated_security_helper-0.0.0-py3-none-any.whl"
PACKAGE_FILES = {
    "automated_security_helper/__init__.py": b"",
    "automated_security_helper/cli/scan.py": b"def scan():\n    return 0\n",
    "automated_security_helper/assets/Dockerfile": b"FROM scratch\n",
    REVISION: b"HEAD",
}
#: The entry points a build of the wheel writes, which its install keeps as they are.
ENTRY_POINTS = (
    b"[console_scripts]\nash = automated_security_helper.cli.entrypoint:main\n"
)
#: What ``uv pip install --system ./<wheel>`` can record for the wheel the image built.
IMAGE_DIRECT_URL = {"url": f"file:///deps/{WHEEL_NAME}", "archive_info": {}}
#: The keys of the built-image record, and nothing else.
RECORD_KEYS = {
    "direct_url",
    "version",
    "file_count",
    "files_sha256",
    "metadata_sha256",
    "entry_points_sha256",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _metadata(version: str = "0.0.0", requires: tuple[str, ...] = ()) -> bytes:
    """A wheel's METADATA: its version, and the dependencies a pull request can pin."""
    lines = [
        "Metadata-Version: 2.4",
        "Name: automated-security-helper",
        f"Version: {version}",
        *(f"Requires-Dist: {requirement}" for requirement in requires),
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _build_wheel(
    tmp_path: Path,
    files=None,
    version: str = "0.0.0",
    *,
    metadata: bytes | None = None,
    entry_points: bytes | None = ENTRY_POINTS,
):
    """A wheel holding ``files`` and the dist-info a build writes, and its sha256."""
    files = PACKAGE_FILES if files is None else files
    path = tmp_path / "dist" / f"automated_security_helper-{version}-py3-none-any.whl"
    path.parent.mkdir(parents=True, exist_ok=True)
    info = f"automated_security_helper-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in files.items():
            archive.writestr(member, data)
        archive.writestr(
            f"{info}/METADATA", _metadata(version) if metadata is None else metadata
        )
        if entry_points is not None:
            archive.writestr(f"{info}/entry_points.txt", entry_points)
        archive.writestr(f"{info}/WHEEL", "Wheel-Version: 1.0\n")
        archive.writestr(f"{info}/RECORD", "")
    return path, _sha256(path.read_bytes())


def _files_sha256(counted: dict[str, str]) -> str:
    """The record's digest of its files, by its definition: the sha256 of the JSON
    ``json.dumps`` writes, by default, for the list of ``[path, sha256]`` pairs sorted
    by path."""
    pairs = sorted([path, digest] for path, digest in counted.items())
    return _sha256(json.dumps(pairs).encode("utf-8"))


def _files_fields(files) -> dict:
    """The record's count and digest of the files of ``files`` it counts."""
    counted = {p: _sha256(d) for p, d in files.items() if p != REVISION}
    return {"file_count": len(counted), "files_sha256": _files_sha256(counted)}


def _built_record(
    files=None,
    *,
    version: str = "0.0.0",
    direct_url=None,
    metadata: bytes | None = None,
    entry_points: bytes | None = ENTRY_POINTS,
) -> dict:
    """What the print shows for an image whose installed ASH holds ``files``."""
    files = PACKAGE_FILES if files is None else files
    return {
        "direct_url": direct_url,
        "version": version,
        **_files_fields(files),
        "metadata_sha256": _sha256(
            _metadata(version) if metadata is None else metadata
        ),
        "entry_points_sha256": None if entry_points is None else _sha256(entry_points),
    }


@pytest.mark.unit
def test_an_image_holding_the_files_of_the_wheel_the_run_built_passes(tmp_path):
    wheel, sha256 = _build_wheel(tmp_path)
    check = _api("built_provenance_problems")
    for direct_url in (None, IMAGE_DIRECT_URL):
        record = _built_record(direct_url=direct_url)
        assert check(record, head_sha=HEAD, wheel=wheel, wheel_sha256=sha256) == []


_SCAN = "automated_security_helper/cli/scan.py"
_CHANGED_SCAN = {**PACKAGE_FILES, _SCAN: b"def scan():\n    return 1\n"}


@pytest.mark.unit
@pytest.mark.parametrize(
    "change",
    [
        lambda record: None,
        lambda record: [record],
        lambda record: {**record, **_files_fields(_CHANGED_SCAN)},
        lambda record: {
            **record,
            **_files_fields({k: v for k, v in PACKAGE_FILES.items() if k != _SCAN}),
        },
        lambda record: {
            **record,
            **_files_fields(
                {**PACKAGE_FILES, "automated_security_helper/x.py": b"x = 1\n"}
            ),
        },
        lambda record: {**record, **_files_fields({})},
        lambda record: {**record, "file_count": record["file_count"] + 1},
        lambda record: {**record, "files_sha256": "0" * 64},
        lambda record: {
            **record,
            "files_sha256": _sha256(
                json.dumps(
                    sorted(
                        (
                            [p, _sha256(d)]
                            for p, d in PACKAGE_FILES.items()
                            if p != REVISION
                        ),
                        reverse=True,
                    )
                ).encode("utf-8")
            ),
        },
        lambda record: {**record, "file_count": str(record["file_count"])},
        lambda record: {**record, "files_sha256": None},
        lambda record: {**record, "version": "0.0.1"},
        lambda record: {
            **record,
            "metadata_sha256": _sha256(_metadata(requires=("pyyaml==6.0.2",))),
        },
        lambda record: {**record, "metadata_sha256": None},
        lambda record: {
            **record,
            "entry_points_sha256": _sha256(b"[console_scripts]\nash = other:main\n"),
        },
        lambda record: {**record, "entry_points_sha256": None},
        lambda record: {
            **record,
            "direct_url": {
                "url": f"https://github.com/{REPOSITORY}",
                "vcs_info": {"vcs": "git", "commit_id": HEAD},
            },
        },
        lambda record: {
            **record,
            "direct_url": {"url": "file:///src", "dir_info": {"editable": True}},
        },
        lambda record: {
            **record,
            "direct_url": {
                "url": f"https://files.pythonhosted.org/packages/x/{WHEEL_NAME}",
                "archive_info": {},
            },
        },
        lambda record: {
            **record,
            "direct_url": {
                "url": "file:///deps/other-0.0.0-py3-none-any.whl",
                "archive_info": {},
            },
        },
        lambda record: {**record, "direct_url": {"url": IMAGE_DIRECT_URL["url"]}},
        lambda record: {k: v for k, v in record.items() if k != "files_sha256"},
        lambda record: {**record, "commit": HEAD},
        lambda record: {
            "direct_url": record["direct_url"],
            "version": record["version"],
            "files": {p: _sha256(d) for p, d in PACKAGE_FILES.items() if p != REVISION},
        },
    ],
    ids=[
        "nothing printed",
        "not an object",
        "a file that differs",
        "a file missing",
        "a file the wheel does not have",
        "no files",
        "the files' digest with another count",
        "the count with another digest",
        "a digest of the files in another order",
        "a count that is not a number",
        "no digest of the files",
        "another version",
        "METADATA naming other dependencies",
        "no METADATA digest",
        "other entry points",
        "no entry points digest",
        "installed from git",
        "installed from a directory",
        "installed from an index",
        "installed from another wheel file",
        "a direct_url.json with no archive_info",
        "no files digest key",
        "a key the print does not write",
        "the record of each file instead of a digest",
    ],
)
def test_an_image_whose_ash_is_not_that_wheel_s_fails(tmp_path, change):
    wheel, sha256 = _build_wheel(tmp_path)
    record = change(_built_record(direct_url=IMAGE_DIRECT_URL))
    problems = _api("built_provenance_problems")(
        record, head_sha=HEAD, wheel=wheel, wheel_sha256=sha256
    )
    assert problems and all(isinstance(p, str) for p in problems)


@pytest.mark.unit
@pytest.mark.parametrize(
    "change",
    [
        lambda record: {**record, "file_count": True},
        lambda record: {**record, "file_count": 1.0},
        lambda record: {**record, "files_sha256": record["files_sha256"].upper()},
    ],
    ids=[
        "a count that is a boolean",
        "a count that is a float",
        "a digest in capitals",
    ],
)
def test_a_count_or_digest_the_print_does_not_write_is_refused_as_such(
    tmp_path, change
):
    """The print writes an integer and 64 lower-case hex digits; a boolean or a float
    that compares equal to the wheel's count is no such record."""
    one = {"automated_security_helper/__init__.py": b""}
    wheel, sha256 = _build_wheel(tmp_path, one)
    record = change(_built_record(one))
    problems = _api("built_provenance_problems")(
        record, head_sha=HEAD, wheel=wheel, wheel_sha256=sha256
    )
    assert any("are not a count and a sha256" in p for p in problems), problems


@pytest.mark.unit
def test_a_difference_in_the_files_names_the_head_commit_and_both_digests(tmp_path):
    """The record holds no file names, so the problem gives the two counts and
    digests, the image's and the wheel's, for the head commit."""
    wheel, sha256 = _build_wheel(tmp_path)
    record = _built_record(_CHANGED_SCAN)
    expected = _files_fields(PACKAGE_FILES)
    assert record["files_sha256"] != expected["files_sha256"]
    problems = _api("built_provenance_problems")(
        record, head_sha=HEAD, wheel=wheel, wheel_sha256=sha256
    )
    text = "\n".join(problems)
    assert HEAD in text, text
    assert record["files_sha256"] in text and expected["files_sha256"] in text, text
    assert len(problems) == 1, "only the files differ, so one problem names them"


@pytest.mark.unit
@pytest.mark.parametrize(
    "files,differs,not_said",
    [
        (
            {**PACKAGE_FILES, "automated_security_helper/x.py": b"x = 1\n"},
            "the file count differs",
            "the file count is the same",
        ),
        (_CHANGED_SCAN, "the files digest differs", "the file count differs"),
    ],
    ids=["a file added", "a file changed"],
)
def test_a_difference_in_the_files_says_whether_the_count_or_only_the_digest_differs(
    tmp_path, files, differs, not_said
):
    wheel, sha256 = _build_wheel(tmp_path)
    problems = _api("built_provenance_problems")(
        _built_record(files), head_sha=HEAD, wheel=wheel, wheel_sha256=sha256
    )
    text = "\n".join(problems)
    assert differs in text and not_said not in text, text


#: The keys of the wheel's manifest: the record's, less direct_url, plus the wheel's
#: name and sha256 and its counted files.
MANIFEST_KEYS = {
    "wheel",
    "wheel_sha256",
    "version",
    "file_count",
    "files_sha256",
    "metadata_sha256",
    "entry_points_sha256",
    "files",
}


@pytest.mark.unit
def test_the_wheel_manifest_is_what_the_image_record_is_compared_with(tmp_path):
    """A failed check gives counts and digests only. The run writes this manifest
    beside the failure, so the file that differs can be found by listing the image's
    files the same way: the record's values for the wheel, and the path and sha256 of
    each file the record counts."""
    wheel, sha256 = _build_wheel(tmp_path)
    manifest = _api("built_wheel_manifest")(wheel, wheel_sha256=sha256)
    assert set(manifest) == MANIFEST_KEYS
    assert manifest["wheel"] == wheel.name and manifest["wheel_sha256"] == sha256
    counted = {p: _sha256(d) for p, d in PACKAGE_FILES.items() if p != REVISION}
    assert manifest["files"] == counted
    assert list(manifest["files"]) == sorted(counted), "in path order"
    record = _built_record()
    for key in MANIFEST_KEYS & set(record):
        assert manifest[key] == record[key], key
    assert json.loads(json.dumps(manifest)) == manifest, "it is written as JSON"


@pytest.mark.unit
def test_the_wheel_manifest_is_only_of_the_wheel_the_run_built(tmp_path):
    wheel, sha256 = _build_wheel(tmp_path)
    manifest = _api("built_wheel_manifest")
    with pytest.raises(ValueError, match="sha256"):
        manifest(wheel, wheel_sha256="0" * 64)
    with pytest.raises(ValueError, match="cannot be read"):
        manifest(tmp_path / "absent" / WHEEL_NAME, wheel_sha256=sha256)
    junk = tmp_path / "junk.whl"
    junk.write_bytes(b"not a zip")
    with pytest.raises(ValueError, match="not a wheel"):
        manifest(junk, wheel_sha256=_sha256(b"not a zip"))


@pytest.mark.unit
@pytest.mark.parametrize(
    "metadata,entry_points",
    [(_metadata(requires=("pyyaml==6.0.2",)), ENTRY_POINTS), (None, None)],
    ids=["a wheel pinning other dependencies", "a wheel with no entry points"],
)
def test_the_dist_info_files_compared_are_the_wheel_s_own(
    tmp_path, metadata, entry_points
):
    """A pull request that changes only dependency pins, the description or the entry
    points changes no package file, and its image is told apart by these two."""
    wheel, sha256 = _build_wheel(tmp_path, metadata=metadata, entry_points=entry_points)
    check = _api("built_provenance_problems")
    own = _built_record(metadata=metadata, entry_points=entry_points)
    assert check(own, head_sha=HEAD, wheel=wheel, wheel_sha256=sha256) == []
    base = _built_record()
    assert base != own
    problems = check(base, head_sha=HEAD, wheel=wheel, wheel_sha256=sha256)
    assert problems and all(isinstance(p, str) for p in problems), (
        "the record of an image built without the change fails"
    )


@pytest.mark.unit
def test_the_files_are_compared_with_the_wheel_the_run_built_and_no_other(tmp_path):
    wheel, sha256 = _build_wheel(tmp_path)
    check = _api("built_provenance_problems")
    record = _built_record()
    assert check(record, head_sha=HEAD, wheel=wheel, wheel_sha256="0" * 64), (
        "a wheel whose sha256 is not the session's is no reference"
    )
    absent = tmp_path / "absent" / WHEEL_NAME
    assert check(record, head_sha=HEAD, wheel=absent, wheel_sha256=sha256)


def _image_python(
    base: Path,
    files: dict,
    *,
    version: str = "0.0.0",
    direct_url=None,
    metadata: bytes | None = None,
    entry_points: bytes | None = ENTRY_POINTS,
):
    """A virtual environment whose installed ASH holds ``files``, as an image's does:
    the package files, and the METADATA and entry_points.txt its wheel held, all
    listed in its RECORD."""
    base.mkdir(parents=True)
    python = _venv_with(base, {})
    site = Path(
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    info = site / f"automated_security_helper-{version}.dist-info"
    info.mkdir(parents=True)
    record = []
    for member, data in files.items():
        target = site / member
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        record.append(f"{member},sha256={_sha256(data)},{len(data)}")
    record += [f"{info.name}/METADATA,,", f"{info.name}/RECORD,,", "../../../bin/ash,,"]
    (info / "METADATA").write_bytes(
        _metadata(version) if metadata is None else metadata
    )
    if entry_points is not None:
        (info / "entry_points.txt").write_bytes(entry_points)
        record.append(f"{info.name}/entry_points.txt,,")
    (info / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")
    if direct_url is not None:
        (info / "direct_url.json").write_text(json.dumps(direct_url), encoding="utf-8")
    return python


@pytest.mark.integration
@pytest.mark.parametrize(
    "installed,dist_info,passes",
    [
        ({**PACKAGE_FILES, REVISION: b"build-error"}, {}, True),
        (
            {
                **PACKAGE_FILES,
                "automated_security_helper/cli/__pycache__/scan.cpython-312.pyc": b"x",
            },
            {},
            True,
        ),
        (_CHANGED_SCAN, {}, False),
        ({k: v for k, v in PACKAGE_FILES.items() if k != _SCAN}, {}, False),
        (
            PACKAGE_FILES,
            {"metadata": _metadata(requires=("pyyaml==6.0.2",))},
            False,
        ),
        (
            PACKAGE_FILES,
            {"entry_points": b"[console_scripts]\nash = other:main\n"},
            False,
        ),
        (PACKAGE_FILES, {"entry_points": None}, False),
    ],
    ids=[
        "another revision file",
        "bytecode written after the install",
        "a changed file",
        "a missing file",
        "METADATA naming other dependencies",
        "other entry points",
        "no entry points",
    ],
)
def test_the_built_print_program_reads_the_installed_files(
    tmp_path, installed, dist_info, passes
):
    wheel, sha256 = _build_wheel(tmp_path)
    python = _image_python(
        tmp_path / "image", installed, direct_url=IMAGE_DIRECT_URL, **dist_info
    )
    done = subprocess.run(
        [str(python), "-I", "-c", _api("BUILT_PRINT_PROGRAM")],
        env=_environment(),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    records = _api("direct_urls_in_log")(done.stdout)
    assert len(records) == 1 and isinstance(records[0], dict), done.stdout
    problems = _api("built_provenance_problems")(
        records[0], head_sha=HEAD, wheel=wheel, wheel_sha256=sha256
    )
    assert (problems == []) is passes, problems


def _printed_lines(python: Path, cwd: Path) -> list[str]:
    done = subprocess.run(
        [str(python), "-I", "-c", _api("BUILT_PRINT_PROGRAM")],
        env=_environment(),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


@pytest.mark.integration
def test_the_built_record_is_one_short_line_however_many_files_it_covers(tmp_path):
    """A runner may cut or wrap a long line, and a record split over two lines reads
    as no record. So the line holds a digest of the files, not one entry per file,
    and the program and the check agree on that digest for hundreds of files."""
    begin, end = _markers()
    many = {
        **PACKAGE_FILES,
        **{
            f"automated_security_helper/plugins/module_{i:03d}.py": f"x = {i}\n".encode()
            for i in range(400)
        },
    }
    long_url = {
        "url": "file:///deps/build/output/" + "nested/" * 8 + WHEEL_NAME,
        "archive_info": {},
    }
    lines = {}
    for name, files in (("few", PACKAGE_FILES), ("many", many)):
        python = _image_python(tmp_path / name, files, direct_url=long_url)
        printed = _printed_lines(python, tmp_path)
        assert printed[0] == begin and printed[-1] == end and len(printed) == 3, printed
        lines[name] = printed[1]
        record = json.loads(printed[1])
        assert set(record) == RECORD_KEYS, record
        wheel, sha256 = _build_wheel(tmp_path / name, files)
        assert (
            _api("built_provenance_problems")(
                record, head_sha=HEAD, wheel=wheel, wheel_sha256=sha256
            )
            == []
        )
    assert len(lines["many"].encode("utf-8")) < 1024, lines["many"]
    assert abs(len(lines["many"]) - len(lines["few"])) <= 3, (
        "the line grows only by the digits of the file count"
    )


@pytest.mark.integration
@pytest.mark.skipif(
    sys.platform == "win32", reason="the runners run on Linux; the command is for sh"
)
def test_the_built_print_command_runs_the_program_in_a_shell(tmp_path):
    wheel, sha256 = _build_wheel(tmp_path)
    python = _image_python(tmp_path / "image", PACKAGE_FILES)
    command = _api("built_provenance_print_command")(shlex.quote(str(python)))
    assert _api("BUILT_PRINT_PROGRAM") in command
    done = subprocess.run(
        ["sh", "-c", command],
        env=_environment(),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    (record,) = _api("direct_urls_in_log")(done.stdout)
    assert (
        _api("built_provenance_problems")(
            record, head_sha=HEAD, wheel=wheel, wheel_sha256=sha256
        )
        == []
    )
    missing = _api("built_provenance_print_command")(
        shlex.quote(str(tmp_path / "missing"))
    )
    done = subprocess.run(
        ["sh", "-c", missing],
        env=_environment(),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, "the print never fails the pipeline it is in"
    assert _api("direct_urls_in_log")(done.stdout) == []
