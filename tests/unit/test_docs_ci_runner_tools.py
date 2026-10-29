# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""install_tools.py and the image allowlist check, offline.

WHY THIS EXISTS
---------------
The Docs CI Runners workflow installs its runners with
tests/integration/docs/ci_runners/install_tools.py, and after the runs checks with
image_allowlist.py that every image pulled during the job was one runners.toml pins.
Both are the integrity boundary of the workflow, so this file holds them to it with
local files and no network:

* a download whose sha256 is not the pinned one is refused, and nothing of it is
  extracted, installed or put on any PATH; a good one lands in the bin directory, with
  its execute bits; on the command line each tool gets its own directory,
  <bin-dir>/<name>/, which must hold the manifest's ``executable``;
* a download stays on https at every hop: a 3xx whose target is not https is refused
  before that target is asked, with one refusal for every code and every Python
  version, 3.10 included, whose urllib does not follow a 308 itself; a 308 to https is
  followed there too. The refusal names the target percent-encoded as urllib encodes a
  Location, so it is one line of printable text whatever the server sent, and so is
  each refusal and failure message the command line prints (argparse's usage text and
  docker's own stderr pass through as they are);
* every entry a leg uses is checked before anything is created or downloaded: a pin
  that is not 64 lowercase hex, a url that is not https, a plugin name that is not a
  plain file name or is listed twice, an image not named by digest, or an install
  directory that is taken already. So is the call as a whole: a key of another kind or
  listed twice, a second Jenkins core, an image with no pull log or a core with no
  Jenkins directory, a bin directory, Jenkins directory or pull log that is not of its
  kind and cannot be made one, and an entry's place that is another's or inside it;
* a Jenkins core's WAR becomes <jenkins-dir>/jenkins.war, and each plugin
  <jenkins-dir>/plugins/<name>.hpi, only after its sha256 is checked; one mismatch
  leaves no WAR and no plugin. The Jenkins legs need --jenkins-dir, and the other legs
  refuse it;
* an image is pulled only as ``<name>@sha256:<digest>``, and the docker command is
  built and handed to a runner function, so it can be checked without running it;
* install_tools.py refuses to run anywhere but a GitHub-hosted runner, unless
  DOCTEST_CI_RUNNERS_ANYWHERE=1: the runners it installs mount the Docker socket into
  containers. GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted and no ACT is the
  one environment it accepts on its own;
* the allowlist check reads ``docker events --format '{{json .}}'`` output recorded
  from before the installs, and fails on a pull of anything that is not a digest the
  manifest lists or an image the run built. A pull that install_tools.py recorded and
  the events file does not hold fails it too: the recording did not cover the job. A
  missing pull log fails it as well, since then that comparison never ran.

Both files run on the runner as ``python3 -I <file>``, with the standard library only
(on Python 3.10, which has no tomllib, they import tomli instead), so they are loaded
here by path, each on its own.
"""

from __future__ import annotations

import email.message
import hashlib
import http.client
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import types
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
DIGEST = "b" * 64
OTHER_DIGEST = "c" * 64


def _module(stem: str):
    path = CI_RUNNERS / f"{stem}.py"
    if not path.is_file():
        pytest.fail(f"missing {path.relative_to(REPO_ROOT).as_posix()}")
    name = f"_ash_ci_runners_{stem}"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _api(stem: str, name: str):
    module = _module(stem)
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/{stem}.py defines no {name}")
    return getattr(module, name)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*")}


# ---------------------------------------------------------------------------
# Archives used below
# ---------------------------------------------------------------------------


def _tar_gz(path: Path, members: dict[str, tuple[bytes, int]]) -> Path:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, (data, mode) in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            archive.addfile(info, io.BytesIO(data))
    path.write_bytes(buffer.getvalue())
    return path


def _zip(path: Path, members: dict[str, tuple[bytes, int]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, (data, mode) in members.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, data)
    return path


def _downloads(tmp_path: Path) -> dict[str, tuple[Path, dict]]:
    """name -> (downloaded file, its manifest entry), one per install form."""
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    tar = _tar_gz(
        downloads / "act_Linux_x86_64.tar.gz",
        {"act": (b"#!/bin/sh\necho act\n", 0o755), "LICENSE": (b"MIT\n", 0o644)},
    )
    zipped = _zip(
        downloads / "jenkinsfile-runner-1.0.zip",
        {
            "jenkinsfile-runner-1.0/bin/jenkinsfile-runner": (b"#!/bin/sh\n", 0o755),
            "jenkinsfile-runner-1.0/lib/runner.jar": (b"jar", 0o644),
        },
    )
    script = downloads / "codebuild_build.sh"
    script.write_bytes(b"#!/bin/bash\necho build\n")
    return {
        "tar": (
            tar,
            {
                "version": "v1.0",
                "url": "https://example.invalid/v1.0/act_Linux_x86_64.tar.gz",
                "sha256": _sha256(tar),
                "license": "MIT",
                "source": "release checksums",
            },
        ),
        "zip": (
            zipped,
            {
                "version": "1.0",
                "url": "https://example.invalid/1.0/jenkinsfile-runner-1.0.zip",
                "sha256": _sha256(zipped),
                "license": "MIT",
                "source": "hashed once",
            },
        ),
        "file": (
            script,
            {
                "version": "abc",
                "url": "https://example.invalid/abc/local_builds/codebuild_build.sh",
                "sha256": _sha256(script),
                "license": "Apache-2.0",
                "source": "hashed once",
            },
        ),
    }


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_verified_download_is_installed_with_its_layout_and_execute_bits(
    tmp_path, monkeypatch
):
    github_path = tmp_path / "github_path"
    github_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_PATH", str(github_path))
    path_before = os.environ.get("PATH")
    install_tool = _api("install_tools", "install_tool")
    downloads = _downloads(tmp_path)
    bin_dir = tmp_path / "bin"

    install_tool(downloads["tar"][1], downloads["tar"][0], bin_dir)
    assert (bin_dir / "act").read_bytes() == b"#!/bin/sh\necho act\n"
    assert os.access(bin_dir / "act", os.X_OK)

    install_tool(downloads["zip"][1], downloads["zip"][0], bin_dir)
    runner = bin_dir / "jenkinsfile-runner-1.0" / "bin" / "jenkinsfile-runner"
    assert runner.is_file() and os.access(runner, os.X_OK), (
        "a zip keeps its layout, and its members' execute bits"
    )
    assert (bin_dir / "jenkinsfile-runner-1.0" / "lib" / "runner.jar").is_file()

    install_tool(downloads["file"][1], downloads["file"][0], bin_dir)
    assert os.access(bin_dir / "codebuild_build.sh", os.X_OK)

    assert github_path.read_text(encoding="utf-8") == "", (
        "install_tools.py puts nothing on the job's PATH; the launch environment does"
    )
    assert os.environ.get("PATH") == path_before


@pytest.mark.unit
@pytest.mark.parametrize("form", ["tar", "zip", "file"])
def test_a_download_that_does_not_match_its_sha256_is_refused_and_leaves_nothing(
    tmp_path, monkeypatch, form
):
    github_path = tmp_path / "github_path"
    github_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_PATH", str(github_path))
    install_tool = _api("install_tools", "install_tool")
    integrity_error = _api("install_tools", "IntegrityError")
    downloaded, entry = _downloads(tmp_path)[form]
    entry = dict(entry, sha256="0" * 64)
    bin_dir = tmp_path / "bin"
    before = _tree(tmp_path)
    with pytest.raises(integrity_error) as raised:
        install_tool(entry, downloaded, bin_dir)
    assert "0" * 64 in str(raised.value) and _sha256(downloaded) in str(raised.value), (
        "the refusal names the pinned and the actual sha256"
    )
    after = _tree(tmp_path) - {"bin"}
    assert after == before, f"left behind: {sorted(after - before)}"
    assert not bin_dir.exists() or not any(bin_dir.iterdir())
    assert github_path.read_text(encoding="utf-8") == ""


@pytest.mark.unit
def test_an_archive_member_outside_the_bin_directory_is_refused(tmp_path):
    install_tool = _api("install_tools", "install_tool")
    integrity_error = _api("install_tools", "IntegrityError")
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    tar = _tar_gz(downloads / "x.tar.gz", {"../escaped": (b"x", 0o755)})
    entry = {"url": "https://example.invalid/x.tar.gz", "sha256": _sha256(tar)}
    with pytest.raises(integrity_error):
        install_tool(entry, tar, tmp_path / "bin" / "inner")
    assert not (tmp_path / "bin" / "escaped").exists()
    assert not (tmp_path / "escaped").exists()


def _tar_entries(path: Path, entries: list[dict]) -> Path:
    """A tar.gz of any member types: each entry has a name and optionally a tarfile
    type, a mode, a linkname and data."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry["name"])
            info.type = entry.get("type", tarfile.REGTYPE)
            info.mode = entry.get("mode", 0o644)
            info.linkname = entry.get("linkname", "")
            data = entry.get("data", b"")
            if info.type == tarfile.REGTYPE:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)
    path.write_bytes(buffer.getvalue())
    return path


def _zip_entries(path: Path, entries: list[tuple[str, int, bytes]]) -> Path:
    """A zip of (name, unix mode with its file type bits, data) members."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, mode, data in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, data)
    return path


def _zip_with_stored_name(path: Path, name: str) -> Path:
    """A zip whose stored member name is exactly ``name``, backslash or drive letter
    included, which ZipInfo would otherwise rewrite on some platforms."""
    placeholder = "\x7fQ" * (len(name) // 2) + "\x7f" * (len(name) % 2)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(placeholder)
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, b"x")
    raw = buffer.getvalue()
    assert raw.count(placeholder.encode()) == 2, "the local and the central header"
    path.write_bytes(raw.replace(placeholder.encode(), name.encode()))
    return path


HOSTILE_ARCHIVES = {
    "tar-symlink": lambda p: _tar_entries(
        p / "x.tar.gz",
        [{"name": "link", "type": tarfile.SYMTYPE, "linkname": "../../escaped"}],
    ),
    "tar-symlink-then-a-file-through-it": lambda p: _tar_entries(
        p / "x.tar.gz",
        [
            {"name": "d", "type": tarfile.SYMTYPE, "linkname": "../../escaped-dir"},
            {"name": "d/escaped", "data": b"x"},
        ],
    ),
    "tar-hardlink-inside": lambda p: _tar_entries(
        p / "x.tar.gz",
        [
            {"name": "a", "data": b"x"},
            {"name": "b", "type": tarfile.LNKTYPE, "linkname": "a"},
        ],
    ),
    "tar-hardlink-outside": lambda p: _tar_entries(
        p / "x.tar.gz",
        [{"name": "b", "type": tarfile.LNKTYPE, "linkname": "../../escaped"}],
    ),
    "tar-char-device": lambda p: _tar_entries(
        p / "x.tar.gz", [{"name": "dev", "type": tarfile.CHRTYPE}]
    ),
    "tar-fifo": lambda p: _tar_entries(
        p / "x.tar.gz", [{"name": "fifo", "type": tarfile.FIFOTYPE}]
    ),
    "tar-absolute-path": lambda p: _tar_entries(
        p / "x.tar.gz", [{"name": "/escaped-absolute", "data": b"x"}]
    ),
    "tar-deep-dotdot": lambda p: _tar_entries(
        p / "x.tar.gz", [{"name": "a/../../escaped", "data": b"x"}]
    ),
    "tar-backslash": lambda p: _tar_entries(
        p / "x.tar.gz", [{"name": "..\\..\\escaped", "data": b"x"}]
    ),
    "tar-drive-name": lambda p: _tar_entries(
        p / "x.tar.gz", [{"name": "C:escaped", "data": b"x"}]
    ),
    "zip-symlink-mode": lambda p: _zip_entries(
        p / "x.zip", [("link", stat.S_IFLNK | 0o777, b"../../escaped")]
    ),
    "zip-absolute-path": lambda p: _zip_entries(
        p / "x.zip", [("/escaped-absolute", stat.S_IFREG | 0o644, b"x")]
    ),
    "zip-dotdot": lambda p: _zip_entries(
        p / "x.zip", [("../escaped", stat.S_IFREG | 0o644, b"x")]
    ),
    "zip-char-device-mode": lambda p: _zip_entries(
        p / "x.zip", [("dev", stat.S_IFCHR | 0o644, b"")]
    ),
    "zip-stored-backslash-name": lambda p: _zip_with_stored_name(p / "x.zip", "..\\x"),
    "zip-stored-drive-name": lambda p: _zip_with_stored_name(p / "x.zip", "C:/x"),
}


@pytest.mark.unit
@pytest.mark.parametrize("case", sorted(HOSTILE_ARCHIVES))
def test_an_archive_member_that_is_not_a_plain_file_or_dir_inside_is_refused(
    tmp_path, case
):
    """Links, devices, fifos and names that leave the directory are refused before
    anything is written; regular files and directories are all an install needs."""
    install_tool = _api("install_tools", "install_tool")
    integrity_error = _api("install_tools", "IntegrityError")
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    archive = HOSTILE_ARCHIVES[case](downloads)
    entry = {
        "url": f"https://example.invalid/{archive.name}",
        "sha256": _sha256(archive),
    }
    before = _tree(tmp_path)
    with pytest.raises(integrity_error):
        install_tool(entry, archive, tmp_path / "bin" / "inner")
    assert _tree(tmp_path) == before, f"created: {sorted(_tree(tmp_path) - before)}"


@pytest.mark.unit
def test_a_tar_whose_members_start_with_dot_slash_installs(tmp_path):
    """Control for the refusals above: a ./ prefix and the archive's root directory
    entry are plain names."""
    install_tool = _api("install_tools", "install_tool")
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    archive = _tar_entries(
        downloads / "x.tar.gz",
        [
            {"name": "./", "type": tarfile.DIRTYPE, "mode": 0o755},
            {"name": "./act", "data": b"x", "mode": 0o755},
        ],
    )
    entry = {"url": "https://example.invalid/x.tar.gz", "sha256": _sha256(archive)}
    install_tool(entry, archive, tmp_path / "bin")
    assert (tmp_path / "bin" / "act").read_bytes() == b"x"


@pytest.mark.unit
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
@pytest.mark.parametrize(
    "bits", [0o4000, 0o2000, 0o1000], ids=["setuid", "setgid", "sticky"]
)
@pytest.mark.parametrize("form", ["tar", "zip"])
def test_setuid_setgid_and_sticky_bits_are_not_installed(tmp_path, form, bits):
    install_tool = _api("install_tools", "install_tool")
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    if form == "tar":
        archive = _tar_entries(
            downloads / "x.tar.gz", [{"name": "s", "data": b"x", "mode": 0o755 | bits}]
        )
    else:
        archive = _zip_entries(
            downloads / "x.zip", [("s", stat.S_IFREG | 0o755 | bits, b"x")]
        )
    entry = {
        "url": f"https://example.invalid/{archive.name}",
        "sha256": _sha256(archive),
    }
    install_tool(entry, archive, tmp_path / "bin")
    mode = stat.S_IMODE((tmp_path / "bin" / "s").stat().st_mode)
    assert mode & 0o7000 == 0, oct(mode)
    assert mode & 0o111, "the execute bits stay"


@pytest.mark.unit
@pytest.mark.parametrize("pin", ["", "abc", "A" * 64, "g" * 64, None], ids=repr)
def test_a_pin_that_is_not_64_lowercase_hex_is_a_manifest_error(tmp_path, pin):
    """A malformed pin is a mistake in the manifest, not a download that failed its
    check, so it is a ValueError (exit 1) before anything is read or created."""
    install_tool = _api("install_tools", "install_tool")
    path, entry = _downloads(tmp_path)["tar"]
    entry = dict(entry, sha256=pin)
    before = _tree(tmp_path)
    with pytest.raises(ValueError, match="sha256"):
        install_tool(entry, path, tmp_path / "bin")
    assert _tree(tmp_path) == before


@pytest.mark.unit
def test_a_download_url_must_be_https_before_anything_is_fetched(tmp_path):
    download_file = _api("install_tools", "download_file")
    # A refused connection on this port would raise something else: the check comes
    # before any attempt to connect.
    with pytest.raises(ValueError, match="https") as raised:
        download_file("http://127.0.0.1:9/act.tar.gz", tmp_path / "act.tar.gz")
    # The same kind of refusal as a redirect away from https.
    assert type(raised.value) is _api("install_tools", "NotHttpsError")
    assert not (tmp_path / "act.tar.gz").exists()


# ---------------------------------------------------------------------------
# Downloads, with urllib's https handler answering from a table, no sockets
# ---------------------------------------------------------------------------

SITE = "https://a.example.invalid/f"


class _FakeResponse(io.BytesIO):
    """What urllib's HTTPS handler returns, built from a table instead of a socket.
    headers is a dict, or a message as http.client reads one off the wire; reason is
    the status line's reason phrase."""

    def __init__(
        self,
        url: str,
        code: int,
        headers: dict[str, str] | email.message.Message,
        body: bytes,
        reason: str = "test",
    ):
        super().__init__(body)
        self.url, self.code, self.status, self.msg = url, code, code, reason
        if isinstance(headers, email.message.Message):
            self.headers = headers
        else:
            self.headers = email.message.Message()
            for key, value in headers.items():
                self.headers[key] = value

    def info(self):
        return self.headers

    def geturl(self):
        return self.url

    def getcode(self):
        return self.code


def _serve(monkeypatch, routes, *, served_as=None) -> list[str]:
    """Answer https requests from routes, {url: (status, headers, body[, reason])}, and
    fail any http, ftp or file request. Returns the urls asked for, in order. served_as
    maps a url to the url its response reports it was served from."""
    asked: list[str] = []

    def https_open(self, request):
        asked.append(request.full_url)
        if request.full_url not in routes:
            raise AssertionError(f"unexpected request {request.full_url}")
        code, headers, body, *reason = routes[request.full_url]
        url = (served_as or {}).get(request.full_url, request.full_url)
        return _FakeResponse(url, code, headers, body, *reason)

    def refuse(self, request):
        asked.append(request.full_url)
        raise AssertionError(
            f"a request went out over {request.type}: {request.full_url}"
        )

    # No proxy from the environment or the system settings: a proxied request would
    # go out over the proxy's scheme instead of through https_open.
    monkeypatch.setattr(urllib.request, "getproxies", dict)
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", https_open)
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", refuse)
    monkeypatch.setattr(urllib.request.FTPHandler, "ftp_open", refuse)
    monkeypatch.setattr(urllib.request.FileHandler, "file_open", refuse)
    return asked


#: Redirect targets that are not https: plain http in either case, a scheme urllib's
#: redirect handler follows (ftp), and schemes it turns away by itself (file, data).
#: Each is absolute, so each is also the url the refusal names.
NOT_HTTPS = [
    "http://b.example.invalid/g",
    "HTTP://b.example.invalid/g",
    "ftp://b.example.invalid/g",
    "file:///b/g",
    "data:,b",
]

#: urllib's redirect handling as this Python has it, and as Python 3.10 has it.
HANDLERS = ["this-python", "python-3.10"]


def _handled_as(monkeypatch, handler: str) -> None:
    """For "python-3.10", make urllib's redirect handler act as 3.10's does: it has no
    http_error_308, so a 308 goes to the default error handler and comes out of the
    opener as an HTTPError, and its redirect_request turns a 308 away."""
    if handler == "this-python":
        return
    stock = urllib.request.HTTPRedirectHandler.redirect_request

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code == 308:
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
        return stock(self, req, fp, code, msg, headers, newurl)

    monkeypatch.delattr(
        urllib.request.HTTPRedirectHandler, "http_error_308", raising=False
    )
    monkeypatch.setattr(
        urllib.request.HTTPRedirectHandler, "redirect_request", redirect_request
    )


def _refusal(url: str, target: str) -> str:
    """The one message for a download that leaves https, at any hop, on any Python."""
    return (
        f"refusing the download of {url}: it redirects to {target}, and downloads are"
        " https only"
    )


def _raised(call) -> Exception:
    try:
        call()
    except Exception as error:  # the caller checks its type and message
        return error
    pytest.fail("nothing was raised")


def _assert_refused(error: Exception, url: str, target: str) -> None:
    """One refusal: the same type and message whatever turned the download away."""
    assert str(error) == _refusal(url, target), repr(error)
    assert type(error) is _api("install_tools", "NotHttpsError"), repr(error)


@pytest.mark.unit
def test_a_download_follows_absolute_relative_and_scheme_relative_https_redirects(
    tmp_path, monkeypatch
):
    download_file = _api("install_tools", "download_file")
    routes = {
        SITE: (302, {"Location": "https://b.example.invalid/g"}, b""),
        "https://b.example.invalid/g": (301, {"Location": "/h"}, b""),
        "https://b.example.invalid/h": (
            307,
            {"Location": "//c.example.invalid/i"},
            b"",
        ),
        "https://c.example.invalid/i": (200, {}, b"payload"),
    }
    asked = _serve(monkeypatch, routes)
    dest = tmp_path / "out"
    download_file(SITE, dest)
    assert dest.read_bytes() == b"payload"
    assert asked == list(routes)


@pytest.mark.unit
@pytest.mark.parametrize("handler", HANDLERS)
def test_an_https_308_is_followed_on_every_python(tmp_path, monkeypatch, handler):
    """A 308 to an https url is followed like a 307, on Python 3.10 too, whose urllib
    does not follow a 308 itself."""
    download_file = _api("install_tools", "download_file")
    _handled_as(monkeypatch, handler)
    routes = {
        SITE: (308, {"Location": "https://b.example.invalid/g"}, b""),
        "https://b.example.invalid/g": (308, {"Location": "/h"}, b""),
        "https://b.example.invalid/h": (200, {}, b"payload"),
    }
    asked = _serve(monkeypatch, routes)
    dest = tmp_path / "out"
    download_file(SITE, dest)
    assert dest.read_bytes() == b"payload"
    assert asked == list(routes)


@pytest.mark.unit
@pytest.mark.parametrize("handler", HANDLERS)
@pytest.mark.parametrize("location", NOT_HTTPS)
@pytest.mark.parametrize("code", range(300, 309))
def test_a_redirect_away_from_https_is_refused_and_leaves_nothing(
    tmp_path, monkeypatch, code, location, handler
):
    """Any 3xx whose target is not https gets the one refusal before the target is
    asked: the codes urllib follows, the ones it hands back to the caller, the 308
    Python 3.10 hands back, and the targets urllib turns away by itself."""
    download_file = _api("install_tools", "download_file")
    _handled_as(monkeypatch, handler)
    asked = _serve(monkeypatch, {SITE: (code, {"Location": location}, b"")})
    error = _raised(lambda: download_file(SITE, tmp_path / "out"))
    _assert_refused(error, SITE, location)
    assert asked == [SITE], "nothing is asked of the redirect's target"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.unit
@pytest.mark.parametrize("location", NOT_HTTPS)
def test_a_308_that_reaches_the_opener_as_an_http_error_gets_the_same_refusal(
    tmp_path, monkeypatch, location
):
    """Python 3.10's path for a 308: the response comes out of the handler chain as an
    HTTPError holding the code and the Location. That gets the same refusal, and
    nothing is written."""
    download_file = _api("install_tools", "download_file")
    asked = _serve(monkeypatch, {})

    def https_open(self, request):
        asked.append(request.full_url)
        headers = email.message.Message()
        headers["Location"] = location
        raise urllib.error.HTTPError(
            request.full_url, 308, "Permanent Redirect", headers, io.BytesIO()
        )

    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", https_open)
    error = _raised(lambda: download_file(SITE, tmp_path / "out"))
    _assert_refused(error, SITE, location)
    assert asked == [SITE]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.unit
@pytest.mark.parametrize("handler", HANDLERS)
@pytest.mark.parametrize("code", [302, 308])
def test_an_https_hop_then_an_http_hop_is_refused_at_the_second(
    tmp_path, monkeypatch, code, handler
):
    download_file = _api("install_tools", "download_file")
    _handled_as(monkeypatch, handler)
    second = "https://b.example.invalid/g"
    asked = _serve(
        monkeypatch,
        {
            SITE: (code, {"Location": second}, b""),
            second: (code, {"Location": "http://c.example.invalid/h"}, b""),
        },
    )
    error = _raised(lambda: download_file(SITE, tmp_path / "out"))
    _assert_refused(error, SITE, "http://c.example.invalid/h")
    assert asked == [SITE, second]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.unit
def test_a_response_that_reports_a_plain_http_url_is_refused(tmp_path, monkeypatch):
    """The url the response was served from is checked too, not only each redirect."""
    download_file = _api("install_tools", "download_file")
    _serve(
        monkeypatch,
        {SITE: (200, {}, b"data")},
        served_as={SITE: "http://a.example.invalid/f"},
    )
    error = _raised(lambda: download_file(SITE, tmp_path / "out"))
    _assert_refused(error, SITE, "http://a.example.invalid/f")
    assert list(tmp_path.iterdir()) == []


def _wire_headers(*lines: bytes) -> http.client.HTTPMessage:
    """Header lines as http.client reads them off the wire: decoded as ISO-8859-1, and
    a line that starts with a space or a tab continues the header before it."""
    raw = b"".join(line + b"\r\n" for line in lines) + b"\r\n"
    return http.client.parse_headers(io.BytesIO(raw))


#: A Location a server can send, as header lines or, for a character an HTTP header
#: cannot carry, as a string; and the target the refusal names, percent-encoded as
#: urllib encodes a Location before it follows one, so it is one line of printable text.
RAW_LOCATIONS = {
    "folded": (
        (b"Location: http://b.example.invalid/g", b" h"),
        "http://b.example.invalid/g%0D%0A%20h",
    ),
    "tab": (
        (b"Location: http://b.example.invalid/\tg",),
        "http://b.example.invalid/%09g",
    ),
    "escape": (
        (b"Location: http://b.example.invalid/\x1b[2Jg",),
        "http://b.example.invalid/%1B[2Jg",
    ),
    "delete": (
        (b"Location: http://b.example.invalid/\x7fg",),
        "http://b.example.invalid/%7Fg",
    ),
    "space": (
        (b"Location: http://b.example.invalid/a b",),
        "http://b.example.invalid/a%20b",
    ),
    "latin-1 byte": (
        (b"Location: http://b.example.invalid/\xe9",),
        "http://b.example.invalid/%E9",
    ),
    "past latin-1": (
        "http://b.example.invalid/" + chr(0x2603),
        "http://b.example.invalid/\\u2603",
    ),
}


@pytest.mark.unit
@pytest.mark.parametrize("code", [300, 302, 308])
@pytest.mark.parametrize("case", sorted(RAW_LOCATIONS))
def test_a_refused_redirect_names_its_target_on_one_printable_line(
    tmp_path, monkeypatch, case, code
):
    """A folded header's line break, a tab, an escape character or a byte past ASCII in
    the Location reaches the refusal percent-encoded, never as itself, on the path
    urllib's handler takes (302, 308) and on the one it hands back (300)."""
    download_file = _api("install_tools", "download_file")
    raw, shown = RAW_LOCATIONS[case]
    headers = {"Location": raw} if isinstance(raw, str) else _wire_headers(*raw)
    asked = _serve(monkeypatch, {SITE: (code, headers, b"")})
    error = _raised(lambda: download_file(SITE, tmp_path / "out"))
    _assert_refused(error, SITE, shown)
    assert str(error).isprintable(), repr(error)
    assert asked == [SITE]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.unit
@pytest.mark.parametrize("handler", HANDLERS)
@pytest.mark.parametrize(
    "newurl,shown",
    [
        *[(target, target) for target in NOT_HTTPS],
        ("http://b.example.invalid/g\r\n h", "http://b.example.invalid/g%0D%0A%20h"),
    ],
)
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_the_redirect_handler_refuses_a_new_url_that_is_not_https(
    monkeypatch, code, newurl, shown, handler
):
    """redirect_request is the last check before urllib asks the new url. Called on its
    own, it refuses one that is not https with the one refusal, whatever the code."""
    handlers = _api("install_tools", "_HttpsOnlyRedirects")
    _handled_as(monkeypatch, handler)
    request = urllib.request.Request(SITE)
    error = _raised(
        lambda: handlers(SITE).redirect_request(
            request, io.BytesIO(), code, "test", email.message.Message(), newurl
        )
    )
    _assert_refused(error, SITE, shown)


@pytest.mark.unit
@pytest.mark.parametrize("handler", HANDLERS)
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_the_redirect_handler_hands_on_a_new_https_url(monkeypatch, code, handler):
    """Control for the test above: the same call with an https url returns the request
    urllib asks next, a GET of that url, for a 308 on Python 3.10 too."""
    handlers = _api("install_tools", "_HttpsOnlyRedirects")
    _handled_as(monkeypatch, handler)
    newurl = "https://b.example.invalid/g"
    request = handlers(SITE).redirect_request(
        urllib.request.Request(SITE),
        io.BytesIO(),
        code,
        "test",
        email.message.Message(),
        newurl,
    )
    assert isinstance(request, urllib.request.Request), request
    assert (request.full_url, request.get_method()) == (newurl, "GET")


@pytest.mark.unit
@pytest.mark.parametrize("handler", HANDLERS)
@pytest.mark.parametrize("location", ["http://b.example.invalid/g", "file:///b/g"])
@pytest.mark.parametrize("code", [300, 302, 307, 308])
def test_a_redirect_named_only_by_a_uri_header_is_held_to_https(
    tmp_path, monkeypatch, code, location, handler
):
    """urllib reads a redirect's target from URI when there is no Location; so does
    the https check, on the path urllib's handler takes and on the one it hands back."""
    download_file = _api("install_tools", "download_file")
    _handled_as(monkeypatch, handler)
    asked = _serve(monkeypatch, {SITE: (code, {"URI": location}, b"")})
    error = _raised(lambda: download_file(SITE, tmp_path / "out"))
    _assert_refused(error, SITE, location)
    assert asked == [SITE]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.unit
def test_a_uri_header_to_https_is_followed_and_a_location_comes_first(
    tmp_path, monkeypatch
):
    download_file = _api("install_tools", "download_file")
    routes = {
        SITE: (302, {"URI": "https://b.example.invalid/g"}, b""),
        "https://b.example.invalid/g": (
            302,
            {
                "Location": "https://c.example.invalid/h",
                "URI": "http://c.example.invalid/h",
            },
            b"",
        ),
        "https://c.example.invalid/h": (200, {}, b"payload"),
    }
    asked = _serve(monkeypatch, routes)
    dest = tmp_path / "out"
    download_file(SITE, dest)
    assert dest.read_bytes() == b"payload"
    assert asked == list(routes)


@pytest.mark.unit
def test_a_refused_redirect_fails_the_install_without_a_retry(tmp_path, monkeypatch):
    """The refusal is final: the tool's download is not tried again, and nothing of
    it is installed."""
    install_pins = _api("install_tools", "install_pins")
    slept = _no_sleep(monkeypatch)
    _path, entry = _downloads(tmp_path)["tar"]
    target = "http://b.example.invalid/g"
    asked = _serve(monkeypatch, {entry["url"]: (302, {"Location": target}, b"")})
    error = _raised(
        lambda: install_pins(
            ["tools.tar"],
            {"tools": {"tar": dict(entry, executable="act")}},
            manifest_dir=tmp_path,
            bin_dir=tmp_path / "bin",
            pull_log=tmp_path / "pulls.log",
            run=_fake_run([]),
        )
    )
    _assert_refused(error, entry["url"], target)
    assert asked == [entry["url"]] and slept == []
    assert list((tmp_path / "bin").iterdir()) == []


@pytest.mark.unit
def test_a_download_past_the_size_cap_is_refused_and_removed(tmp_path, monkeypatch):
    download_file = _api("install_tools", "download_file")
    monkeypatch.setattr(_module("install_tools"), "MAX_DOWNLOAD_BYTES", 2 << 20)
    _serve(
        monkeypatch,
        {
            SITE: (200, {}, b"x" * (3 << 20)),
            "https://a.example.invalid/at-the-cap": (200, {}, b"x" * (2 << 20)),
        },
    )
    with pytest.raises(ValueError, match="larger than"):
        download_file(SITE, tmp_path / "out")
    assert list(tmp_path.iterdir()) == []
    # Control: a file of exactly the cap's size is kept.
    kept = download_file("https://a.example.invalid/at-the-cap", tmp_path / "kept")
    assert kept.stat().st_size == 2 << 20


@pytest.mark.unit
def test_the_download_size_cap_holds_every_pinned_download_and_stays_between_128_mib_and_1_gib():
    """The largest pinned download, the 2.375.4 Jenkins WAR, is about 94 MB; the cap
    leaves room for a later pin and stays at most 1 GiB of the runner's disk."""
    cap = _api("install_tools", "MAX_DOWNLOAD_BYTES")
    assert type(cap) is int and 128 << 20 <= cap <= 1 << 30, cap


# ---------------------------------------------------------------------------
# Jenkins cores
# ---------------------------------------------------------------------------

JENKINS_PLUGINS = ("junit", "workflow-job")


def _jenkins_downloads(tmp_path: Path):
    """A core, its plugins' entries, and local files standing in for their downloads."""
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    war = downloads / "war.download"
    war.write_bytes(b"PK\x03\x04 a stand-in for jenkins.war")
    hpis = {}
    for name in JENKINS_PLUGINS:
        hpi = downloads / f"{name}.download"
        hpi.write_bytes(f"PK\x03\x04 a stand-in for {name}.hpi".encode())
        hpis[name] = hpi
    core = {
        "core_version": "2.500.1",
        "war_url": "https://get.jenkins.io/war-stable/2.500.1/jenkins.war",
        "war_sha256": _sha256(war),
        "java": "21",
        "plugins": "jenkins/plugins-lts.toml",
    }
    plugins = [
        {
            "name": name,
            "version": "1.0",
            "url": f"https://get.jenkins.io/plugins/{name}/1.0/{name}.hpi",
            "sha256": _sha256(hpi),
            "dependencies": [],
        }
        for name, hpi in hpis.items()
    ]
    return core, plugins, war, hpis


def _installed_jenkins() -> set[str]:
    return {"jenkins.war", "plugins"} | {f"plugins/{n}.hpi" for n in JENKINS_PLUGINS}


@pytest.mark.unit
def test_a_jenkins_core_and_its_plugins_get_their_names_only_after_their_checks(
    tmp_path, monkeypatch
):
    install = _api("install_tools", "install_jenkins_core")
    core, plugins, war, hpis = _jenkins_downloads(tmp_path)
    dest = tmp_path / "jenkins"
    # For every sha256 taken, the files under dest at that moment.
    at_digest: dict[str, set[str]] = {}
    real_sha256 = hashlib.sha256

    class Recording:
        def __init__(self, *args, **kwargs):
            self._hash = real_sha256(*args, **kwargs)

        def update(self, data):
            self._hash.update(data)

        def digest(self):
            self._seen()
            return self._hash.digest()

        def hexdigest(self):
            self._seen()
            return self._hash.hexdigest()

        def _seen(self):
            at_digest.setdefault(
                self._hash.hexdigest(), _tree(dest) if dest.exists() else set()
            )

    monkeypatch.setattr(hashlib, "sha256", Recording)
    placed = install(core, plugins, war=war, hpis=hpis, dest=dest)
    monkeypatch.undo()

    assert placed == dest / "jenkins.war"
    assert placed.read_bytes() == war.read_bytes()
    assert _tree(dest) == _installed_jenkins(), "no partial download is left in dest"
    for name, hpi in hpis.items():
        assert (dest / "plugins" / f"{name}.hpi").read_bytes() == hpi.read_bytes()
    finals = {core["war_sha256"]: "jenkins.war"}
    finals.update({p["sha256"]: f"plugins/{p['name']}.hpi" for p in plugins})
    for digest, final in finals.items():
        assert digest in at_digest, f"the sha256 of {final} was not taken with hashlib"
        assert final not in at_digest[digest], (
            f"{final} existed under its final name before its sha256 was checked"
        )


@pytest.mark.unit
def test_a_jenkins_war_that_does_not_match_leaves_no_war_and_no_plugin(tmp_path):
    install = _api("install_tools", "install_jenkins_core")
    integrity_error = _api("install_tools", "IntegrityError")
    core, plugins, war, hpis = _jenkins_downloads(tmp_path)
    actual = core["war_sha256"]
    core = dict(core, war_sha256="0" * 64)
    dest = tmp_path / "jenkins"
    before = _tree(tmp_path)
    with pytest.raises(integrity_error) as raised:
        install(core, plugins, war=war, hpis=hpis, dest=dest)
    assert "0" * 64 in str(raised.value) and actual in str(raised.value), (
        "the refusal names the pinned and the actual sha256"
    )
    assert not dest.exists() or _tree(dest) == set(), sorted(_tree(dest))
    assert _tree(tmp_path) - {"jenkins"} == before


@pytest.mark.unit
@pytest.mark.parametrize("bad", JENKINS_PLUGINS)
def test_a_plugin_that_does_not_match_leaves_no_war_and_no_plugin(tmp_path, bad):
    install = _api("install_tools", "install_jenkins_core")
    integrity_error = _api("install_tools", "IntegrityError")
    core, plugins, war, hpis = _jenkins_downloads(tmp_path)
    actual = _sha256(hpis[bad])
    plugins = [dict(p, sha256="0" * 64) if p["name"] == bad else p for p in plugins]
    dest = tmp_path / "jenkins"
    before = _tree(tmp_path)
    with pytest.raises(integrity_error) as raised:
        install(core, plugins, war=war, hpis=hpis, dest=dest)
    message = str(raised.value)
    assert bad in message and "0" * 64 in message and actual in message, message
    assert not dest.exists() or _tree(dest) == set(), sorted(_tree(dest))
    assert _tree(tmp_path) - {"jenkins"} == before


@pytest.mark.unit
@pytest.mark.parametrize("name", ["../escaped", "sub/escaped", ".escaped"])
def test_a_plugin_name_that_is_not_a_plain_file_name_is_refused(tmp_path, name):
    install = _api("install_tools", "install_jenkins_core")
    integrity_error = _api("install_tools", "IntegrityError")
    core, plugins, war, hpis = _jenkins_downloads(tmp_path)
    hpi = hpis.pop("junit")
    hpis[name] = hpi
    plugins = [dict(p, name=name) if p["name"] == "junit" else p for p in plugins]
    dest = tmp_path / "jenkins"
    with pytest.raises(integrity_error):
        install(core, plugins, war=war, hpis=hpis, dest=dest)
    assert not dest.exists() or _tree(dest) == set(), sorted(_tree(dest))
    assert not (tmp_path / "escaped.hpi").exists()


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["war", *JENKINS_PLUGINS])
def test_a_jenkins_pin_that_is_not_64_lowercase_hex_is_a_manifest_error(tmp_path, bad):
    """Every pin is read before anything is copied, so a malformed one leaves no
    staging directory either."""
    install = _api("install_tools", "install_jenkins_core")
    core, plugins, war, hpis = _jenkins_downloads(tmp_path)
    if bad == "war":
        core = dict(core, war_sha256="ABC")
    else:
        plugins = [dict(p, sha256="ABC") if p["name"] == bad else p for p in plugins]
    dest = tmp_path / "jenkins"
    with pytest.raises(ValueError, match="sha256"):
        install(core, plugins, war=war, hpis=hpis, dest=dest)
    assert not dest.exists()


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_an_image_is_pulled_only_by_digest():
    docker_pull_argv = _api("install_tools", "docker_pull_argv")
    ref = f"public.ecr.aws/docker/library/python@sha256:{DIGEST}"
    assert docker_pull_argv(ref) == ["docker", "pull", ref]
    for bad in (
        "python:3.12",
        "public.ecr.aws/docker/library/python",
        f"public.ecr.aws/docker/library/python:3.12@sha256:{DIGEST}",
        f"python@sha256:{DIGEST[:40]}",
    ):
        with pytest.raises(ValueError):
            docker_pull_argv(bad)


@pytest.mark.unit
def test_pull_image_hands_the_argv_to_its_runner_and_records_the_pull(tmp_path):
    pull_image = _api("install_tools", "pull_image")
    ref = f"public.ecr.aws/codebuild/local-builds@sha256:{DIGEST}"
    pull_log = tmp_path / "pulls.txt"
    calls = []

    def run(argv, *args, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    pull_image(ref, pull_log=pull_log, run=run)
    assert calls == [["docker", "pull", ref]]
    assert pull_log.read_text(encoding="utf-8").split() == [ref]

    calls.clear()
    with pytest.raises(ValueError):
        pull_image("python:3.12", pull_log=pull_log, run=run)
    assert calls == [], "a tag-only reference is refused before docker is run"
    assert pull_log.read_text(encoding="utf-8").split() == [ref]


@pytest.mark.unit
def test_a_failed_pull_is_not_logged(tmp_path, monkeypatch):
    """The log lists pulls that happened, so the allowlist check can ask the events
    file for each one."""
    pull_image = _api("install_tools", "pull_image")
    _no_sleep(monkeypatch)
    pull_log = tmp_path / "pulls.txt"

    def run(argv, *args, **kwargs):
        raise subprocess.CalledProcessError(1, argv)

    with pytest.raises(subprocess.CalledProcessError):
        pull_image(REF, pull_log=pull_log, run=run)
    assert not pull_log.exists() or pull_log.read_text(encoding="utf-8") == ""


@pytest.mark.unit
def test_a_pull_the_registry_throttles_is_tried_again_and_logged_once(
    tmp_path, monkeypatch, capsys
):
    """ECR Public's "toomanyrequests: Data limit exceeded" clears with time, and the
    job has no credential to pull with an allowance of its own."""
    pull_image = _api("install_tools", "pull_image")
    attempts_allowed = _api("install_tools", "PULL_ATTEMPTS")
    slept = _no_sleep(monkeypatch)
    pull_log = tmp_path / "pulls.txt"
    calls: list[list[str]] = []

    def run(argv, *args, **kwargs):
        calls.append(list(argv))
        if len(calls) < attempts_allowed:
            raise subprocess.CalledProcessError(1, argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    pull_image(REF, pull_log=pull_log, run=run)
    assert len(calls) == attempts_allowed and attempts_allowed >= 2
    assert all(call == ["docker", "pull", REF] for call in calls)
    assert len(slept) == attempts_allowed - 1 and all(s > 0 for s in slept)
    assert pull_log.read_text(encoding="utf-8").split() == [REF]
    assert capsys.readouterr().err.count("trying again") == attempts_allowed - 1


@pytest.mark.unit
def test_a_pull_that_fails_every_time_is_tried_the_set_number_of_times(
    tmp_path, monkeypatch
):
    pull_image = _api("install_tools", "pull_image")
    attempts_allowed = _api("install_tools", "PULL_ATTEMPTS")
    _no_sleep(monkeypatch)
    calls: list[list[str]] = []

    def run(argv, *args, **kwargs):
        calls.append(list(argv))
        raise subprocess.CalledProcessError(1, argv)

    with pytest.raises(subprocess.CalledProcessError):
        pull_image(REF, pull_log=tmp_path / "pulls.txt", run=run)
    assert len(calls) == attempts_allowed


@pytest.mark.unit
def test_a_timed_out_pull_is_not_tried_again(tmp_path, monkeypatch):
    pull_image = _api("install_tools", "pull_image")
    slept = _no_sleep(monkeypatch)
    calls: list[list[str]] = []

    def run(argv, *args, **kwargs):
        calls.append(list(argv))
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

    with pytest.raises(subprocess.TimeoutExpired):
        pull_image(REF, pull_log=tmp_path / "pulls.txt", run=run)
    assert len(calls) == 1 and slept == []


@pytest.mark.unit
def test_a_pull_has_a_timeout_and_a_timed_out_pull_is_not_logged(tmp_path):
    pull_image = _api("install_tools", "pull_image")
    timeout = _api("install_tools", "PULL_TIMEOUT_SECONDS")
    assert isinstance(timeout, int) and 0 < timeout <= 30 * 60, timeout
    pull_log = tmp_path / "pulls.txt"
    seen: dict = {}

    def run(argv, *args, **kwargs):
        seen.update(kwargs)
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

    with pytest.raises(subprocess.TimeoutExpired):
        pull_image(REF, pull_log=pull_log, run=run)
    assert seen.get("timeout") == timeout
    assert not pull_log.exists() or pull_log.read_text(encoding="utf-8") == ""


@pytest.mark.unit
def test_a_timed_out_pull_fails_the_install_with_exit_1(tmp_path, monkeypatch, capsys):
    main = _api("install_tools", "main")
    module = _module("install_tools")

    def stalled(*args, **kwargs):
        raise subprocess.TimeoutExpired(["docker", "pull", REF], 1200)

    monkeypatch.setattr(module, "install_pins", stalled)
    argv = ["--runner", "act", "--bin-dir", str(tmp_path / "bin")]
    argv += ["--pull-log", str(tmp_path / "pulls.log")]
    assert main(argv, environ=ANYWHERE) == 1
    assert "docker" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Only on a GitHub-hosted runner
# ---------------------------------------------------------------------------

HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
ALLOWED = [
    ("GitHub-hosted runner", HOSTED),
    ("override", {"DOCTEST_CI_RUNNERS_ANYWHERE": "1"}),
    ("override under act", {"DOCTEST_CI_RUNNERS_ANYWHERE": "1", "ACT": "true"}),
]
REFUSED = [
    ("nothing set", {}),
    ("act sets no RUNNER_ENVIRONMENT", {"GITHUB_ACTIONS": "true", "ACT": "true"}),
    ("self-hosted", {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}),
    ("act on a hosted runner", {**HOSTED, "ACT": "true"}),
    ("not actions", {"GITHUB_ACTIONS": "false", "RUNNER_ENVIRONMENT": "github-hosted"}),
    ("override off", {"DOCTEST_CI_RUNNERS_ANYWHERE": "0"}),
    ("override not 1", {"DOCTEST_CI_RUNNERS_ANYWHERE": "true"}),
]


@pytest.mark.unit
@pytest.mark.parametrize("case,environ", ALLOWED, ids=[c[0] for c in ALLOWED])
def test_install_tools_runs_on_a_github_hosted_runner(case, environ):
    assert _api("install_tools", "runner_environment_problem")(environ) is None


@pytest.mark.unit
@pytest.mark.parametrize("case,environ", REFUSED, ids=[c[0] for c in REFUSED])
def test_install_tools_refuses_anywhere_else(case, environ):
    problem = _api("install_tools", "runner_environment_problem")(environ)
    assert isinstance(problem, str) and "DOCTEST_CI_RUNNERS_ANYWHERE=1" in problem, (
        f"{case}: the refusal says how to override it: {problem!r}"
    )


def _script(stem: str) -> Path:
    path = CI_RUNNERS / f"{stem}.py"
    if not path.is_file():
        pytest.fail(f"missing {path.relative_to(REPO_ROOT).as_posix()}")
    return path


def _run_isolated(script: Path, args: list[str], env: dict[str, str]):
    # Python on Windows does not start without SYSTEMROOT.
    keep = {k: os.environ[k] for k in ("SYSTEMROOT",) if k in os.environ}
    return subprocess.run(
        [sys.executable, "-I", str(script), *args],
        cwd=script.parent,
        env={**keep, **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.integration
def test_install_tools_runs_standalone_in_isolated_mode(tmp_path):
    result = _run_isolated(
        _script("install_tools"),
        ["--help"],
        {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    assert "--runner" in result.stdout and "--bin-dir" in result.stdout


@pytest.mark.integration
@pytest.mark.parametrize(
    "environ",
    [{}, {**HOSTED, "ACT": "true"}],
    ids=["no runner", "under act"],
)
def test_install_tools_refuses_before_it_installs_anything(tmp_path, environ):
    bin_dir = tmp_path / "bin"
    result = _run_isolated(
        _script("install_tools"),
        ["--runner", "act", "--bin-dir", str(bin_dir)],
        {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "home"), **environ},
    )
    assert result.returncode != 0
    assert "DOCTEST_CI_RUNNERS_ANYWHERE=1" in result.stdout + result.stderr
    assert not bin_dir.exists()
    assert not (tmp_path / "home").exists()


# ---------------------------------------------------------------------------
# The command line's legs and layout, with the network replaced
# ---------------------------------------------------------------------------

JENKINS_LEGS = ("jenkinsfile-runner-lts", "jenkinsfile-runner-bundled")
OTHER_LEGS = ("act", "gitlab-ci-local", "codebuild-agent", "circleci")
ANYWHERE = {"DOCTEST_CI_RUNNERS_ANYWHERE": "1"}
REF = f"public.ecr.aws/docker/library/python@sha256:{DIGEST}"


class _ReachedTheNetwork(BaseException):
    """Raised by the stand-ins for download_file and pull_image. A BaseException, so an
    ``except Exception`` in the code under test cannot swallow it."""


def _main_without_network(monkeypatch):
    """install_tools.main, with download_file and pull_image replaced, so a test of the
    command line cannot download or pull even when the code under test is wrong."""
    main = _api("install_tools", "main")
    _api("install_tools", "download_file")
    _api("install_tools", "pull_image")
    module = _module("install_tools")

    def refuse(*args, **kwargs):
        raise _ReachedTheNetwork(args)

    monkeypatch.setattr(module, "download_file", refuse)
    monkeypatch.setattr(module, "pull_image", refuse)
    return main


def _exit_code(call):
    try:
        return call()
    except SystemExit as exited:
        return exited.code


def _argv(tmp_path: Path, leg: str, *extra: str) -> list[str]:
    return [
        "--runner",
        leg,
        "--bin-dir",
        str(tmp_path / "bin"),
        "--pull-log",
        str(tmp_path / "pulls.log"),
        *extra,
    ]


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_a_jenkins_leg_without_a_jenkins_dir_is_a_usage_error(
    tmp_path, monkeypatch, capsys, leg
):
    main = _main_without_network(monkeypatch)
    code = _exit_code(lambda: main(_argv(tmp_path, leg), environ=ANYWHERE))
    assert code not in (0, None)
    assert "--jenkins-dir" in capsys.readouterr().err
    assert _tree(tmp_path) == set(), "a usage error creates nothing"


@pytest.mark.unit
@pytest.mark.parametrize("leg", OTHER_LEGS)
def test_a_jenkins_dir_on_another_leg_is_a_usage_error(
    tmp_path, monkeypatch, capsys, leg
):
    main = _main_without_network(monkeypatch)
    argv = _argv(tmp_path, leg, "--jenkins-dir", str(tmp_path / "jenkins"))
    code = _exit_code(lambda: main(argv, environ=ANYWHERE))
    assert code not in (0, None)
    assert "--jenkins-dir" in capsys.readouterr().err
    assert _tree(tmp_path) == set(), "a usage error creates nothing"


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_a_jenkins_leg_with_a_jenkins_dir_goes_on_to_its_downloads(
    tmp_path, monkeypatch, leg
):
    """Control for the two tests above: with --jenkins-dir the same command line passes
    the usage checks and reaches the replaced download."""
    main = _main_without_network(monkeypatch)
    argv = _argv(tmp_path, leg, "--jenkins-dir", str(tmp_path / "jenkins"))
    with pytest.raises(_ReachedTheNetwork):
        main(argv, environ=ANYWHERE)


def _fake_download(files: dict[str, Path], fetched: list[str]):
    def download(url, dest):
        fetched.append(url)
        dest = Path(dest)
        dest.write_bytes(files[url].read_bytes())
        return dest

    return download


def _fake_run(calls: list[list[str]]):
    def run(argv, *args, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    return run


@pytest.mark.unit
def test_each_tool_gets_its_own_directory_holding_its_executable(tmp_path):
    install_pins = _api("install_tools", "install_pins")
    downloads = _downloads(tmp_path)
    executables = {
        "tar": "act",
        "zip": "jenkinsfile-runner-1.0/bin/jenkinsfile-runner",
        "file": "codebuild_build.sh",
    }
    manifest = {
        "tools": {
            form: dict(entry, executable=executables[form])
            for form, (_path, entry) in downloads.items()
        },
        "images": {"python": {"ref": REF, "license": "unknown", "source": "test"}},
    }
    files = {entry["url"]: path for path, entry in downloads.values()}
    fetched: list[str] = []
    calls: list[list[str]] = []
    bin_dir, pull_log = tmp_path / "bin", tmp_path / "pulls.log"
    keys = ["tools.tar", "tools.zip", "tools.file", "images.python"]
    lines = install_pins(
        keys,
        manifest,
        manifest_dir=tmp_path,
        bin_dir=bin_dir,
        pull_log=pull_log,
        download=_fake_download(files, fetched),
        run=_fake_run(calls),
    )
    assert sorted(fetched) == sorted(files)
    for form, executable in executables.items():
        program = bin_dir / form / executable
        assert program.is_file() and os.access(program, os.X_OK), program
    assert sorted(p.name for p in bin_dir.iterdir()) == sorted(executables), (
        "one directory per tool, and no download left beside them"
    )
    assert (bin_dir / "tar" / "LICENSE").is_file(), "an archive keeps its layout"
    assert calls == [["docker", "pull", REF]]
    assert pull_log.read_text(encoding="utf-8").split() == [REF]
    for key in keys:
        assert any(key in line for line in lines), (key, lines)


@pytest.mark.unit
def test_a_tool_whose_executable_is_not_installed_is_refused_and_removed(tmp_path):
    install_pins = _api("install_tools", "install_pins")
    integrity_error = _api("install_tools", "IntegrityError")
    path, entry = _downloads(tmp_path)["tar"]
    manifest = {"tools": {"tar": dict(entry, executable="bin/act")}}
    with pytest.raises(integrity_error) as raised:
        install_pins(
            ["tools.tar"],
            manifest,
            manifest_dir=tmp_path,
            bin_dir=tmp_path / "bin",
            pull_log=tmp_path / "pulls.log",
            download=_fake_download({entry["url"]: path}, []),
            run=_fake_run([]),
        )
    assert "bin/act" in str(raised.value)
    assert not (tmp_path / "bin" / "tar").exists()


@pytest.mark.unit
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bits")
def test_the_named_executable_is_made_executable_when_its_archive_stores_no_bit(
    tmp_path,
):
    """Jenkinsfile Runner's release zip stores bin/jenkinsfile-runner with mode 0644, so
    the install sets the execute bit on the file the manifest names, and only on it."""
    install_pins = _api("install_tools", "install_pins")
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    zipped = _zip(
        downloads / "runner-1.0.zip",
        {"bin/runner": (b"#!/usr/bin/env sh\n", 0o644), "lib/a.jar": (b"jar", 0o644)},
    )
    entry = {
        "version": "1.0",
        "url": "https://example.invalid/1.0/runner-1.0.zip",
        "sha256": _sha256(zipped),
        "executable": "bin/runner",
    }
    install_pins(
        ["tools.runner"],
        {"tools": {"runner": entry}},
        manifest_dir=tmp_path,
        bin_dir=tmp_path / "bin",
        pull_log=tmp_path / "pulls.log",
        download=_fake_download({entry["url"]: zipped}, []),
        run=_fake_run([]),
    )
    assert os.access(tmp_path / "bin" / "runner" / "bin" / "runner", os.X_OK)
    assert not os.access(tmp_path / "bin" / "runner" / "lib" / "a.jar", os.X_OK)


@pytest.mark.unit
def test_a_jenkins_core_is_installed_from_its_plugins_file(tmp_path):
    install_pins = _api("install_tools", "install_pins")
    core, plugins, war, hpis = _jenkins_downloads(tmp_path)
    manifest_dir = tmp_path / "manifest"
    (manifest_dir / "jenkins").mkdir(parents=True)
    toml = []
    for plugin in plugins:
        toml += ["[[plugin]]"]
        toml += [
            f'{key} = "{plugin[key]}"' for key in ("name", "version", "url", "sha256")
        ]
        toml += ["dependencies = []", ""]
    (manifest_dir / "jenkins" / "plugins-lts.toml").write_text(
        "\n".join(toml), encoding="utf-8"
    )
    files = {core["war_url"]: war}
    files.update({p["url"]: hpis[p["name"]] for p in plugins})
    fetched: list[str] = []
    jenkins_dir, pull_log = tmp_path / "jenkins", tmp_path / "pulls.log"
    install_pins(
        ["jenkins.cores.lts"],
        {"jenkins": {"cores": {"lts": core}}},
        manifest_dir=manifest_dir,
        bin_dir=tmp_path / "bin",
        pull_log=pull_log,
        jenkins_dir=jenkins_dir,
        download=_fake_download(files, fetched),
        run=_fake_run([]),
    )
    assert sorted(fetched) == sorted(files)
    assert _tree(jenkins_dir) == _installed_jenkins()
    assert pull_log.read_text(encoding="utf-8") == "", (
        "the pull log exists, empty, so the allowlist check can tell it was written"
    )


@pytest.mark.unit
def test_a_plugins_file_that_lists_bundled_plugins_is_refused_before_any_download(
    tmp_path,
):
    """Jenkinsfile Runner's release zip ships no plugins, so a plugin listed as bundled
    would be missing at run time; the install refuses the file instead."""
    install_pins = _api("install_tools", "install_pins")
    core, plugins, war, hpis = _jenkins_downloads(tmp_path)
    manifest_dir = tmp_path / "manifest"
    (manifest_dir / "jenkins").mkdir(parents=True)
    toml = ['bundled = ["junit"]', ""]
    for plugin in plugins:
        if plugin["name"] == "junit":
            continue
        toml += ["[[plugin]]"]
        toml += [
            f'{key} = "{plugin[key]}"' for key in ("name", "version", "url", "sha256")
        ]
        toml += ["dependencies = []", ""]
    (manifest_dir / "jenkins" / "plugins-lts.toml").write_text(
        "\n".join(toml), encoding="utf-8"
    )
    files = {core["war_url"]: war}
    files.update({p["url"]: hpis[p["name"]] for p in plugins})
    fetched: list[str] = []
    jenkins_dir = tmp_path / "jenkins"
    with pytest.raises(ValueError, match="bundled"):
        install_pins(
            ["jenkins.cores.lts"],
            {"jenkins": {"cores": {"lts": core}}},
            manifest_dir=manifest_dir,
            bin_dir=tmp_path / "bin",
            pull_log=tmp_path / "pulls.log",
            jenkins_dir=jenkins_dir,
            download=_fake_download(files, fetched),
            run=_fake_run([]),
        )
    assert fetched == []
    assert not jenkins_dir.exists()


def _plugins_toml(plugins: list[dict]) -> str:
    """A plugins file listing plugins; a key an entry lacks is left out."""
    lines: list[str] = []
    for plugin in plugins:
        lines.append("[[plugin]]")
        lines += [
            f"{key} = {json.dumps(plugin[key])}"
            for key in ("name", "version", "url", "sha256")
            if key in plugin
        ]
        lines += ["dependencies = []", ""]
    return "\n".join(lines)


def _jenkins_leg(tmp_path: Path):
    """A leg shaped like the Jenkins ones, with an image too: a tool, a core and an
    image. Returns their tables (tool, core, the core's plugins, image), for a test to
    change, and the file each url serves."""
    (tmp_path / "t").mkdir()
    (tmp_path / "j").mkdir()
    tool_path, tool = _downloads(tmp_path / "t")["zip"]
    tool = dict(tool, executable="jenkinsfile-runner-1.0/bin/jenkinsfile-runner")
    core, plugins, war, hpis = _jenkins_downloads(tmp_path / "j")
    image = {"ref": REF, "license": "unknown", "source": "test"}
    files = {tool["url"]: tool_path, core["war_url"]: war}
    files.update({plugin["url"]: hpis[plugin["name"]] for plugin in plugins})
    return (tool, core, plugins, image), files


#: The leg's keys in install_pins' order: the tool's first, the image's last.
LEG_KEYS = ("tools.runner", "jenkins.cores.lts", "images.python")


def _install_leg(tmp_path: Path, tables, files, fetched: list, calls: list, **changes):
    """Write the core's plugins file, then return a call of install_pins for LEG_KEYS
    that records what it fetches and runs. changes replaces any of its arguments by
    name (keys, bin_dir, pull_log, jenkins_dir), and ``more`` adds or replaces
    top-level manifest tables."""
    tool, core, plugins, image = tables
    manifest_dir = tmp_path / "manifest"
    (manifest_dir / "jenkins").mkdir(parents=True)
    (manifest_dir / "jenkins" / "plugins-lts.toml").write_text(
        _plugins_toml(plugins), encoding="utf-8"
    )
    install_pins = _api("install_tools", "install_pins")
    manifest = {
        "tools": {"runner": tool},
        "jenkins": {"cores": {"lts": core}},
        "images": {"python": image},
        **changes.pop("more", {}),
    }
    keys = list(changes.pop("keys", LEG_KEYS))
    arguments = {
        "manifest_dir": manifest_dir,
        "bin_dir": tmp_path / "bin",
        "pull_log": tmp_path / "out" / "pulls.log",
        "jenkins_dir": tmp_path / "jenkins",
        "download": _fake_download(files, fetched),
        "run": _fake_run(calls),
        **changes,
    }
    return lambda: install_pins(keys, manifest, **arguments)


@pytest.mark.unit
def test_the_jenkins_shaped_leg_installs_when_its_entries_are_right(tmp_path):
    """Control for the two tests below: the same leg, unchanged, installs everything."""
    tables, files = _jenkins_leg(tmp_path)
    fetched: list[str] = []
    calls: list[list[str]] = []
    _install_leg(tmp_path, tables, files, fetched, calls)()
    assert sorted(fetched) == sorted(files)
    assert calls == [["docker", "pull", REF]]
    assert (tmp_path / "bin" / "runner" / tables[0]["executable"]).is_file()
    assert _tree(tmp_path / "jenkins") == _installed_jenkins()
    assert (tmp_path / "out" / "pulls.log").read_text(encoding="utf-8").split() == [REF]


#: A mistake in one entry of the leg: how to make it, the refusal's type, and a word
#: its message holds.
LEG_MISTAKES = {
    "tool pin": (lambda t, c, p, i: t.update(sha256="abc"), "ValueError", "sha256"),
    "tool url": (
        lambda t, c, p, i: t.update(url=t["url"].replace("https:", "http:")),
        "NotHttpsError",
        "https",
    ),
    "war pin": (
        lambda t, c, p, i: c.update(war_sha256="0" * 63),
        "ValueError",
        "sha256",
    ),
    "no war pin": (lambda t, c, p, i: c.pop("war_sha256"), "ValueError", "sha256"),
    "war url": (
        lambda t, c, p, i: c.update(war_url=c["war_url"].replace("https:", "http:")),
        "NotHttpsError",
        "https",
    ),
    "first plugin pin": (
        lambda t, c, p, i: p[0].update(sha256="A" * 64),
        "ValueError",
        "sha256",
    ),
    "no last plugin pin": (
        lambda t, c, p, i: p[-1].pop("sha256"),
        "ValueError",
        "sha256",
    ),
    "last plugin url": (
        lambda t, c, p, i: p[-1].update(url=p[-1]["url"].replace("https:", "http:")),
        "NotHttpsError",
        "https",
    ),
    "last plugin name": (
        lambda t, c, p, i: p[-1].update(name="../escaped"),
        "IntegrityError",
        "escaped",
    ),
    "plugin listed twice": (
        lambda t, c, p, i: p.append(dict(p[0])),
        "ValueError",
        "twice",
    ),
    "image by tag": (
        lambda t, c, p, i: i.update(ref="python:3.12"),
        "ValueError",
        "python:3.12",
    ),
}


@pytest.mark.unit
@pytest.mark.parametrize("mistake", sorted(LEG_MISTAKES))
def test_a_mistake_in_any_entry_of_a_leg_is_refused_before_anything_is_fetched(
    tmp_path, mistake
):
    """Every entry the leg uses, its plugins file included, is checked before anything
    is created or fetched: a mistake in the core or the image, which come after the
    tool, leaves the tool undownloaded, and not even the pull log is made."""
    kinds = {
        "ValueError": ValueError,
        "NotHttpsError": _api("install_tools", "NotHttpsError"),
        "IntegrityError": _api("install_tools", "IntegrityError"),
    }
    tables, files = _jenkins_leg(tmp_path)
    make, kind, word = LEG_MISTAKES[mistake]
    make(*tables)
    fetched: list[str] = []
    calls: list[list[str]] = []
    install = _install_leg(tmp_path, tables, files, fetched, calls)
    before = _tree(tmp_path)
    error = _raised(install)
    assert type(error) is kinds[kind] and word in str(error), repr(error)
    assert fetched == [] and calls == [], (fetched, calls)
    assert _tree(tmp_path) == before, sorted(_tree(tmp_path) ^ before)


@pytest.mark.unit
@pytest.mark.parametrize(
    "taken", ["bin/runner", "jenkins/jenkins.war", "jenkins/plugins"]
)
def test_a_leg_whose_install_directory_is_taken_is_refused_before_anything_is_fetched(
    tmp_path, taken
):
    tables, files = _jenkins_leg(tmp_path)
    fetched: list[str] = []
    calls: list[list[str]] = []
    install = _install_leg(tmp_path, tables, files, fetched, calls)
    path = tmp_path / taken
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.name == "jenkins.war":
        path.write_bytes(b"an earlier core")
    else:
        path.mkdir()
    before = _tree(tmp_path)
    error = _raised(install)
    assert type(error) is FileExistsError and path.name in str(error), repr(error)
    assert fetched == [] and calls == [], (fetched, calls)
    assert _tree(tmp_path) == before, sorted(_tree(tmp_path) ^ before)


#: install_pins called wrongly for the leg: the change to its arguments, made from the
#: leg's tables (tool, core, plugins, image), and the ValueError's exact message.
CALL_MISTAKES = {
    "a key of another kind": (
        lambda t, c, p, i: {
            "keys": ("tools.runner", "tool.runner", *LEG_KEYS[1:]),
            "more": {"tool": {"runner": t}},
        },
        "tool.runner is not a tools., images. or jenkins.cores. key",
    ),
    "a key of another kind with no table": (
        lambda t, c, p, i: {"keys": ("tools.runner", "tool.runner", *LEG_KEYS[1:])},
        "tool.runner is not a tools., images. or jenkins.cores. key",
    ),
    "an image with no pull log": (
        lambda t, c, p, i: {"pull_log": None},
        "images.python: pulling an image needs a pull log",
    ),
    "a core with no Jenkins directory": (
        lambda t, c, p, i: {"jenkins_dir": None},
        "jenkins.cores.lts: a Jenkins core needs a Jenkins directory",
    ),
    "the tool listed twice": (
        lambda t, c, p, i: {"keys": (*LEG_KEYS, "tools.runner")},
        "tools.runner is listed twice",
    ),
    "the core listed twice": (
        lambda t, c, p, i: {"keys": (*LEG_KEYS, "jenkins.cores.lts")},
        "jenkins.cores.lts is listed twice",
    ),
    "the image listed twice": (
        lambda t, c, p, i: {"keys": (*LEG_KEYS, "images.python")},
        "images.python is listed twice",
    ),
    "two cores": (
        lambda t, c, p, i: {
            "keys": (*LEG_KEYS, "jenkins.cores.bundled"),
            "more": {"jenkins": {"cores": {"lts": c, "bundled": dict(c)}}},
        },
        (
            "jenkins.cores.lts, jenkins.cores.bundled: one install takes one Jenkins"
            " core at most, since a core is the Jenkins directory's jenkins.war and"
            " plugins/"
        ),
    ),
}


@pytest.mark.unit
@pytest.mark.parametrize("mistake", sorted(CALL_MISTAKES))
def test_a_leg_called_wrongly_is_refused_before_anything_is_fetched(tmp_path, mistake):
    """The call as a whole is checked with its entries, before anything is created or
    fetched: each key's kind, each key once, one Jenkins core at most, and a pull log
    and a Jenkins directory for the entries that need them. Each mistake comes after
    the tool, so an install that checked as it went would have fetched the tool."""
    tables, files = _jenkins_leg(tmp_path)
    change, message = CALL_MISTAKES[mistake]
    fetched: list[str] = []
    calls: list[list[str]] = []
    install = _install_leg(tmp_path, tables, files, fetched, calls, **change(*tables))
    before = _tree(tmp_path)
    error = _raised(install)
    assert type(error) is ValueError and str(error) == message, repr(error)
    assert fetched == [] and calls == [], (fetched, calls)
    assert _tree(tmp_path) == before, sorted(_tree(tmp_path) ^ before)


def _a_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"in the way")


def _a_dangling_link(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(path.parent / "nowhere")


_OVERLAP = "; refusing an install whose places overlap"

#: A place the leg writes to that cannot be used: what is on disk first (from
#: tmp_path), the change to install_pins' arguments, and the exact refusal.
PLACE_MISTAKES = {
    "the Jenkins directory is a file": (
        lambda tmp: _a_file(tmp / "jenkins"),
        lambda tmp: {},
        NotADirectoryError,
        lambda tmp: (
            f"the Jenkins directory {tmp / 'jenkins'} exists and is not a directory"
        ),
    ),
    "the Jenkins directory is a dangling link": (
        lambda tmp: _a_dangling_link(tmp / "jenkins"),
        lambda tmp: {},
        NotADirectoryError,
        lambda tmp: (
            f"the Jenkins directory {tmp / 'jenkins'} exists and is not a directory"
        ),
    ),
    "the Jenkins directory is below a file": (
        lambda tmp: _a_file(tmp / "taken"),
        lambda tmp: {"jenkins_dir": tmp / "taken" / "jenkins"},
        NotADirectoryError,
        lambda tmp: (
            f"the Jenkins directory {tmp / 'taken' / 'jenkins'} cannot be created:"
            f" {tmp / 'taken'} is not a directory"
        ),
    ),
    "the bin directory is a file": (
        lambda tmp: _a_file(tmp / "bin"),
        lambda tmp: {},
        NotADirectoryError,
        lambda tmp: f"the bin directory {tmp / 'bin'} exists and is not a directory",
    ),
    "the pull log is a directory": (
        lambda tmp: (tmp / "out" / "pulls.log").mkdir(parents=True),
        lambda tmp: {},
        FileExistsError,
        lambda tmp: (
            f"the pull log {tmp / 'out' / 'pulls.log'} exists and is not a regular file"
        ),
    ),
    "the pull log is a dangling link": (
        lambda tmp: _a_dangling_link(tmp / "out" / "pulls.log"),
        lambda tmp: {},
        FileExistsError,
        lambda tmp: (
            f"the pull log {tmp / 'out' / 'pulls.log'} exists and is not a regular file"
        ),
    ),
    "the pull log is below a file": (
        lambda tmp: _a_file(tmp / "out"),
        lambda tmp: {},
        NotADirectoryError,
        lambda tmp: (
            f"the pull log {tmp / 'out' / 'pulls.log'} cannot be created:"
            f" {tmp / 'out'} is not a directory"
        ),
    ),
    "the pull log is in the tool's directory": (
        lambda tmp: None,
        lambda tmp: {"pull_log": tmp / "bin" / "runner" / "pulls.log"},
        ValueError,
        lambda tmp: (
            f"the pull log {tmp / 'bin' / 'runner' / 'pulls.log'} is inside the"
            f" directory of tools.runner {tmp / 'bin' / 'runner'}{_OVERLAP}"
        ),
    ),
    "the pull log is in the tool's directory through a link": (
        lambda tmp: ((tmp / "bin").mkdir(), (tmp / "link").symlink_to(tmp / "bin")),
        lambda tmp: {"pull_log": tmp / "link" / "runner" / "pulls.log"},
        ValueError,
        lambda tmp: (
            f"the pull log {tmp / 'link' / 'runner' / 'pulls.log'} is inside the"
            f" directory of tools.runner {tmp / 'bin' / 'runner'}{_OVERLAP}"
        ),
    ),
    "the pull log is the Jenkins directory": (
        lambda tmp: None,
        lambda tmp: {"pull_log": tmp / "jenkins"},
        ValueError,
        lambda tmp: (
            f"the Jenkins directory {tmp / 'jenkins'} is the same path as the pull log"
            f" {tmp / 'jenkins'}{_OVERLAP}"
        ),
    ),
    "the Jenkins directory is the tool's directory": (
        lambda tmp: None,
        lambda tmp: {"jenkins_dir": tmp / "bin" / "runner"},
        ValueError,
        lambda tmp: (
            f"the Jenkins directory {tmp / 'bin' / 'runner'} is the same path as the"
            f" directory of tools.runner {tmp / 'bin' / 'runner'}{_OVERLAP}"
        ),
    ),
    "the bin directory is the core's plugins directory": (
        lambda tmp: None,
        lambda tmp: {"bin_dir": tmp / "jenkins" / "plugins"},
        ValueError,
        lambda tmp: (
            f"the bin directory {tmp / 'jenkins' / 'plugins'} is the same path as the"
            f" plugins directory of jenkins.cores.lts {tmp / 'jenkins' / 'plugins'}"
            f"{_OVERLAP}"
        ),
    ),
}


@pytest.mark.unit
@pytest.mark.parametrize(
    "mistake",
    [
        pytest.param(
            name,
            marks=pytest.mark.skipif(sys.platform == "win32", reason="symbolic links"),
        )
        if "link" in name
        else name
        for name in sorted(PLACE_MISTAKES)
    ],
)
def test_a_place_the_leg_cannot_write_to_is_refused_before_anything_is_fetched(
    tmp_path, mistake
):
    """The bin directory, the Jenkins directory and the pull log are checked with the
    entries, before anything is created or fetched: each is a directory, or for the
    pull log a regular file, or can be created as one; and no place an entry or the
    pull log has to itself is the same as, or holds, another place the leg writes."""
    tables, files = _jenkins_leg(tmp_path)
    setup, change, kind, message = PLACE_MISTAKES[mistake]
    setup(tmp_path)
    fetched: list[str] = []
    calls: list[list[str]] = []
    install = _install_leg(tmp_path, tables, files, fetched, calls, **change(tmp_path))
    before = _tree(tmp_path)
    error = _raised(install)
    assert type(error) is kind and str(error) == message(tmp_path), repr(error)
    assert fetched == [] and calls == [], (fetched, calls)
    assert _tree(tmp_path) == before, sorted(_tree(tmp_path) ^ before)


#: Places that share a directory without any being another's or inside it.
SHARED_LAYOUTS = {
    "one directory for the tools and the core": lambda tmp: {
        "bin_dir": tmp / "shared",
        "jenkins_dir": tmp / "shared",
    },
    "the Jenkins directory in the bin directory": lambda tmp: {
        "jenkins_dir": tmp / "bin" / "jenkins"
    },
    "the pull log in the bin directory": lambda tmp: {
        "pull_log": tmp / "bin" / "pulls.log"
    },
    "the pull log in the Jenkins directory": lambda tmp: {
        "pull_log": tmp / "jenkins" / "pulls.log"
    },
}


@pytest.mark.unit
@pytest.mark.parametrize("layout", sorted(SHARED_LAYOUTS))
def test_places_that_share_a_directory_without_overlapping_are_installed(
    tmp_path, layout
):
    """Control for the test above: directories may be shared, and the pull log may sit
    beside an entry's place, so long as none is another's or inside it."""
    tables, files = _jenkins_leg(tmp_path)
    changes = SHARED_LAYOUTS[layout](tmp_path)
    fetched: list[str] = []
    calls: list[list[str]] = []
    _install_leg(tmp_path, tables, files, fetched, calls, **changes)()
    bin_dir = changes.get("bin_dir", tmp_path / "bin")
    jenkins_dir = changes.get("jenkins_dir", tmp_path / "jenkins")
    pull_log = changes.get("pull_log", tmp_path / "out" / "pulls.log")
    assert sorted(fetched) == sorted(files)
    assert calls == [["docker", "pull", REF]]
    assert (bin_dir / "runner" / tables[0]["executable"]).is_file()
    core_files = {
        path
        for path in _tree(jenkins_dir)
        if path == "jenkins.war" or path.split("/")[0] == "plugins"
    }
    assert core_files == _installed_jenkins()
    assert pull_log.read_text(encoding="utf-8").split() == [REF]


@pytest.mark.unit
@pytest.mark.parametrize("leg", JENKINS_LEGS)
def test_a_jenkins_dir_that_is_a_file_fails_the_install_before_anything_is_made(
    tmp_path, monkeypatch, capsys, leg
):
    """From the command line too: the real manifest and plugins files are checked, then
    the Jenkins directory, and the install exits 1 with neither the tool nor the pull
    log made, before any download."""
    main = _main_without_network(monkeypatch)
    jenkins = tmp_path / "jenkins"
    _a_file(jenkins)
    argv = _argv(tmp_path, leg, "--jenkins-dir", str(jenkins))
    assert main(argv, environ=ANYWHERE) == 1
    assert capsys.readouterr().err == (
        f"install_tools.py: the Jenkins directory {jenkins} exists and is not a"
        " directory\n"
    )
    assert _tree(tmp_path) == {"jenkins"}


@pytest.mark.unit
def test_a_directory_where_the_executable_should_be_is_refused(tmp_path):
    install_pins = _api("install_tools", "install_pins")
    integrity_error = _api("install_tools", "IntegrityError")
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    archive = _tar_entries(
        downloads / "act.tar.gz",
        [
            {"name": "act", "type": tarfile.DIRTYPE, "mode": 0o755},
            {"name": "act/inner", "data": b"x", "mode": 0o755},
        ],
    )
    entry = {
        "version": "1",
        "url": "https://example.invalid/1/act.tar.gz",
        "sha256": _sha256(archive),
        "executable": "act",
    }
    with pytest.raises(integrity_error, match="act"):
        install_pins(
            ["tools.act"],
            {"tools": {"act": entry}},
            manifest_dir=tmp_path,
            bin_dir=tmp_path / "bin",
            pull_log=tmp_path / "pulls.log",
            download=_fake_download({entry["url"]: archive}, []),
            run=_fake_run([]),
        )
    assert _tree(tmp_path / "bin") == set(), "the tool's directory is removed"


@pytest.mark.unit
def test_a_tool_download_has_a_neutral_name_until_it_is_checked(tmp_path):
    """Nothing is given its final name before its sha256 check: the download is kept
    under <bin-dir>/.download-*/<name>.download, not under its url's file name."""
    install_pins = _api("install_tools", "install_pins")
    path, entry = _downloads(tmp_path)["file"]
    targets: list[Path] = []

    def download(url, dest):
        targets.append(Path(dest))
        Path(dest).write_bytes(path.read_bytes())
        return Path(dest)

    install_pins(
        ["tools.file"],
        {"tools": {"file": dict(entry, executable="codebuild_build.sh")}},
        manifest_dir=tmp_path,
        bin_dir=tmp_path / "bin",
        pull_log=tmp_path / "pulls.log",
        download=download,
        run=_fake_run([]),
    )
    (target,) = targets
    assert target.name.endswith(".download") and target.name != "codebuild_build.sh"
    assert target.parent.parent == tmp_path / "bin"
    assert target.parent.name.startswith(".download-")
    assert (tmp_path / "bin" / "file" / "codebuild_build.sh").is_file()


@pytest.mark.unit
def test_a_malformed_pin_is_refused_before_the_tool_is_downloaded(tmp_path):
    install_pins = _api("install_tools", "install_pins")
    path, entry = _downloads(tmp_path)["tar"]
    fetched: list[str] = []
    with pytest.raises(ValueError, match="sha256"):
        install_pins(
            ["tools.tar"],
            {"tools": {"tar": dict(entry, sha256="abc", executable="act")}},
            manifest_dir=tmp_path,
            bin_dir=tmp_path / "bin",
            pull_log=tmp_path / "pulls.log",
            download=_fake_download({entry["url"]: path}, fetched),
            run=_fake_run([]),
        )
    assert fetched == []
    assert not (tmp_path / "bin" / "tar").exists()


def _flaky_download(path: Path, codes: list[int], attempts: list[str]):
    """Fails with each HTTP status in codes in turn, then serves path."""

    def download(url, dest):
        attempts.append(url)
        if len(attempts) <= len(codes):
            code = codes[len(attempts) - 1]
            raise urllib.error.HTTPError(
                url, code, "test", email.message.Message(), None
            )
        Path(dest).write_bytes(path.read_bytes())
        return Path(dest)

    return download


def _no_sleep(monkeypatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(
        _module("install_tools"), "time", types.SimpleNamespace(sleep=slept.append)
    )
    return slept


@pytest.mark.unit
@pytest.mark.parametrize("code", [408, 429, 500, 503])
def test_a_download_is_tried_again_after_a_timeout_a_throttle_or_a_server_error(
    tmp_path, monkeypatch, code
):
    install_pins = _api("install_tools", "install_pins")
    slept = _no_sleep(monkeypatch)
    path, entry = _downloads(tmp_path)["tar"]
    attempts: list[str] = []
    install_pins(
        ["tools.tar"],
        {"tools": {"tar": dict(entry, executable="act")}},
        manifest_dir=tmp_path,
        bin_dir=tmp_path / "bin",
        pull_log=tmp_path / "pulls.log",
        download=_flaky_download(path, [code], attempts),
        run=_fake_run([]),
    )
    assert len(attempts) == 2 and len(slept) == 1
    assert (tmp_path / "bin" / "tar" / "act").is_file()


@pytest.mark.unit
@pytest.mark.parametrize("code", [403, 404, 410])
def test_a_download_the_server_refuses_for_good_is_not_tried_again(
    tmp_path, monkeypatch, code
):
    install_pins = _api("install_tools", "install_pins")
    slept = _no_sleep(monkeypatch)
    path, entry = _downloads(tmp_path)["tar"]
    attempts: list[str] = []
    with pytest.raises(urllib.error.HTTPError):
        install_pins(
            ["tools.tar"],
            {"tools": {"tar": dict(entry, executable="act")}},
            manifest_dir=tmp_path,
            bin_dir=tmp_path / "bin",
            pull_log=tmp_path / "pulls.log",
            download=_flaky_download(path, [code], attempts),
            run=_fake_run([]),
        )
    assert len(attempts) == 1 and slept == []
    assert not (tmp_path / "bin" / "tar").exists()


@pytest.mark.unit
@pytest.mark.parametrize("code", [404, 503])
def test_each_message_about_a_failed_download_is_one_printable_line(
    tmp_path, monkeypatch, capsys, code
):
    """A reason phrase is the server's text. Each message main prints about the
    download, a notice of each retry included, is one line, with every character that
    is not printable written as its escape."""
    main = _api("install_tools", "main")
    module = _module("install_tools")
    _no_sleep(monkeypatch)
    url = module.load_toml(module.MANIFEST)["tools"]["act"]["url"]
    _serve(monkeypatch, {url: (code, {}, b"", "Not\x1b[2J Found\x07\x85\tnow")})
    argv = ["--runner", "act", "--bin-dir", str(tmp_path / "bin")]
    assert main(argv, environ=ANYWHERE) == 1
    printed = capsys.readouterr().err.split("\n")
    messages = module.DOWNLOAD_ATTEMPTS if code >= 500 else 1
    assert len(printed) == messages + 1 and printed[-1] == "", printed
    assert all(line.isprintable() for line in printed), printed
    assert all("Not\\x1b[2J Found\\x07\\x85\\tnow" in line for line in printed[:-1])


@pytest.mark.unit
def test_the_host_refusal_is_one_printable_line(tmp_path, capsys):
    main = _api("install_tools", "main")
    environ = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted\nsecond"}
    argv = ["--runner", "act", "--bin-dir", str(tmp_path / "bin")]
    assert main(argv, environ=environ) == 3
    printed = capsys.readouterr().err.split("\n")
    assert len(printed) == 2 and printed[1] == "", printed
    assert printed[0].isprintable() and "self-hosted\\nsecond" in printed[0], printed
    assert _tree(tmp_path) == set()


# ---------------------------------------------------------------------------
# The image allowlist
# ---------------------------------------------------------------------------

PYTHON = f"public.ecr.aws/docker/library/python@sha256:{DIGEST}"
CIMG = f"docker.io/cimg/python@sha256:{DIGEST}"
PICARD = f"circleci/picard@sha256:{OTHER_DIGEST}"
BUILT = "registry.example.com/security/automated-security-helper:ci"


def _manifest(tmp_path: Path) -> Path:
    path = tmp_path / "runners.toml"
    path.write_text(
        "\n".join(
            f'[images.{name}]\nref = "{ref}"\nlicense = "unknown"\nsource = "test"\n'
            for name, ref in (("python", PYTHON), ("cimg", CIMG), ("picard", PICARD))
        ),
        encoding="utf-8",
    )
    return path


def _event(ref: str, action: str = "pull") -> str:
    name = ref.split("@", 1)[0]
    return json.dumps(
        {
            "Type": "image",
            "Action": action,
            "Actor": {"ID": ref, "Attributes": {"name": name}},
            "scope": "local",
            "time": 1767225600,
            "timeNano": 1767225600000000000,
        }
    )


def _files(tmp_path: Path, events: list[str] | None, pulls: list[str]):
    events_path = tmp_path / "docker-events.jsonl"
    if events is not None:
        events_path.write_text("".join(e + "\n" for e in events), encoding="utf-8")
    pulls_path = tmp_path / "pulls.txt"
    pulls_path.write_text("".join(p + "\n" for p in pulls), encoding="utf-8")
    return events_path, pulls_path


def _problems(tmp_path, events, pulls, built=()):
    check = _api("image_allowlist", "image_allowlist_problems")
    events_path, pulls_path = _files(tmp_path, events, pulls)
    return check(events_path, pulls_path, _manifest(tmp_path), built=built)


@pytest.mark.unit
def test_pulls_of_listed_digests_and_built_images_pass(tmp_path):
    problems = _problems(
        tmp_path,
        [_event(PYTHON), _event(PICARD), _event(BUILT), _event(BUILT, "tag")],
        [PYTHON, PICARD],
        built=[BUILT],
    )
    assert problems == []


@pytest.mark.unit
def test_a_docker_hub_image_matches_in_its_short_and_its_full_form(tmp_path):
    short_cimg = f"cimg/python@sha256:{DIGEST}"
    full_picard = f"docker.io/circleci/picard@sha256:{OTHER_DIGEST}"
    assert _problems(tmp_path, [_event(short_cimg), _event(full_picard)], []) == []


def _problems_with(tmp_path, refs, events, pulls=()):
    """The allowlist's problems against a manifest listing exactly refs."""
    check = _api("image_allowlist", "image_allowlist_problems")
    manifest = tmp_path / "listed.toml"
    manifest.write_text(
        "".join(
            f'[images.i{n}]\nref = "{ref}"\nlicense = "unknown"\nsource = "test"\n'
            for n, ref in enumerate(refs)
        ),
        encoding="utf-8",
    )
    events_path, pulls_path = _files(tmp_path, events, list(pulls))
    return check(events_path, pulls_path, manifest)


@pytest.mark.unit
@pytest.mark.parametrize(
    "pulled",
    [
        f"python@sha256:{DIGEST}",
        f"library/python@sha256:{DIGEST}",
        f"docker.io/python@sha256:{DIGEST}",
        f"docker.io/library/python@sha256:{DIGEST}",
        f"index.docker.io/library/python@sha256:{DIGEST}",
        f"registry-1.docker.io/python@sha256:{DIGEST}",
    ],
)
def test_a_docker_hub_official_image_matches_in_every_spelling(tmp_path, pulled):
    listed = [f"docker.io/library/python@sha256:{DIGEST}"]
    assert _problems_with(tmp_path, listed, [_event(pulled)]) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "pulled",
    [
        f"index.docker.io/cimg/python@sha256:{DIGEST}",
        f"registry-1.docker.io/cimg/python@sha256:{DIGEST}",
    ],
)
def test_docker_hub_s_other_registry_names_are_docker_hub(tmp_path, pulled):
    assert _problems_with(tmp_path, [CIMG], [_event(pulled)]) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "pulled",
    [
        f"quay.io/cimg/python@sha256:{DIGEST}",
        f"docker.io/library/cimg/python@sha256:{DIGEST}",
        f"python/python@sha256:{DIGEST}",
    ],
)
def test_the_same_name_on_another_registry_or_path_is_not_listed(tmp_path, pulled):
    """Control for the spellings above: the mapping adds docker.io and library/ only
    where Docker would."""
    listed = [CIMG, f"docker.io/library/python@sha256:{DIGEST}"]
    problems = _problems_with(tmp_path, listed, [_event(pulled)])
    assert any(pulled in p for p in problems), problems


def _legacy_event(ref: str, status: str = "pull") -> str:
    """The older event shape: the reference in id and the action in status."""
    return json.dumps(
        {"status": status, "id": ref, "from": ref.split("@", 1)[0], "time": 1767225600}
    )


@pytest.mark.unit
def test_a_legacy_event_s_id_and_status_are_read(tmp_path):
    problems = _problems(
        tmp_path,
        [
            _legacy_event(PYTHON),
            _legacy_event("python:3.12"),
            _legacy_event(CIMG, "tag"),
        ],
        [PYTHON],
    )
    assert len(problems) == 1 and "python:3.12" in problems[0], problems


@pytest.mark.unit
def test_tag_events_and_events_of_other_types_are_not_pulls(tmp_path):
    unlisted = f"docker.io/library/ruby@sha256:{DIGEST}"
    others = [
        _event(unlisted, "tag"),
        _event(unlisted, "delete"),
        json.dumps({"Type": "container", "Action": "pull", "Actor": {"ID": unlisted}}),
        json.dumps({"Type": "network", "Action": "pull", "Actor": {"ID": unlisted}}),
    ]
    assert _problems(tmp_path, [_event(PYTHON), *others], [PYTHON]) == []
    # Control: the same reference in an image pull event is a problem.
    problems = _problems(tmp_path, [_event(PYTHON), _event(unlisted)], [PYTHON])
    assert any(unlisted in p for p in problems), problems


@pytest.mark.unit
@pytest.mark.parametrize(
    "ref",
    [
        "python:3.12",
        "public.ecr.aws/docker/library/python:3.12",
        f"public.ecr.aws/docker/library/python@sha256:{OTHER_DIGEST}",
        f"docker.io/library/ruby@sha256:{DIGEST}",
    ],
    ids=["tag", "tag on ecr", "unlisted digest", "unlisted image"],
)
def test_a_pull_of_anything_else_fails(tmp_path, ref):
    problems = _problems(tmp_path, [_event(PYTHON), _event(ref)], [PYTHON])
    assert any(ref in problem for problem in problems), problems


@pytest.mark.unit
def test_a_missing_events_file_fails(tmp_path):
    problems = _problems(tmp_path, None, [])
    assert problems and any("docker-events.jsonl" in p for p in problems), problems


@pytest.mark.unit
def test_a_missing_pull_log_fails(tmp_path):
    """Without install_tools.py's pull log, the check that the recording covered the
    installs cannot run, so it is a failure, not an empty log."""
    check = _api("image_allowlist", "image_allowlist_problems")
    events_path, pulls_path = _files(tmp_path, [_event(PYTHON)], [])
    pulls_path.unlink()
    problems = check(events_path, pulls_path, _manifest(tmp_path))
    assert any("pulls.txt" in p for p in problems), problems


@pytest.mark.unit
def test_an_events_file_that_missed_the_installs_pulls_fails(tmp_path):
    """Empty, as a recording started after the installs would be."""
    problems = _problems(tmp_path, [], [PYTHON, PICARD])
    assert any(PYTHON in p for p in problems) and any(PICARD in p for p in problems), (
        problems
    )


@pytest.mark.unit
def test_an_events_line_that_is_not_json_fails(tmp_path):
    problems = _problems(tmp_path, [_event(PYTHON), "not json"], [PYTHON])
    assert any("line 2" in p for p in problems), problems


@pytest.mark.integration
def test_the_allowlist_check_runs_standalone_and_fails_the_step(tmp_path):
    script = _script("image_allowlist")
    events_path, pulls_path = _files(tmp_path, [_event("python:3.12")], [])
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    args = ["--events", str(events_path), "--pulls", str(pulls_path)]
    args += ["--manifest", str(_manifest(tmp_path))]
    refused = _run_isolated(script, args, env)
    assert refused.returncode != 0 and "python:3.12" in refused.stdout + refused.stderr
    events_path.write_text(_event(PYTHON) + "\n", encoding="utf-8")
    passed = _run_isolated(script, [*args, "--built", BUILT], env)
    assert passed.returncode == 0, passed.stdout + passed.stderr
