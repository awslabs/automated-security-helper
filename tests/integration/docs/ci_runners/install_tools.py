# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Install the pinned runners, Jenkins cores and images one Docs CI Runners leg needs.

WHY THIS EXISTS
---------------
The Docs CI Runners workflow runs the CI pages' pipelines with each CI system's own
local runner. Every tool, Jenkins WAR, Jenkins plugin and image those runners use is
pinned in runners.toml beside this file and in the plugin files it names. This script
is the one place that fetches them: each download is https only, at every redirect and
on every Python version it runs on; its sha256 is checked against the pin before
anything is unpacked or given its final name; and images are pulled only by digest.
Nothing is looked up at run time: no plugin, dependency or core
is resolved by name, so a pinned file that changed upstream fails the install instead
of being used.

Usage::

    python3 -I tests/integration/docs/ci_runners/install_tools.py \\
        --runner <leg> --bin-dir <dir> --pull-log <file> [--jenkins-dir <dir>]

What it installs, for the leg's pins in RUNNER_PINS:

* each tool under <bin-dir>/<name>/, with its archive's layout and execute bits (a
  file that is not an archive keeps its file name, and a ``.sh`` is executable); the
  manifest's ``executable`` must then be a regular file there, and it is made
  executable, since an archive can store its launcher without an execute bit;
* a Jenkins core as <jenkins-dir>/jenkins.war, and its plugin closure as
  <jenkins-dir>/plugins/<name>.hpi; the Jenkins legs need --jenkins-dir and the other
  legs refuse it;
* each image with ``docker pull <name>@sha256:<digest>``, appending the reference to
  the pull log, which the image allowlist check compares with the docker events
  recorded during the job. The log is created even when the leg pulls nothing.

Every entry the leg uses is checked before anything is created or downloaded: its
table in runners.toml, a Jenkins core's plugins file, and that the directory it goes
into holds nothing yet. So is the call as a whole: each key is of a known kind and
listed once, there is at most one Jenkins core, the bin and Jenkins directories are
directories and the pull log a regular file (or each can be created as one), and no
tool's directory, core file or pull log is the same path as another place the install
writes, or holds one. A mistake in any of them leaves nothing behind, not even the
pull log.

It prints one line per installed item. Each refusal and failure message it prints,
a retry notice included, is one line of printable text: a character that is not
printable, such as one in a server's reason phrase, is written as its escape.
argparse's usage message and what docker pull writes to stderr pass through as they
are. Nothing is written to GITHUB_PATH: the runners' launch environment builds PATH
itself.

It refuses to run anywhere but a GitHub-hosted runner unless
DOCTEST_CI_RUNNERS_ANYWHERE=1, because the runners it installs start containers that
mount the Docker socket. Usage errors are reported first; the host check comes before
anything is created.

Exit codes:

* 0 when everything the leg needs is installed;
* 1 when a download, an install or a pull failed (a download refused for leaving
  https, and a pull that runs past PULL_TIMEOUT_SECONDS, included), or the manifest
  is wrong (a missing entry, a path with ``..``, a url that is not https, a pin that
  is not 64 lowercase hex, a plugin listed twice, or an image not named by digest),
  or the keys are wrong (one of another kind, one listed twice, or a second Jenkins
  core), or an install directory is taken already, the bin or Jenkins directory or
  the pull log is of another kind or cannot be created, or two places overlap;
* 2 for a usage error;
* 3 when the host is not a GitHub-hosted runner;
* 4 when a download does not match its pin, an archive member is not a regular file
  or a directory, a member or plugin name would land outside its directory, or a
  tool's archive does not hold its ``executable`` as a regular file.

A download is retried after a connection error, a server error (5xx), a request
timeout (408) or a throttle (429); any other HTTP error is final, and so is a download
refused for leaving https.

It runs as ``python3 -I`` on Python 3.10 and later and imports nothing from the files
beside it. On Python 3.11 and later it uses the standard library only, reading TOML
with tomllib; 3.10 has no tomllib, so there it imports tomli, which must be installed
for that Python.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import re
import shutil
import stat
import string
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import quote, urljoin, urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

MANIFEST = Path(__file__).resolve().parent / "runners.toml"

#: The manifest entries each leg uses: ``tools.<name>``, ``images.<name>`` and
#: ``jenkins.cores.<core>`` keys of runners.toml, installed in this order.
RUNNER_PINS: dict[str, tuple[str, ...]] = {
    "act": ("tools.act",),
    "gitlab-ci-local": (
        "tools.gitlab-ci-local",
        "images.python-3-12",
        "images.python-3-12-slim-bookworm",
        "images.debian-bookworm-slim",
    ),
    "jenkinsfile-runner-lts": ("tools.jenkinsfile-runner", "jenkins.cores.lts"),
    "jenkinsfile-runner-bundled": (
        "tools.jenkinsfile-runner",
        "jenkins.cores.bundled",
    ),
    "codebuild-agent": (
        "tools.codebuild-build-sh",
        "images.codebuild-local-agent",
        "images.codebuild-standard-5",
    ),
    "circleci": (
        "tools.circleci-cli-local-execute",
        "tools.circleci-cli",
        "images.cimg-python-3-12-node",
        "images.circleci-picard",
    ),
}
JENKINS_LEGS = frozenset(
    leg
    for leg, keys in RUNNER_PINS.items()
    if any(key.startswith("jenkins.cores.") for key in keys)
)

OVERRIDE = "DOCTEST_CI_RUNNERS_ANYWHERE"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_HOST = 3
EXIT_INTEGRITY = 4

SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_HOST = (
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?::[0-9]+)?"
)
_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
#: <registry host>/<path>@sha256:<digest>, or a Docker Hub <path>@sha256:<digest>. No
#: tag, digest or not, and no component that could start an option.
DIGEST_REF = re.compile(
    rf"(?:{_HOST}/)?{_COMPONENT}(?:/{_COMPONENT})*@sha256:[0-9a-f]{{64}}"
)
#: A file, directory or plugin name that stays where it is put.
PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
TAR_SUFFIXES = (".tar.gz", ".tgz")

CHUNK = 1 << 20
DOWNLOAD_TIMEOUT = 120
DOWNLOAD_ATTEMPTS = 3
#: HTTP errors that are tried again, besides 5xx: request timeout and throttling.
RETRIED_STATUSES = frozenset({408, 429})
#: A docker pull that takes longer is a failure. The largest pinned image is about
#: 6.3 GB compressed, so this leaves several times its expected pull time. In the
#: Docs CI Runners workflow a stalled pull is ended by whichever runs out first: the
#: install step's timeout-minutes, counted from the step's start, or this limit,
#: counted from the pull's start. Outside that step only this limit applies.
PULL_TIMEOUT_SECONDS = 20 * 60
#: A docker pull that exits non-zero is tried this many times in all, waiting
#: PULL_RETRY_SECONDS times the attempt number after each failure.
PULL_ATTEMPTS = 3
PULL_RETRY_SECONDS = 60
#: A download larger than this is refused and removed. The largest pinned download,
#: the 2.375.4 Jenkins WAR, is about 94 MB, so this leaves room for a later pin and
#: still bounds what one download can write to the runner's disk.
MAX_DOWNLOAD_BYTES = 1 << 30
USER_AGENT = "automated-security-helper-docs-ci-runners"


class IntegrityError(Exception):
    """A download that does not match its pin; an archive member that is not a regular
    file or a directory, or whose name would land outside its directory; a plugin name
    that is not a plain file name; or a tool whose archive does not hold its executable
    as a regular file. A pin that is not 64 lowercase hex is a manifest mistake, and a
    ValueError."""


class NotHttpsError(ValueError):
    """A download refused because it would leave https: its url is not https, or a
    redirect at some hop leads to a url that is not, or the response was served from
    one. The same type and, for a redirect, the same message on every Python version."""


def _one_line(message: object) -> str:
    """message as it is printed: each character that is not printable, a line break or
    an escape character say, is written as its Python escape, so a message that quotes
    what a server sent, such as an HTTP reason phrase, stays one line of text."""
    return "".join(
        char if char.isprintable() else repr(char)[1:-1] for char in str(message)
    )


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


def _sha256_of_stream(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(CHUNK), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _copy_hashed(source: Path, target: Path) -> str:
    """Copy source to target, a new file, and return the sha256 of the bytes written,
    so the bytes checked are the bytes installed."""
    digest = hashlib.sha256()
    with source.open("rb") as reader, target.open("xb") as writer:
        for chunk in iter(lambda: reader.read(CHUNK), b""):
            digest.update(chunk)
            writer.write(chunk)
    return digest.hexdigest()


def _require_pin(what: str, pinned: object) -> str:
    """The pinned sha256, or ValueError: a malformed pin is a mistake in the manifest,
    found before anything is downloaded or read."""
    if not (isinstance(pinned, str) and SHA256_HEX.fullmatch(pinned)):
        raise ValueError(
            f"{what}: the pinned sha256 {pinned!r} is not 64 lowercase hex"
        )
    return pinned


def _check(what: str, pinned: object, actual: str) -> None:
    pinned = _require_pin(what, pinned)
    if actual != pinned:
        raise IntegrityError(
            f"{what}: its sha256 is {actual}, not the pinned {pinned}; refusing it"
        )


# ---------------------------------------------------------------------------
# One verified download into a directory
# ---------------------------------------------------------------------------


def _plain_relative(value: object) -> bool:
    """A relative POSIX path written plainly: no leading /, no . or .. or empty
    segment, no backslash."""
    if not (isinstance(value, str) and value) or "\\" in value:
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def _url_file_name(url: object) -> str:
    name = PurePosixPath(urlsplit(url).path).name if isinstance(url, str) else ""
    if not PLAIN_NAME.fullmatch(name):
        raise ValueError(f"{url!r}: its file name {name!r} is not a plain file name")
    return name


def _require_https(url: object) -> None:
    """NotHttpsError unless url is an https url that names a host."""
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme != "https" or not parts.hostname:
        raise NotHttpsError(f"refusing {url!r}: downloads are https only")


def _member_parts(name: str, label: str) -> tuple[str, ...]:
    """The path of an archive member under the destination, refusing anything that
    would land outside it. The empty tuple is the archive's root directory."""
    if (
        name.startswith("/")
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or ".." in name.split("/")
    ):
        raise IntegrityError(
            f"{label}: member {name!r} would land outside the install directory"
        )
    return tuple(part for part in name.split("/") if part not in ("", "."))


def _inside(target: Path, root: Path) -> bool:
    root = root.resolve()
    resolved = target.resolve()
    return resolved == root or root in resolved.parents


def _write_new(target: Path, source: BinaryIO, *, executable: bool) -> None:
    # "x": a new file only, so nothing is written through an existing file or link.
    with target.open("xb") as writer:
        shutil.copyfileobj(source, writer, CHUNK)
    target.chmod(0o755 if executable else 0o644)


def _place(
    dest_dir: Path,
    label: str,
    members: list[tuple[tuple[str, ...], bool, bool, Callable[[], BinaryIO]]],
) -> list[Path]:
    """Create the checked members, (parts, is_dir, executable, opener), under dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    installed = []
    for parts, is_dir, executable, opener in members:
        if not parts:
            continue
        target = dest_dir.joinpath(*parts)
        if not _inside(target, dest_dir):
            raise IntegrityError(
                f"{label}: {'/'.join(parts)} resolves outside {dest_dir}"
            )
        if is_dir:
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with opener() as source:
            _write_new(target, source, executable=executable)
        installed.append(target)
    return installed


def _install_tar(handle: BinaryIO, dest_dir: Path, label: str) -> list[Path]:
    with tarfile.open(fileobj=handle, mode="r:gz") as archive:
        members = []
        for member in archive.getmembers():
            parts = _member_parts(member.name, label)
            if not (member.isfile() or member.isdir()):
                raise IntegrityError(
                    f"{label}: member {member.name!r} is not a regular file or a"
                    " directory, and only those are installed"
                )

            def opener(member=member) -> BinaryIO:
                source = archive.extractfile(member)
                if source is None:
                    raise IntegrityError(f"{label}: member {member.name!r} has no data")
                return source

            members.append((parts, member.isdir(), bool(member.mode & 0o111), opener))
        return _place(dest_dir, label, members)


def _install_zip(handle: BinaryIO, dest_dir: Path, label: str) -> list[Path]:
    with zipfile.ZipFile(handle) as archive:
        members = []
        for info in archive.infolist():
            parts = _member_parts(info.filename, label)
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind and kind not in (stat.S_IFREG, stat.S_IFDIR):
                raise IntegrityError(
                    f"{label}: member {info.filename!r} is not a regular file or a"
                    " directory, and only those are installed"
                )

            def opener(info=info) -> BinaryIO:
                return archive.open(info)

            members.append((parts, info.is_dir(), bool(mode & 0o111), opener))
        return _place(dest_dir, label, members)


def install_tool(entry: Mapping, downloaded: Path, dest_dir: Path) -> list[Path]:
    """Check a downloaded tool against its manifest entry, then install it in dest_dir.

    The sha256 is checked before anything is created, so a mismatch leaves nothing. A
    ``.tar.gz``/``.tgz`` or ``.zip`` (by the url's file name) is unpacked with its
    layout and execute bits, refusing members that would land outside dest_dir and
    anything but regular files and directories; any other file is copied under its url
    file name, executable when it is a ``.sh``. Returns the files installed.
    """
    name = _url_file_name(entry.get("url"))
    _require_pin(name, entry.get("sha256"))
    downloaded, dest_dir = Path(downloaded), Path(dest_dir)
    with downloaded.open("rb") as handle:
        _check(name, entry.get("sha256"), _sha256_of_stream(handle))
        handle.seek(0)
        if name.endswith(TAR_SUFFIXES):
            return _install_tar(handle, dest_dir, name)
        if name.endswith(".zip"):
            return _install_zip(handle, dest_dir, name)
        dest_dir.mkdir(parents=True, exist_ok=True)
        target = dest_dir / name
        _write_new(target, handle, executable=name.endswith(".sh"))
        return [target]


# ---------------------------------------------------------------------------
# Jenkins cores
# ---------------------------------------------------------------------------


def _plugin_names(plugins: Sequence[Mapping], where: object) -> list[str]:
    """The plugins' names. Each must be a plain file name, so plugins/<name>.hpi stays
    in the plugins directory (else IntegrityError), and listed once (else ValueError)."""
    names: list[str] = []
    for plugin in plugins:
        name = plugin.get("name")
        if not (isinstance(name, str) and PLAIN_NAME.fullmatch(name)):
            raise IntegrityError(
                f"{where}: plugin name {name!r} is not a plain file name, so"
                " plugins/<name>.hpi would not stay in the plugins directory"
            )
        if name in names:
            raise ValueError(f"{where}: plugin {name} is listed twice")
        names.append(name)
    return names


def _refuse_earlier_core(dest: Path) -> None:
    """FileExistsError when dest holds a Jenkins core already."""
    for path in (dest / "jenkins.war", dest / "plugins"):
        if path.exists() or path.is_symlink():
            raise FileExistsError(
                f"{path} exists already; a Jenkins core is installed into a directory"
                " that holds no earlier core"
            )


def install_jenkins_core(
    core: Mapping,
    plugins: Sequence[Mapping],
    *,
    war: Path,
    hpis: Mapping[str, Path],
    dest: Path,
) -> Path:
    """Install a Jenkins core's WAR and its plugin closure into dest.

    ``war`` and ``hpis`` (plugin name to file) are the downloaded files; they are
    copied, not moved. Each copy is hashed as it is written into a staging directory
    inside dest, and only when the WAR and every plugin match their pins do they get
    their final names, dest/jenkins.war and dest/plugins/<name>.hpi. A mismatch raises
    IntegrityError naming the pinned and the actual sha256 and leaves neither the WAR
    nor any plugin. Returns dest/jenkins.war.
    """
    dest = Path(dest)
    names = _plugin_names(plugins, dest / "plugins")
    if set(hpis) != set(names):
        raise ValueError(
            f"the downloaded plugins {sorted(hpis)} are not the plugins {sorted(names)}"
        )
    _require_pin(f"Jenkins {core.get('core_version')} WAR", core.get("war_sha256"))
    for plugin in plugins:
        _require_pin(f"plugin {plugin['name']}", plugin.get("sha256"))
    _refuse_earlier_core(dest)
    final_war, final_plugins = dest / "jenkins.war", dest / "plugins"
    dest.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=dest))
    try:
        staged_war = staging / "jenkins.war"
        _check(
            f"Jenkins {core.get('core_version')} WAR {core.get('war_url')}",
            core.get("war_sha256"),
            _copy_hashed(Path(war), staged_war),
        )
        staged_plugins = staging / "plugins"
        staged_plugins.mkdir()
        for plugin in plugins:
            name = plugin["name"]
            _check(
                f"plugin {name} {plugin.get('version')} {plugin.get('url')}",
                plugin.get("sha256"),
                _copy_hashed(Path(hpis[name]), staged_plugins / f"{name}.hpi"),
            )
        os.replace(staged_plugins, final_plugins)
        try:
            os.replace(staged_war, final_war)
        except BaseException:
            shutil.rmtree(final_plugins, ignore_errors=True)
            raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return final_war


# ---------------------------------------------------------------------------
# Network: https downloads, images by digest
# ---------------------------------------------------------------------------


def _not_https(url: str, target: str) -> NotHttpsError:
    """The refusal for a download of url that led to target, a url that is not https.
    Every such case gets this one message, whichever hop and Python version found it.

    target is the server's text, so the message shows it percent-encoded as urllib
    encodes a Location before it follows one: a header's line break becomes %0D%0A,
    an escape character %1B, and each byte past ASCII its own %XX. The message is one
    line of printable text whatever the server sent.
    """
    shown = quote(
        target,
        safe=string.punctuation,
        encoding="iso-8859-1",
        # http.client decodes headers as ISO-8859-1, so only a caller can pass a
        # character past U+00FF; it is shown as its escape rather than raising.
        errors="backslashreplace",
    )
    return NotHttpsError(
        f"refusing the download of {url}: it redirects to {shown}, and downloads are"
        " https only"
    )


def _redirect_target(base: str, code: object, headers: object) -> str | None:
    """The absolute url a 3xx response points to, read as urllib reads it (Location,
    else URI, relative to base), or None for a response that is not a 3xx or names no
    target."""
    if not (isinstance(code, int) and 300 <= code < 400) or headers is None:
        return None
    for name in ("location", "uri"):
        if name in headers:
            return urljoin(base, headers[name])
    return None


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """urllib's redirect handling, held to https and the same on every Python version.

    A redirect whose target is not https is refused before urllib's own checks of it
    and before the target is asked. A 308 is followed the way a 307 is: Python 3.10's
    handler has no http_error_308 and its redirect_request turns a 308 away, while 3.11
    and later follow a 308 exactly as they follow a 307, keeping the method.
    """

    def __init__(self, origin: str):
        self.origin = origin

    def http_error_302(self, req, fp, code, msg, headers):
        target = _redirect_target(req.full_url, code, headers)
        if target is not None and urlsplit(target).scheme != "https":
            if fp is not None:
                fp.close()
            raise _not_https(self.origin, target)
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise _not_https(self.origin, newurl)
        if code == 308:
            code = 307
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_https(url: str):
    """The response to a GET of url, an https url, after its https redirects.

    urllib hands back as an HTTP error each 3xx code it does not follow, and Python
    3.10's urllib does so for a 308 unless a handler takes it; one whose target is not
    https gets the same refusal as a redirect the handler turned away. So does a
    response that reports it was served from a url that is not https.
    """
    opener = urllib.request.build_opener(_HttpsOnlyRedirects(url))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        response = opener.open(request, timeout=DOWNLOAD_TIMEOUT)
    except urllib.error.HTTPError as error:
        base = error.filename if isinstance(error.filename, str) else url
        target = _redirect_target(base, error.code, error.hdrs)
        if target is None or urlsplit(target).scheme == "https":
            raise
        error.close()
        raise _not_https(url, target) from None
    final = response.geturl()
    if urlsplit(final).scheme != "https":
        response.close()
        raise _not_https(url, final)
    return response


def download_file(url: str, dest: Path) -> Path:
    """Download an https url, following only https redirects, into dest, a new file.

    A url that is not https is refused before any connection. A redirect to a url that
    is not https, at any hop and by any 3xx code, is refused before that url is asked,
    and a response served from one is refused too, with one refusal naming url and
    where it led, on every Python version. A 308 to https is followed on all of them.
    On any failure dest is removed.
    """
    _require_https(url)
    dest = Path(dest)
    created = False
    try:
        with _open_https(url) as response:
            with dest.open("xb") as writer:
                created = True
                written = 0
                for chunk in iter(lambda: response.read(CHUNK), b""):
                    written += len(chunk)
                    if written > MAX_DOWNLOAD_BYTES:
                        raise ValueError(
                            f"{url} is larger than {MAX_DOWNLOAD_BYTES} bytes; refusing it"
                        )
                    writer.write(chunk)
    except BaseException:
        if created:
            dest.unlink()
        raise
    return dest


def _fetch(download: Callable[[str, Path], Path], url: str, dest: Path) -> Path:
    """download(url, dest), tried again after a connection error, a server error, a
    request timeout or a throttle."""
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            return Path(download(url, dest))
        except (OSError, http.client.HTTPException) as error:
            permanent = (
                isinstance(error, urllib.error.HTTPError)
                and error.code < 500
                and error.code not in RETRIED_STATUSES
            )
            if permanent or isinstance(error, FileExistsError):
                raise
            if attempt == DOWNLOAD_ATTEMPTS:
                raise
            print(
                _one_line(f"download of {url} failed ({error}); trying again"),
                file=sys.stderr,
                flush=True,
            )
            time.sleep(5 * attempt)
    raise AssertionError("unreachable")


def docker_pull_argv(ref: str) -> list[str]:
    """``docker pull <ref>`` for a <name>@sha256:<digest> reference, else ValueError."""
    if not (isinstance(ref, str) and DIGEST_REF.fullmatch(ref)):
        raise ValueError(
            f"refusing to pull {ref!r}: an image is pulled only as"
            " <name>@sha256:<64 lowercase hex>, with no tag"
        )
    return ["docker", "pull", ref]


def pull_image(
    ref: str, *, pull_log: Path, run: Callable[..., object] = subprocess.run
) -> None:
    """Pull an image by digest with run, then append its reference to pull_log. A bad
    reference raises ValueError before run is called; a pull that fails or runs past
    PULL_TIMEOUT_SECONDS raises, and in each case the log is unchanged."""
    argv = docker_pull_argv(ref)
    for attempt in range(1, PULL_ATTEMPTS + 1):
        try:
            run(
                argv,
                check=True,
                stdout=subprocess.DEVNULL,
                timeout=PULL_TIMEOUT_SECONDS,
            )
            break
        except subprocess.CalledProcessError as error:
            # ECR Public answers "toomanyrequests: Data limit exceeded" when the
            # runner's address has used its anonymous pull allowance, and that
            # clears with time. The job holds no AWS credential to pull with an
            # allowance of its own, so the same pull is tried again after a wait.
            # A pull that timed out is not tried again: it already used its limit.
            if attempt == PULL_ATTEMPTS:
                raise
            print(
                _one_line(
                    f"pull of {ref} failed (exit {error.returncode}); "
                    f"trying again in {PULL_RETRY_SECONDS * attempt} seconds"
                ),
                file=sys.stderr,
                flush=True,
            )
            time.sleep(PULL_RETRY_SECONDS * attempt)
    with Path(pull_log).open("a", encoding="utf-8") as log:
        log.write(ref + "\n")


# ---------------------------------------------------------------------------
# Only on a GitHub-hosted runner
# ---------------------------------------------------------------------------


def runner_environment_problem(environ: Mapping[str, str]) -> str | None:
    """None on a GitHub-hosted runner outside act, or with DOCTEST_CI_RUNNERS_ANYWHERE=1;
    otherwise why not, and how to override it."""
    if environ.get(OVERRIDE) == "1":
        return None
    hosted = (
        environ.get("GITHUB_ACTIONS") == "true"
        and environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    )
    if hosted and "ACT" not in environ:
        return None
    found = ", ".join(
        f"{name}={environ[name]}" if name in environ else f"{name} unset"
        for name in ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "ACT", OVERRIDE)
    )
    return (
        "install_tools.py runs only on a GitHub-hosted runner (GITHUB_ACTIONS=true,"
        " RUNNER_ENVIRONMENT=github-hosted, ACT unset), because the runners it installs"
        f" start containers that mount the Docker socket; found {found}. Set"
        f" {OVERRIDE}=1 to run it anyway."
    )


# ---------------------------------------------------------------------------
# The leg's pins
# ---------------------------------------------------------------------------


def load_toml(path: Path) -> dict:
    with Path(path).open("rb") as handle:
        return tomllib.load(handle)


def _entry(manifest: Mapping, key: str) -> Mapping:
    node: object = manifest
    for part in key.split("."):
        if not isinstance(node, Mapping) or part not in node:
            raise ValueError(f"runners.toml has no [{key}]")
        node = node[part]
    if not isinstance(node, Mapping):
        raise ValueError(f"runners.toml's {key} is not a table")
    return node


def _require_usable(path: Path, role: str, *, directory: bool) -> None:
    """Refuse path, a place the install writes to, unless it is a directory already
    (for directory=False, a regular file), or is nothing yet and the nearest of its
    parents that exists is a directory, so it can be created. NotADirectoryError when
    a directory is needed and something else is there, or a parent is not one;
    FileExistsError when a regular file is needed and something else is there."""
    if path.exists() or path.is_symlink():
        if directory and not path.is_dir():
            raise NotADirectoryError(f"the {role} {path} exists and is not a directory")
        if not directory and not path.is_file():
            raise FileExistsError(f"the {role} {path} exists and is not a regular file")
        return
    for parent in path.parents:
        if parent.is_dir():
            return
        if parent.exists() or parent.is_symlink():
            raise NotADirectoryError(
                f"the {role} {path} cannot be created: {parent} is not a directory"
            )


def _check_keys(keys: Sequence[str]) -> None:
    """ValueError for a key listed twice, or for more than one Jenkins core: every
    core is the Jenkins directory's jenkins.war and plugins/."""
    seen: set[str] = set()
    for key in keys:
        if key in seen:
            raise ValueError(f"{key} is listed twice")
        seen.add(key)
    cores = [key for key in keys if key.startswith("jenkins.cores.")]
    if len(cores) > 1:
        raise ValueError(
            f"{', '.join(cores)}: one install takes one Jenkins core at most, since a"
            " core is the Jenkins directory's jenkins.war and plugins/"
        )


def _refuse_overlaps(needed: Mapping[str, Path], owned: Mapping[str, Path]) -> None:
    """ValueError when a place the install writes is the same path as a place another
    role owns, or lies inside it. ``owned`` maps each role to the place that is its
    alone: a tool's directory, a core's WAR and plugins directory, the pull log.
    ``needed`` maps a role to a directory the install puts owned places in, the bin
    and the Jenkins directories, which may hold each other and any owned place but
    may not be one or lie inside one."""
    places = {role: path.resolve() for role, path in owned.items()}
    for role, path in [*needed.items(), *owned.items()]:
        resolved = path.resolve()
        for other, place in places.items():
            if other == role:
                continue
            if resolved == place:
                relation = "is the same path as"
            elif place in resolved.parents:
                relation = "is inside"
            else:
                continue
            raise ValueError(
                f"the {role} {path} {relation} the {other} {owned[other]}; refusing an"
                " install whose places overlap"
            )


def _check_tool(key: str, entry: Mapping, bin_dir: Path) -> Path:
    """<bin-dir>/<name>, the directory tool ``key`` goes into, once its entry passes
    every check that needs no download: a plain name, a plain relative executable, an
    https url that ends in a plain file name, a pin of 64 lowercase hex, a bin
    directory that is one or can be created, and nothing at that path yet."""
    name = key.split(".", 1)[1]
    executable = entry.get("executable")
    if not PLAIN_NAME.fullmatch(name):
        raise ValueError(f"{key}: {name!r} is not a plain directory name")
    if not _plain_relative(executable):
        raise ValueError(
            f"{key}: executable {executable!r} is not a relative POSIX path without .."
        )
    _url_file_name(entry.get("url"))
    _require_https(entry.get("url"))
    _require_pin(key, entry.get("sha256"))
    _require_usable(bin_dir, "bin directory", directory=True)
    dest = bin_dir / name
    if dest.exists() or dest.is_symlink():
        raise FileExistsError(
            f"{dest} exists already; each tool goes into a new directory"
        )
    return dest


def _install_pinned_tool(
    key: str, entry: Mapping, bin_dir: Path, download: Callable[[str, Path], Path]
) -> str:
    dest = _check_tool(key, entry, bin_dir)
    executable, file_name = entry["executable"], _url_file_name(entry["url"])
    bin_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".download-", dir=bin_dir) as scratch:
        # A neutral name: nothing has its final name before its check.
        downloaded = _fetch(
            download, entry["url"], Path(scratch) / f"{dest.name}.download"
        )
        try:
            install_tool(entry, downloaded, dest)
            program = dest.joinpath(*executable.split("/"))
            if not (
                program.is_file()
                and not program.is_symlink()
                and _inside(program, dest)
            ):
                raise IntegrityError(
                    f"{key}: {file_name} does not install {executable} as a regular file"
                    f" under {dest}"
                )
            # Jenkinsfile Runner's zip stores its launcher script without an execute
            # bit, so the program the manifest names is made executable here.
            program.chmod(program.stat().st_mode | 0o111)
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise
    return f"{key} {entry.get('version')} sha256:{entry.get('sha256')} {program}"


def _check_core(
    key: str, core: Mapping, manifest_dir: Path, jenkins_dir: Path | None
) -> tuple[Path, list[Mapping]]:
    """The Jenkins directory and the plugins of core ``key``, read from its plugins
    file, once the core passes every check that needs no download: a plugins file that
    names no bundled plugin and lists each plugin once, by a plain file name; an https
    url and a pin of 64 lowercase hex for the WAR and for each plugin; and a Jenkins
    directory that is one or can be created, and holds no earlier core."""
    if jenkins_dir is None:
        raise ValueError(f"{key}: a Jenkins core needs a Jenkins directory")
    rel = core.get("plugins")
    if not _plain_relative(rel):
        raise ValueError(
            f"{key}: plugins {rel!r} is not a relative POSIX path without .."
        )
    document = load_toml(manifest_dir.joinpath(*rel.split("/")))
    if document.get("bundled"):
        raise ValueError(
            f"{rel} lists bundled plugins {document['bundled']}, but Jenkinsfile Runner's"
            " release zip ships none; pin each as a [[plugin]] entry"
        )
    plugins = document.get("plugin", [])
    if not (isinstance(plugins, list) and all(isinstance(p, Mapping) for p in plugins)):
        raise ValueError(f"{rel}: [[plugin]] must be a list of tables")
    _plugin_names(plugins, rel)
    _require_pin(f"{key} WAR", core.get("war_sha256"))
    _require_https(core.get("war_url"))
    for plugin in plugins:
        _require_pin(f"{rel}: plugin {plugin['name']}", plugin.get("sha256"))
        _require_https(plugin.get("url"))
    _require_usable(jenkins_dir, "Jenkins directory", directory=True)
    _refuse_earlier_core(jenkins_dir)
    return jenkins_dir, plugins


def _install_pinned_core(
    key: str,
    core: Mapping,
    manifest_dir: Path,
    jenkins_dir: Path | None,
    download: Callable[[str, Path], Path],
) -> list[str]:
    jenkins_dir, plugins = _check_core(key, core, manifest_dir, jenkins_dir)
    jenkins_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".download-", dir=jenkins_dir) as scratch:
        scratch_dir = Path(scratch)
        war = _fetch(download, core["war_url"], scratch_dir / "jenkins.war.download")
        hpis = {
            plugin["name"]: _fetch(
                download, plugin["url"], scratch_dir / f"{plugin['name']}.hpi.download"
            )
            for plugin in plugins
        }
        war_path = install_jenkins_core(
            core, plugins, war=war, hpis=hpis, dest=jenkins_dir
        )
    lines = [
        f"{key} {core.get('core_version')} sha256:{core.get('war_sha256')} {war_path}"
    ]
    lines += [
        f"{key} plugin {plugin['name']} {plugin.get('version')}"
        f" sha256:{plugin.get('sha256')} {jenkins_dir / 'plugins' / (plugin['name'] + '.hpi')}"
        for plugin in plugins
    ]
    return lines


def _check_image(key: str, entry: Mapping, pull_log: Path | None) -> Path:
    """The pull log, once image ``key`` passes every check that needs no pull: there
    is a pull log, and its ref is <name>@sha256:<digest> with no tag."""
    if pull_log is None:
        raise ValueError(f"{key}: pulling an image needs a pull log")
    docker_pull_argv(entry.get("ref"))
    return pull_log


def _install_pinned_image(
    key: str, entry: Mapping, pull_log: Path | None, run: Callable[..., object]
) -> str:
    pull_log = _check_image(key, entry, pull_log)
    pull_image(entry["ref"], pull_log=pull_log, run=run)
    return f"{key} {entry['ref']}"


def install_pins(
    keys: Iterable[str],
    manifest: Mapping,
    *,
    manifest_dir: Path,
    bin_dir: Path,
    pull_log: Path | None = None,
    jenkins_dir: Path | None = None,
    download: Callable[[str, Path], Path] | None = None,
    run: Callable[..., object] | None = None,
    report: Callable[[str], object] | None = None,
) -> list[str]:
    """Install the manifest entries named by keys, in order, and return one line per
    installed item (also passed to report as it is installed).

    Everything is checked first, before anything is created or downloaded, so a
    mistake anywhere leaves an earlier entry uninstalled and nothing behind: the keys
    (each of a known kind and listed once, and one Jenkins core at most), each entry
    on its own, the pull log, and the places against each other (no tool's
    directory, core file or pull log may be the same path as another place the call
    writes, or hold one). Then the pull log, when given, is created, so it exists
    even when nothing is pulled. Each install checks its entry again right before it
    uses it. ``download(url, dest)`` and ``run`` default to download_file and
    subprocess.run.
    """
    download = download_file if download is None else download
    run = subprocess.run if run is None else run
    keys, manifest_dir, bin_dir = list(keys), Path(manifest_dir), Path(bin_dir)
    pull_log = None if pull_log is None else Path(pull_log)
    jenkins_dir = None if jenkins_dir is None else Path(jenkins_dir)
    _check_keys(keys)
    # Each role's places, for the overlap check: "owned" ones are that role's alone,
    # "needed" ones are directories that hold them.
    owned: dict[str, Path] = {}
    needed: dict[str, Path] = {}
    for key in keys:
        if key.startswith("tools."):
            owned[f"directory of {key}"] = _check_tool(
                key, _entry(manifest, key), bin_dir
            )
            needed["bin directory"] = bin_dir
        elif key.startswith("images."):
            _check_image(key, _entry(manifest, key), pull_log)
        elif key.startswith("jenkins.cores."):
            core_dir, _plugins = _check_core(
                key, _entry(manifest, key), manifest_dir, jenkins_dir
            )
            needed["Jenkins directory"] = core_dir
            owned[f"WAR of {key}"] = core_dir / "jenkins.war"
            owned[f"plugins directory of {key}"] = core_dir / "plugins"
        else:
            raise ValueError(f"{key} is not a tools., images. or jenkins.cores. key")
    if pull_log is not None:
        _require_usable(pull_log, "pull log", directory=False)
        owned["pull log"] = pull_log
    _refuse_overlaps(needed, owned)
    if pull_log is not None:
        pull_log.parent.mkdir(parents=True, exist_ok=True)
        pull_log.touch()
    lines: list[str] = []

    def done(new: Iterable[str]) -> None:
        for line in new:
            lines.append(line)
            if report is not None:
                report(line)

    for key in keys:
        entry = _entry(manifest, key)
        if key.startswith("tools."):
            done([_install_pinned_tool(key, entry, bin_dir, download)])
        elif key.startswith("images."):
            done([_install_pinned_image(key, entry, pull_log, run)])
        else:  # a jenkins.cores. key; the first loop refused any other
            done(_install_pinned_core(key, entry, manifest_dir, jenkins_dir, download))
    return lines


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install_tools.py",
        description=(
            "Install the pinned tools, Jenkins core and images of one Docs CI Runners"
            " leg. Runs only on a GitHub-hosted runner unless"
            f" {OVERRIDE}=1."
        ),
    )
    parser.add_argument(
        "--runner", required=True, choices=sorted(RUNNER_PINS), help="the leg"
    )
    parser.add_argument(
        "--bin-dir",
        required=True,
        type=Path,
        help="each tool is installed under <bin-dir>/<name>/",
    )
    parser.add_argument(
        "--pull-log",
        type=Path,
        help=(
            "file each pulled image reference is appended to; created even when"
            " nothing is pulled; needed by the legs that pull images"
        ),
    )
    parser.add_argument(
        "--jenkins-dir",
        type=Path,
        help=(
            "Jenkins legs only, and required there: receives jenkins.war and"
            " plugins/<name>.hpi"
        ),
    )
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """The command line, with each leg's needs checked; a usage error exits 2."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.runner in JENKINS_LEGS and args.jenkins_dir is None:
        parser.error(
            f"--runner {args.runner} needs --jenkins-dir, the directory that receives"
            " jenkins.war and plugins/"
        )
    if args.runner not in JENKINS_LEGS and args.jenkins_dir is not None:
        parser.error(
            f"--jenkins-dir is only for {' and '.join(sorted(JENKINS_LEGS))}, not"
            f" --runner {args.runner}"
        )
    pulls = any(key.startswith("images.") for key in RUNNER_PINS[args.runner])
    if pulls and args.pull_log is None:
        parser.error(f"--runner {args.runner} pulls images, so it needs --pull-log")
    return args


def main(
    argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None
) -> int:
    args = parse_args(argv)
    problem = runner_environment_problem(os.environ if environ is None else environ)
    if problem is not None:
        print(_one_line(problem), file=sys.stderr)
        return EXIT_HOST
    try:
        install_pins(
            RUNNER_PINS[args.runner],
            load_toml(MANIFEST),
            manifest_dir=MANIFEST.parent,
            bin_dir=args.bin_dir,
            pull_log=args.pull_log,
            jenkins_dir=args.jenkins_dir,
            report=lambda line: print(line, flush=True),
        )
    except IntegrityError as error:
        print(_one_line(f"install_tools.py: {error}"), file=sys.stderr)
        return EXIT_INTEGRITY
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,  # a failed pull, or one past PULL_TIMEOUT_SECONDS
        http.client.HTTPException,
        tarfile.TarError,
        zipfile.BadZipFile,
        tomllib.TOMLDecodeError,
    ) as error:
        print(_one_line(f"install_tools.py: {error}"), file=sys.stderr)
        return EXIT_FAILED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
