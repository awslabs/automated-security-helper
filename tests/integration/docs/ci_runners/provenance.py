# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ASH a pipeline installed, read back from the installed distribution.

ASH's version is a static string, so ``ash --version`` reads the same for the release
and for the pull request, and ``pip install --quiet`` prints nothing about its source.
What records the source is the distribution's PEP 610 ``direct_url.json``. rewrite.py
adds, right after each install of the ASH under test, the command
direct_url_print_command builds: it prints that file on one line between
PROVENANCE_BEGIN and PROVENANCE_END. This module finds those prints in a runner's log
(direct_urls_in_log) and checks what they say (wheel_provenance_problems,
git_provenance_problems).

A job on the image the run builds from the checkout's ``Dockerfile --target ci``
installs nothing: the image's Dockerfile builds a wheel from its build context,
installs it with ``uv pip install --system`` and deletes it. That install records no
commit and no hash, and its direct_url.json, where there is one, names a local file,
as the released image's does. What an image built from the pull request holds and a
released image does not is the pull request's files. So for that job the rewrite adds
built_provenance_print_command instead, whose program prints, between the same
markers and on one line of a few hundred bytes, the installed distribution's version
and direct_url.json, the number of files it lists under ``automated_security_helper/``
and a digest of their paths and sha256s (files_digest), and the sha256 of its
METADATA and entry_points.txt. built_provenance_problems compares those with the
wheel the run built from the same checkout. The installers copy a wheel's METADATA
and entry_points.txt as they are, so those two carry what a pull request can change
outside the package: its dependencies, its description and its commands.

The two installers record a wheel install differently, and each check passes exactly
its shape. pip takes the sha256 from the URL fragment, checks the file against it,
records it in ``archive_info.hashes`` and drops the fragment from ``url``. uv neither
checks the fragment nor drops it: ``url`` is the URL as given, ``#sha256=<hex>`` and
all, and ``archive_info`` records no hash. So a uv record says which file was named,
not what it held; the harness hashes the wheel file again after each run for that. The
scan workflow installs from ``git+https://github.com/<repository>@<ref>``, with no
``.git``, so the git check takes the repository URL with or without it.

Runners decorate their output: ANSI colors, carriage-return overwrites, a prefix on
each line (``build_1  | `` from the CodeBuild agent, ``<job> > `` from
gitlab-ci-local), and act's ``--json`` mode wraps each line in a JSON object whose
``msg`` is the text. So a marker counts only where it ends its line and what comes
before it is nothing, or a prefix ending in ``|``, ``>`` or ``]``. A runner that echoes
a command before running it (GitLab's ``$ ...``, the shell's ``set -x`` ``+ ...``,
CodeBuild's ``Running command ...``) shows the markers inside the printing command,
never at the end of a line, so an echo is not read as a print.

Limits: the file is printed on one line, and an object split over several lines reads
as None; a runner whose line prefix ends in another character hides the markers, which
the first run of that runner shows as a missing print. The built-image check compares
contents, not a commit, and the record names no file: a difference shows as another
count or digest of the files, or another sha256 of METADATA or entry_points.txt, and
the problem says which. built_wheel_manifest gives the wheel's side with each file's
path and sha256, for the run to write beside the failure. A file that one build of
the checkout includes and the other does not (the image's build context leaves out
.gitignore, which the wheel's build reads) shows as a difference, which fails the run,
and so does METADATA written differently by another release of the build backend,
which each build resolves when it runs.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from email.parser import HeaderParser
from pathlib import Path, PurePath, PureWindowsPath
from typing import Any
from urllib.parse import quote

PROVENANCE_BEGIN = "ASH-DIRECT-URL-BEGIN"
PROVENANCE_END = "ASH-DIRECT-URL-END"

#: The distribution every install form on the pages installs.
DISTRIBUTION = "automated-security-helper"

#: What the print shows between the markers when there is no single direct_url.json.
NO_DIRECT_URL = f"no direct_url.json for {DISTRIBUTION}"

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_PREFIX_ENDS = ("|", ">", "]")

#: One line of Python with no backslash, no single quote, no ": " and no " #", so the
#: same text works inside a shell's single quotes, a Groovy ''' string, a YAML block
#: scalar and a YAML single-quoted scalar. It finds the installed distribution by name
#: and prints its direct_url.json, re-serialized onto one line.
PRINT_PROGRAM = (
    "import importlib.metadata as m, json; "
    "d = [x for x in m.distributions() "
    f'if (x.metadata["Name"] or "").lower().replace("_", "-") == "{DISTRIBUTION}"]; '
    f'print("{PROVENANCE_BEGIN}"); '
    't = d[0].read_text("direct_url.json") if len(d) == 1 else None; '
    "print(json.dumps(json.loads(t)) if t else "
    f'"{NO_DIRECT_URL} (" + str(len(d)) + " installed)"); '
    f'print("{PROVENANCE_END}")'
)


#: The files of the installed distribution the built-image print records: those under
#: the package, less bytecode and ASH_INSTALLED_REVISION, into which each build writes
#: the branch name it can find (the image's build has no git checkout to read, so the
#: two builds of one checkout can write different values there).
PACKAGE_PREFIX = "automated_security_helper/"
REVISION_FILE = "automated_security_helper/assets/ASH_INSTALLED_REVISION"
_BYTECODE_SUFFIXES = (".pyc", ".pyo")

#: One line of Python under the same rules as PRINT_PROGRAM. It finds the installed
#: distribution by name and prints, as one JSON object on one line, its direct_url.json
#: (or null) and version; the number of files its RECORD lists that _counted_file
#: counts, and files_digest of their sha256s; and the sha256 of the METADATA and the
#: entry_points.txt its RECORD lists in its dist-info (or null for one it lacks).
BUILT_PRINT_PROGRAM = (
    "import hashlib as h, importlib.metadata as m, json; "
    "d = [x for x in m.distributions() "
    f'if (x.metadata["Name"] or "").lower().replace("_", "-") == "{DISTRIBUTION}"]; '
    f'print("{PROVENANCE_BEGIN}"); '
    "x = d[0] if len(d) == 1 else None; "
    't = x.read_text("direct_url.json") if x else None; '
    "s = lambda p:h.sha256(x.locate_file(p).read_bytes()).hexdigest(); "
    "a = sorted(set(str(p) for p in (x.files or []))) if x else []; "
    f'f = [p for p in a if p.startswith("{PACKAGE_PREFIX}") '
    'and not p.endswith((".pyc", ".pyo")) and "__pycache__/" not in p '
    f'and p != "{REVISION_FILE}"]; '
    'i = lambda n:next((s(p) for p in a if p.count("/") == 1 '
    'and p.endswith(".dist-info/" + n)), None); '
    "print(json.dumps(dict(direct_url=json.loads(t) if t else None, "
    "version=x.version, file_count=len(f), "
    "files_sha256=h.sha256(json.dumps([[p, s(p)] for p in f]).encode()).hexdigest(), "
    'metadata_sha256=i("METADATA"), entry_points_sha256=i("entry_points.txt"))) '
    f'if x else "{NO_DIRECT_URL} (" + str(len(d)) + " installed)"); '
    f'print("{PROVENANCE_END}")'
)

#: The keys of the built-image record, and nothing else.
_BUILT_RECORD_KEYS = frozenset(
    {
        "direct_url",
        "version",
        "file_count",
        "files_sha256",
        "metadata_sha256",
        "entry_points_sha256",
    }
)
#: The files of the dist-info the built-image record gives the sha256 of, by its key.
_DIST_INFO_FILES = {
    "metadata_sha256": "METADATA",
    "entry_points_sha256": "entry_points.txt",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _counted_file(path: str) -> bool:
    """Whether the built-image record counts ``path``, as BUILT_PRINT_PROGRAM does."""
    return (
        path.startswith(PACKAGE_PREFIX)
        and not path.endswith(_BYTECODE_SUFFIXES)
        and "__pycache__/" not in path
        and path != REVISION_FILE
    )


def _dist_info_file(path: str, name: str) -> bool:
    """Whether ``path`` is ``<distribution>-<version>.dist-info/<name>``, as
    BUILT_PRINT_PROGRAM finds it."""
    return path.count("/") == 1 and path.endswith(f".dist-info/{name}")


def files_digest(files: Mapping[str, str]) -> str:
    """The built-image record's digest of its files, path -> sha256.

    It is the sha256 of the JSON that ``json.dumps``, with its default settings,
    writes for the list of ``[path, sha256]`` pairs sorted by path, encoded as UTF-8
    (all ASCII, since json.dumps escapes the rest). BUILT_PRINT_PROGRAM computes the
    same inside the image.
    """
    pairs = [[path, files[path]] for path in sorted(files)]
    return hashlib.sha256(json.dumps(pairs).encode("utf-8")).hexdigest()


def _print_command(python: str, program: str, what: str) -> str:
    if not python or "'" in python or "\n" in python:
        raise ValueError(f"not a usable interpreter word: {python!r}")
    return f"{python} -I -c '{program}' || echo \"{what} could not be printed\""


def direct_url_print_command(python: str) -> str:
    """The shell command that prints the direct_url.json of the ASH in ``python``.

    ``python`` is the interpreter of the environment the install wrote to, as shell
    words: ``/opt/ash/bin/python``, ``"$HOME/ash-venv/bin/python"``, or
    ``uvx --from "${ASH_UVX_SOURCE}" python``. It runs isolated (``-I``), so neither
    the directory the pipeline runs in nor PYTHONPATH can put another module in front
    of the standard library's. The command never fails the pipeline: when the
    interpreter cannot run, it says so and the markers are missing, which the
    provenance check reports.
    """
    return _print_command(
        python, PRINT_PROGRAM, "the direct_url.json of the installed ASH"
    )


def built_provenance_print_command(python: str) -> str:
    """The shell command that prints the record of the ASH installed in an image.

    ``python`` is the image's interpreter as shell words (``python3`` in the image the
    run builds, where ``uv pip install --system`` installed ASH). Like
    direct_url_print_command, it runs isolated and never fails the pipeline.
    """
    return _print_command(
        python, BUILT_PRINT_PROGRAM, "the files of the ASH in the image"
    )


def file_uri(path: PurePath) -> str:
    """The ``file://`` URI of an absolute path, the string ``PurePath.as_uri()`` gives.

    Built here because ``PurePath.as_uri()`` is deprecated from Python 3.14.
    """
    if not path.is_absolute():
        raise ValueError(f"a file URI needs an absolute path, not {str(path)!r}")
    if isinstance(path, PureWindowsPath):
        drive, posix = path.drive, path.as_posix()
        if len(drive) == 2 and drive[1] == ":":
            return f"file:///{drive}/{quote(posix[2:].lstrip('/'))}"
        return f"file:{quote(posix)}"
    return f"file://{quote(path.as_posix())}"


def _log_text(raw: str) -> str:
    """A log line's text: act's ``--json`` entries carry it as ``msg``."""
    stripped = raw.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            entry = json.loads(stripped)
        except ValueError:
            return raw
        if isinstance(entry, dict) and isinstance(entry.get("msg"), str):
            return entry["msg"]
    return raw


def _lines(log: str) -> Iterator[str]:
    """The visible lines of a log: ANSI codes removed, carriage returns split."""
    for raw in log.split("\n"):
        for part in _ANSI_ESCAPE.sub("", _log_text(raw)).splitlines():
            yield part.rstrip()


def _marker(line: str) -> str | None:
    for marker in (PROVENANCE_BEGIN, PROVENANCE_END):
        if line.endswith(marker):
            before = line[: -len(marker)].rstrip()
            if not before or before.endswith(_PREFIX_ENDS):
                return marker
    return None


def _object_in(lines: list[str]) -> dict[str, Any] | None:
    """The one JSON object printed between a pair of markers, or None."""
    found = []
    for line in lines:
        start, end = line.find("{"), line.rfind("}")
        if 0 <= start < end:
            try:
                value = json.loads(line[start : end + 1])
            except ValueError:
                continue
            if isinstance(value, dict):
                found.append(value)
    return found[0] if len(found) == 1 else None


def direct_urls_in_log(log: str) -> list[dict[str, Any] | None]:
    """One item per marker pair in ``log``, in order: the JSON object between, or None.

    A begin marker with no end marker after it is not a pair and gives no item.
    """
    found: list[dict[str, Any] | None] = []
    inside: list[str] | None = None
    for line in _lines(log):
        marker = _marker(line)
        if marker == PROVENANCE_BEGIN:
            inside = []
        elif marker == PROVENANCE_END:
            if inside is not None:
                found.append(_object_in(inside))
            inside = None
        elif inside is not None:
            inside.append(line)
    return found


def _recorded_sha256(archive_info: Mapping[str, Any]) -> list[str]:
    """Every sha256 an archive_info records: ``hashes``, and the older ``hash``."""
    recorded = []
    hashes = archive_info.get("hashes")
    if isinstance(hashes, Mapping) and isinstance(hashes.get("sha256"), str):
        recorded.append(hashes["sha256"])
    legacy = archive_info.get("hash")
    if isinstance(legacy, str) and legacy.startswith("sha256="):
        recorded.append(legacy[len("sha256=") :])
    return recorded


def _not_an_object(direct_url: Any) -> list[str] | None:
    if direct_url is None:
        return [
            (
                "no direct_url.json was printed for the installed ASH, so where it "
                "was installed from is unknown"
            )
        ]
    if not isinstance(direct_url, Mapping):
        return [f"the printed direct_url.json is not a JSON object: {direct_url!r}"]
    return None


def wheel_provenance_problems(
    direct_url: Mapping[str, Any] | None, *, wheel: PurePath, sha256: str
) -> list[str]:
    """Why ``direct_url`` is not an install of ``wheel`` with that sha256; [] if it is.

    ``wheel`` is the path as the installer saw it: the host path, or the path inside
    the container the wheel was mounted into. Two records pass, and nothing else:
    pip's, ``url`` the wheel's file URI and ``archive_info`` recording ``sha256`` (in
    ``hashes``, or the older ``hash``); and uv's, ``url`` that URI followed by exactly
    ``#sha256=<sha256>`` and ``archive_info`` recording no hash.
    """
    problems = _not_an_object(direct_url)
    if problems is not None:
        return problems
    assert direct_url is not None
    problems = []
    uri = file_uri(wheel)
    uv_url = f"{uri}#sha256={sha256}"
    url = direct_url.get("url")
    for key, source in (("dir_info", "a directory"), ("vcs_info", "a repository")):
        if key in direct_url:
            problems.append(
                f"the installed ASH was installed from {source} ({key}), not a wheel"
            )
    archive_info = direct_url.get("archive_info")
    if not isinstance(archive_info, Mapping):
        problems.append(
            "direct_url.json has no archive_info, so it is not a record of a wheel"
        )
        return problems
    recorded = _recorded_sha256(archive_info)
    if url == uv_url:
        if recorded or "hashes" in archive_info or "hash" in archive_info:
            problems.append(
                "the record names the wheel with its sha256 in the URL, as uv writes "
                "it, but also records a hash, which uv does not write"
            )
    elif url == uri:
        if not recorded:
            problems.append("archive_info records no sha256 of the installed wheel")
        elif any(value != sha256 for value in recorded):
            problems.append(
                f"archive_info records sha256 {', '.join(sorted(set(recorded)))}, not "
                f"{sha256}, the sha256 of the wheel the run built"
            )
    else:
        problems.append(
            f"the installed ASH came from {url!r}, not from the wheel the run built: "
            f"{uri!r} as pip records it, or {uv_url!r} as uv does"
        )
    return problems


def git_provenance_problems(
    direct_url: Mapping[str, Any] | None, *, head_sha: str, repository: str
) -> list[str]:
    """Why ``direct_url`` is not a git install of ``repository`` at ``head_sha``.

    ``url`` is the repository's GitHub URL exactly, with or without ``.git``.
    """
    problems = _not_an_object(direct_url)
    if problems is not None:
        return problems
    assert direct_url is not None
    problems = []
    expected = (
        f"https://github.com/{repository}.git",
        f"https://github.com/{repository}",
    )
    if direct_url.get("url") not in expected:
        problems.append(
            f"the installed ASH came from {direct_url.get('url')!r}, not from "
            f"{expected[0]!r} or {expected[1]!r}"
        )
    for key in ("archive_info", "dir_info"):
        if key in direct_url:
            problems.append(
                f"the installed ASH was installed from {key}, not a git checkout"
            )
    vcs_info = direct_url.get("vcs_info")
    if not isinstance(vcs_info, Mapping):
        problems.append("direct_url.json has no vcs_info, so no commit was recorded")
        return problems
    if vcs_info.get("vcs") != "git":
        problems.append(
            f"the installed ASH came from {vcs_info.get('vcs')!r}, not from git"
        )
    if vcs_info.get("commit_id") != head_sha:
        problems.append(
            f"the installed ASH is commit {vcs_info.get('commit_id')!r}, not the head "
            f"commit {head_sha}"
        )
    return problems


@dataclass(frozen=True)
class _WheelContents:
    """What the built-image record is compared with, read from the run's wheel."""

    #: METADATA's Version, or None.
    version: str | None
    #: path -> sha256 of each file _counted_file counts.
    files: dict[str, str]
    #: record key -> sha256 of that dist-info file, or None where the wheel has none.
    dist_info: dict[str, str | None]


def _wheel_contents(data: bytes) -> _WheelContents:
    """A wheel's version, the sha256 of each file it counts, and the sha256 of its
    METADATA and entry_points.txt, each the first in path order, as the print finds
    them."""
    files: dict[str, str] = {}
    found: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in sorted(archive.infolist(), key=lambda entry: entry.filename):
            name = info.filename
            if name.endswith("/"):
                continue
            if _counted_file(name):
                files[name] = hashlib.sha256(archive.read(info)).hexdigest()
            for key, file in _DIST_INFO_FILES.items():
                if key not in found and _dist_info_file(name, file):
                    found[key] = archive.read(info)
    metadata = found.get("metadata_sha256")
    version = (
        HeaderParser().parsestr(metadata.decode("utf-8", "replace")).get("Version")
        if metadata is not None
        else None
    )
    return _WheelContents(
        version=version,
        files=files,
        dist_info={
            key: hashlib.sha256(found[key]).hexdigest() if key in found else None
            for key in _DIST_INFO_FILES
        },
    )


def _reference_wheel(wheel: Path, wheel_sha256: str) -> _WheelContents | str:
    """The contents of the wheel the run built, or why ``wheel`` is not that wheel: it
    cannot be read, its sha256 is not ``wheel_sha256``, or it is not a wheel. Nothing
    past the sha256 check is read from a file that fails it."""
    try:
        data = Path(wheel).read_bytes()
    except OSError as error:
        return (
            f"the wheel the run built cannot be read ({error}), so there is nothing to "
            "compare the image's ASH with"
        )
    actual = hashlib.sha256(data).hexdigest()
    if actual != wheel_sha256:
        return (
            f"{wheel} has sha256 {actual}, not {wheel_sha256}, so it is not the wheel "
            "the run built and no reference for the image's ASH"
        )
    try:
        return _wheel_contents(data)
    except (zipfile.BadZipFile, KeyError, ValueError) as error:
        return f"{wheel} is not a wheel that can be read: {error}"


def built_wheel_manifest(wheel: Path, *, wheel_sha256: str) -> dict[str, Any]:
    """What built_provenance_problems compares an image's record with, read from the
    wheel the run built, for the run to write beside a failed check.

    The record holds a count and a digest of the image's files, not their names, so
    a failure says which of the file count, the files digest, METADATA and
    entry_points.txt differs, and no more. This manifest has the wheel's side of
    each, under the record's keys (version, file_count, files_sha256,
    metadata_sha256, entry_points_sha256), the wheel's file name and sha256
    (``wheel``, ``wheel_sha256``), and ``files``: each counted file's path and sha256,
    in path order, whose files_digest is ``files_sha256``. Listing the image's files
    the same way finds the one that differs. It is JSON as it is.

    Raises ValueError, naming why, when ``wheel`` cannot be read, its sha256 is not
    ``wheel_sha256``, or it is not a wheel.
    """
    contents = _reference_wheel(wheel, wheel_sha256)
    if isinstance(contents, str):
        raise ValueError(contents)
    files = dict(sorted(contents.files.items()))
    return {
        "wheel": PurePath(wheel).name,
        "wheel_sha256": wheel_sha256,
        "version": contents.version,
        "file_count": len(files),
        "files_sha256": files_digest(files),
        **contents.dist_info,
        "files": files,
    }


def built_provenance_problems(
    record: Mapping[str, Any] | None,
    *,
    head_sha: str,
    wheel: Path,
    wheel_sha256: str,
) -> list[str]:
    """Why ``record`` is not the ASH of an image built from the head commit's checkout.

    ``record`` is what built_provenance_print_command printed inside the image.
    ``wheel`` is the wheel the run built on the host from the same checkout of
    ``head_sha``, and ``wheel_sha256`` the sha256 the run holds for it: a file with
    any other sha256 is no reference, and none is read past that check. The record
    passes only when all of these hold:

    * its keys are exactly direct_url, version, file_count, files_sha256,
      metadata_sha256 and entry_points_sha256;
    * version is the wheel's METADATA Version;
    * direct_url is null (the install recorded none) or an archive install of a
      ``file:///`` URL whose file name is the wheel's: not a repository, a directory
      or a download;
    * file_count is the number of the wheel's files under
      ``automated_security_helper/``, less bytecode and ASH_INSTALLED_REVISION, and
      files_sha256 is files_digest of their sha256s, so no file is missing, added or
      different;
    * metadata_sha256 and entry_points_sha256 are the sha256 of the wheel's METADATA
      and entry_points.txt, or null where the wheel has none.

    Why that is the pull request's ASH: the image installs the wheel its own build
    made from the build context, and the run builds both that image and ``wheel``
    from the checkout of ``head_sha``, so their package files, METADATA and entry
    points are the pull request's. An image built from any other tree, the released
    image included, differs in every one of those the pull request changed: a file of
    the package, a dependency pin or the description (METADATA), or a command
    (entry_points.txt). The version and direct_url checks refuse a record of an
    install from anywhere but a local wheel. They cannot tell two local wheels apart,
    and the rest is what does.
    """
    if record is None:
        return ["no record of the ASH installed in the image was printed"]
    if not isinstance(record, Mapping):
        return [f"the printed record is not a JSON object: {record!r}"]
    problems: list[str] = []
    keys = set(record)
    if keys != _BUILT_RECORD_KEYS:
        problems.append(
            f"the record has the keys {sorted(keys)}, not {sorted(_BUILT_RECORD_KEYS)}"
        )
    contents = _reference_wheel(wheel, wheel_sha256)
    if isinstance(contents, str):
        return [*problems, contents]
    if contents.version is None:
        problems.append(f"{wheel} has no METADATA with a Version")
    elif record.get("version") != contents.version:
        problems.append(
            f"the image's ASH is version {record.get('version')!r}, not "
            f"{contents.version}, the version of the wheel the run built"
        )
    problems += _built_direct_url_problems(record.get("direct_url"), wheel)
    problems += _built_files_problems(record, contents, wheel, head_sha)
    for key, file in _DIST_INFO_FILES.items():
        if record.get(key) != contents.dist_info[key]:
            problems.append(
                f"the image's ASH has a {file} with sha256 {record.get(key)!r}, not "
                f"{contents.dist_info[key]!r}, that of the {file} of the wheel built "
                f"from the head commit {head_sha}"
            )
    return problems


def _built_files_problems(
    record: Mapping[str, Any], contents: _WheelContents, wheel: Path, head_sha: str
) -> list[str]:
    """Why the record's count and digest of files are not those of the wheel's."""
    count, digest = record.get("file_count"), record.get("files_sha256")
    if not (
        isinstance(count, int)
        and not isinstance(count, bool)
        and isinstance(digest, str)
        and _SHA256.fullmatch(digest)
    ):
        return [
            (
                "the record's file_count and files_sha256 are not a count and a "
                f"sha256: {count!r}, {digest!r}"
            )
        ]
    problems = []
    if not contents.files:
        problems.append(f"{wheel} holds no files under {PACKAGE_PREFIX}")
    expected_count, expected_digest = len(contents.files), files_digest(contents.files)
    if (count, digest) == (expected_count, expected_digest):
        return problems
    if count != expected_count:
        what = (
            f"the file count differs, {count} under {PACKAGE_PREFIX} in the image and "
            f"{expected_count} in the wheel"
        )
    else:
        what = (
            f"the file count is the same, {count} under {PACKAGE_PREFIX}, but the "
            "files digest differs: a file's path or content is not the same"
        )
    problems.append(
        "the image's ASH is not the files of the wheel built from the head commit "
        f"{head_sha}: {what}; the files digest is {digest} in the image and "
        f"{expected_digest} in the wheel"
    )
    return problems


def _built_direct_url_problems(direct_url: Any, wheel: Path) -> list[str]:
    """Why an image's direct_url.json is not an install of a local wheel like ``wheel``."""
    if direct_url is None:
        return []
    if not isinstance(direct_url, Mapping):
        return [f"the image's direct_url.json is not a JSON object: {direct_url!r}"]
    problems = []
    for key, source in (("vcs_info", "a repository"), ("dir_info", "a directory")):
        if key in direct_url:
            problems.append(f"the image's ASH was installed from {source} ({key})")
    if not isinstance(direct_url.get("archive_info"), Mapping):
        problems.append("the image's direct_url.json has no archive_info")
    url = direct_url.get("url")
    name = PurePath(wheel).name
    if not (
        isinstance(url, str)
        and url.startswith("file:///")
        and url.rpartition("/")[2] == name
    ):
        problems.append(
            f"the image's ASH was installed from {url!r}, not from a local file named "
            f"{name}"
        )
    return problems
