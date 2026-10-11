# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How the running ASH was installed, and the install commands hints name.

ASH installs from git and is not published to PyPI. On PyPI the distribution
name ``automated-security-helper`` belongs to an unrelated placeholder project
whose version number outranks every ASH release, so any install that asks an
index for that name, with or without an extra, gets that project instead of
ASH. Every message that tells a user how to reinstall ASH or add one of its
extras builds the command here.

What a hint names
-----------------
An extra is installed by naming its packages, read from the running
distribution's own metadata (:func:`extra_install_command`). A reinstall names
where the running ASH was installed from, as the installer recorded it in the
PEP 610 ``direct_url.json`` (:func:`ash_reinstall_command`): the commit of a git
install, the directory of an editable or local install, the archive of an
archive install.

Pinning to the release tag ``v<version>`` was tried first and is wrong on
every build between releases: main reports the last release's version while
its tree has moved on, and the release tag can lack an extra main has (v3.7.0
has no ``symbols`` extra), so the hint asked for an extra the tag does not
define and a reinstall downgraded main to the release. The tag is now only the
fallback for an install that left no record, such as a wheel installed from an
index, and an unknown version gets the repository URL with no ref.

Limits: the commands are pip commands with POSIX shell quoting. An ASH run by
``uvx`` or installed with ``uv tool`` or ``pipx`` needs that tool's form, which
the docs pages give.
"""

from __future__ import annotations

import json
import re
import shlex
from importlib.metadata import (
    PackageNotFoundError,
    distribution,
    distributions,
    requires,
)
from pathlib import Path
from typing import Any, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit
from urllib.request import url2pathname

# From the backport rather than the standard library. On Python 3.10 the standard
# library's packages_distributions() reads only top_level.txt, which hatchling
# does not write, so a non-editable ASH install was not found there and every
# hint fell back to the release tag. The backport, a declared dependency, also
# reads RECORD on every Python version.
from importlib_metadata import packages_distributions

from automated_security_helper.core.constants import ASH_REPO_URL
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER

#: ASH's distribution name. Only meaningful with a direct reference after it.
ASH_DISTRIBUTION_NAME = "automated-security-helper"

#: The top-level package this module ships in, used to find ASH's distribution
#: without naming it (see ``_distributions_declaring_this_module``).
_ROOT_PACKAGE = __name__.split(".", 1)[0]


def _local_path_from_file_url(url: object) -> Optional[Path]:
    """The path on this host that a PEP 610 ``file://`` URL names, or None.

    Slicing the scheme off the front and handing the remainder to ``Path`` is
    what this used to do inline, and it is wrong twice over. Both mistakes are
    invisible on Linux, where the leftover text happens to be exactly the path:

    * ``file:///D:/proj`` leaves ``/D:/proj``, which on Windows is *rooted with
      no drive* -- ``PureWindowsPath("/D:/proj").drive`` is ``""`` -- so it
      resolves against whichever drive is current and can never equal the real
      ``D:\\proj``. Every comparison against it missed, which is what took out
      all four Windows cells: on 3.12 and 3.13 only the two tests that force the
      declared mapping empty, and on 3.10 and 3.11 the drift guards too, because
      there this route is the only one that resolves at all.
    * A directory whose name needs percent-encoding stays encoded, because
      nothing unquoted it. That one misses on every platform; CI simply never
      checks out into such a directory.

    ``url2pathname`` is the standard library's inverse of the conversion pip and
    uv perform when they write the file, and it is platform specific on purpose:
    on Windows it turns ``/D:/proj`` into ``D:\\proj``, and on POSIX it unquotes
    and does nothing else. A Windows-shaped URL read on POSIX therefore yields a
    path that matches nothing, which is the right answer -- ``direct_url.json``
    is written by the installer that ran on this host, so its URL always names a
    path here.

    Deliberately not ``workspace.aggregation._strip_file_scheme``, which is
    textual for a reason of its own: it normalizes scanner-emitted SARIF URIs
    that are frequently not valid URIs at all, and has to reduce ``file:///C:/x``
    the same way on every host. This URL is machine-written and well formed, and
    what is wanted from it is a path on *this* host, so the two cannot share an
    implementation.
    """
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        # An unterminated IPv6 authority, e.g. "file://[::1/proj". One malformed
        # sibling distribution must not take out the walk over all of them.
        return None
    if parts.scheme != "file":
        return None
    # Keep a host authority in the string handed to url2pathname: on Windows that
    # is what turns "file://server/share/x" into the UNC path \\server\share\x,
    # and dropping it would silently reinterpret a share as a local directory.
    # "localhost" is RFC 8089's spelling of "this host" and names no path itself.
    host = "" if parts.netloc.lower() == "localhost" else parts.netloc
    try:
        return Path(url2pathname(f"//{host}{parts.path}" if host else parts.path))
    except (OSError, ValueError):
        # nturl2path raises OSError for a drive specifier it cannot parse.
        return None


def _distributions_declaring_this_module(root_package: str) -> List[str]:
    """Names of installed distributions that ship ``root_package``.

    Two strategies, in order, because the first one silently fails for the
    install mode this project's own CI uses.

    ``packages_distributions()`` maps a top-level import name to distributions
    using only what the ``*.dist-info`` declares about its contents, and for an
    editable install there is nothing usable there. Hatchling writes no
    ``top_level.txt``, and an editable RECORD lists the import shim rather than
    the project's own files -- no ``.py`` under the package at all. So:

    * 3.10 reads ``top_level.txt`` and nothing else. Absent, so no mapping, in
      either install mode.
    * 3.11 also infers from RECORD but filters on ``suffix == ".py"``, and an
      editable RECORD has none, so the inferred set is empty. A non-editable
      install works.
    * 3.12 dropped that suffix filter, so non-Python files that happen to sit
      under the package directory yield the name.

    Measured at 804036ba on one editable install: 3.10.20 and 3.11.15 got
    ``None``, 3.12.13 and 3.13.12 got ``['automated-security-helper']``. That is
    why ``_cdk_extra_requirements`` had been returning the pinned fallback as its
    NORMAL path on half the support matrix, and why the guard comparing the two
    was comparing the fallback against itself and could not fail.

    The second strategy does not ask what a distribution declares it contains. It
    asks which distribution was installed FROM the directory this module lives
    in, via the PEP 610 ``direct_url.json`` that pip and uv write for any install
    from a local path. That file records the project directory as a ``file://``
    URL -- see ``_local_path_from_file_url`` for why reading one back is not a
    string slice -- and depends on neither RECORD nor ``top_level.txt``, so it
    resolves on every version.

    Still never names a distribution literally. A literal name is one someone
    else can own on a package index, and installing by such a name is the defect
    this whole path exists to remove -- so the fallback strategy is keyed on a
    filesystem path this module can see from the inside, not on a string.
    """
    try:
        mapped = packages_distributions().get(root_package) or []
    except (PackageNotFoundError, OSError) as exc:
        ASH_LOGGER.debug(
            f"Could not enumerate the distributions providing {root_package!r} "
            f"({exc}); trying the install-location strategy instead."
        )
        mapped = []
    if mapped:
        return list(mapped)

    try:
        here = Path(__file__).resolve()
    except OSError:  # pragma: no cover - resolve() on an unreadable cwd
        return []

    located: List[str] = []
    try:
        candidates = list(distributions())
    except OSError as exc:
        ASH_LOGGER.debug(
            f"Could not enumerate installed distributions ({exc}); treating "
            f"ASH's own metadata as unreadable."
        )
        return []

    for dist in candidates:
        # Every read here is defensive on purpose: this loop walks EVERY
        # installed distribution, so one malformed sibling must not take out the
        # command. read_text returns None for an absent file rather than raising.
        try:
            raw = dist.read_text("direct_url.json")
            name = dist.metadata["Name"]
        except (OSError, KeyError, ValueError):
            continue
        if not raw or not name:
            continue
        try:
            url = json.loads(raw).get("url", "")
        except (ValueError, AttributeError):
            continue
        project_dir = _local_path_from_file_url(url)
        if project_dir is None:
            continue
        # Compare resolved paths rather than strings: the URL is absolute but may
        # differ from this module's path by a symlink or a trailing separator.
        try:
            project_dir = project_dir.resolve()
        except (OSError, ValueError):
            continue
        if project_dir == here or project_dir in here.parents:
            if name not in located:
                located.append(name)

    if not located:
        ASH_LOGGER.debug(
            f"No installed distribution declares or contains {root_package!r}; "
            f"treating ASH's own metadata as unreadable."
        )
    return located


def _extra_marker(extra: str) -> "re.Pattern[str]":
    """The ``extra == "<extra>"`` half of a PEP 508 marker, as a pattern.

    importlib.metadata renders the marker with single quotes while pyproject.toml
    and pip emit double quotes, so neither style can be assumed. The name is
    matched whole, so ``cdk`` does not match ``extra == "cdk2"``.
    """
    return re.compile(rf"""\bextra\s*==\s*['"]{re.escape(extra)}['"]""")


def extra_requirements_from_metadata(extra: str) -> Optional[List[str]]:
    """The requirements of ASH's ``extra`` as the installed metadata declares it.

    Returns None when no distribution containing this module declares the extra,
    including when the metadata could not be read at all. It does NOT return
    an empty list for an unreadable read, and the distinction is the reason the
    cdk scanner keeps its pinned fallback separate from this read: a caller that
    substitutes a copy on failure cannot tell "metadata declares this" from
    "metadata was unreadable, here is the copy", and a drift guard comparing the
    copy against such a value compares the copy against itself.

    The distribution is located by asking which distribution provides this
    module's top-level package, never by naming one; see
    ``_distributions_declaring_this_module``. Every located distribution is
    searched, so a stale ``*.dist-info`` that declares requirements but not the
    extra cannot mask a good one. Each requirement is returned without its
    marker: pip evaluates markers with ``extra`` undefined, so a requirement
    still carrying ``extra == "cdk"`` is skipped while pip exits 0.
    """
    marker = _extra_marker(extra)
    accumulated: List[str] = []

    for dist_name in _distributions_declaring_this_module(_ROOT_PACKAGE):
        try:
            declared = requires(dist_name)
        except (PackageNotFoundError, OSError, ValueError) as exc:
            ASH_LOGGER.debug(
                f"Could not read requirements from distribution {dist_name!r} "
                f"providing {_ROOT_PACKAGE!r} ({exc}); skipping it."
            )
            continue
        if declared is None:
            continue
        for requirement in declared:
            if not marker.search(requirement):
                continue
            bare = requirement.split(";", 1)[0].strip()
            # Deduplicated in place rather than through a set, so the order the
            # metadata declares is the order pip receives and a logged command
            # does not vary run to run.
            if bare and bare not in accumulated:
                accumulated.append(bare)

    return accumulated or None


def _direct_url() -> Any:
    """The parsed PEP 610 ``direct_url.json`` of ASH's distribution, or None.

    None means the install left no record (an install from an index writes
    none), the distribution could not be found, or the file does not parse. The
    first distribution that contains this module decides; its record is not
    mixed with a sibling's.
    """
    for name in _distributions_declaring_this_module(_ROOT_PACKAGE):
        try:
            raw = distribution(name).read_text("direct_url.json")
        except (PackageNotFoundError, OSError, ValueError):
            continue
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None
    return None


def _without_credentials(url: str) -> str:
    """``url`` with any user and password removed from its authority.

    PEP 610 tells installers to strip credentials before recording a URL, and
    pip and uv do. A hint is printed into logs, so it does not rely on that.
    ``git@`` with no password is the ssh convention, not a credential, and is
    kept.
    """
    parts = urlsplit(url)
    if parts.username is None and parts.password is None:
        return url
    if parts.username == "git" and parts.password is None:
        return url
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return urlunsplit(parts._replace(netloc=host))


def _recorded_source(record: Any) -> Optional[Tuple[str, str]]:
    """``(kind, source)`` for a PEP 610 record, or None if it cannot be used.

    ``kind`` is ``"url"`` for a git commit or an archive (a local archive as a
    ``file:`` URL), ``"path"`` for a local directory, and ``"editable"`` for an
    editable directory. A record without the field its kind needs (a git record
    with no commit, a directory record whose URL is not a local path) is
    unusable rather than guessed at, and so is a local directory or archive that
    no longer exists: the container image installs ASH from a wheel and then
    deletes it.
    """
    if not isinstance(record, dict):
        return None
    url = record.get("url")
    if not isinstance(url, str) or not url:
        return None

    vcs_info = record.get("vcs_info")
    if isinstance(vcs_info, dict):
        vcs = vcs_info.get("vcs")
        commit = vcs_info.get("commit_id")
        if not (isinstance(vcs, str) and vcs and isinstance(commit, str) and commit):
            return None
        source = f"{vcs}+{_without_credentials(url)}@{commit}"
        subdirectory = record.get("subdirectory")
        if isinstance(subdirectory, str) and subdirectory:
            source = f"{source}#subdirectory={subdirectory}"
        return "url", source

    local = _local_path_from_file_url(url)
    dir_info = record.get("dir_info")
    if isinstance(dir_info, dict):
        if local is None or not local.is_dir():
            return None
        return ("editable" if dir_info.get("editable") is True else "path"), str(local)

    if isinstance(record.get("archive_info"), dict):
        if local is not None:
            return ("url", local.as_uri()) if local.is_file() else None
        if urlsplit(url).scheme in ("http", "https"):
            return "url", _without_credentials(url)
    return None


def ash_install_arguments(extra: Optional[str] = None) -> str:
    """The pip arguments, shell-quoted, that install the running ASH again.

    With ``extra``, the same source with that extra. From the install's own
    record when it has one: a git commit, an editable directory (``-e <dir>``),
    a local directory, a local or remote archive, as long as a local one still
    exists. Without a usable record,
    ``git+<repo>.git@v<version>``, and without a known version the repository
    URL with no ref; ``get_version()`` returns the literal "unknown" then, and
    there is no tag ``vunknown``. It never names ASH's distribution without a
    direct reference after it.
    """
    recorded = _recorded_source(_direct_url())
    if recorded is None:
        version = get_ash_version()
        ref = "" if version == "unknown" else f"@v{version}"
        kind, source = "url", f"git+{ASH_REPO_URL}.git{ref}"
    else:
        kind, source = recorded

    with_extra = f"[{extra}]" if extra else ""
    if kind == "editable":
        return f"-e {shlex.quote(source + with_extra)}"
    if kind == "path":
        return shlex.quote(source + with_extra)
    if extra:
        return shlex.quote(f"{ASH_DISTRIBUTION_NAME}{with_extra} @ {source}")
    return shlex.quote(source)


def ash_reinstall_command() -> str:
    """The pip command that reinstalls the running ASH from where it came from."""
    return f"pip install --force-reinstall {ash_install_arguments()}"


def extra_install_command(extra: str) -> str:
    """The pip command that installs ASH's ``extra`` into the running install.

    Names the extra's packages, read from the running distribution's metadata,
    so it installs what this ASH declares whatever its version or source. Only
    when that metadata cannot be read does it fall back to reinstalling this
    ASH from its own source with the extra.
    """
    declared = extra_requirements_from_metadata(extra)
    if declared:
        return "pip install " + " ".join(shlex.quote(r) for r in declared)
    return f"pip install {ash_install_arguments(extra)}"
