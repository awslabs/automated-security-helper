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

How a hint installs
-------------------
Every command runs the uv that ASH depends on through the interpreter that runs
ASH, and installs into that interpreter's environment:
``<python> -m uv pip install --python <python> ...``. A bare ``pip`` is not used:
uv-made environments (``uv sync``, ``uv tool install``, uvx) have none, so it ran
whatever pip came next on PATH, often another Python's. The interpreter is named
by path, so the command also reaches a ``uv tool`` or ``pipx`` environment.

Limits: POSIX shell quoting. uvx runs ASH from a cached environment that it
rebuilds from its own arguments, so an extra installed there does not last; the
docs pages give the uvx form. The commands need the ``uv`` package to import,
which an install missing several dependencies may also lack.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
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
    except (PackageNotFoundError, OSError, KeyError, TypeError, ValueError) as exc:
        # packages_distributions walks EVERY installed distribution and reads
        # each one's metadata: a sibling dist-info with no METADATA (its
        # ``metadata`` is None, read as a mapping) or no Name raises TypeError
        # or KeyError out of it, which is the sibling's defect, not this
        # install's, and the install-location strategy below reads no sibling.
        # The cause goes with the record (``exc_info``), which the log handler
        # formats once, rather than quoted into the message: a message that
        # quoted the error showed its text twice.
        ASH_LOGGER.debug(
            f"Could not enumerate the distributions providing {root_package!r}; "
            "trying the install-location strategy instead.",
            exc_info=exc,
        )
        mapped = []
    # A dist-info with a top_level.txt or RECORD but no METADATA maps the package
    # to None (cdk_nag_scanner notes the same shape). A list holding only None is
    # truthy, so it used to be returned as the located distributions: the
    # requirement read and the install record then asked for a distribution
    # named None and got nothing, and the install-location strategy below, which
    # would have found the real one, never ran.
    mapped = [name for name in mapped if isinstance(name, str) and name]
    if mapped:
        return list(mapped)

    try:
        here = Path(__file__).resolve()
    except OSError:  # pragma: no cover - resolve() on an unreadable cwd
        return []
    accepted = _project_directories_of(here, root_package)

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
        except (OSError, KeyError, ValueError, TypeError):
            # TypeError: a .dist-info with no METADATA file gives a None
            # ``metadata`` on some importlib versions, and subscripting it
            # raised out of every hint and the cdk install-command builder.
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
        # A directory OF the project providing this package, never an ancestor
        # above it: an editable project that merely ENCLOSES an ASH checkout (a
        # monorepo, a workspace directory) records a file:// URL that is an
        # ancestor too, and was taken for ASH (its reinstall source, its own
        # "cdk" extra installed into ASH's environment).
        if _declares_this_module(project_dir, here, accepted):
            if name not in located:
                located.append(name)

    if not located:
        ASH_LOGGER.debug(
            f"No installed distribution declares or contains {root_package!r}; "
            f"treating ASH's own metadata as unreadable."
        )
    return located


def _project_directories_of(module_file: Path, root_package: str) -> set:
    """The directories a project providing ``root_package`` installs from.

    ``module_file`` is a module inside the package. The package directory is
    its nearest ancestor named ``root_package`` (the package's parent when none
    is, for a layout that renamed it); a project is installed from that
    directory's parent (a flat layout) or, when that parent is ``src``, from the
    directory above it (a src layout). Nothing higher: an ancestor above the
    project is another project.
    """
    package_dir: Optional[Path] = None
    for parent in module_file.parents:
        if parent.name == root_package:
            package_dir = parent
            break
    if package_dir is None:
        package_dir = module_file.parent.parent
    project_dir = package_dir.parent
    accepted = {project_dir}
    if project_dir.name == "src" and project_dir.parent != project_dir:
        accepted.add(project_dir.parent)
    return accepted


def _declares_this_module(project_dir: Path, module_file: Path, accepted: set) -> bool:
    """Whether a recorded install directory belongs to the project providing
    ``module_file``: one of the project's install directories (``accepted``,
    from :func:`_project_directories_of`), or a directory INSIDE the project
    that encloses the module (a record naming the package directory or one
    below it). A directory above the project is another project's, however
    many of this module's ancestors it is."""
    if project_dir in accepted:
        return True
    if project_dir not in module_file.parents:
        return False
    return any(root == project_dir or root in project_dir.parents for root in accepted)


def _extra_marker(extra: str) -> "re.Pattern[str]":
    """The ``extra == "<extra>"`` half of a PEP 508 marker, as a pattern.

    importlib.metadata renders the marker with single quotes while pyproject.toml
    and pip emit double quotes, so neither style can be assumed. The name is
    matched whole, so ``cdk`` does not match ``extra == "cdk2"``.
    """
    return re.compile(rf"""\bextra\s*==\s*['"]{re.escape(extra)}['"]""")


def _without_extra_clause(requirement: str, extra: str) -> str:
    """``requirement`` with the ``extra == "<extra>"`` clause taken out of its marker.

    pip evaluates a marker with ``extra`` undefined, so a requirement still
    carrying ``extra == "cdk"`` is skipped while pip exits 0; the clause has to
    go. The REST of the marker stays: ``tomli; python_version < "3.11" and extra
    == "cdk"`` is gated on the interpreter, and dropping the whole marker, which
    this used to do, installed the requirement on every platform and interpreter
    the extra never meant it for. Only a marker that is a conjunction of clauses
    is edited; one holding ``or`` (no extra of ASH's is declared that way) is
    dropped whole, as before, since removing one term of a disjunction changes
    what the others mean.
    """
    bare, separator, marker_text = requirement.partition(";")
    bare = bare.strip()
    if not separator:
        return bare
    if re.search(r"\bor\b", marker_text):
        return bare
    pattern = _extra_marker(extra)
    clauses = [clause.strip() for clause in re.split(r"\band\b", marker_text)]
    kept = [clause for clause in clauses if clause and not pattern.search(clause)]
    if not kept:
        return bare
    return f"{bare}; {' and '.join(kept)}"


def _same_named(name: str) -> List[Any]:
    """Every installed distribution named ``name``, in ``sys.path`` order.

    More than one when a stale ``*.dist-info`` of an earlier install sits beside
    the current one. ``importlib.metadata.distribution(name)`` returns the
    first of them only, so a read by name could not reach the one that ships
    this module when a stale one came first on ``sys.path``. Empty when the name
    resolves to nothing this way (the callers then fall back to the by-name
    read, which also serves the tests that replace it).
    """
    try:
        return list(distributions(name=name))
    except (OSError, ValueError, TypeError):
        return []


def _ships_this_module(dist: Any, here: Path, accepted: set) -> bool:
    """Whether ``dist`` is the distribution this very module was installed from.

    True for a non-editable install whose RECORD lists this file at this path,
    and for an editable or local install whose PEP 610 record names one of the
    project directories this module sits in (``_project_directories_of``).
    Every read is defensive: the distribution is a sibling's until proven ours.
    """
    try:
        raw = dist.read_text("direct_url.json")
        if raw:
            url = json.loads(raw).get("url", "")
            project_dir = _local_path_from_file_url(url)
            if project_dir is not None and project_dir.resolve() in accepted:
                return True
        for entry in dist.files or ():
            if Path(str(entry)).name != here.name:
                continue
            if Path(str(dist.locate_file(entry))).resolve() == here:
                return True
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False
    return False


def _distributions_to_read(name: str) -> List[Any]:
    """The distribution objects to read for a located ``name``: the one that
    ships this module when it can be told apart, else every one of that name.

    Two same-named dist-infos (a stale one left behind and the current one)
    used to both resolve to whichever came first on ``sys.path``, so a stale one
    masked the good one's record and requirements, and the stale bounds merged
    into the current extra made the cdk install unsatisfiable. Empty when the
    name resolves to no distribution object (the by-name read is then used).
    """
    candidates = _same_named(name)
    if len(candidates) < 2:
        return candidates
    try:
        here = Path(__file__).resolve()
    except OSError:  # pragma: no cover - resolve() on an unreadable cwd
        return candidates
    accepted = _project_directories_of(here, _ROOT_PACKAGE)
    ours = [dist for dist in candidates if _ships_this_module(dist, here, accepted)]
    return ours or candidates


def _requirements_declared(dist_name: str) -> List[Optional[List[str]]]:
    """The ``Requires-Dist`` lists to search for ``dist_name``, one per
    distribution read (``_distributions_to_read``), or the by-name read's."""
    chosen = _distributions_to_read(dist_name)
    if not chosen:
        return [requires(dist_name)]
    declared: List[Optional[List[str]]] = []
    for dist in chosen:
        try:
            declared.append(dist.requires)
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            ASH_LOGGER.debug(
                f"Could not read requirements from a distribution named "
                f"{dist_name!r}; skipping that copy.",
                exc_info=exc,
            )
    return declared


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
    extra cannot mask a good one; where two carry one name, the one that ships
    this module is read alone (``_distributions_to_read``), so a stale copy's
    older bounds do not merge into the current extra. Each requirement is
    returned without its ``extra`` clause and with the rest of its marker
    (``_without_extra_clause``): pip evaluates markers with ``extra`` undefined,
    so a requirement still carrying ``extra == "cdk"`` is skipped while pip
    exits 0, and one stripped of its ``python_version`` clause is installed
    where the extra never meant it.
    """
    marker = _extra_marker(extra)
    accumulated: List[str] = []

    for dist_name in _distributions_declaring_this_module(_ROOT_PACKAGE):
        try:
            declared_lists = _requirements_declared(dist_name)
        except (PackageNotFoundError, OSError, ValueError) as exc:
            ASH_LOGGER.debug(
                f"Could not read requirements from distribution {dist_name!r} "
                f"providing {_ROOT_PACKAGE!r}; skipping it.",
                exc_info=exc,
            )
            continue
        for declared in declared_lists:
            if declared is None:
                continue
            for requirement in declared:
                if not marker.search(requirement):
                    continue
                kept = _without_extra_clause(requirement, extra)
                # Deduplicated in place rather than through a set, so the order the
                # metadata declares is the order pip receives and a logged command
                # does not vary run to run.
                if kept and kept not in accumulated:
                    accumulated.append(kept)

    return accumulated or None


def _direct_url() -> Any:
    """The parsed PEP 610 ``direct_url.json`` of ASH's distribution, or None.

    None means the install left no record (an install from an index writes
    none), the distribution could not be found or read, or the file does not
    parse. Only the first distribution located for this module is read. A second
    one (a fork installed beside ASH, an old dist-info left behind) describes
    another install, so its record is never used in place of the first one's,
    even when the first one has none. Where two dist-infos carry the first
    name, the one that ships this module is the one read
    (``_distributions_to_read``), not whichever ``sys.path`` lists first.
    """
    located = _distributions_declaring_this_module(_ROOT_PACKAGE)
    if not located:
        return None
    try:
        chosen = _distributions_to_read(located[0])
        source = chosen[0] if chosen else distribution(located[0])
        raw = source.read_text("direct_url.json")
    except (PackageNotFoundError, OSError, ValueError, TypeError, AttributeError):
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _without_credentials(url: str) -> Optional[str]:
    """``url`` with any user and password removed from its authority, or None.

    PEP 610 tells installers to strip credentials before recording a URL, and
    pip and uv do. A hint is printed into logs, so it does not rely on that.
    A user name with no password on an ssh URL is the ssh convention for which
    account to log in as (``git@``, or a deployment account a host requires), not
    a credential, and is kept: a hint stripped of it could not authenticate.
    Over http(s) a user name alone can be a token, so it is stripped there.
    None for a URL that does not parse, such as an unterminated IPv6 host or a
    port outside 0-65535: uv refuses those too, and the hint is built while
    something else is being reported, so it must not raise.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.username is None and parts.password is None:
        return url
    if parts.password is None and (
        parts.username == "git" or parts.scheme.lower() in _SSH_SCHEMES
    ):
        return url
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    return urlunsplit(parts._replace(netloc=host))


def _remote_archive(url: str) -> Optional[str]:
    """The URL to name for an archive installed from ``url``, or None.

    Only http and https with a host: uv reads any other scheme as a relative
    path or refuses it. A scheme is case-insensitive, but uv reads ``HTTPS://``
    as a relative path too, so the URL is rebuilt with the scheme in lower case.
    The query is dropped: a presigned or tokened archive URL carries its
    credential there (a signature, an access token), and the hint is printed
    into logs. A query is no part of naming an archive, and one whose query
    was its credential has expired by the time anyone reads the hint anyway.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return _without_credentials(urlunsplit(parts._replace(query="")))


def _recorded_source(record: Any) -> Optional[Tuple[str, str]]:
    """``(kind, source)`` for a PEP 610 record, or None if it cannot be used.

    ``kind`` is ``"url"`` for a git commit or an archive (a local archive as a
    ``file:`` URL), ``"path"`` for a local directory, and ``"editable"`` for an
    editable directory. A record without the field its kind needs (a git record
    with no commit, a directory record whose URL is not a local path) is
    unusable rather than guessed at, and so is a local directory, archive or
    clone that no longer exists: the container image installs ASH from a wheel
    and then deletes it, and a ``git+file://`` install names a clone that can
    be gone the same way. A URL uv could not fetch is unusable too: a remote
    archive that is not http or https with a host, or any URL that does not
    parse. A local path this process cannot stat (Python 3.10-3.12 re-raise
    EACCES from ``is_dir`` and ``is_file``) is unusable rather than an error:
    the hint is built while something else is being reported.
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
        clone = _local_path_from_file_url(url)
        if clone is not None and not _is_dir(clone):
            # A clone on this host that is gone, as a local directory or archive
            # record is checked below; the remote spelling is checked by uv.
            return None
        remote = _without_credentials(url)
        if remote is None:
            return None
        source = f"{vcs}+{remote}@{commit}"
        subdirectory = record.get("subdirectory")
        if isinstance(subdirectory, str) and subdirectory:
            source = f"{source}#subdirectory={subdirectory}"
        return "url", source

    local = _local_path_from_file_url(url)
    dir_info = record.get("dir_info")
    if isinstance(dir_info, dict):
        if local is None or not _is_dir(local):
            return None
        return ("editable" if dir_info.get("editable") is True else "path"), str(local)

    if isinstance(record.get("archive_info"), dict):
        if local is not None:
            return ("url", local.as_uri()) if _is_file(local) else None
        remote = _remote_archive(url)
        return ("url", remote) if remote is not None else None
    return None


#: URL schemes whose user name is the account to log in as, never a credential.
_SSH_SCHEMES = frozenset({"ssh", "git+ssh", "ssh+git", "git"})


def _is_dir(path: Path) -> bool:
    """``path.is_dir()``, False for a path this process cannot stat."""
    try:
        return path.is_dir()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    """``path.is_file()``, False for a path this process cannot stat."""
    try:
        return path.is_file()
    except OSError:
        return False


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


def _uv_pip_install() -> str:
    """``<python> -P -m uv pip install --no-config --python <python>`` for the
    running interpreter.

    A hint is copied and run where the operator stands, which is usually the
    repository being scanned. ``--no-config`` keeps uv from reading that
    repository's ``uv.toml`` or ``pyproject.toml`` (an index URL there would
    choose where the packages come from). ``-P`` keeps the interpreter from
    putting the working directory first on ``sys.path`` for the ``-m uv``
    import, so a ``uv`` module in the repository is not the one that runs; it
    exists from Python 3.11, and the hint names the interpreter that is running,
    so it is printed only when that interpreter accepts it.
    """
    python = shlex.quote(sys.executable)
    safe_path = " -P" if sys.version_info >= (3, 11) else ""
    return f"{python}{safe_path} -m uv pip install --no-config --python {python}"


def install_command(*requirements: str) -> str:
    """The command that installs ``requirements`` into the environment ASH runs in."""
    return f"{_uv_pip_install()} {shlex.join(requirements)}"


def ash_reinstall_command() -> str:
    """The command that reinstalls the running ASH from where it came from.

    Only ASH itself is reinstalled (``--reinstall-package``); a dependency that is
    missing is installed with it, and the others are left as they are.
    """
    return (
        f"{_uv_pip_install()} --reinstall-package {ASH_DISTRIBUTION_NAME} "
        f"{ash_install_arguments()}"
    )


def extra_install_command(extra: str) -> str:
    """The command that installs ASH's ``extra`` into the running install.

    Names the extra's packages, read from the running distribution's metadata,
    so it installs what this ASH declares whatever its version or source. Only
    when that metadata cannot be read does it fall back to reinstalling this
    ASH from its own source with the extra.
    """
    declared = extra_requirements_from_metadata(extra)
    if declared:
        return install_command(*declared)
    return f"{_uv_pip_install()} {ash_install_arguments(extra)}"
