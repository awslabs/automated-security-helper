#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Install one of ASH's pinned scanner binaries during the container build.

Why this exists
---------------
The image provisioned syft, grype and trivy by piping each vendor's install script
into a shell::

    RUN with-retry 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/${SYFT_VERSION}/install.sh | sh -s -- -b /usr/local/bin ${SYFT_VERSION}'

``utils/tool_downloads.py`` already names that as the alternative it rejected, and
names the container image as the place still doing it. Piping a remote script into
a shell gives the endpoint arbitrary code execution at build time and pins
nothing, in an image whose whole subject is supply-chain risk.

It also cost the merge queue a run. On run 35246976698 the anchore installer could
not resolve ``get.anchore.io`` (it logged ``HTTP status=000``), fell back to
``github.com``, received the 302 that every GitHub release download answers with,
and treated that 302 as a failure. The tarball was therefore never written, its
checksum "did not verify" against a file that did not exist, and ``RUN syft
--version`` failed the build with exit 127. All three attempts went that way.
Fetching the release asset directly with a client that follows redirects drops two
of the four hosts involved -- ``raw.githubusercontent.com`` for the bootstrap
script and ``get.anchore.io`` for the versioned one -- and drops the
redirect-handling in a third party's shell script along with them.

Why this does not call install_pinned_tool()
--------------------------------------------
``utils/download_utils.install_pinned_tool`` is the same operation and is the
obvious thing to reuse. Importing it pulls in 19 ASH modules, ``plugin_base``,
``plugin_manager`` and the pydantic-backed config among them, so it cannot run
until the ASH wheel is installed. In the Dockerfile that wheel lands *after* these
three tools, and moving it earlier would put the tool-download layers downstream
of every source change: the three binaries would be re-fetched on every image
build instead of almost never, which increases exposure to precisely the network
failure described above.

So this shares the pins rather than the code. ``utils/tool_downloads.py`` stays
the single authority for versions, URLs and digests. It is loaded here by path
rather than by package import because ``automated_security_helper/__init__.py``
imports ``toml``, and at this point in the build nothing is installed.

What was rejected
-----------------
1. Duplicating the digests into the Dockerfile as literals. Two copies of a
   checksum drift, and the one in the Dockerfile is the one no test reads.
2. Generating a committed manifest from the table, with a freshness gate. It
   works, and it is a second artifact carrying the same 16 digests for no gain
   over reading the table directly.
3. ``curl`` plus ``sha256sum -c`` in the ``RUN`` line, with this script only
   emitting the url/digest pairs. That splits the verification away from the
   resolution, and shell has no equivalent of the exactly-one-member rule below.

Known limitations
-----------------
* No install receipt is written. ``read_receipt``/``write_receipt`` live in
  ``download_utils``, unavailable here for the reason above. None is needed: the
  extracted executable is checked against its own pinned digest
  (``ToolAsset.executable_digest``) before it is moved into place, so anything
  that later finds this binary -- ``ash dependencies install`` does, and then
  leaves it alone rather than installing a second copy -- can verify it from the
  table alone, with no on-disk record to trust.
* Retries are the caller's job. ``with-retry`` wraps the invocation in the
  Dockerfile, which is why nothing here loops. A transient failure must therefore
  leave no partial file behind, which is why the extract goes to a temporary
  directory and only a verified binary is moved into place.
* A digest mismatch is fatal and is not retried, matching
  ``_is_transient_download_error``'s treatment of ``ToolDownloadIntegrityError``.
  Exit code 3 marks it, so a caller can tell it from a network failure.

License and notice files
------------------------
With ``ASH_THIRD_PARTY_DIR`` set, as the image's core stage sets it, installing a
tool also installs its license files from ``THIRD_PARTY_LICENSES`` in
``utils/tool_downloads.py``, and a tool with no entry there is refused. Two more
modes serve the same table::

    install-pinned-tool --licenses-only opengrep      # binary installed elsewhere
    install-pinned-tool --uv-tool-pins                # for `ash dependencies install`
    install-pinned-tool --verify-third-party          # last step of the core stage

``--uv-tool-pins`` prints the ``--config-overrides`` that make ``ash dependencies
install`` install each Python tool with a license entry (bandit, checkov, semgrep)
at exactly the entry's version. ``--licenses-only`` then reads those tools' license
files from the wheel's installed dist-info, found under ``uv tool dir``, falling
back to an entry's URL-pinned copy where the wheel ships none. The last mode checks
the built image against every entry and writes ``index.json``. A URL-pinned license
file that does not match its digest exits 3, like a binary, and so does a dist-info
file that does not match its RECORD.
"""

import argparse
import base64
import csv
import errno
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess  # nosec B404 - runs pinned executables' --version only
import sys
import sysconfig
import tarfile
import tempfile
import threading
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

# The two files this needs out of the ASH tree, relative to the package root.
_PINS_MODULE = ("utils", "tool_downloads.py")
_EXCEPTIONS_MODULE = ("core", "exceptions.py")

# Exit codes. Distinguished so the Dockerfile's `with-retry` wrapper is not the
# only thing that knows a failure happened, and so an integrity failure is
# legible as such in a build log rather than reading as another dropped
# connection.
#
# _EXIT_USAGE marks a request that cannot succeed as written: a tool or bundle
# the table does not pin, a platform it has no asset for, a table entry that is
# half-applied. A second attempt gets the same answer.
#
# _EXIT_INTEGRITY marks bytes or a transport that is not what the table pinned: a
# digest mismatch, an archive layout the installer refuses, a redirect off https.
# with-retry's default no-retry list is exactly these two statuses.
_EXIT_USAGE = 2
_EXIT_INTEGRITY = 3
# Seconds a download socket may stay silent before the attempt fails. Per read,
# not for the whole transfer, so a slow but moving download is never cut, while
# a stalled one ends and with-retry gets its next attempt.
_DOWNLOAD_TIMEOUT = 60

# platform.machine() spellings mapped onto the arch vocabulary tool_downloads.py
# uses. Both x86 spellings appear in the wild; arm64 is what macOS reports and
# aarch64 is what Linux reports for the same processor.
_ARCH_ALIASES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


def _refuse(message: str, code: int) -> SystemExit:
    """Print ``message`` and return a ``SystemExit`` that leaves with ``code``.

    ``raise SystemExit(message)`` prints the message but always exits 1, the same
    status as a dropped connection, so with-retry tries again at a refusal that
    no retry can change. ``SystemExit(code)`` exits right and prints nothing.
    This does both, and keeps the message as the exception's text for a caller
    that reads it.
    """
    print(message, file=sys.stderr)
    request = SystemExit(message)
    request.code = code
    return request


def _load_by_path(name: str, path: Path):
    """Import one module from an explicit path, without importing its package.

    ``importlib`` rather than ``__import__`` because the package's ``__init__``
    imports toml, which is not installed at this point in the container build.
    The module is registered in ``sys.modules`` under ``name`` before it is
    executed, so ``tool_downloads``'s own ``from automated_security_helper.core
    .exceptions import ...`` resolves to the module loaded here and not to a stub.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# The sys.modules keys load_pins has to occupy while it executes tool_downloads.py,
# and therefore the keys it has to put back afterwards.
_BORROWED_MODULES = (
    "automated_security_helper",
    "automated_security_helper.core",
    "automated_security_helper.core.exceptions",
    "automated_security_helper.utils.tool_downloads",
)

# Held for the whole of load_pins. The save and restore below are a read and a
# write of process-global state: two overlapping calls would each save the other's
# path-loaded modules as the originals, and the later restore would put them back
# for good.
_LOAD_PINS_LOCK = threading.Lock()


def load_pins(package_root: Path):
    """Load ``tool_downloads`` and the exception module it imports.

    ``package_root`` is the ``automated_security_helper`` directory, whether that
    is a checkout or the handful of files copied into the image.

    ``sys.modules`` is restored before returning, and that is not tidiness. The
    real ``automated_security_helper.core.exceptions`` may already be imported --
    it is whenever anything other than the container build calls this -- and
    leaving a second, path-loaded copy registered under that name gives the
    process two distinct ``ScannerError`` classes. Measured: with the entries left
    in place, ``tests/unit/plugin_modules/scanners/test_grep_scanner_base.py``
    failed with the exception it was asserting on escaping ``pytest.raises``,
    because the class the test imported was no longer the class the code raised.
    Under xdist that reached any test sharing the worker, so the damage landed in
    a module this file has nothing to do with.

    The returned module keeps working after the restore: it has already executed,
    and its globals hold a direct reference to the exception class rather than
    looking it up again.

    Calls are serialized by a lock, because overlapping ones corrupt each other's
    restore (see ``_LOAD_PINS_LOCK``). The lock does not keep an unrelated thread
    from importing one of these names while a call is running, so a program that
    starts threads of its own should load the pins before it does.
    """
    with _LOAD_PINS_LOCK:
        saved = {name: sys.modules.get(name) for name in _BORROWED_MODULES}

        try:
            # Namespace packages for the two parents, so the dotted names
            # tool_downloads imports under exist without executing any real
            # __init__ -- which is the thing that needs toml.
            for parent in (
                "automated_security_helper",
                "automated_security_helper.core",
            ):
                if parent not in sys.modules:
                    sys.modules[parent] = importlib.util.module_from_spec(
                        importlib.machinery.ModuleSpec(parent, None, is_package=True)
                    )

            _load_by_path(
                "automated_security_helper.core.exceptions",
                package_root.joinpath(*_EXCEPTIONS_MODULE),
            )
            return _load_by_path(
                "automated_security_helper.utils.tool_downloads",
                package_root.joinpath(*_PINS_MODULE),
            )
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module


def default_package_root() -> Path:
    """Where to find the pinned table.

    ``ASH_PINS_DIR`` first, which is what the Dockerfile sets, then the checkout
    layout inferred from this file's own location -- assets/ and utils/ are
    siblings -- so the script is runnable and testable straight from a clone with
    no environment set up.
    """
    from_env = os.environ.get("ASH_PINS_DIR")
    if from_env:
        return Path(from_env)
    return Path(__file__).resolve().parent.parent


def resolve_arch(machine: str) -> str:
    """Map ``platform.machine()`` onto an arch name the pinned table uses."""
    try:
        return _ARCH_ALIASES[machine.lower()]
    except KeyError:
        raise _refuse(
            f"unsupported machine {machine!r}; "
            f"known: {', '.join(sorted(set(_ARCH_ALIASES)))}",
            _EXIT_USAGE,
        )


def _plain_url(url: str) -> str:
    """``url`` as scheme://host[:port]/path, for a message.

    The query string, the fragment, any user name or password and the ``;parameters``
    of a path segment are left out: on a signed download URL they carry the
    credential. The port stays, because ``http://host:8080/x`` and ``http://host/x``
    are different servers. A URL that does not parse is replaced, not echoed and not
    raised on, and the result is cut at 200 characters.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable URL>"
    host = parts.netloc.rpartition("@")[2]
    # urlsplit leaves ``;params`` in the path, on the segment that carries them.
    path = "/".join(segment.partition(";")[0] for segment in parts.path.split("/"))
    return f"{parts.scheme}://{host}{path}"[:200]


def _plain_reason(reason: object) -> str:
    """A server's status text, cut to 80 characters and kept to printable ASCII.

    The text after the status code is the server's, up to the 64 KiB http.client reads
    for a line, and it may hold carriage returns or terminal escapes that would reach
    a build log as they are.
    """
    return "".join(
        char for char in str(reason)[:80] if char.isascii() and char.isprintable()
    )


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to an https URL.

    Every URL this script fetches is checked for https before the request. A
    redirect is a second request the check never saw, and urllib follows one to
    http:// as readily as to https://.

    A refused redirect leaves with ``_EXIT_INTEGRITY``. It used to escape as an
    ``HTTPError``, a traceback with status 1, which with-retry answers by fetching
    the same URL, and being sent to plain http, again. Both URLs in the message, the
    one that answered and the one it named, are printed through ``_plain_url``: a
    signed download URL carries its credential in the query string, and on a chain
    of redirects the request that answered is itself a signed URL. The status text
    the server sent is printed through ``_plain_reason``.
    """

    @staticmethod
    def _refuse_unless_https(req, code, msg, newurl):
        try:
            scheme = urllib.parse.urlsplit(newurl).scheme.lower()
        except ValueError:
            scheme = ""
        if scheme != "https":
            raise _refuse(
                f"{_plain_url(req.full_url)} answered {code} {_plain_reason(msg)}: "
                "refusing a "
                f"redirect to the non-https URL {_plain_url(newurl)}",
                _EXIT_INTEGRITY,
            )

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._refuse_unless_https(req, code, msg, newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(self, req, fp, code, msg, headers):
        """Check the Location before urllib's own handler reads it.

        ``HTTPRedirectHandler.http_error_302`` refuses a scheme outside http,
        https and ftp (``file:``, ``data:``, ``gopher:``) before it ever calls
        ``redirect_request``, by raising an ``HTTPError`` that names the whole
        Location, query included, and leaves as a traceback with status 1. The
        Location is joined to the request URL here, as urllib will join it, and
        anything but https leaves through the refusal in ``redirect_request``.
        """
        location = headers.get("location") or headers.get("uri")
        if location:
            try:
                target = urllib.parse.urljoin(req.full_url, location)
            except ValueError:
                target = location
            self._refuse_unless_https(req, code, msg, target)
        return super().http_error_302(req, fp, code, msg, headers)

    # urllib binds these names to its own http_error_302, so each has to be bound
    # again here. 308 is an alias only from Python 3.11; binding it on every version
    # keeps the scheme check on all of them.
    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def download(url: str, target: Path) -> str:
    """Fetch ``url`` to ``target`` and return the SHA256 of what landed.

    urllib follows redirects, which is the behaviour the vendor install script
    lacked: a GitHub release download always answers 302 to
    objects.githubusercontent.com, and treating that as an error is what left the
    build with no tarball and a checksum failure against a missing file. Only
    redirects to https are followed; one to anything else exits
    ``_EXIT_INTEGRITY`` (``_HttpsOnlyRedirects``).

    Hashed while streaming rather than by re-reading the file, so the digest
    describes the bytes that were written and not whatever is at the path
    afterwards.

    A socket that stops answering raises after ``_DOWNLOAD_TIMEOUT`` seconds
    instead of hanging: urlopen with no timeout waits forever, and with-retry
    cannot retry an attempt that never ends. A response cut short of its
    Content-Length is a network failure too, and is raised as one: written to
    the file and returned, the short body was reported as a SHA256 mismatch and
    took the integrity exit that with-retry must never retry, for a cause that
    a retry is exactly the cure for.
    """
    digest = hashlib.sha256()
    written = 0
    opener = urllib.request.build_opener(_HttpsOnlyRedirects)
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with opener.open(url, timeout=_DOWNLOAD_TIMEOUT) as response:  # nosec B310 - https enforced by the callers and on redirects
        expected = response.headers.get("Content-Length")
        with target.open("wb") as handle:
            for chunk in iter(lambda: response.read(1024 * 256), b""):
                digest.update(chunk)
                handle.write(chunk)
                written += len(chunk)
    if expected is not None and expected.strip().isdigit():
        if written != int(expected):
            raise ConnectionError(
                f"short read from {url}: {written} of {expected} bytes arrived "
                "before the connection closed"
            )
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_member(archive: Path, member_name: str, destination: Path) -> None:
    """Extract the single archive member called ``member_name`` to ``destination``.

    Matched on basename, and exactly one match is required. That is the rule
    ``ToolAsset.member_name`` documents: a vendor moving the binary from the
    archive root into a subdirectory keeps working, while an archive holding two
    entries of that name is rejected instead of resolved by whichever came first.
    """
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            # Files only, as the tar branch below: a directory entry that happens
            # to carry the member's name is not a second copy of the executable.
            entries = [
                i
                for i in bundle.infolist()
                if not i.is_dir() and Path(i.filename).name == member_name
            ]
            _require_exactly_one(entries, member_name, archive)
            with bundle.open(entries[0]) as source, destination.open("wb") as handle:
                shutil.copyfileobj(source, handle)
        return

    with tarfile.open(archive) as bundle:
        members = [
            m
            for m in bundle.getmembers()
            if m.isfile() and Path(m.name).name == member_name
        ]
        _require_exactly_one(members, member_name, archive)
        source = bundle.extractfile(members[0])
        if source is None:
            raise _refuse(
                f"{member_name} in {archive.name} is not readable", _EXIT_USAGE
            )
        with source, destination.open("wb") as handle:
            shutil.copyfileobj(source, handle)


def _require_exactly_one(matches: list, member_name: str, archive: Path) -> None:
    if not matches:
        raise _refuse(
            f"{archive.name} contains no member named {member_name}", _EXIT_USAGE
        )
    if len(matches) > 1:
        raise _refuse(
            f"{archive.name} contains {len(matches)} members named {member_name}; "
            "refusing to guess which one is the executable",
            _EXIT_USAGE,
        )


def install(
    tool: str,
    bin_dir: Path,
    package_root: Path,
    third_party_dir: "Path | None" = None,
) -> Path:
    """Install ``tool`` into ``bin_dir``, and its license files if asked to.

    With ``third_party_dir`` set, the tool's license and notice files go to
    ``third_party_dir/<tool>/`` once the executable has been extracted and
    checked, and before it is moved into place, so the executable never lands
    without them, a failed extraction leaves no license directory behind, and a
    tool with no license entry is refused. ``main`` sets it from
    ``ASH_THIRD_PARTY_DIR``, which the image's core stage declares.
    """
    pins = load_pins(package_root)
    arch = resolve_arch(platform.machine())
    target_platform = {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(
        platform.system().lower(), platform.system().lower()
    )
    try:
        asset = pins.get_tool_asset(tool, target_platform, arch)
    except pins.ToolNotProvisionableError as exc:
        raise _refuse(str(exc), _EXIT_USAGE)
    # Resolved before anything is downloaded, so a tool with no license entry, or
    # one whose entry names another version, fails without fetching 80 MB first.
    entry = (
        _third_party_entry(pins, tool, asset.version)
        if third_party_dir is not None
        else None
    )

    if not asset.url.startswith("https://"):
        raise _refuse(f"refusing a non-https asset URL: {asset.url}", _EXIT_USAGE)

    bin_dir.mkdir(parents=True, exist_ok=True)
    final = bin_dir / asset.install_as
    if final.is_dir() and not final.is_symlink():
        # Refused before the download: nothing placed beside the name can make
        # this a file, and moving the binary inside the directory would report
        # success at a path nothing runs.
        raise _refuse(
            f"refusing to install {asset.tool} over {final}: it is a directory",
            _EXIT_USAGE,
        )
    # getattr: an older table has no executable digests, and then there is nothing
    # to check the extracted member against.
    executable_digest = getattr(asset, "executable_digest", None)

    if (
        executable_digest
        and not final.is_symlink()
        and final.is_file()
        and os.access(final, os.X_OK)
    ):
        try:
            installed_digest = _sha256_file(final)
        except OSError:
            # Executable but not readable (a mode such as 0111), or gone since
            # the check. Neither is a binary this call can vouch for, and the
            # install below replaces it.
            installed_digest = None
        if installed_digest == executable_digest.lower():
            # Not reinstalling is right only when everything this call would
            # install is in place. The license files come from the same archive,
            # so a matching binary with a missing or incomplete license directory
            # (an image layer rebuilt without ASH_THIRD_PARTY_DIR, an entry that
            # gained a file) used to return here and leave the directory as it was,
            # with no mode that repaired it.
            if entry is None or _third_party_installed(entry, third_party_dir):
                print(
                    f"{asset.tool} {asset.version} is already at {final} and matches "
                    f"the pinned SHA256 {executable_digest.lower()}; not reinstalling",
                    flush=True,
                )
                return final
            print(
                f"{asset.tool} {asset.version} is already at {final}, but its "
                f"license files under {third_party_dir} are missing or incomplete; "
                "reinstalling from the release archive to restore them",
                flush=True,
            )

    with tempfile.TemporaryDirectory(prefix="ash-pinned-tool-") as staging_name:
        staging = Path(staging_name)
        archive = staging / asset.url.rsplit("/", 1)[-1]
        print(f"Fetching {asset.tool} {asset.version} from {asset.url}", flush=True)
        actual = download(asset.url, archive)

        if actual.lower() != asset.sha256.lower():
            # Never retried: one mismatch on a pinned digest is disqualifying, and
            # retrying it would turn a supply-chain control into a coin flip.
            print(
                f"SHA256 mismatch for {asset.url}: "
                f"expected {asset.sha256.lower()}, got {actual.lower()}",
                file=sys.stderr,
            )
            raise SystemExit(_EXIT_INTEGRITY)
        print(f"Verified SHA256 {asset.sha256.lower()}", flush=True)

        staged_licenses = None
        if entry is not None and third_party_dir is not None:
            # From the archive just verified, so license files ride on the same
            # digest as the executable. getattr: a table from before
            # ToolAsset.archive existed holds archives only. Only staged here;
            # they are published below, once the executable has been extracted
            # and checked.
            source_archive = archive if getattr(asset, "archive", True) else None
            staged_licenses = stage_third_party(
                entry, source_archive, staging, installed_from=asset.url
            )

        staged = staging / asset.install_as
        # getattr, not attribute access: an image built from an older table whose
        # ToolAsset has no `archive` field is all archives.
        if getattr(asset, "archive", True):
            extract_member(archive, asset.member_name, staged)
            if executable_digest:
                extracted = _sha256_file(staged)
                if extracted != executable_digest.lower():
                    # The archive matched its pin, so this is a wrong executable digest
                    # in the table or an archive holding a different binary. Fatal for
                    # the same reason as the archive check: nothing could later prove
                    # the installed file is the pinned one.
                    print(
                        f"SHA256 mismatch for {asset.member_name} extracted from "
                        f"{asset.url}: expected {executable_digest.lower()}, "
                        f"got {extracted}",
                        file=sys.stderr,
                    )
                    raise SystemExit(_EXIT_INTEGRITY)
                print(f"Verified executable SHA256 {extracted}", flush=True)
        else:
            # The asset is the executable itself (opengrep), so the digest just
            # verified covers the exact bytes being installed, and it is also the
            # executable digest (ToolAsset.executable_digest falls back to it).
            archive.rename(staged)

        # The bytes are moved beside the destination first (the step that can run
        # out of space or hit a permission error), then the licenses are
        # published, then a single rename puts the executable at its name. Only
        # that rename sits between the two writes: a copy that fails leaves the
        # old binary and the old license directory exactly as they were.
        partial = _prepare_executable(staged, final)
        try:
            if staged_licenses is not None and third_party_dir is not None:
                # After the executable is extracted and its digest checked, so a
                # failure there leaves no license directory for a release that
                # was not installed; before the executable is placed, so it never
                # lands without them.
                publish_third_party(staged_licenses, third_party_dir)
            _commit_executable(partial, final)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise

    print(f"Installed {asset.tool} {asset.version} to {final}", flush=True)
    return final


def _prepare_executable(staged: Path, final: Path) -> Path:
    """Put the verified ``staged`` file beside ``final``, ready to be renamed onto it.

    ``staged`` is in the system temp directory, which can be another filesystem
    than ``final``'s. ``shutil.move`` then copies across in place: it truncates
    and rewrites ``final``, through a symlink there onto the link's target, and an
    interrupt leaves a half-written executable where the next layer runs it. So
    the bytes go to a file beside ``final`` first, and ``_commit_executable``
    renames only that file over it. The rename replaces a symlink with the new
    file instead of writing through it.

    The bytes are always copied, never renamed from ``staged``, even when both
    directories share a filesystem. The file beside ``final`` is created by
    ``mkstemp`` in ``final.parent``, so it gets that directory's SELinux label,
    default ACLs and setgid group; a file renamed in from the staging directory
    would keep that directory's label (``tmp_t`` or ``user_tmp_t``) and none of
    the others, and on an SELinux-enforcing host a binary installed to
    ``/usr/local/bin`` that way can be refused by a confined domain until
    ``restorecon`` is run on it. The cost is one more read and write of the 80 MB
    at install time. Returns the file beside ``final``, or leaves nothing behind
    and raises.
    """
    descriptor, partial_name = tempfile.mkstemp(
        prefix=f".{final.name}.", suffix=".partial", dir=final.parent
    )
    os.close(descriptor)
    partial = Path(partial_name)
    try:
        shutil.copyfile(staged, partial)
        partial.chmod(0o755)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return partial


def _commit_executable(partial: Path, final: Path) -> None:
    """Rename ``partial``, made by ``_prepare_executable``, over ``final``."""
    os.replace(partial, final)


# Must match automated_security_helper/utils/rules_bundles.py: the image installs a
# bundle with this script, and `ash dependencies install` later checks what it wrote
# against the same pinned contents to decide the bundle is already in place.
# tests/unit/utils/test_rules_bundles.py installs one fake bundle both ways and
# asserts the two directories are identical. The manifest is a record, not part of
# that check; the image's license step reads the installed version from it.
_RULES_MANIFEST_NAME = ".ash-rules-manifest.json"
_SAFE_MEMBER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 128 * 1024 * 1024


def _bundle_members(bundle_zip: zipfile.ZipFile, bundle) -> "list[tuple]":
    """(ZipInfo, basename) for every rule file in the bundle, refusing unsafe names.

    The same selection rules_bundles.extract_bundle applies: regular files directly
    inside ``member_dir`` ending in ``member_suffix``, each written to its basename,
    so no path from the archive is used as a destination.
    """
    members = []
    seen: "dict[str, str]" = {}
    for info in bundle_zip.infolist():
        if info.is_dir():
            continue
        parts = info.filename.replace("\\", "/").split("/")
        if len(parts) != 2 or parts[0] != bundle.member_dir:
            continue
        name = parts[1]
        if not name.endswith(bundle.member_suffix):
            continue
        # These refusals exit _EXIT_INTEGRITY, like the in-process installer's
        # ToolDownloadIntegrityError for the same archives. The archive already
        # matched its pinned digest, so a bad layout is the same on every attempt
        # and with-retry must not repeat it.
        if not _SAFE_MEMBER_NAME.match(name):
            raise _refuse(
                f"bundle member {info.filename!r} has an unsafe name", _EXIT_INTEGRITY
            )
        # Names are compared with case folded, as extract_bundle does: on a
        # case-insensitive filesystem the second of "Rules.guard" and "rules.guard"
        # would be written over the first.
        if name.lower() in seen:
            raise _refuse(
                f"bundle holds two members named {seen[name.lower()]} and {name}",
                _EXIT_INTEGRITY,
            )
        if info.file_size > _MAX_MEMBER_BYTES:
            raise _refuse(f"bundle member {name} is over the size cap", _EXIT_INTEGRITY)
        seen[name.lower()] = name
        members.append((info, name))
    if not members:
        raise _refuse(
            f"bundle holds no {bundle.member_suffix} files under {bundle.member_dir}/",
            _EXIT_INTEGRITY,
        )
    return members


def contents_digest(files: "dict[str, str]") -> str:
    """rules_bundles.contents_digest: what ``RulesBundle.contents_sha256`` pins.

    The SHA256 of one ``"<basename>\\t<sha256>\\n"`` line per file, sorted by
    basename.
    """
    lines = "".join(
        f"{name}\t{digest.lower()}\n" for name, digest in sorted(files.items())
    )
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def _installed_rule_files(
    directory: Path, suffix: str
) -> "tuple[dict[str, str], str | None]":
    """rules_bundles._installed_members: the rule files in ``directory``, hashed.

    Every entry whose name ends in ``suffix``; one that is not a regular file, or
    whose name the installer would not write, is the problem returned. Other names,
    the manifest among them, are not opened.
    """
    members: "dict[str, str]" = {}
    try:
        with os.scandir(directory) as listing:
            entries = sorted(listing, key=lambda entry: entry.name)
    except OSError as exc:
        return members, f"{directory} could not be read ({exc})"
    for entry in entries:
        if not entry.name.endswith(suffix):
            continue
        path = directory / entry.name
        if not _SAFE_MEMBER_NAME.match(entry.name):
            return members, f"{path} has a name the installer does not write"
        if not entry.is_file(follow_symlinks=False):
            return members, f"{path} is not a regular file"
        try:
            members[entry.name] = _sha256_file(path)
        except OSError as exc:
            return members, f"{path} could not be read ({exc})"
    return members, None


def _bundle_matches_pin(directory: Path, bundle) -> bool:
    """Whether the rule files in ``directory`` are the bundle's pinned contents."""
    members, problem = _installed_rule_files(directory, bundle.member_suffix)
    return (
        problem is None and contents_digest(members) == bundle.contents_sha256.lower()
    )


def install_bundle(
    name: str,
    rules_dir: Path,
    package_root: Path,
    third_party_dir: "Path | None" = None,
) -> Path:
    """Install the pinned rules bundle ``name`` under ``rules_dir``.

    Verifies the archive against its pinned digest before reading it, extracts the
    rule files into a staging directory, checks them against the pinned contents,
    writes the manifest, and moves the staging directory into place with one rename.
    Extracted files that do not match the pinned contents exit ``_EXIT_INTEGRITY``
    and install nothing.

    With ``third_party_dir`` set (``ASH_THIRD_PARTY_DIR``, as for a tool), the
    bundle's license entry is resolved and its URL-pinned license files are
    fetched and checked before the rules are downloaded, and installed once the
    rules are checked, just before they are renamed into place. The rules never
    land without them, and a failed download leaves no license directory for a
    release that was not installed.

    Two installs of one bundle at once both end well: the one that loses the final
    rename finds the pinned rules already in place and reports success.
    """
    pins = load_pins(package_root)
    try:
        bundle = pins.get_rules_bundle(name)
    except pins.ToolNotProvisionableError as exc:
        raise _refuse(str(exc), _EXIT_USAGE)
    if not bundle.url.startswith("https://"):
        raise _refuse(f"refusing a non-https bundle URL: {bundle.url}", _EXIT_USAGE)
    entry = (
        _third_party_entry(pins, name, bundle.version)
        if third_party_dir is not None
        else None
    )

    rules_dir.mkdir(parents=True, exist_ok=True)
    final = rules_dir / f"{bundle.name}-{bundle.version}"
    staging = Path(tempfile.mkdtemp(prefix=".ash-rules-staging-", dir=rules_dir))
    license_scratch = None
    try:
        staged_licenses = None
        if entry is not None:
            license_scratch = Path(tempfile.mkdtemp(prefix="ash-third-party-"))
            staged_licenses = stage_third_party(
                entry, None, license_scratch, installed_from=bundle.url
            )
        with tempfile.TemporaryDirectory(prefix="ash-rules-download-") as dl:
            archive = Path(dl) / bundle.url.rsplit("/", 1)[-1]
            print(
                f"Fetching {bundle.name} {bundle.version} from {bundle.url}", flush=True
            )
            actual = download(bundle.url, archive)
            if actual.lower() != bundle.sha256.lower():
                print(
                    f"SHA256 mismatch for {bundle.url}: "
                    f"expected {bundle.sha256.lower()}, got {actual.lower()}",
                    file=sys.stderr,
                )
                raise SystemExit(_EXIT_INTEGRITY)
            print(f"Verified SHA256 {bundle.sha256.lower()}", flush=True)
            files = {}
            total = 0
            with zipfile.ZipFile(archive) as bundle_zip:
                for info, member in _bundle_members(bundle_zip, bundle):
                    digest = hashlib.sha256()
                    size = 0
                    with (
                        bundle_zip.open(info) as source,
                        (staging / member).open("xb") as handle,
                    ):
                        for chunk in iter(lambda: source.read(1024 * 256), b""):
                            size += len(chunk)
                            total += len(chunk)
                            if size > _MAX_MEMBER_BYTES or total > _MAX_TOTAL_BYTES:
                                raise _refuse(
                                    "bundle expands past the size cap", _EXIT_INTEGRITY
                                )
                            digest.update(chunk)
                            handle.write(chunk)
                    files[member] = digest.hexdigest()
        extracted = contents_digest(files)
        if extracted != bundle.contents_sha256.lower():
            # The archive matched its pin, so the selection above took other files
            # than the ones pinned: a changed layout, or a pin not updated with the
            # archive's. Fatal for the same reason as the archive check.
            print(
                f"the {len(files)} files extracted from {bundle.url} do not match "
                f"the pinned contents of {bundle.name} {bundle.version}: expected "
                f"{bundle.contents_sha256.lower()}, got {extracted}",
                file=sys.stderr,
            )
            raise SystemExit(_EXIT_INTEGRITY)
        print(f"Verified contents SHA256 {extracted}", flush=True)
        manifest = {
            "bundle": bundle.name,
            "version": bundle.version,
            "url": bundle.url,
            "sha256": bundle.sha256.lower(),
            "files": dict(sorted(files.items())),
        }
        (staging / _RULES_MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        # A directory: group/other need read and search (x) to load the rules, and
        # nothing beyond the owner may write. B103 flags any group x bit.
        os.chmod(staging, 0o755)  # nosec B103 - read-only rules directory
        for child in staging.iterdir():
            os.chmod(child, 0o644)
        if staged_licenses is not None and third_party_dir is not None:
            publish_third_party(staged_licenses, third_party_dir)
        if final.exists() or final.is_symlink():
            aside = Path(tempfile.mkdtemp(prefix=".ash-rules-old-", dir=rules_dir))
            try:
                os.replace(final, aside / "old")
            except FileNotFoundError:
                # A concurrent install of the same bundle moved it aside first.
                pass
            shutil.rmtree(aside, ignore_errors=True)
        try:
            os.replace(staging, final)
        except OSError:
            # A concurrent install of the same bundle renamed first, and a
            # directory cannot be renamed onto a populated one. If what is there
            # is the pinned rules, the install this call was asked for is done,
            # and its own copy is surplus.
            if not _bundle_matches_pin(final, bundle):
                raise
            shutil.rmtree(staging, ignore_errors=True)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        if license_scratch is not None:
            shutil.rmtree(license_scratch, ignore_errors=True)
    print(f"Installed {bundle.name} {bundle.version} to {final}", flush=True)
    return final


def installed_bundle_problem(
    name: str, rules_dir: Path, package_root: Path
) -> "str | None":
    """Why the bundle under ``rules_dir`` is not the pinned ``name``; None when it is.

    The same test as rules_bundles.verify_installed_bundle, which ``ash dependencies
    install`` makes before it skips a bundle: the pinned version's directory holds
    rule files whose ``contents_digest`` is the pinned ``contents_sha256``. The
    manifest beside them is not read. Nothing is downloaded. The nix shell runs this
    (``--check``) on every entry, so an ASH upgrade that bumps the pin reinstalls the
    rules instead of leaving only the previous release's directory, where the scanner
    does not look, and a rule file that no longer matches the pin is replaced.
    tests/unit/test_nix_cfn_guard_rules_reseed.py asks both functions about the same
    directories and requires the same answer.
    """
    pins = load_pins(package_root)
    try:
        bundle = pins.get_rules_bundle(name)
    except pins.ToolNotProvisionableError as exc:
        raise _refuse(str(exc), _EXIT_USAGE)
    directory = rules_dir / f"{bundle.name}-{bundle.version}"
    if not directory.is_dir():
        if directory.exists() or directory.is_symlink():
            return f"{directory} is not a directory"
        return f"{directory} does not exist"
    members, problem = _installed_rule_files(directory, bundle.member_suffix)
    detail = f" ({problem})" if problem else ""
    if problem or contents_digest(members) != bundle.contents_sha256.lower():
        return (
            f"the rules in {directory} do not match the pinned contents of "
            f"{bundle.name} {bundle.version}{detail}"
        )
    return None


# ---------------------------------------------------------------------------
# Third-party license and notice files
#
# What goes where, and the convention for copyleft tools, is documented beside
# the table these read: THIRD_PARTY_LICENSES in utils/tool_downloads.py.
# ---------------------------------------------------------------------------

# Set by the Dockerfile's core stage. Unset, `install-pinned-tool <tool>` installs
# the executable only, which is what the uv-reqs stage and a developer want.
_THIRD_PARTY_ENV = "ASH_THIRD_PARTY_DIR"
_THIRD_PARTY_MODES = ("--licenses-only", "--uv-tool-pins", "--verify-third-party")
_SOURCE_FILE = "SOURCE"
_INDEX_FILE = "index.json"
_VERSION_TIMEOUT_SECONDS = 120


def _plain_name(name: str, what: str) -> str:
    """Refuse a table value that would leave the directory it names a file in."""
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise _refuse(f"refusing {what} {name!r}: not a plain file name", _EXIT_USAGE)
    return name


def _third_party_installed(entry, third_party_dir: Path) -> bool:
    """Whether ``third_party_dir`` holds every file ``entry`` installs for its tool.

    The directory ``publish_third_party`` writes: one file per entry in
    ``entry.files`` plus the SOURCE notice. An empty file counts as missing,
    the same way ``stage_third_party`` refuses to stage one.
    """
    installed = third_party_dir / entry.tool
    names = [license_file.name for license_file in entry.files] + [_SOURCE_FILE]
    return all(
        (installed / name).is_file() and (installed / name).stat().st_size > 0
        for name in names
    )


def _third_party_entry(pins, tool: str, version: "str | None" = None):
    """The license entry for ``tool``, refusing a missing or stale one."""
    try:
        entry = pins.get_third_party_license(tool)
    except pins.ToolNotProvisionableError as exc:
        raise _refuse(str(exc), _EXIT_USAGE)
    if version is not None and entry.version != version:
        raise _refuse(
            f"{tool} is pinned to {version} but its license entry records "
            f"{entry.version}. The files and source commit would describe another "
            f"release; a version bump is half-applied.",
            _EXIT_USAGE,
        )
    return entry


def uv_tool_dir() -> Path:
    """Where ``uv tool install`` put each tool's environment: ``uv tool dir``.

    Asked of uv rather than derived from ``$HOME``, because uv also honors
    ``UV_TOOL_DIR`` and ``XDG_DATA_HOME`` and is the authority on which applies.
    ``--color never`` because uv colors the path when ``FORCE_COLOR`` is set, even
    into a pipe, and the escape codes then become part of a path that does not
    exist.
    """
    uv = _on_absolute_path("uv")
    if uv is None:
        raise _refuse("`uv tool dir` failed: uv was not found on PATH", _EXIT_USAGE)
    try:
        result = subprocess.run(  # nosec B603 - uv is on PATH in every stage that runs this
            [uv, "--color", "never", "tool", "dir"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"`uv tool dir` failed: {exc}")
    location = result.stdout.strip()
    if result.returncode != 0 or not location:
        raise SystemExit(
            f"`uv tool dir` exited {result.returncode}: {result.stderr.strip()}"
        )
    return Path(location)


def _metadata_version(dist_info: Path) -> "str | None":
    """The ``Version:`` header of ``dist_info``'s METADATA."""
    with (dist_info / "METADATA").open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                break
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    return None


def find_dist_info(entry, tool_dir: Path) -> Path:
    """The installed dist-info of ``entry.distribution`` in its uv tool environment.

    Exactly one, at exactly the entry's version. Another version means ``ash
    dependencies install`` did not take the pin from ``--uv-tool-pins``, and the
    files and source commit would describe a release the image does not contain.
    """
    distribution = entry.distribution
    normalized = re.sub(r"[-_.]+", "_", distribution).lower()
    matches = sorted(
        (tool_dir / distribution).glob(
            f"lib/python*/site-packages/{normalized}-*.dist-info"
        )
    )
    matches = [m for m in matches if (m / "METADATA").is_file()]
    if len(matches) != 1:
        raise _refuse(
            f"expected one installed {distribution} dist-info under "
            f"{tool_dir / distribution}, found {len(matches)}: "
            f"{', '.join(str(m) for m in matches) or 'none'}. Is it installed with "
            "`uv tool install`?",
            _EXIT_USAGE,
        )
    installed = _metadata_version(matches[0])
    wanted = entry.version.lstrip("v")
    if installed != wanted:
        raise _refuse(
            f"{entry.tool}: {matches[0]} is version {installed}, but its license "
            f"entry records {entry.version}. `ash dependencies install` was run "
            "without `install-pinned-tool --uv-tool-pins`, or a version bump is "
            "half-applied.",
            _EXIT_USAGE,
        )
    return matches[0]


def _record_hashes(dist_info: Path) -> "dict[str, str]":
    """RECORD's ``sha256`` for each file, keyed by its path relative to the dist-info."""
    hashes: "dict[str, str]" = {}
    prefix = dist_info.name + "/"
    with (dist_info / "RECORD").open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if (
                len(row) >= 2
                and row[0].startswith(prefix)
                and row[1].startswith("sha256=")
            ):
                hashes[row[0][len(prefix) :]] = row[1][len("sha256=") :]
    return hashes


def _dist_info_member(
    dist_info: Path, name: str, record: "dict[str, str]"
) -> "Path | None":
    """``name`` as the wheel installed it, or None if the wheel ships no such file.

    PEP 639 wheels keep license files under ``licenses/``; older ones put them at
    the top of the dist-info. A file RECORD does not list, or lists with another
    hash, exits ``_EXIT_INTEGRITY``: it is not the file the wheel shipped.
    """
    for relative in (f"licenses/{name}", name):
        path = dist_info / relative
        if not path.is_file():
            continue
        expected = record.get(relative)
        actual = (
            base64.urlsafe_b64encode(bytes.fromhex(_sha256_of(path)))
            .rstrip(b"=")
            .decode("ascii")
        )
        if expected != actual:
            print(
                f"{path} does not match the hash its RECORD lists "
                f"(expected {expected}, got {actual})",
                file=sys.stderr,
            )
            raise SystemExit(_EXIT_INTEGRITY)
        return path
    return None


def stage_third_party(
    entry,
    archive: "Path | None",
    staging: Path,
    installed_from: "str | None",
    dist_info: "Path | None" = None,
) -> Path:
    """Assemble ``entry``'s directory under ``staging`` and return its path.

    Archive-member files are read from ``archive``, which the caller has already
    verified. With ``dist_info`` (an entry with a ``distribution``), every file
    the installed wheel ships is read from there instead, checked against the
    wheel's RECORD, and a URL-pinned one must still match its pin. URL files are
    otherwise fetched and must match their pinned digest; a mismatch exits
    ``_EXIT_INTEGRITY`` exactly like a binary's. Nothing is written outside
    ``staging``.
    """
    target = staging / "third-party" / _plain_name(entry.tool, "tool name")
    target.mkdir(parents=True)
    record = _record_hashes(dist_info) if dist_info is not None else {}
    for license_file in entry.files:
        destination = target / _plain_name(license_file.name, "license file name")
        shipped = (
            _dist_info_member(dist_info, license_file.name, record)
            if dist_info is not None
            else None
        )
        if shipped is not None:
            print(f"Copying {entry.tool} {license_file.name} from {shipped}")
            shutil.copyfile(shipped, destination)
            if license_file.sha256 and (
                _sha256_of(destination) != license_file.sha256.lower()
            ):
                print(
                    f"{shipped} does not match the SHA256 pinned for "
                    f"{license_file.url}. The wheel now ships this file itself; "
                    f"make the entry's {license_file.name} a plain "
                    f'LicenseFile("{license_file.name}") and drop its pin.',
                    file=sys.stderr,
                )
                raise SystemExit(_EXIT_INTEGRITY)
        elif license_file.from_archive and dist_info is not None:
            raise _refuse(
                f"{entry.tool}'s {license_file.name} is not in {dist_info}. Give it "
                "a URL pinned at the entry's commit instead.",
                _EXIT_USAGE,
            )
        elif license_file.from_archive:
            if archive is None:
                raise _refuse(
                    f"{entry.tool}'s {license_file.name} is read from its release "
                    f"archive, which only `install-pinned-tool {entry.tool}` has. "
                    "--licenses-only can install URL-pinned files only.",
                    _EXIT_USAGE,
                )
            extract_member(archive, license_file.name, destination)
        else:
            if not license_file.url.startswith("https://"):
                raise _refuse(
                    f"refusing a non-https URL: {license_file.url}", _EXIT_USAGE
                )
            if not license_file.sha256:
                # A URL file is trusted only by its digest. Without one there is
                # nothing to compare the download to, so it is refused before it
                # is fetched rather than after, with a clean message.
                raise _refuse(
                    f"{entry.tool}'s {license_file.name} has a URL but no pinned "
                    "SHA256, so nothing could verify what it fetches",
                    _EXIT_USAGE,
                )
            print(f"Fetching {entry.tool} {license_file.name} from {license_file.url}")
            actual = download(license_file.url, destination)
            if actual.lower() != license_file.sha256.lower():
                print(
                    f"SHA256 mismatch for {license_file.url}: expected "
                    f"{license_file.sha256.lower()}, got {actual.lower()}",
                    file=sys.stderr,
                )
                raise SystemExit(_EXIT_INTEGRITY)
        if destination.stat().st_size == 0:
            raise _refuse(f"{entry.tool}'s {license_file.name} is empty", _EXIT_USAGE)
    (target / _SOURCE_FILE).write_text(
        entry.source_notice(installed_from), encoding="utf-8"
    )
    return target


def _rename_or_copy(src: Path, dst: Path) -> None:
    """``os.replace(src, dst)``, falling back to copy-then-delete for a directory.

    On Docker overlay2 without ``redirect_dir``, renaming a directory that lives in
    a lower image layer fails with EXDEV, although ``dst`` is in the same tree. A
    reinstall over an earlier layer's license directory meets that. The fallback
    copies the directory to ``dst`` and then removes ``src``. A copy that fails is
    removed again, leaving ``src`` as it was; a removal that fails part way is
    made good from the copy, so one of the two names holds the whole directory.
    """
    try:
        os.replace(src, dst)
    except OSError as exc:
        if exc.errno != errno.EXDEV or src.is_symlink() or not src.is_dir():
            raise
        try:
            shutil.copytree(src, dst, symlinks=True)
        except BaseException:
            shutil.rmtree(dst, ignore_errors=True)
            raise
        try:
            shutil.rmtree(src)
        except BaseException:
            shutil.copytree(dst, src, symlinks=True, dirs_exist_ok=True)
            shutil.rmtree(dst, ignore_errors=True)
            raise


# Names the scratch directory publish_third_party works in, inside third_party_dir.
_PUBLISH_WORK_PREFIX = ".ash-third-party-"
# A file naming the tool, written into a work directory that is kept because the old
# entry in it may be the only complete copy. The next publish of that tool that
# finishes removes the directory, and verify_third_party reports one still there.
_PUBLISH_KEPT_MARKER = "KEPT"


def _remove_kept_work_dirs(third_party_dir: Path, final: Path, staged: Path) -> bool:
    """Delete the work directories an earlier publish of ``final.name`` kept.

    Called once a publish of the tool has put its new entry at ``final``, which
    supersedes the old copy those directories were kept for. Only a directory
    carrying the kept marker for this tool goes: another publish's work directory
    that is still in use has no marker. A directory that cannot be read or removed
    stays, and verify_third_party reports it.

    Nothing goes unless an entry stands at ``final`` now, or the files there are
    the ones this call staged. A concurrent publish of the same tool can have moved
    the entry this call placed aside and failed to put it back; the directory it
    kept then holds the only copy, and deleting it would leave the name empty with
    the install reported as done.

    Returns False when nothing stood at ``final`` and so no directory was looked at,
    True otherwise.
    """
    if not (_present(final, unknown=False) or _same_files(staged, final)):
        return False
    tool = final.name
    try:
        candidates = sorted(third_party_dir.iterdir())
    except OSError:
        return True
    for path in candidates:
        if not path.name.startswith(_PUBLISH_WORK_PREFIX):
            continue
        try:
            marked = (path / _PUBLISH_KEPT_MARKER).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if marked.strip() == tool:
            shutil.rmtree(path, ignore_errors=True)
    return True


def _same_files(first: Path, second: Path) -> bool:
    """Whether two directories hold the same plain files with the same bytes."""
    try:
        names = sorted(p.name for p in first.iterdir())
        if names != sorted(p.name for p in second.iterdir()):
            return False
        return all(
            (first / name).is_file()
            and (second / name).is_file()
            and (first / name).read_bytes() == (second / name).read_bytes()
            for name in names
        )
    except OSError:
        return False


def _present(path: Path, unknown: bool) -> bool:
    """Whether something (a link included) is at ``path``.

    ``unknown`` is the answer when asking raises, which the caller picks to fail
    safe: True where a missing answer must not lead to a delete, False where it
    must not be taken as proof of an entry.
    """
    try:
        return path.is_symlink() or path.exists()
    except OSError:
        return unknown


def publish_third_party(staged: Path, third_party_dir: Path) -> Path:
    """Move a staged tool directory into ``third_party_dir``, world-readable.

    The staging directory comes from ``tempfile``, which creates it 0700, and a
    file moved out of it keeps its mode. Set explicitly here, because the image's
    final stage runs as a non-root user who must be able to read these. An
    existing directory for the tool is replaced, not merged into, so a file
    dropped from an entry does not linger from an earlier layer.

    The new directory is copied beside the old one first, because ``staged`` can
    be on another filesystem than ``third_party_dir`` and a move across is a copy
    that can stop half way. The old entry (a directory, or a file or symlink put
    there by hand) is then renamed aside, not deleted, and the new directory is
    renamed into place; if that last rename fails, the old entry is put back.

    The work directory, and the old entry in it, is deleted only once that is safe,
    and anything unknown counts as unsafe. From the moment the old entry may be the
    only complete copy (the aside step has started) the directory is kept, and its
    path printed, if the call ends in an exception. It is released when the new
    entry has been renamed into place, when the old one has been restored, when an
    identical entry from a concurrent publish stands, or when an entry is confirmed
    at the name after a failed restore. A check that itself raises, or an aside step
    that fails twice (the EXDEV copy made, the removal stopped part way, the copy
    back failed), therefore keeps it.

    A kept directory is marked with the tool's name. with-retry runs the install
    again after the failure, and a later publish of the same tool that finishes
    removes the directories marked for it, because the old copy they hold is
    superseded by then, but only while an entry stands at the name. One that
    nothing removed is reported by
    verify_third_party, so it cannot ship unnoticed in the image.
    """
    third_party_dir.mkdir(parents=True, exist_ok=True)
    for path in staged.iterdir():
        path.chmod(0o644)
    staged.chmod(0o755)
    final = third_party_dir / staged.name
    work = Path(tempfile.mkdtemp(prefix=_PUBLISH_WORK_PREFIX, dir=third_party_dir))
    old = work / "old"
    # True while `old` may hold the only complete copy of the previous entry.
    old_at_risk = False
    try:
        incoming = work / "incoming"
        shutil.copytree(staged, incoming)
        incoming.chmod(0o755)
        if _present(final, unknown=True):
            old_at_risk = True
            try:
                _rename_or_copy(final, old)
            except FileNotFoundError:
                # A concurrent publish of this tool moved it aside first.
                old_at_risk = _present(old, unknown=True)
            except BaseException:
                # _rename_or_copy undoes its own half-made copy, which leaves
                # `final` whole and `old` gone. If it could not (the removal
                # stopped part way and the copy back failed), `old` is the whole
                # entry and `final` is not.
                old_at_risk = _present(old, unknown=True)
                raise
        try:
            os.replace(incoming, final)
            old_at_risk = False
        except BaseException as exc:
            # A concurrent publish of the same tool can have put its directory at
            # the name first, and a directory cannot be renamed onto a populated
            # one. The files are the same pinned files, so what is there is what
            # this call was asked to publish and its own copy is surplus.
            if isinstance(exc, OSError) and _same_files(incoming, final):
                old_at_risk = False
            else:
                if _present(old, unknown=True):
                    try:
                        _rename_or_copy(old, final)
                    except BaseException:
                        # Something confirmed at the name (a concurrent publish's
                        # entry) supersedes the old one. With nothing there, or no
                        # answer, `old` is all that is left of it.
                        old_at_risk = not _present(final, unknown=False)
                        raise
                old_at_risk = False
                raise
    finally:
        if old_at_risk:
            try:
                (work / _PUBLISH_KEPT_MARKER).write_text(
                    final.name + "\n", encoding="utf-8"
                )
            except OSError:
                pass
            print(
                f"the previous {final.name} license entry may exist only at {old}; "
                f"the publish to {final} did not finish, so that directory is kept",
                file=sys.stderr,
            )
        else:
            shutil.rmtree(work, ignore_errors=True)
    if not _remove_kept_work_dirs(third_party_dir, final, staged):
        print(
            f"no license entry stands at {final} now, so a directory kept for the "
            f"previous {final.name} entry stays in place; install {final.name} again",
            file=sys.stderr,
        )
    print(f"Installed {staged.name} license files to {final}", flush=True)
    return final


def install_licenses_only(tool: str, package_root: Path, third_party_dir: Path) -> Path:
    """Install ``tool``'s license files for a binary installed some other way.

    For opengrep, which ``ash dependencies install`` provisions later in the
    build, every file must be URL-pinned, because there is no archive here to
    read members from. For an entry with a ``distribution`` -- bandit, checkov,
    semgrep, which ``ash dependencies install`` has already installed with ``uv
    tool install`` -- the installed wheel's dist-info is the archive.
    """
    pins = load_pins(package_root)
    entry = _third_party_entry(pins, tool)
    dist_info = installed_from = None
    if entry.distribution:
        dist_info = find_dist_info(entry, uv_tool_dir())
        installed_from = (
            f"PyPI {entry.distribution}=={entry.version.lstrip('v')}, "
            "by `uv tool install`"
        )
    with tempfile.TemporaryDirectory(prefix="ash-third-party-") as staging_name:
        staged = stage_third_party(
            entry, None, Path(staging_name), installed_from, dist_info
        )
        return publish_third_party(staged, third_party_dir)


def uv_tool_pins(package_root: Path) -> "list[str]":
    """``ash dependencies install`` arguments pinning each Python tool to its entry.

    A scanner's own default is a range (semgrep's is ``>=1.125.0,<2.0.0``), so
    without these the image would carry whatever release PyPI had on the day,
    and the license entry's tag and commit would describe some other release.
    """
    pins = load_pins(package_root)
    argv: "list[str]" = []
    for tool in sorted(pins.THIRD_PARTY_LICENSES):
        entry = pins.THIRD_PARTY_LICENSES[tool]
        if entry.distribution:
            argv += [
                "--config-overrides",
                f"scanners.{entry.tool}.options.tool_version==="
                + entry.version.lstrip("v"),
            ]
    return argv


def reports_version(output: str, bare_version: str) -> bool:
    """Whether ``output`` names ``bare_version`` as a whole version number.

    Bounded on both sides, so 0.12.2 is not found inside 0.12.23 and 1.2 is not
    found inside 11.2. A suffix that makes it another build fails the match too:
    0.12.2rc1, 0.12.2-1, 3.1.2-dev, 1.125.0.post1, 1.2.3.dev0, 1.2.3.rc1 and
    1.2.3~rc1 are not 0.12.2, 3.1.2, 1.125.0 or 1.2.3. A dot that ends a sentence
    (``v2.12.0.``, ``1.2.3. Built``) is punctuation and does not.
    """
    pattern = (
        rf"(?<![0-9.]){re.escape(bare_version)}"
        r"(?![0-9A-Za-z_]|\.[0-9A-Za-z]|[-+~][0-9A-Za-z])"
    )
    return re.search(pattern, output) is not None


def version_output(executable: str, argv: "list[str] | None" = None) -> str:
    """``executable --version``'s combined output, run in a throwaway HOME.

    With ``argv``, that command is run instead (an entry's ``version_probe``).

    Throwaway because a version query is not always read-only. opengrep is a
    self-extracting bundle that unpacks 208 MB into ``$HOME/.cache/opengrep`` on
    first run; in the image build that landed in the verification layer and grew
    the image by 218 MB, measured, for a check that should add nothing.

    Decoded with ``errors="replace"``: a banner that is not valid text in the
    locale's encoding must reach ``reports_version`` as text, where it fails the
    version match, and not raise ``UnicodeDecodeError`` out of the verification.
    """
    with tempfile.TemporaryDirectory(prefix="ash-version-probe-") as scratch:
        env = dict(
            os.environ, HOME=scratch, XDG_CACHE_HOME=f"{scratch}/cache", TMPDIR=scratch
        )
        result = subprocess.run(  # nosec B603 - executable from the pinned table, resolved on PATH
            argv or [executable, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_VERSION_TIMEOUT_SECONDS,
            check=False,
            env=env,
        )
    return result.stdout + result.stderr


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()


def python_package_files(site_dirs: "list[str] | None" = None) -> "set[str]":
    """Real paths of every file a Python distribution's RECORD says it installed.

    ``site_dirs`` defaults to this interpreter's site-packages. A console script
    such as ``/usr/local/bin/uv`` from the uv wheel appears in RECORD as
    ``../../../bin/uv``, relative to the site-packages directory.
    """
    if site_dirs is None:
        paths = sysconfig.get_paths()
        site_dirs = sorted({paths["purelib"], paths["platlib"]})
    owned: "set[str]" = set()
    for site_dir in site_dirs:
        for record in Path(site_dir).glob("*.dist-info/RECORD"):
            with record.open(encoding="utf-8", errors="replace", newline="") as handle:
                for row in csv.reader(handle):
                    if row:
                        owned.add(os.path.realpath(os.path.join(site_dir, row[0])))
    return owned


def _absolute_entries(search_path: "str | None") -> "list[str]":
    """The absolute entries of ``search_path``, or of PATH.

    A relative or empty entry names a directory under the working directory, so a
    program found through one is not counted or run.
    """
    entries = (search_path or os.environ.get("PATH", "")).split(os.pathsep)
    return [entry for entry in entries if entry and os.path.isabs(entry)]


def _on_absolute_path(executable: str) -> "str | None":
    """``shutil.which(executable)`` over PATH's absolute entries only."""
    directories = _absolute_entries(None)
    if not directories:
        return None
    return shutil.which(executable, path=os.pathsep.join(directories))


def _copies_on_path(executable: str, search_path: "str | None") -> "list[str]":
    """Every executable file named ``executable`` on the path, once per real file."""
    copies, seen = [], set()
    for directory in _absolute_entries(search_path):
        candidate = os.path.join(directory, executable)
        real = os.path.realpath(candidate)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            if real not in seen:
                seen.add(real)
                copies.append(candidate)
    return copies


def _probe_program(name: str) -> "str | None":
    """Where a version probe's program runs from, or None when it cannot be placed.

    An absolute name is used as given. A bare name is looked up on PATH's absolute
    entries only, as ``uv_tool_dir`` looks up uv: subprocess's own search would
    also try an empty or relative PATH entry, a directory under the working
    directory. A name with a directory part that is not absolute would be
    resolved from the working directory too, and is refused.
    """
    if os.path.isabs(name):
        return name
    if os.path.dirname(name):
        return None
    return _on_absolute_path(name)


def _uv_tool_dir() -> "str | None":
    """What ``uv tool dir`` prints, or None if uv is not there to ask."""
    uv = _on_absolute_path("uv")
    if uv is None:
        return None
    try:
        result = subprocess.run(  # nosec B603 - fixed argv, uv resolved on PATH
            [uv, "tool", "dir"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _probe_argv(
    probe: "tuple[str, ...]", uv_tool_dir: "str | None"
) -> "list[str] | None":
    """``probe`` with ``{uv_tool_dir}`` filled in; None if it is needed and unknown."""
    if any("{uv_tool_dir}" in part for part in probe) and not uv_tool_dir:
        return None
    return [part.replace("{uv_tool_dir}", uv_tool_dir or "") for part in probe]


def verify_third_party(
    package_root: Path,
    third_party_dir: Path,
    search_path: "str | None" = None,
    site_dirs: "list[str] | None" = None,
) -> "list[str]":
    """Check the built image against every license entry; return the problems.

    For each entry: its directory exists; every listed file and ``SOURCE`` is
    present, non-empty and world-readable; every URL file still matches its
    digest; ``SOURCE`` names the entry's commit; its first executable is on
    ``search_path`` (PATH when None) in a copy no Python package installed; and
    every such copy of any of its executables reports the recorded version. A
    directory with no entry is a problem too: it would be a license claim for
    something this table no longer describes. So is a publish's work directory
    that still holds an earlier entry, which a publish that did not finish leaves.

    Reading a file as another user also takes search permission on the
    directories the path goes through, which a mode on the file does not give:
    the third-party directory and each entry's directory must be searchable by
    others. (Their parents belong to the image, not to this script, and are not
    checked.)

    Copies a Python package installed are left out because they are not the
    release binary the entry describes. uv is the case: ASH depends on it from
    PyPI too, at whatever version pyproject's range resolves to on the day, and
    that copy ships its license metadata in its own dist-info.

    Writes ``index.json`` only when there are no problems, so the index lists
    exactly what was verified to be present. A run that finds problems removes
    the index an earlier passing run left, because it no longer describes the
    tree.
    """
    pins = load_pins(package_root)
    problems: "list[str]" = []
    entries = pins.THIRD_PARTY_LICENSES
    package_files = python_package_files(site_dirs)
    uv_tool_dir: "str | None" = None
    if any(getattr(entries[t], "version_probe", ()) for t in entries):
        uv_tool_dir = _uv_tool_dir()

    if not third_party_dir.is_dir():
        return [f"{third_party_dir} does not exist; no license files were installed"]
    if third_party_dir.stat().st_mode & 0o001 == 0:
        problems.append(f"{third_party_dir} cannot be searched by other users")

    for unexpected in sorted(
        p.name
        for p in third_party_dir.iterdir()
        if p.is_dir()
        and p.name not in entries
        # The work directory of a publish that was killed: this script's own
        # scratch space, not a license claim for a tool.
        and not p.name.startswith(_PUBLISH_WORK_PREFIX)
    ):
        problems.append(f"{unexpected}: directory with no license entry")

    # A work directory is skipped above because it is not a license claim, but one
    # that still holds an earlier entry (`old`) or the kept marker is a stale copy of
    # license files, shipped in a hidden directory, so it is reported.
    for leftover in sorted(
        p.name
        for p in third_party_dir.iterdir()
        if p.is_dir()
        and p.name.startswith(_PUBLISH_WORK_PREFIX)
        and (os.path.lexists(p / "old") or os.path.lexists(p / _PUBLISH_KEPT_MARKER))
    ):
        problems.append(
            f"{leftover}: left by a license publish that did not finish and still "
            "holds an earlier license entry; remove it once the entry it belongs "
            "to is confirmed"
        )

    for tool in sorted(entries):
        entry = entries[tool]
        directory = third_party_dir / tool
        if not directory.is_dir():
            problems.append(f"{tool}: {directory} is missing")
            continue
        if directory.stat().st_mode & 0o001 == 0:
            problems.append(f"{tool}: {directory} cannot be searched by other users")
        expected = [(f.name, f.sha256) for f in entry.files] + [(_SOURCE_FILE, None)]
        for name, sha256 in expected:
            path = directory / name
            if not path.is_file() or path.stat().st_size == 0:
                problems.append(f"{tool}: {path} is missing or empty")
            elif path.stat().st_mode & 0o004 == 0:
                problems.append(f"{tool}: {path} is not world-readable")
            elif sha256 and _sha256_of(path) != sha256.lower():
                problems.append(f"{tool}: {path} does not match its pinned SHA256")
        source = directory / _SOURCE_FILE
        if source.is_file():
            try:
                notice = source.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                problems.append(f"{tool}: {source} could not be read as text ({exc})")
            else:
                if entry.commit not in notice:
                    problems.append(
                        f"{tool}: {source} does not name commit {entry.commit}"
                    )

        bare_version = entry.version.lstrip("v")
        # getattr: a table from before version_probe existed has executables only.
        probe = getattr(entry, "version_probe", ())
        if probe:
            # Not an executable on PATH (a rules bundle, a library inside a uv tool
            # environment): the probe reports the version that is installed.
            argv = _probe_argv(probe, uv_tool_dir)
            if argv is None:
                problems.append(
                    f"{tool}: its version probe needs `uv tool dir`, and uv did not "
                    "answer"
                )
                continue
            program = _probe_program(argv[0])
            if program is None:
                problems.append(
                    f"{tool}: version probe program {argv[0]} is not on an "
                    "absolute PATH entry"
                )
                continue
            argv = [program, *argv[1:]]
            try:
                output = version_output(program, argv)
            except (OSError, subprocess.TimeoutExpired) as exc:
                problems.append(f"{tool}: version probe {program} failed: {exc}")
                continue
            if not reports_version(output, bare_version):
                problems.append(
                    f"{tool}: its version probe does not report {bare_version}, so "
                    f"the files under {directory} describe a different release than "
                    f"the one installed. Output: {output.strip()[:200]!r}"
                )
            continue
        for position, executable in enumerate(entry.executable_names):
            copies = [
                c
                for c in _copies_on_path(executable, search_path)
                if os.path.realpath(c) not in package_files
            ]
            if not copies and position == 0:
                problems.append(
                    f"{tool}: {executable} is not on PATH, other than as a "
                    "Python package's copy"
                )
            for found in copies:
                try:
                    output = version_output(found)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    problems.append(f"{tool}: `{found} --version` failed: {exc}")
                    continue
                if not reports_version(output, bare_version):
                    problems.append(
                        f"{tool}: `{found} --version` does not report {bare_version}, "
                        f"so the files under {directory} describe a different "
                        f"release than the one installed. Output: "
                        f"{output.strip()[:200]!r}"
                    )

    index = third_party_dir / _INDEX_FILE
    if problems:
        try:
            index.unlink(missing_ok=True)
        except OSError as exc:
            problems.append(f"{index}: a stale index could not be removed ({exc})")
        return problems
    index.write_text(
        json.dumps(
            {"tools": [entries[t].index_record() for t in sorted(entries)]},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    index.chmod(0o644)
    return problems


def third_party_main(argv: "list[str]") -> int:
    parser = argparse.ArgumentParser(
        prog="install-pinned-tool",
        description=(
            "Install license files for tools installed another way "
            "(--licenses-only), print the `ash dependencies install` arguments "
            "that pin the Python tools to their license entries (--uv-tool-pins), "
            "or verify the image's third-party license directory and write its "
            "index (--verify-third-party)."
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--licenses-only", nargs="+", metavar="TOOL")
    mode.add_argument("--uv-tool-pins", action="store_true")
    mode.add_argument("--verify-third-party", action="store_true")
    parser.add_argument(
        "--third-party-dir",
        default=None,
        help="default: $ASH_THIRD_PARTY_DIR, else the table's THIRD_PARTY_DOC_DIR",
    )
    parser.add_argument("--pins-dir", default=None)
    args = parser.parse_args(argv)

    package_root = Path(args.pins_dir) if args.pins_dir else default_package_root()
    if args.uv_tool_pins:
        print(" ".join(uv_tool_pins(package_root)))
        return 0
    chosen = args.third_party_dir or os.environ.get(_THIRD_PARTY_ENV)
    third_party_dir = Path(chosen or load_pins(package_root).THIRD_PARTY_DOC_DIR)

    if args.licenses_only:
        for tool in args.licenses_only:
            install_licenses_only(tool, package_root, third_party_dir)
        return 0

    problems = verify_third_party(package_root, third_party_dir)
    for problem in problems:
        print(f"third-party license check: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"Verified license files for every bundled tool under {third_party_dir}")
    return 0


# ---------------------------------------------------------------------------
# Root-only install targets
#
# The image installs content a later scan trusts (the cfn-guard rules bundle) as
# root, so the scan user cannot change it. A file's own mode is not enough: in a
# directory the scan user can write, it can rename the file or its directory away
# and put another in its place, which the sticky bit is what prevents. So the
# check covers every ancestor up to "/" as well as everything under the target.
# ---------------------------------------------------------------------------

_ASSERT_ROOT_ONLY = "--assert-root-only"
# The kernel's own limit on symlinks followed in one lookup is 40 on Linux.
_MAX_SYMLINK_HOPS = 40


def root_only_problems(
    paths: "list[Path]", trusted_uids: "tuple[int, ...]" = (0,)
) -> "list[str]":
    """Why each of ``paths`` could be changed by a user other than its owner.

    A path passes when it and everything under it is owned by a trusted uid and
    writable by neither group nor others, and when every directory the lookup of
    it goes through, up to "/", is owned by a trusted uid and either writable by
    neither group nor others, or a directory with the sticky bit (a user who can
    write it still cannot rename or remove what someone else owns, which is what
    /tmp relies on).

    The lookup is followed the way the kernel does it, one component at a time:
    a symlink on the way is read, its owner must be trusted, and its text
    continues the walk, so the directories it leads through are checked as well.
    A symlink's own mode is not checked, because the kernel never reads it (it
    is always 0777 on Linux), and ``..`` is applied to the directory reached,
    not to the text of the path. The target is the directory or file the lookup
    ends at. A symlink under the target is refused: it can be pointed at content
    others can change, and this check does not follow it.
    """
    import stat

    problems: "list[str]" = []

    def check(path: Path, allow_sticky: bool, inside_target: bool = False) -> None:
        try:
            info = os.lstat(path)
        except OSError as exc:
            problems.append(f"{path}: {exc.strerror or exc}")
            return
        if info.st_uid not in trusted_uids:
            problems.append(f"{path}: owned by uid {info.st_uid}")
        if stat.S_ISLNK(info.st_mode):
            if inside_target:
                problems.append(
                    f"{path}: is a symlink; a link inside the tree can be pointed "
                    "at content others can change, and is not followed"
                )
            return
        writable = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        sticky_dir = stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX
        if writable and not (allow_sticky and sticky_dir):
            problems.append(
                f"{path}: mode {stat.filemode(info.st_mode)} lets group or others "
                "write it"
            )

    def resolve(given: Path) -> "tuple[Path, list[Path], list[Path]] | None":
        """The target ``given`` names, the directories the lookup walks through
        on the way, and the symlinks it reads; None after recording a problem."""
        try:
            start = given if given.is_absolute() else Path.cwd() / given
            parts = start.parts
            resolved = Path(parts[0])
            walked = [resolved]
            links: "list[Path]" = []
            pending = list(reversed(parts[1:]))
            while pending:
                name = pending.pop()
                if name == "..":
                    resolved = resolved.parent
                elif name != ".":
                    candidate = resolved / name
                    if candidate.is_symlink():
                        links.append(candidate)
                        if len(links) > _MAX_SYMLINK_HOPS:
                            problems.append(f"{given}: too many levels of symlinks")
                            return None
                        text = Path(os.readlink(candidate))
                        if text.is_absolute():
                            resolved = Path(text.anchor)
                            walked.append(resolved)
                            pending.extend(reversed(text.parts[1:]))
                        else:
                            pending.extend(reversed(text.parts))
                        continue
                    resolved = candidate
                walked.append(resolved)
        except OSError as exc:
            problems.append(f"{given}: {exc.strerror or exc}")
            return None
        return resolved, walked, links

    def unreadable(exc: OSError) -> None:
        problems.append(f"{exc.filename}: {exc.strerror or exc}; not examined")

    for given in paths:
        found = resolve(Path(given))
        if found is None:
            continue
        target, walked, links = found
        for directory in dict.fromkeys(walked):
            if directory != target:
                check(directory, allow_sticky=True)
        for link in links:
            check(link, allow_sticky=False)
        check(target, allow_sticky=False)
        if target.is_dir() and not target.is_symlink():
            for root, dirs, files in os.walk(target, onerror=unreadable):
                for name in sorted(dirs) + sorted(files):
                    check(Path(root) / name, allow_sticky=False, inside_target=True)
    return problems


def assert_root_only_main(argv: "list[str]") -> int:
    parser = argparse.ArgumentParser(
        prog=f"install-pinned-tool {_ASSERT_ROOT_ONLY}",
        description=(
            "Fail unless each PATH, everything under it and every ancestor is "
            "owned by root and cannot be changed by any other user."
        ),
    )
    parser.add_argument("paths", nargs="+", metavar="PATH")
    parser.add_argument(
        "--trusted-uid",
        type=int,
        action="append",
        default=[],
        help="another owner to accept besides root (repeatable; for tests)",
    )
    args = parser.parse_args(argv)
    problems = root_only_problems([Path(p) for p in args.paths], (0, *args.trusted_uid))
    for problem in problems:
        print(f"root-only check: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"Root-only: {', '.join(args.paths)}")
    return 0


def _names_option(argv: "list[str]", options: "tuple[str, ...]") -> bool:
    """Whether ``argv`` carries one of ``options``, as ``--option`` or ``--option=value``.

    Anywhere before a bare ``--``, so the mode flag does not have to come first.
    """
    for argument in argv:
        if argument == "--":
            return False
        if argument.split("=", 1)[0] in options:
            return True
    return False


def main(argv: "list[str] | None" = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if _names_option(argv, (_ASSERT_ROOT_ONLY,)):
        rest = list(argv)
        if _ASSERT_ROOT_ONLY in rest:
            rest.remove(_ASSERT_ROOT_ONLY)
        return assert_root_only_main(rest)
    if _names_option(argv, _THIRD_PARTY_MODES):
        return third_party_main(argv)
    parser = argparse.ArgumentParser(
        description="Install a pinned ASH scanner binary, verified against its digest.",
    )
    parser.add_argument(
        "tool",
        help=("actionlint, cfn-guard, gitleaks, grype, opengrep, syft, trivy or uv"),
    )
    parser.add_argument(
        "-b",
        "--bin-dir",
        default="/usr/local/bin",
        help="directory to install into (default: %(default)s)",
    )
    parser.add_argument(
        "--pins-dir",
        default=None,
        help=(
            "the automated_security_helper package directory holding "
            "utils/tool_downloads.py (default: $ASH_PINS_DIR, else inferred "
            "from this script's location)"
        ),
    )
    parser.add_argument(
        "--rules-bundle",
        action="store_true",
        help=(
            "treat TOOL as the name of a pinned rules bundle "
            "(e.g. aws-guard-rules-registry) and install it under --rules-dir"
        ),
    )
    parser.add_argument(
        "-d",
        "--rules-dir",
        default=None,
        help="directory to install a rules bundle under (required with --rules-bundle)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "with --rules-bundle, install nothing: exit 0 when the rule files under "
            "--rules-dir match the bundle's pinned contents, 1 otherwise (2 for a "
            "bundle the table does not pin)"
        ),
    )
    args = parser.parse_args(argv)

    package_root = Path(args.pins_dir) if args.pins_dir else default_package_root()
    third_party_dir = os.environ.get(_THIRD_PARTY_ENV)
    if args.check and not args.rules_bundle:
        parser.error("--check needs --rules-bundle")
    if args.rules_bundle:
        if not args.rules_dir:
            parser.error("--rules-bundle needs --rules-dir")
        if args.check:
            problem = installed_bundle_problem(
                args.tool, Path(args.rules_dir), package_root
            )
            if problem is not None:
                print(
                    f"{args.tool} is not the pinned bundle: {problem}", file=sys.stderr
                )
                return 1
            print(f"{args.tool} is installed and matches its pin")
            return 0
        install_bundle(
            args.tool,
            Path(args.rules_dir),
            package_root,
            Path(third_party_dir) if third_party_dir else None,
        )
        return 0
    install(
        args.tool,
        Path(args.bin_dir),
        package_root,
        Path(third_party_dir) if third_party_dir else None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
