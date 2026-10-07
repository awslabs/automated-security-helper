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
  ``download_utils``, unavailable here for the reason above. A container layer is
  immutable, so the skip-if-already-installed path a receipt enables has nothing
  to skip.
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

    install-pinned-tool --licenses-only opengrep uv   # binary installed elsewhere
    install-pinned-tool --verify-third-party          # last step of the core stage

The second checks the built image against every entry and writes ``index.json``.
A URL-pinned license file that does not match its digest exits 3, like a binary.
"""

import argparse
import csv
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
_EXIT_USAGE = 2
_EXIT_INTEGRITY = 3

# platform.machine() spellings mapped onto the arch vocabulary tool_downloads.py
# uses. Both x86 spellings appear in the wild; arm64 is what macOS reports and
# aarch64 is what Linux reports for the same processor.
_ARCH_ALIASES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


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
    """
    saved = {name: sys.modules.get(name) for name in _BORROWED_MODULES}

    try:
        # Namespace packages for the two parents, so the dotted names
        # tool_downloads imports under exist without executing any real
        # __init__ -- which is the thing that needs toml.
        for parent in ("automated_security_helper", "automated_security_helper.core"):
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
        raise SystemExit(
            f"unsupported machine {machine!r}; "
            f"known: {', '.join(sorted(set(_ARCH_ALIASES)))}"
        )


def download(url: str, target: Path) -> str:
    """Fetch ``url`` to ``target`` and return the SHA256 of what landed.

    urllib follows redirects, which is the behaviour the vendor install script
    lacked: a GitHub release download always answers 302 to
    objects.githubusercontent.com, and treating that as an error is what left the
    build with no tarball and a checksum failure against a missing file.

    Hashed while streaming rather than by re-reading the file, so the digest
    describes the bytes that were written and not whatever is at the path
    afterwards.
    """
    digest = hashlib.sha256()
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(url) as response:  # nosec B310 - https enforced below
        with target.open("wb") as handle:
            for chunk in iter(lambda: response.read(1024 * 256), b""):
                digest.update(chunk)
                handle.write(chunk)
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
            names = [n for n in bundle.namelist() if Path(n).name == member_name]
            _require_exactly_one(names, member_name, archive)
            with bundle.open(names[0]) as source, destination.open("wb") as handle:
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
            raise SystemExit(f"{member_name} in {archive.name} is not readable")
        with source, destination.open("wb") as handle:
            shutil.copyfileobj(source, handle)


def _require_exactly_one(matches: list, member_name: str, archive: Path) -> None:
    if not matches:
        raise SystemExit(f"{archive.name} contains no member named {member_name}")
    if len(matches) > 1:
        raise SystemExit(
            f"{archive.name} contains {len(matches)} members named {member_name}; "
            "refusing to guess which one is the executable"
        )


def install(
    tool: str,
    bin_dir: Path,
    package_root: Path,
    third_party_dir: "Path | None" = None,
) -> Path:
    """Install ``tool`` into ``bin_dir``, and its license files if asked to.

    With ``third_party_dir`` set, the tool's license and notice files go to
    ``third_party_dir/<tool>/`` before the executable is moved into place, so the
    executable never lands without them, and a tool with no license entry is
    refused. ``main`` sets it from ``ASH_THIRD_PARTY_DIR``, which the image's
    core stage declares.
    """
    pins = load_pins(package_root)
    arch = resolve_arch(platform.machine())
    target_platform = {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(
        platform.system().lower(), platform.system().lower()
    )
    asset = pins.get_tool_asset(tool, target_platform, arch)
    # Resolved before anything is downloaded, so a tool with no license entry, or
    # one whose entry names another version, fails without fetching 80 MB first.
    entry = (
        _third_party_entry(pins, tool, asset.version)
        if third_party_dir is not None
        else None
    )

    if not asset.url.startswith("https://"):
        raise SystemExit(f"refusing a non-https asset URL: {asset.url}")

    bin_dir.mkdir(parents=True, exist_ok=True)
    final = bin_dir / asset.install_as

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

        if entry is not None:
            # From the archive just verified, so license files ride on the same
            # digest as the executable. getattr: a table from before
            # ToolAsset.archive existed holds archives only.
            source_archive = archive if getattr(asset, "archive", True) else None
            staged_licenses = stage_third_party(
                entry, source_archive, staging, installed_from=asset.url
            )
            publish_third_party(staged_licenses, third_party_dir)

        staged = staging / asset.install_as
        extract_member(archive, asset.member_name, staged)
        staged.chmod(0o755)
        # Replaced via the staging path so an interrupted run cannot leave a
        # half-written executable at the destination for the next layer to run.
        shutil.move(str(staged), str(final))

    print(f"Installed {asset.tool} {asset.version} to {final}", flush=True)
    return final


# ---------------------------------------------------------------------------
# Third-party license and notice files
#
# What goes where, and the convention for copyleft tools, is documented beside
# the table these read: THIRD_PARTY_LICENSES in utils/tool_downloads.py.
# ---------------------------------------------------------------------------

# Set by the Dockerfile's core stage. Unset, `install-pinned-tool <tool>` installs
# the executable only, which is what the uv-reqs stage and a developer want.
_THIRD_PARTY_ENV = "ASH_THIRD_PARTY_DIR"
_THIRD_PARTY_MODES = ("--licenses-only", "--verify-third-party")
_SOURCE_FILE = "SOURCE"
_INDEX_FILE = "index.json"
_VERSION_TIMEOUT_SECONDS = 120


def _plain_name(name: str, what: str) -> str:
    """Refuse a table value that would leave the directory it names a file in."""
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise SystemExit(f"refusing {what} {name!r}: not a plain file name")
    return name


def _third_party_entry(pins, tool: str, version: "str | None" = None):
    """The license entry for ``tool``, refusing a missing or stale one."""
    try:
        entry = pins.get_third_party_license(tool)
    except pins.ToolNotProvisionableError as exc:
        raise SystemExit(str(exc))
    if version is not None and entry.version != version:
        raise SystemExit(
            f"{tool} is pinned to {version} but its license entry records "
            f"{entry.version}. The files and source commit would describe another "
            f"release; a version bump is half-applied."
        )
    return entry


def stage_third_party(
    entry, archive: "Path | None", staging: Path, installed_from: "str | None"
) -> Path:
    """Assemble ``entry``'s directory under ``staging`` and return its path.

    Archive-member files are read from ``archive``, which the caller has already
    verified. URL files are fetched and must match their pinned digest; a
    mismatch exits ``_EXIT_INTEGRITY`` exactly like a binary's. Nothing is
    written outside ``staging``.
    """
    target = staging / "third-party" / _plain_name(entry.tool, "tool name")
    target.mkdir(parents=True)
    for license_file in entry.files:
        destination = target / _plain_name(license_file.name, "license file name")
        if license_file.from_archive:
            if archive is None:
                raise SystemExit(
                    f"{entry.tool}'s {license_file.name} is read from its release "
                    f"archive, which only `install-pinned-tool {entry.tool}` has. "
                    "--licenses-only can install URL-pinned files only."
                )
            extract_member(archive, license_file.name, destination)
        else:
            if not license_file.url.startswith("https://"):
                raise SystemExit(f"refusing a non-https URL: {license_file.url}")
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
            raise SystemExit(f"{entry.tool}'s {license_file.name} is empty")
    (target / _SOURCE_FILE).write_text(
        entry.source_notice(installed_from), encoding="utf-8"
    )
    return target


def publish_third_party(staged: Path, third_party_dir: Path) -> Path:
    """Move a staged tool directory into ``third_party_dir``, world-readable.

    The staging directory comes from ``tempfile``, which creates it 0700, and a
    file moved out of it keeps its mode. Set explicitly here, because the image's
    final stage runs as a non-root user who must be able to read these. An
    existing directory for the tool is replaced, not merged into, so a file
    dropped from an entry does not linger from an earlier layer.
    """
    third_party_dir.mkdir(parents=True, exist_ok=True)
    for path in staged.iterdir():
        path.chmod(0o644)
    staged.chmod(0o755)
    final = third_party_dir / staged.name
    if final.exists():
        shutil.rmtree(final)
    shutil.move(str(staged), str(final))
    print(f"Installed {staged.name} license files to {final}", flush=True)
    return final


def install_licenses_only(tool: str, package_root: Path, third_party_dir: Path) -> Path:
    """Install ``tool``'s license files for a binary installed some other way.

    For opengrep, which ``ash dependencies install`` provisions later in the
    build, and for uv. Every file such an entry lists must be URL-pinned, because
    there is no archive here to read members from.
    """
    pins = load_pins(package_root)
    entry = _third_party_entry(pins, tool)
    with tempfile.TemporaryDirectory(prefix="ash-third-party-") as staging_name:
        staged = stage_third_party(entry, None, Path(staging_name), None)
        return publish_third_party(staged, third_party_dir)


def reports_version(output: str, bare_version: str) -> bool:
    """Whether ``output`` names ``bare_version`` as a whole version number.

    Bounded on both sides, so 0.12.2 is not found inside 0.12.23 and 1.2 is not
    found inside 11.2.
    """
    pattern = rf"(?<![0-9.]){re.escape(bare_version)}(?![0-9]|\.[0-9])"
    return re.search(pattern, output) is not None


def version_output(executable: str) -> str:
    """``executable --version``'s combined output, run in a throwaway HOME.

    Throwaway because a version query is not always read-only. opengrep is a
    self-extracting bundle that unpacks 208 MB into ``$HOME/.cache/opengrep`` on
    first run; in the image build that landed in the verification layer and grew
    the image by 218 MB, measured, for a check that should add nothing.
    """
    with tempfile.TemporaryDirectory(prefix="ash-version-probe-") as scratch:
        env = dict(
            os.environ, HOME=scratch, XDG_CACHE_HOME=f"{scratch}/cache", TMPDIR=scratch
        )
        result = subprocess.run(  # nosec B603 - executable from the pinned table, resolved on PATH
            [executable, "--version"],
            capture_output=True,
            text=True,
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


def _copies_on_path(executable: str, search_path: "str | None") -> "list[str]":
    """Every executable file named ``executable`` on the path, once per real file."""
    directories = (search_path or os.environ.get("PATH", "")).split(os.pathsep)
    copies, seen = [], set()
    for directory in directories:
        candidate = os.path.join(directory, executable)
        real = os.path.realpath(candidate)
        if directory and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            if real not in seen:
                seen.add(real)
                copies.append(candidate)
    return copies


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
    something this table no longer describes.

    Copies a Python package installed are left out because they are not the
    release binary the entry describes. uv is the case: ASH depends on it from
    PyPI too, at whatever version pyproject's range resolves to on the day, and
    that copy ships its license metadata in its own dist-info.

    Writes ``index.json`` only when there are no problems, so the index lists
    exactly what was verified to be present.
    """
    pins = load_pins(package_root)
    problems: "list[str]" = []
    entries = pins.THIRD_PARTY_LICENSES
    package_files = python_package_files(site_dirs)

    if not third_party_dir.is_dir():
        return [f"{third_party_dir} does not exist; no license files were installed"]

    for unexpected in sorted(
        p.name
        for p in third_party_dir.iterdir()
        if p.is_dir() and p.name not in entries
    ):
        problems.append(f"{unexpected}: directory with no license entry")

    for tool in sorted(entries):
        entry = entries[tool]
        directory = third_party_dir / tool
        if not directory.is_dir():
            problems.append(f"{tool}: {directory} is missing")
            continue
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
        if source.is_file() and entry.commit not in source.read_text(encoding="utf-8"):
            problems.append(f"{tool}: {source} does not name commit {entry.commit}")

        bare_version = entry.version.lstrip("v")
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

    if not problems:
        index = third_party_dir / _INDEX_FILE
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
            "(--licenses-only), or verify the image's third-party license "
            "directory and write its index (--verify-third-party)."
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--licenses-only", nargs="+", metavar="TOOL")
    mode.add_argument("--verify-third-party", action="store_true")
    parser.add_argument(
        "--third-party-dir",
        default=None,
        help="default: $ASH_THIRD_PARTY_DIR, else the table's THIRD_PARTY_DOC_DIR",
    )
    parser.add_argument("--pins-dir", default=None)
    args = parser.parse_args(argv)

    package_root = Path(args.pins_dir) if args.pins_dir else default_package_root()
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


def main(argv: "list[str] | None" = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] in _THIRD_PARTY_MODES:
        return third_party_main(argv)
    parser = argparse.ArgumentParser(
        description="Install a pinned ASH scanner binary, verified against its digest.",
    )
    parser.add_argument("tool", help="grype, syft or trivy")
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
    args = parser.parse_args(argv)

    package_root = Path(args.pins_dir) if args.pins_dir else default_package_root()
    third_party_dir = os.environ.get(_THIRD_PARTY_ENV)
    install(
        args.tool,
        Path(args.bin_dir),
        package_root,
        Path(third_party_dir) if third_party_dir else None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
