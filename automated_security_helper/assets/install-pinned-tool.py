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
"""

import argparse
import hashlib
import importlib.machinery
import importlib.util
import os
import platform
import shutil
import sys
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


def install(tool: str, bin_dir: Path, package_root: Path) -> Path:
    pins = load_pins(package_root)
    arch = resolve_arch(platform.machine())
    target_platform = {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(
        platform.system().lower(), platform.system().lower()
    )
    asset = pins.get_tool_asset(tool, target_platform, arch)

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

        staged = staging / asset.install_as
        extract_member(archive, asset.member_name, staged)
        staged.chmod(0o755)
        # Replaced via the staging path so an interrupted run cannot leave a
        # half-written executable at the destination for the next layer to run.
        shutil.move(str(staged), str(final))

    print(f"Installed {asset.tool} {asset.version} to {final}", flush=True)
    return final


def main(argv: "list[str] | None" = None) -> int:
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
    install(args.tool, Path(args.bin_dir), package_root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
