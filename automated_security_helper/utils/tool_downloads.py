# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pinned release assets for the tools ASH provisions itself.

Why this module exists
----------------------
ASH ships ten scanners but, until this module, could only *install* three of them
(bandit, checkov and semgrep, via ``uv tool install``) plus opengrep by binary
download. grype, syft and trivy had no install path inside ASH at all, so a
machine without them scanned with those scanners absent. That state was invisible
from the outside: the scan reported them as not having run and still exited 0.

Every asset here is identified by an exact version and an exact SHA256. For
grype, syft and trivy both are transcribed from the ``*_checksums.txt`` published
alongside the upstream GitHub release, which is the same file the vendors' own
install scripts consult. opengrep and uv publish no such file; where their digests
came from is recorded above the digest table. The digest is not decoration -- ``verified_download`` refuses to install an asset
whose bytes do not hash to the pinned value, so a compromised or truncated
release download fails the install instead of silently becoming the binary a
security scan then trusts.

What was rejected
-----------------
1. ``curl … | sh`` against each vendor's install script, which is how ASH's
   container image provisions these three tools. Piping a remote script into a
   shell gives the endpoint arbitrary code execution at install time and pins
   nothing; in a tool whose subject is supply-chain risk it is not defensible,
   even though it is less code.
2. Fetching ``*_checksums.txt`` at install time and trusting whatever it says.
   That authenticates the download against the same server that served it, so it
   detects corruption but not substitution. Pinning in the repository means a
   changed digest shows up in a diff and a review.
3. Deriving the asset filename with one shared template. The three vendors do not
   agree on a naming scheme -- anchore uses ``linux_amd64`` while aquasecurity
   uses ``Linux-64bit`` -- so the filenames are listed per tool, verbatim, in the
   form they appear upstream.

Known limitations
-----------------
* Not every tool publishes an asset for every platform ASH runs on.
  ``get_tool_asset`` raises :class:`ToolNotProvisionableError` for those pairs
  rather than guessing at a nearby architecture. The absences are real: grype,
  hadolint and trivy publish no windows/arm64 asset, and trivy publishes no 32-bit
  macOS one.
* cfn-nag is not here. It is a Ruby gem with a dependency closure, not a single
  release binary, so it is provisioned through the committed
  ``assets/Gemfile.lock`` instead -- see ``cfn_nag_scanner``.
* npm-audit is not here either. It is a subcommand of npm, so its dependency is a
  Node.js runtime, which ASH does not install. See
  ``npm_audit_scanner.install_prerequisite_message``.
* Bumping a version means replacing every digest for that tool, in both tables:
  the archive digests and the executable digests (see ``_EXECUTABLE_DIGESTS``).
  A version bumped without its digests will fail every install with an integrity
  error, which is the intended direction to fail in. cfn-guard, hadolint, opengrep and uv name their assets
  without a version, so for those a bump would not even change a filename; see
  ``_DIGESTS_TAKEN_AT`` for what catches it instead.
  Nothing bumps these pins on its own, and Dependabot cannot see a Python dict.
  ``scripts/check_pinned_tool_versions.py`` compares every pin here with its
  upstream's latest release and lists what a bump must change; the weekly ASH -
  Pinned Tool Versions workflow runs it and fails when a pin is behind.
* opengrep is pinned for one Linux build per architecture. Through v1.x that was the
  manylinux build (the scanner hardcoded it, with a TODO to detect musl). v2.0.0
  removed Python from opengrep and renamed the Linux assets ``opengrep_linux_*``; they
  are statically linked executables, so one build serves glibc and musl hosts alike
  and there is no second Linux build to pin. ``get_opengrep_url`` still names the
  manylinux asset for a configured v1.x version.
* opengrep's Windows asset is a zip from v2.0.0 on (it was a bare ``.exe``). The zip
  holds ``opengrep.exe`` and six MinGW runtime DLLs. The executable's import table
  names libgmp, libpcre2, libstdc++ and libzstd; libgcc_s_seh and libwinpthread are
  those libraries' own runtime. An ``.exe`` extracted alone would not start. The DLLs are pinned in
  ``_COMPANION_DIGESTS`` and installed beside the executable, each checked against its
  own digest.
* opengrep's version is a user-facing scanner option, and this table has digests
  only for the version it pins. A configuration naming another version must also
  supply that release's digest per platform in ``scanners.opengrep.options.sha256``;
  ``opengrep_scanner`` refuses to install a platform it has no digest for, and
  installs one it does have through the same verified download.
* opengrep also publishes a cosign signature and certificate beside each asset.
  They are not checked: that needs cosign at install time, and the digest pin
  already fixes the exact bytes, which is a stronger statement than "signed by
  whoever holds the release identity".
* uv is here for the container image only, which installs it before ASH exists
  (see ``assets/install-pinned-tool.py``). It is pinned for linux, the only
  platform the image is built for, and no scanner plugin installs it.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from automated_security_helper.base.plugin_provisioning import (
    tool_versions as _declared_tool_versions,
)
from automated_security_helper.core.exceptions import ToolNotProvisionableError

# Platform/architecture pair, in the vocabulary cli/dependencies.py already uses:
# platform is one of linux/darwin/windows, arch is one of amd64/arm64.
PlatformArch = tuple[str, str]


class Linkage(str, Enum):
    """What a Linux release asset links the C library as.

    ``static`` needs no C library from the host and runs on glibc and musl hosts alike.
    ``glibc`` and ``musl`` need that library. ``unread`` says nothing has measured the
    asset, which is the honest value for every asset until someone reads it: a guess
    would refuse a working install on one kind of host or allow a broken one on the other.
    """

    STATIC = "static"
    GLIBC = "glibc"
    MUSL = "musl"
    UNREAD = "unread"


@dataclass(frozen=True)
class ToolAsset:
    """One downloadable release asset for one tool on one platform/arch.

    ``member_name`` is the basename of the executable *inside* the archive, not a
    path. The extractor locates the single member with that basename and refuses
    an archive where zero or more than one member matches, so a vendor moving the
    binary from the archive root into a subdirectory keeps working while an
    archive containing two same-named entries is rejected instead of resolved
    arbitrarily.

    ``archive`` is False when the release asset *is* the executable, which is how
    hadolint and, except for its Windows zip, opengrep publish. There is nothing to extract, ``member_name`` is
    unused, and the pinned digest then covers the very bytes that will be executed
    -- which is what lets a cached copy be checked against the pin directly. It is
    a field rather than something inferred from the filename's extension because
    hadolint's Linux and macOS assets have no extension at all.
    """

    tool: str
    version: str
    url: str
    sha256: str
    member_name: str
    install_as: str
    archive: bool = True
    # SHA256 of the executable inside the archive, from _EXECUTABLE_DIGESTS. None
    # when no executable digest is pinned for the asset; see executable_digest.
    executable_sha256: Optional[str] = None
    # (basename, SHA256) of files the archive carries that the executable needs
    # beside it, from _COMPANION_DIGESTS. Empty for every asset but opengrep's Windows
    # zip. Each is extracted next to the executable and refused unless it hashes to
    # its digest; the installer places the executable last, so an executable on disk
    # means its companions are too.
    companion_sha256: tuple[tuple[str, str], ...] = ()
    # What the executable links the C library as, from _LINKAGE_READS, and the read it
    # came from. ``unread`` for every asset no read covers; a value other than
    # ``unread`` needs ``linkage_source`` (where it was read) and ``linkage_read_version``
    # (the release it was read at, which must be the pinned one). A read is of one
    # release: when a pin moves, the asset is ``unread`` again until someone reads the
    # new one. See ``__post_init__``.
    linkage: Linkage = Linkage.UNREAD
    linkage_source: str = ""
    linkage_read_version: str = ""

    def __post_init__(self) -> None:
        # A plain string that names a member is that member; any other spelling raises.
        linkage = Linkage(self.linkage)
        object.__setattr__(self, "linkage", linkage)
        source = self.linkage_source.strip()
        read_version = self.linkage_read_version.strip()
        if linkage is Linkage.UNREAD:
            if source or read_version:
                raise ValueError(
                    f"{self.tool} {self.version}: the linkage is 'unread' but the asset "
                    "carries a read record; name the value that was read, or drop the "
                    "record"
                )
            return
        if not source or not read_version:
            raise ValueError(
                f"{self.tool} {self.version}: the linkage {linkage.value!r} needs a "
                "recorded read (linkage_source and linkage_read_version); an asset "
                "nothing has measured is 'unread'"
            )
        if read_version != self.version:
            raise ValueError(
                f"{self.tool}: its linkage was read at {read_version!r}, not at the "
                f"pinned {self.version!r}; read the pinned asset, or leave it 'unread'"
            )

    @property
    def executable_digest(self) -> Optional[str]:
        """The pinned SHA256 of the executable this asset installs, or None.

        ``sha256`` covers the release asset as downloaded. For an archive that is
        not the file that runs, so it cannot tell whether a binary already on disk
        is the pinned one; ``executable_sha256`` can. An asset that is the
        executable itself, with no archive around it, needs no second digest: the
        asset digest already covers the bytes that run (opengrep and hadolint, ``archive`` False).

        None means there is nothing to compare a binary on disk against. Callers
        then install as they always have; they never treat None as a match.
        """
        if self.executable_sha256:
            return self.executable_sha256
        if not self.archive:
            return self.sha256
        return None


# The release each tool is pinned to is DECLARED by the plugin that owns the tool (its
# ``Provisioning.tool_pins`` in ``base/plugin_provisioning.py``, reachable as
# ``scanner_manifests()[...].provisioning``), and by the engine for the tool no plugin owns
# (uv). This is the table derived from those declarations; it lists no version itself, so
# bumping a tool is an edit to its plugin's block. The asset filenames and digests below stay
# here and are checked against it (``_DIGESTS_TAKEN_AT``, the filename-version check).
#
# Versions are deliberately the same pins the container image already builds with (see the
# ARG lines in Dockerfile), so a scan run from a container, from nix and from a bare
# `ash dependencies install` all execute the same tool versions.
TOOL_VERSIONS: dict[str, str] = _declared_tool_versions()

# The gem version cfn-nag installs at, kept beside the binary pins so there is one
# place to read ASH's external tool versions from. The authoritative pin for the
# whole gem closure is assets/Gemfile.lock; this must agree with assets/Gemfile.
CFN_NAG_GEM_VERSION = "0.8.10"

# The Bundler the container image installs cfn-nag's gems with: the Dockerfile's
# `ARG BUNDLER_VERSION`, and the `BUNDLED WITH` line of assets/Gemfile.lock. All three
# must agree; tests/unit/test_pinned_tool_version_check.py checks that they do.
BUNDLER_VERSION = "2.6.9"


# ---------------------------------------------------------------------------
# Asset filenames, per tool, exactly as published upstream.
# ---------------------------------------------------------------------------

_ACTIONLINT_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "actionlint_1.7.12_linux_amd64.tar.gz",
    ("linux", "arm64"): "actionlint_1.7.12_linux_arm64.tar.gz",
    ("darwin", "amd64"): "actionlint_1.7.12_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "actionlint_1.7.12_darwin_arm64.tar.gz",
    ("windows", "amd64"): "actionlint_1.7.12_windows_amd64.zip",
    ("windows", "arm64"): "actionlint_1.7.12_windows_arm64.zip",
}

_BETTERLEAKS_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "betterleaks_1.10.1_linux_x64.tar.gz",
    ("linux", "arm64"): "betterleaks_1.10.1_linux_arm64.tar.gz",
    ("darwin", "amd64"): "betterleaks_1.10.1_darwin_x64.tar.gz",
    ("darwin", "arm64"): "betterleaks_1.10.1_darwin_arm64.tar.gz",
    ("windows", "amd64"): "betterleaks_1.10.1_windows_x64.zip",
    ("windows", "arm64"): "betterleaks_1.10.1_windows_arm64.zip",
}

# cfn-guard's release assets carry no version in their names: every release
# publishes ``cfn-guard-v3-<arch>-<os>-latest.tar.gz``, and the version lives only
# in the release tag, which is the path segment of the URL. So for cfn-guard the
# digest is the whole pin, and a version bump that forgets the digests fails every
# install with an integrity error rather than being caught by the filename check
# the other tools get (see _DIGESTS_TAKEN_AT).
#
# The linux assets are the statically linked builds (``ldd`` reports "statically
# linked" for x86_64-linux at 3.2.1), so they run on glibc and musl hosts alike.
# The ``ubuntu-latest`` assets the same release also publishes are not used.
_CFN_GUARD_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "cfn-guard-v3-x86_64-linux-latest.tar.gz",
    ("linux", "arm64"): "cfn-guard-v3-aarch64-linux-latest.tar.gz",
    ("darwin", "amd64"): "cfn-guard-v3-x86_64-macos-latest.tar.gz",
    ("darwin", "arm64"): "cfn-guard-v3-aarch64-macos-latest.tar.gz",
    ("windows", "amd64"): "cfn-guard-v3-x86_64-windows-latest.tar.gz",
    ("windows", "arm64"): "cfn-guard-v3-aarch64-windows-latest.tar.gz",
}

_GITLEAKS_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "gitleaks_8.30.1_linux_x64.tar.gz",
    ("linux", "arm64"): "gitleaks_8.30.1_linux_arm64.tar.gz",
    ("darwin", "amd64"): "gitleaks_8.30.1_darwin_x64.tar.gz",
    ("darwin", "arm64"): "gitleaks_8.30.1_darwin_arm64.tar.gz",
    ("windows", "amd64"): "gitleaks_8.30.1_windows_x64.zip",
    ("windows", "arm64"): "gitleaks_8.30.1_windows_arm64.zip",
}

_CRANE_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "go-containerregistry_Linux_x86_64.tar.gz",
    ("linux", "arm64"): "go-containerregistry_Linux_arm64.tar.gz",
    ("darwin", "amd64"): "go-containerregistry_Darwin_x86_64.tar.gz",
    ("darwin", "arm64"): "go-containerregistry_Darwin_arm64.tar.gz",
    ("windows", "amd64"): "go-containerregistry_Windows_x86_64.tar.gz",
    # windows/arm64: the release publishes one; ASH's table does not list it.
}

_GRYPE_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "grype_0.122.1_linux_amd64.tar.gz",
    ("linux", "arm64"): "grype_0.122.1_linux_arm64.tar.gz",
    ("darwin", "amd64"): "grype_0.122.1_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "grype_0.122.1_darwin_arm64.tar.gz",
    ("windows", "amd64"): "grype_0.122.1_windows_amd64.zip",
    # windows/arm64: upstream publishes no such asset for this release.
}

# hadolint publishes bare executables, not archives, and its filenames carry no
# version -- the version is only in the release tag in the URL. See
# ToolAsset.archive, _BARE_EXECUTABLE_TOOLS and _DIGESTS_TAKEN_AT.
_HADOLINT_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "hadolint-linux-x86_64",
    ("linux", "arm64"): "hadolint-linux-arm64",
    ("darwin", "amd64"): "hadolint-macos-x86_64",
    ("darwin", "arm64"): "hadolint-macos-arm64",
    ("windows", "amd64"): "hadolint-windows-x86_64.exe",
    # windows/arm64: upstream publishes no such asset for this release.
}

_SYFT_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "syft_1.57.2_linux_amd64.tar.gz",
    ("linux", "arm64"): "syft_1.57.2_linux_arm64.tar.gz",
    ("darwin", "amd64"): "syft_1.57.2_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "syft_1.57.2_darwin_arm64.tar.gz",
    ("windows", "amd64"): "syft_1.57.2_windows_amd64.zip",
    ("windows", "arm64"): "syft_1.57.2_windows_arm64.zip",
}

# Bare executables, except the Windows zip. The names carry no version; see
# _DIGESTS_TAKEN_AT. v2.0.0 renamed the Linux assets from ``opengrep_manylinux_*`` and
# ships Windows as a zip of ``opengrep.exe`` plus its DLLs (_COMPANION_DIGESTS).
_OPENGREP_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "opengrep_linux_x86",
    ("linux", "arm64"): "opengrep_linux_aarch64",
    ("darwin", "amd64"): "opengrep_osx_x86",
    ("darwin", "arm64"): "opengrep_osx_arm64",
    ("windows", "amd64"): "opengrep_windows_x86.zip",
    # windows/arm64: upstream publishes no such asset for this release.
}

# linux only: uv is pinned for the container image, which is built for linux alone.
_UV_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "uv-x86_64-unknown-linux-gnu.tar.gz",
    ("linux", "arm64"): "uv-aarch64-unknown-linux-gnu.tar.gz",
}

_TRIVY_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "trivy_0.76.2_Linux-64bit.tar.gz",
    ("linux", "arm64"): "trivy_0.76.2_Linux-ARM64.tar.gz",
    ("darwin", "amd64"): "trivy_0.76.2_macOS-64bit.tar.gz",
    ("darwin", "arm64"): "trivy_0.76.2_macOS-ARM64.tar.gz",
    ("windows", "amd64"): "trivy_0.76.2_windows-64bit.zip",
    # windows/arm64: upstream publishes no such asset for this release.
}


# ---------------------------------------------------------------------------
# SHA256 digests, keyed by asset filename.
#
# Transcribed verbatim from the checksums file published with each release, so a
# reviewer can diff this block against the upstream file line for line:
#   https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_checksums.txt
#   https://github.com/betterleaks/betterleaks/releases/download/v1.10.1/checksums.txt
#   https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt
#   https://github.com/anchore/grype/releases/download/v0.122.1/grype_0.122.1_checksums.txt
#   https://github.com/hadolint/hadolint/releases/download/v2.15.1/checksums.sha256
#   https://github.com/anchore/syft/releases/download/v1.57.2/syft_1.57.2_checksums.txt
#   https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_checksums.txt
#
# Two entries have no upstream checksums file to transcribe from, so their digests
# were obtained differently and are stated here so a reviewer can redo it:
#
# * cfn-guard 3.3.0 publishes no checksums file. Its digests are the ``digest``
#   field GitHub's release API reports for each asset
#   (``gh release view 3.3.0 --repo aws-cloudformation/cloudformation-guard
#   --json assets``), and each was confirmed by downloading the asset from
#   https://github.com/aws-cloudformation/cloudformation-guard/releases/tag/3.3.0
#   and hashing it with sha256sum.
# * The AWS Guard Rules Registry 1.0.2 release predates GitHub's asset digests,
#   so its one digest is sha256sum of
#   https://github.com/aws-cloudformation/aws-guard-rules-registry/releases/download/1.0.2/ruleset-build-v1.0.2.zip
#   as downloaded on 2026-10-06.
#
# opengrep publishes no checksums file. Its five digests were obtained two ways on
# 2026-11-23 and both agreed byte for byte: the `digest` field GitHub reports for
# each asset of the v2.0.0 release (`gh api repos/opengrep/opengrep/releases/tags/
# v2.0.0`) and sha256sum over each asset downloaded once. The same day each pinned
# asset's `.sig` was also checked with openssl against the public key in its `.cert`
# ("Verified OK" for all five), and every certificate's identity is opengrep's
# rolling-release.yml workflow at refs/heads/main, built from commit 526deafe (the
# commit the v2.0.0 tag points to), with the GitHub Actions OIDC issuer. The v1.33.1
# certificates named refs/heads/release-v1.33.1 instead: from v2.0.0 the release is
# built from main. The check is not made at install time (see the module docstring).
# tests/unit/utils/test_opengrep_pinned_download.py
# keeps nix/opengrep.nix's SRI copy of the four non-Windows digests equal to this one.
#
# The six DLLs in _COMPANION_DIGESTS and the SHA256 of opengrep.exe in
# _EXECUTABLE_DIGESTS were taken from the pinned zip's members on 2026-11-23, after the
# zip matched its digest: Python's zipfile read each member and hashed it, and the member
# listing (seven regular files, no directories, no nested paths) was read with the same
# module.
#
# uv publishes a `<asset>.sha256` beside each asset. Those two files were downloaded
# with the assets, and each agreed with sha256sum over its asset and with the `digest`
# field GitHub reports for it.
#
# Every line carries `# pragma: allowlist secret`, which is detect-secrets' own
# inline marker. It is needed and it is honest: a 64-character hex string is exactly
# what a high-entropy-string detector is built to find, and ASH scanning itself
# reported every one as a CRITICAL secret -- correctly, by its own heuristic. A published
# release checksum is public by construction and is the opposite of a credential:
# it exists so that everyone can compare against it.
#
# Marked per line rather than by suppressing the file or the rule, so a real secret
# added to this file later is still found.
#
# _EXECUTABLE_DIGESTS, directly after this table, holds a second digest per archive:
# the SHA256 of the executable inside it (the member ``member_name`` selects). The
# archive digest says nothing about a binary already on disk, because that binary was
# extracted from the archive and is not the archive. The executable digest is what
# lets ``ash dependencies install`` recognize a copy that is already present -- the
# container image installs every pinned tool into /usr/local/bin before ASH runs --
# and leave it alone, instead of writing a second copy of every binary into
# ASH_BIN_PATH. trivy alone is 162 MB uncompressed.
#
# Derived, not transcribed: no vendor publishes it. Each archive was downloaded,
# checked against its digest in _DIGESTS, and the member extracted and hashed, on
# 2026-10-07. Two extractors agreed on every entry: Python's tarfile/zipfile with the same
# exactly-one-basename rule the installer uses, and `tar -xzOf` / `unzip -p` piped to
# sha256sum. Every install re-checks it: the installer refuses an extracted
# executable that does not hash to this value, so a wrong entry fails the first real
# install of that asset in CI rather than sitting here unnoticed.
#
# _BUNDLE_CONTENTS_DIGESTS, directly after that, does the same for a rules bundle
# (RULES_BUNDLES): the archive is not what the scanner reads, the rule files extracted
# from it are. Its value is ``rules_bundles.contents_digest`` of every file
# ``rules_bundles.extract_bundle`` writes: the SHA256 of their sorted
# ``<basename><TAB><sha256>`` lines. Derived the same way, not transcribed. For the
# Guard Rules Registry 1.0.2 the archive was downloaded and checked against its digest
# in _DIGESTS on 2026-10-12, then extracted with ``extract_bundle``: 50 files, 4,088,497
# bytes. ``sha256sum`` over the extracted files, written as those lines in
# ``LC_ALL=C`` order, gave the same value. Both installers refuse an extraction that
# does not hash to it, and an installed bundle is checked against it and nothing else.
#
# hadolint has no entry: its asset is the executable itself, so the asset digest
# already covers the bytes that run (ToolAsset.executable_digest; the same holds for
# opengrep's Linux and macOS assets, but not its Windows zip, which has one).
#
# _COMPANION_DIGESTS, last, holds the SHA256 of each file a zip carries that its
# executable needs beside it. Derived the same way as the executable digests, for the
# one asset that has any (opengrep's Windows zip).
#
# The four tables are adjacent so that one line-pinned suppression covers them (see
# .ash/.ash_alpha_plugins.yaml); keep nothing but digests between them.
# ---------------------------------------------------------------------------

_DIGESTS: dict[str, str] = {
    # actionlint v1.7.12
    "actionlint_1.7.12_linux_amd64.tar.gz": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",  # pragma: allowlist secret
    "actionlint_1.7.12_linux_arm64.tar.gz": "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6",  # pragma: allowlist secret
    "actionlint_1.7.12_darwin_amd64.tar.gz": "5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644",  # pragma: allowlist secret
    "actionlint_1.7.12_darwin_arm64.tar.gz": "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f",  # pragma: allowlist secret
    "actionlint_1.7.12_windows_amd64.zip": "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9",  # pragma: allowlist secret
    "actionlint_1.7.12_windows_arm64.zip": "cadcf7ea4efe3a68728893813643cebe1185e5b1d4be5b96245f65c9a4d5ea41",  # pragma: allowlist secret
    # betterleaks v1.10.1
    "betterleaks_1.10.1_linux_x64.tar.gz": "c174b42d7aa60caf58c0c3e555c0e4bed01fe6b0d99a412bce777b5af4ce913e",  # pragma: allowlist secret
    "betterleaks_1.10.1_linux_arm64.tar.gz": "62a63199f9f61a6b5e5a6f58f048493db20fbc8c770014f4d903a4d97886e1bf",  # pragma: allowlist secret
    "betterleaks_1.10.1_darwin_x64.tar.gz": "1ae2e3885d161918d8ad2e911e205e73f0d9ffba52c85b38126586c52d355ef4",  # pragma: allowlist secret
    "betterleaks_1.10.1_darwin_arm64.tar.gz": "ca91eb3b006f15478411f235b5e2712fb15cea74f6701ebadc2364efe0af1403",  # pragma: allowlist secret
    "betterleaks_1.10.1_windows_x64.zip": "53d4b37635a999992fb8e1d79f8215279315cbb3b4139314289b69407e79143d",  # pragma: allowlist secret
    "betterleaks_1.10.1_windows_arm64.zip": "f93d26dfc7b939f967c74e3f908b44faec1b1cb6ffb29c75c0a1d7e713ab8f70",  # pragma: allowlist secret
    # cfn-guard 3.3.0
    "cfn-guard-v3-x86_64-linux-latest.tar.gz": "ecf25d586c98057836fac28a8e498569f6daded8f386fd13327c82a4daa45d6e",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-linux-latest.tar.gz": "7b8a7b4befdf47e7f53c0023a8c79799b7d8dde69ab8a77ce3078211920c8ff4",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-macos-latest.tar.gz": "9c4c3f75b9d0519fecb171b492c8d32f66dde2d1d13121fcc347171a5934f722",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-macos-latest.tar.gz": "9cc5fd2ae3febe56ecccdad0caa73e4693131632871a1305c7ce49a2563e836e",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-windows-latest.tar.gz": "256a3c11db6617e7130fc8bd127de96c9e3ec7b64b3a37edddabe5aae91305cf",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-windows-latest.tar.gz": "1c76d8ddc0de2beb7d37a25babe3cddf7e72b3930a9df6908c119c5b9b3aa35c",  # pragma: allowlist secret
    # aws-guard-rules-registry 1.0.2 (a rules bundle, not a binary; see RULES_BUNDLES)
    "ruleset-build-v1.0.2.zip": "dc21aaad601c673843c299191d864cd9b9db32475b1937d930d6069ddde73296",  # pragma: allowlist secret
    # crane v0.22.1 (go-containerregistry)
    "go-containerregistry_Linux_x86_64.tar.gz": "0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0",  # pragma: allowlist secret
    "go-containerregistry_Linux_arm64.tar.gz": "898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110",  # pragma: allowlist secret
    "go-containerregistry_Darwin_x86_64.tar.gz": "6fedd06a648c11335f0e8b9547e4783002c30e9336047fec292942cd518bb799",  # pragma: allowlist secret
    "go-containerregistry_Darwin_arm64.tar.gz": "2231fc8df8806d20d680ff1225db44e095a55dd6ac1ae8eced4faf4b278b78fb",  # pragma: allowlist secret
    "go-containerregistry_Windows_x86_64.tar.gz": "0e073ea8192c3b8442ec8aaf44d53c1050a09084669fae3a6ceb0f2026cf8b21",  # pragma: allowlist secret
    # gitleaks v8.30.1
    "gitleaks_8.30.1_linux_x64.tar.gz": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",  # pragma: allowlist secret
    "gitleaks_8.30.1_linux_arm64.tar.gz": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",  # pragma: allowlist secret
    "gitleaks_8.30.1_darwin_x64.tar.gz": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",  # pragma: allowlist secret
    "gitleaks_8.30.1_darwin_arm64.tar.gz": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",  # pragma: allowlist secret
    "gitleaks_8.30.1_windows_x64.zip": "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",  # pragma: allowlist secret
    "gitleaks_8.30.1_windows_arm64.zip": "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f",  # pragma: allowlist secret
    # grype v0.122.1
    "grype_0.122.1_linux_amd64.tar.gz": "f1ba7e2917ee1395618de20a98da0aa7c0fb1788927797651047c50502a37538",  # pragma: allowlist secret
    "grype_0.122.1_linux_arm64.tar.gz": "819e5be3d9516432fedb7b6b56df7306c3a16607606dfc05826eefbb00e471da",  # pragma: allowlist secret
    "grype_0.122.1_darwin_amd64.tar.gz": "8063aef11b52e6da342068aa6980e92f40b28849eff990c8375a0a8e6b6dfbc5",  # pragma: allowlist secret
    "grype_0.122.1_darwin_arm64.tar.gz": "8bbb3c01695d1e954875cf9f7403c5d3cdb652caf763867955fad520e3cd6c00",  # pragma: allowlist secret
    "grype_0.122.1_windows_amd64.zip": "24e19d6378782d2da343b80c632e342bcdd3bd1bf44e415a0ff81cf85ce1043a",  # pragma: allowlist secret
    # hadolint v2.15.1
    "hadolint-linux-x86_64": "c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507",  # pragma: allowlist secret
    "hadolint-linux-arm64": "f6198ef8090f404dbb771abfee086eb8c48ac177f30da7fd3510aca35b344b5d",  # pragma: allowlist secret
    "hadolint-macos-x86_64": "ffe9bb18b23d5ed1eae50237aecdbb523d016e96da0bd4e7aa432040acfc3fde",  # pragma: allowlist secret
    "hadolint-macos-arm64": "5c09f3213f8e40406abe048233d985eebef336d4a6a20021be47fadb6cf480a2",  # pragma: allowlist secret
    "hadolint-windows-x86_64.exe": "01d927294962b5387f9ead4f18679158452be4f17c765ad0bdffe5264b9c7b0a",  # pragma: allowlist secret
    # syft v1.57.2
    "syft_1.57.2_linux_amd64.tar.gz": "ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b",  # pragma: allowlist secret
    "syft_1.57.2_linux_arm64.tar.gz": "8efe605309c98798e1ee0cffdcf8c05ca26819b4cd44c0b03650f1e963e9bdb6",  # pragma: allowlist secret
    "syft_1.57.2_darwin_amd64.tar.gz": "73c6100bc43fbcc1c99aed3428d859c6289c4076be7e296dde7e427324c15908",  # pragma: allowlist secret
    "syft_1.57.2_darwin_arm64.tar.gz": "38afbcc03a9d9afac2d7572432fd2c435e051e03930582ea90f4710ffb515224",  # pragma: allowlist secret
    "syft_1.57.2_windows_amd64.zip": "0a10e03ffd124c304fd7e7491262dba2e5f68eb12378b106d7525146675b2e3a",  # pragma: allowlist secret
    "syft_1.57.2_windows_arm64.zip": "7f3cace29c2a7d2478de834aaa42663b8dbf82c9e8abc6a0917b437584ea54e1",  # pragma: allowlist secret
    # trivy v0.76.2
    "trivy_0.76.2_Linux-64bit.tar.gz": "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",  # pragma: allowlist secret
    "trivy_0.76.2_Linux-ARM64.tar.gz": "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3",  # pragma: allowlist secret
    "trivy_0.76.2_macOS-64bit.tar.gz": "e08bb9ea449ecf66c6bfb03cbb8697c503ff33d35fc585c9747e3eaeb7ed4c7b",  # pragma: allowlist secret
    "trivy_0.76.2_macOS-ARM64.tar.gz": "ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8",  # pragma: allowlist secret
    "trivy_0.76.2_windows-64bit.zip": "691f737a7e5566a673c3a74dab9160552ec32101e953b659e5c77443d16dddb6",  # pragma: allowlist secret
    # opengrep v2.0.0
    "opengrep_linux_x86": "37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0",  # pragma: allowlist secret
    "opengrep_linux_aarch64": "6257b65423a744b704af2ff9beeb8f222c2f6925236af386b56b031d4c06d6d8",  # pragma: allowlist secret
    "opengrep_osx_x86": "51d2f918d7aad0afc1426bb4fbf56e32fc70c3ffd5ddb78e32e7d61e51c029a2",  # pragma: allowlist secret
    "opengrep_osx_arm64": "b51b3d83f165a2e0934497b8f1b08abb1c3041ef20ef911c97e04cb39af1ad55",  # pragma: allowlist secret
    "opengrep_windows_x86.zip": "899a17e2b15863367cfd15032c93cdf482fd4e7ec8719c69de46f4f38b227864",  # pragma: allowlist secret
    # uv 0.13.9
    "uv-x86_64-unknown-linux-gnu.tar.gz": "a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5",  # pragma: allowlist secret
    "uv-aarch64-unknown-linux-gnu.tar.gz": "0797542018e541a9288855df555c8077eed06f7a47d206362030480e8ecc9f3d",  # pragma: allowlist secret
}

# SHA256 of the executable inside each archive above; see the comment before _DIGESTS.
_EXECUTABLE_DIGESTS: dict[str, str] = {
    # actionlint v1.7.12
    "actionlint_1.7.12_linux_amd64.tar.gz": "c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4",  # pragma: allowlist secret
    "actionlint_1.7.12_linux_arm64.tar.gz": "ac0323433c2853ec3fb978c611430c5b3dc5d43c58d1a1ec031b00ab572beb60",  # pragma: allowlist secret
    "actionlint_1.7.12_darwin_amd64.tar.gz": "d1f7cee75ae2873609bd9567b4600bebc5315a5e733e73202987a44fafdd53b2",  # pragma: allowlist secret
    "actionlint_1.7.12_darwin_arm64.tar.gz": "8db11704dc296f096216db4db65d86cd7f0ebfdf4c38453a1da276b137b88388",  # pragma: allowlist secret
    "actionlint_1.7.12_windows_amd64.zip": "54ca21be3de4c7cfa26914aa8b61bd76bf573ef3caac5f80d110558cdf241718",  # pragma: allowlist secret
    "actionlint_1.7.12_windows_arm64.zip": "dc172c9dd32275b4a563143a318a48c91dff44fabafb23b7d1a05ed9c106a488",  # pragma: allowlist secret
    # betterleaks v1.10.1
    "betterleaks_1.10.1_linux_x64.tar.gz": "506082605cad984abd6ecf979a5f00fd6d701bc3ab2104a6029b1d068b3e320c",  # pragma: allowlist secret
    "betterleaks_1.10.1_linux_arm64.tar.gz": "a83657a5747c35ed35e0ef9a8a3d60ded4b29713e27856c2fbe7c63a1b972cb0",  # pragma: allowlist secret
    "betterleaks_1.10.1_darwin_x64.tar.gz": "d09400141ae0a155666f22ab974cff27c409c2c968445f7f0fc5958c4c5de62b",  # pragma: allowlist secret
    "betterleaks_1.10.1_darwin_arm64.tar.gz": "13ac5109fa85a590c7ba6e7f130311e0c60a2bf582c3aac073176c93b46621a8",  # pragma: allowlist secret
    "betterleaks_1.10.1_windows_x64.zip": "d9946b77870a30838f9a6a3591ea45c9c6530abfb0cf3890d2046b3d42816049",  # pragma: allowlist secret
    "betterleaks_1.10.1_windows_arm64.zip": "ed9ee26a6f1a8d7f042712e524802911e23fd1b1cb0561ecb606b4faab5882d4",  # pragma: allowlist secret
    # cfn-guard 3.3.0
    "cfn-guard-v3-x86_64-linux-latest.tar.gz": "308d1d109c0952036ed917fb09e45f3b9fb780f1dd65e15d8519816d70e0d9ab",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-linux-latest.tar.gz": "3b189145bdd679d7537a1385de94f9c95e338b40e57ffa3bd81fe9a01c5831fa",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-macos-latest.tar.gz": "c5aa74b9b43fe3cc84acde7cbabb30bf6468c23f75533e884caa675d4395daae",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-macos-latest.tar.gz": "d6d254eb422edd329658e9da6ec51751efb8038774346a6c28294b73bd203d2b",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-windows-latest.tar.gz": "1454eb1f5b0d7946fdc732c1776cc1219b24d66d3c7847595415d2debb14f90c",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-windows-latest.tar.gz": "1385d021ecda3e29fc74ab4003a096c1f5e886d75ec63f888cea1c9c15fbb95a",  # pragma: allowlist secret
    # crane v0.22.1 (go-containerregistry)
    "go-containerregistry_Linux_x86_64.tar.gz": "8e75c326adb43b053cfd78b9b987663f8f4fe4557f4d3915905643f25c730992",  # pragma: allowlist secret
    "go-containerregistry_Linux_arm64.tar.gz": "1799f559c299f068951822a5efe6689ebab6974f2054d5562e60798fa9db6a55",  # pragma: allowlist secret
    "go-containerregistry_Darwin_x86_64.tar.gz": "ea88e2619c139c69c6022c04bd6fd75692935f16798de281fa30a4fbf5c15069",  # pragma: allowlist secret
    "go-containerregistry_Darwin_arm64.tar.gz": "712be73700414edb792c9d7dd07315ff6ef1200decd6b2363e4ab834babb302d",  # pragma: allowlist secret
    "go-containerregistry_Windows_x86_64.tar.gz": "e22e47202cece45d09fe92919bdb683f56f548d360cb96f6a852defd965c935d",  # pragma: allowlist secret
    # gitleaks v8.30.1
    "gitleaks_8.30.1_linux_x64.tar.gz": "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",  # pragma: allowlist secret
    "gitleaks_8.30.1_linux_arm64.tar.gz": "00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b",  # pragma: allowlist secret
    "gitleaks_8.30.1_darwin_x64.tar.gz": "cee01fea7173f1b779dff188e1c26ecbcb4027d394acc573b23aaf0be260e291",  # pragma: allowlist secret
    "gitleaks_8.30.1_darwin_arm64.tar.gz": "ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f",  # pragma: allowlist secret
    "gitleaks_8.30.1_windows_x64.zip": "17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c",  # pragma: allowlist secret
    "gitleaks_8.30.1_windows_arm64.zip": "200df852fdecbedb19a33960657333cba5e231740bc8968972b507b50f93b194",  # pragma: allowlist secret
    # grype v0.122.1
    "grype_0.122.1_linux_amd64.tar.gz": "322a7839c1c9f6c1b6ac0aa6b61a7d94139b7f24780b82a05b63caab56d4286b",  # pragma: allowlist secret
    "grype_0.122.1_linux_arm64.tar.gz": "bd313717cfe7fa6807fed57942b661b02aa1709c77faaf3079a9b217b3a3d98c",  # pragma: allowlist secret
    "grype_0.122.1_darwin_amd64.tar.gz": "ca82c975f0788c9fa5a882c5eaa4b848e9d2c7c7d28d20519eadfe3cdc9a22f4",  # pragma: allowlist secret
    "grype_0.122.1_darwin_arm64.tar.gz": "df8effdd7d4069cfd8762516aa37ddc9e5bf026469f4f509daae2ef730c517f1",  # pragma: allowlist secret
    "grype_0.122.1_windows_amd64.zip": "663d5d39c88013ef043a159f7ccc3bf6a17a1bb1346edfc2272e2b7e241daf27",  # pragma: allowlist secret
    # syft v1.57.2
    "syft_1.57.2_linux_amd64.tar.gz": "17cc40c1e40dbfdeb8c84b6d9928909bceb793f22e8a8023ef408625f1d96ec5",  # pragma: allowlist secret
    "syft_1.57.2_linux_arm64.tar.gz": "2bbe674996bbe831dcc68fa50b0c5e68acd728c5d9da7cc68d88713a9ef6b748",  # pragma: allowlist secret
    "syft_1.57.2_darwin_amd64.tar.gz": "937b74689e65014b1f5720ded9b3bbf6a464c0e3f50f1c162cbaf3373199bd8e",  # pragma: allowlist secret
    "syft_1.57.2_darwin_arm64.tar.gz": "a55d46242c69903c31c10fdceb4579a9f712280b6994001949f8ef634558a99f",  # pragma: allowlist secret
    "syft_1.57.2_windows_amd64.zip": "5c9d2ba5affae29c3c5ba5796ad28fc72780189fafcb893544325902a298b17e",  # pragma: allowlist secret
    "syft_1.57.2_windows_arm64.zip": "fc0dc146da865c78c3be317bbdfaa2d28e90dd80594c39cccd56ec5603c82621",  # pragma: allowlist secret
    # trivy v0.76.2
    "trivy_0.76.2_Linux-64bit.tar.gz": "6a972c69606c7b3ea4c6bdcc6fc9332ea9ad38381624310c1e85cc77345909f3",  # pragma: allowlist secret
    "trivy_0.76.2_Linux-ARM64.tar.gz": "7844c3851b28470b6d7f0975fa0b3262c5b2272c9a54a91f522801bb8926f51f",  # pragma: allowlist secret
    "trivy_0.76.2_macOS-64bit.tar.gz": "d92df6dbfad2bc30e05e10508d43cdbc43f1e8553285f9d04473a10545f2e928",  # pragma: allowlist secret
    "trivy_0.76.2_macOS-ARM64.tar.gz": "7a15c426f963473a485a4f315e21f8e2c881269d500bf0de35da13a4421fa108",  # pragma: allowlist secret
    "trivy_0.76.2_windows-64bit.zip": "dd07adf881a72b54d1a922191d62fa939938df2155be85a727da93b67b24e617",  # pragma: allowlist secret
    # opengrep v2.0.0 (the Windows zip only; its other assets are bare executables)
    "opengrep_windows_x86.zip": "3c9d000363cfe48df8ea153f3023cbe05fb848cb1d31fbc2858c0eed1361ea25",  # pragma: allowlist secret
    # uv 0.13.9
    "uv-x86_64-unknown-linux-gnu.tar.gz": "b73acdf73b96c3ac9e56d2fa933427b3ee6a901e3cce6ba1e3ecb3f91ca0d86a",  # pragma: allowlist secret
    "uv-aarch64-unknown-linux-gnu.tar.gz": "6109e47a75f2380d1cc90b00a6ee82b7b5792ddf66588625ec168545ae17512e",  # pragma: allowlist secret
}

# What each rules bundle archive extracts to; see the comment before _DIGESTS.
_BUNDLE_CONTENTS_DIGESTS: dict[str, str] = {
    # aws-guard-rules-registry 1.0.2: 50 rule files
    "ruleset-build-v1.0.2.zip": "5b5c48e45051dbd862894d9fd494deee1f52319163ea19ebabd8fb08896cd323",  # pragma: allowlist secret
}

# Files an archive carries beside its executable, by member name; see before _DIGESTS.
_COMPANION_DIGESTS: dict[str, dict[str, str]] = {
    # opengrep v2.0.0 Windows: the MinGW runtime beside opengrep.exe
    "opengrep_windows_x86.zip": {
        "libgcc_s_seh-1.dll": "645763b1b6f52c6a755444dfb781e6a606e1fda3061b2a3d9806780bb3dc54b4",  # pragma: allowlist secret
        "libgmp-10.dll": "c188e570157c109181e6788c2837fcead79747a7b10209cd82ebf5365787f508",  # pragma: allowlist secret
        "libpcre2-8-0.dll": "563cb7436d6eba69b18080557bacaa5f620789a3b7a528a6eb2f8fad485e3dea",  # pragma: allowlist secret
        "libstdc++-6.dll": "6244b77e3635c735ec7d463dcd748beef08a7e6facfa6e47e5463f388fa3b178",  # pragma: allowlist secret
        "libwinpthread-1.dll": "fe0259c7c8bf875cce79dc63f7af2c350138e77e60c51cb44d35aaee4d45e3ee",  # pragma: allowlist secret
        "libzstd-1.dll": "bbf5c934a2a80cf28b944e2e493aef3b4886fa6f9b4b026f42531f3f53c62907",  # pragma: allowlist secret
    },
}

# The version each unversioned tool's digests above were taken from.
#
# The other tools put the version in every asset name, so bumping
# TOOL_VERSIONS without the table changes every URL to a filename the digest table
# has no entry for, and get_tool_asset refuses it by name. opengrep and uv do not:
# `opengrep_linux_x86` is the name of that asset in every 2.x release. Bumping the
# version alone would therefore resolve the new URL to the OLD release's digest. That
# still fails closed -- the download would not match -- but as a SHA256 mismatch, the
# message that means "possible supply-chain substitution", for what is a half-applied
# edit. Recording the version here turns it into the same refusal by name instead.
_DIGESTS_TAKEN_AT: dict[str, str] = {
    "cfn-guard": "3.3.0",
    # go-containerregistry names its assets for the repository and platform only
    # (go-containerregistry_Linux_x86_64.tar.gz), the version being in the tag.
    "crane": "v0.22.1",
    "hadolint": "v2.15.1",
    "opengrep": "v2.0.0",
    "uv": "0.13.9",
}

# Tools whose release asset is the executable itself rather than an archive, except an
# asset whose name says it is one (opengrep's Windows zip; see get_tool_asset).
_BARE_EXECUTABLE_TOOLS = frozenset({"hadolint", "opengrep"})


_RELEASE_BASE_URLS: dict[str, str] = {
    "actionlint": "https://github.com/rhysd/actionlint/releases/download",
    "betterleaks": "https://github.com/betterleaks/betterleaks/releases/download",
    "cfn-guard": "https://github.com/aws-cloudformation/cloudformation-guard/releases/download",
    "crane": "https://github.com/google/go-containerregistry/releases/download",
    "gitleaks": "https://github.com/gitleaks/gitleaks/releases/download",
    "grype": "https://github.com/anchore/grype/releases/download",
    "hadolint": "https://github.com/hadolint/hadolint/releases/download",
    "opengrep": "https://github.com/opengrep/opengrep/releases/download",
    "syft": "https://github.com/anchore/syft/releases/download",
    "trivy": "https://github.com/aquasecurity/trivy/releases/download",
    "uv": "https://github.com/astral-sh/uv/releases/download",
}

_ASSET_TABLES: dict[str, dict[PlatformArch, str]] = {
    "actionlint": _ACTIONLINT_ASSETS,
    "betterleaks": _BETTERLEAKS_ASSETS,
    "cfn-guard": _CFN_GUARD_ASSETS,
    "crane": _CRANE_ASSETS,
    "gitleaks": _GITLEAKS_ASSETS,
    "grype": _GRYPE_ASSETS,
    "hadolint": _HADOLINT_ASSETS,
    "opengrep": _OPENGREP_ASSETS,
    "syft": _SYFT_ASSETS,
    "trivy": _TRIVY_ASSETS,
    "uv": _UV_ASSETS,
}


@dataclass(frozen=True)
class LinkageRead:
    """What one asset is recorded to link the C library as, at which release, and from
    where the reading came."""

    linkage: Linkage
    #: The release the asset was read at. A pin that has moved to another release does
    #: not inherit the read (``get_tool_asset`` reads the asset as ``unread``).
    version: str
    source: str


# The linkage of the assets this module already records a reading of, keyed by asset
# filename. No other asset is here, and none is guessed: an asset not listed, or listed
# for a release the pin has moved past, is ``unread``.
#
# * opengrep's Linux assets are the statically linked executables the module docstring
#   describes for v2.0.0 (``opengrep_linux_*``). Its other platforms are not those
#   builds, so they are not listed.
# * uv's Linux assets are the builds whose names carry the ``unknown-linux-gnu`` target
#   triple (``_UV_ASSETS``), which names a glibc build.
# * cfn-guard is not here. Its Linux assets were read as statically linked at 3.2.1
#   (the comment above ``_CFN_GUARD_ASSETS``) and the pin is 3.3.0.
_OPENGREP_STATIC_READ = (
    "the module docstring's account of opengrep v2.0.0: the Linux assets are "
    "statically linked executables"
)
_UV_GNU_READ = (
    "the pinned asset name: its unknown-linux-gnu target triple is uv's glibc build"
)
_LINKAGE_READS: dict[str, LinkageRead] = {
    "opengrep_linux_x86": LinkageRead(Linkage.STATIC, "v2.0.0", _OPENGREP_STATIC_READ),
    "opengrep_linux_aarch64": LinkageRead(
        Linkage.STATIC, "v2.0.0", _OPENGREP_STATIC_READ
    ),
    "uv-x86_64-unknown-linux-gnu.tar.gz": LinkageRead(
        Linkage.GLIBC, "0.13.9", _UV_GNU_READ
    ),
    "uv-aarch64-unknown-linux-gnu.tar.gz": LinkageRead(
        Linkage.GLIBC, "0.13.9", _UV_GNU_READ
    ),
}


@dataclass(frozen=True)
class RulesBundle:
    """A pinned archive of rule files, installed as a directory rather than a binary.

    ``member_dir`` is the directory inside the archive that holds the rule files
    and ``member_suffix`` the extension they carry. Only regular files directly in
    that directory with that suffix are extracted, each to its basename, so the
    archive's own paths are never used as a destination. That also drops the
    ``__MACOSX/`` resource-fork entries the registry's zip carries.

    ``sha256`` pins the archive (``_DIGESTS``). ``contents_sha256`` pins what it
    extracts to (``_BUNDLE_CONTENTS_DIGESTS``): ``rules_bundles.contents_digest`` of
    every file extracted, the SHA256 of the sorted ``"<basename>\\t<sha256>\\n"``
    lines. An installed bundle is checked against it alone, never against the
    manifest the installer writes beside the files. Both values move together when
    the version does: download the new archive, extract it with
    ``rules_bundles.extract_bundle`` and pin ``contents_digest`` of the map it
    returns.
    """

    name: str
    version: str
    url: str
    sha256: str
    contents_sha256: str
    member_dir: str
    member_suffix: str
    license: str


#: The AWS Guard Rules Registry, the rule source for the cfn-guard scanner.
#:
#: Release 1.0.2 (2022-09-02) is the newest release the registry has published;
#: later commits on its default branch were never released, and a release asset is
#: what can be pinned by digest. The archive holds 50 rule-set files, one per
#: compliance framework plus ``guard-rules-registry-all-rules.guard``; all 50 parse
#: under cfn-guard 3.2.1 (each was run against a template and exited 19, the
#: rule-failure code, rather than 255). Apache-2.0, like cfn-guard itself.
# Private, so the pin checker does not count it twice: it reads this release from
# THIRD_PARTY_LICENSES["aws-guard-rules-registry"], which a unit test keeps equal.
_CFN_GUARD_RULES_RELEASE = "1.0.2"

RULES_BUNDLES: dict[str, RulesBundle] = {
    "aws-guard-rules-registry": RulesBundle(
        name="aws-guard-rules-registry",
        version=_CFN_GUARD_RULES_RELEASE,
        url=(
            "https://github.com/aws-cloudformation/aws-guard-rules-registry/"
            f"releases/download/{_CFN_GUARD_RULES_RELEASE}/"
            f"ruleset-build-v{_CFN_GUARD_RULES_RELEASE}.zip"
        ),
        sha256=_DIGESTS[f"ruleset-build-v{_CFN_GUARD_RULES_RELEASE}.zip"],
        contents_sha256=_BUNDLE_CONTENTS_DIGESTS[
            f"ruleset-build-v{_CFN_GUARD_RULES_RELEASE}.zip"
        ],
        member_dir="output",
        member_suffix=".guard",
        license="Apache-2.0",
    ),
}


def get_rules_bundle(name: str) -> RulesBundle:
    """The pinned rules bundle called ``name``.

    Raises:
        ToolNotProvisionableError: if no bundle of that name is pinned.
    """
    bundle = RULES_BUNDLES.get(name)
    if bundle is None:
        raise ToolNotProvisionableError(
            f"{name} is not a pinned rules bundle. "
            f"Pinned bundles: {', '.join(sorted(RULES_BUNDLES))}"
        )
    return bundle


# ---------------------------------------------------------------------------
# License and notice files for the third-party executables the container image
# bundles.
#
# Why this exists
# ---------------
# The image redistributes upstream release binaries -- every tool in TOOL_VERSIONS,
# plus opengrep and uv -- and the Python scanners bandit, checkov and semgrep, which
# ``ash dependencies install`` puts in place with ``uv tool install``. Every one of
# those licenses makes redistribution conditional on shipping something with the
# binary: Apache-2.0 section 4(a) and (d) a copy of the license and the upstream
# NOTICE, MIT the copyright and permission notice, LGPL and GPL the license and a
# way to get the corresponding source. Until this table the image shipped the
# binaries alone. Not even trivy's NOTICE was there, because trivy keeps it in its
# repository and leaves it out of its release archive.
#
# What the image gets
# -------------------
# One directory per entry, ``THIRD_PARTY_DOC_DIR/<tool>/``, holding:
#
# * every file in ``files``, under its upstream name. A file with no ``url`` is
#   read from the release archive the binary itself comes from -- the archive
#   ``install-pinned-tool`` has already checked against the digest above, so a
#   license file costs no extra download and no extra trust. A file with a
#   ``url`` is fetched from the upstream repository AT ``commit`` and must hash to
#   its ``sha256``, like a binary. That is for files the release archive lacks:
#   opengrep publishes a bare executable, uv's archive carries no license, and
#   trivy's NOTICE is only in its repository.
#
#   For an entry with a ``distribution`` -- a Python tool installed with ``uv tool
#   install`` -- the wheel is the archive: a file with no ``url`` is read from the
#   installed wheel's dist-info, checked against the hash its RECORD lists, and the
#   installed version must be the entry's. A file with a ``url`` is the fallback for
#   a wheel that does not carry it: semgrep's wheel declares
#   ``License-Expression: LGPL-2.1-or-later`` in its METADATA and ships no license
#   file at all, so its LICENSE and COPYRIGHT are fetched from its repository. Were
#   a later wheel to carry the file, the dist-info copy is used instead and must
#   still hash to the pin, so the image's bytes are the same either way. These
#   entries are staged by ``install-pinned-tool --licenses-only`` after ``ash
#   dependencies install``, which ``install-pinned-tool --uv-tool-pins`` tells to
#   install exactly the entry's version rather than the newest the scanner's
#   default constraint allows; otherwise the files and the source commit would
#   describe whichever release PyPI had on the day of the build.
# * ``SOURCE``: the tool, version, license expression, upstream repository, tag
#   and commit, and a source archive URL for that commit. Written for every tool.
#
# and the image gets ``THIRD_PARTY_DOC_DIR/index.json``, the machine-readable
# list of everything bundled, which ``install-pinned-tool --verify-third-party``
# writes only after it has checked every entry against the built image: files
# present and matching their digests, each executable on PATH, and each
# executable's ``--version`` reporting the version recorded here.
#
# The copyleft source convention
# ------------------------------
# A tool whose license expression names a copyleft license (``COPYLEFT_SPDX``;
# today opengrep, LGPL-2.1, and in future hadolint, GPL-3.0) gets the same
# directory, and its ``SOURCE`` file additionally carries a "Corresponding source"
# section: the repository, the tag, the full commit SHA the tag points to, and the
# git commands that check that commit out with its submodules. Not a GitHub
# "archive" tarball URL: those omit submodule contents, and opengrep alone has 39
# submodules, so the tarball is not the corresponding source. Its license text is
# a ``files`` entry like any other. ``commit`` is mandatory for every entry, so this costs a copyleft
# entry nothing extra -- it is written from the same fields -- and a tag moved
# upstream after the fact cannot change what the image points at. The commit is
# the one ``gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`` returns. ASH
# ships these binaries unmodified, so upstream's source at that commit IS the
# corresponding source.
#
# Adding a tool
# -------------
# Every key of TOOL_VERSIONS must have an entry here with the same version --
# tests/unit/utils/test_third_party_licenses.py fails otherwise, and the image
# build refuses to install a pinned tool with no entry. For a new tool:
#
# 1. Read its LICENSE (and NOTICE, COPYING, COPYRIGHT if the repository has
#    them) at the release tag, and write the SPDX expression the text supports,
#    e.g. ``GPL-3.0-only`` rather than GitHub's ``GPL-3.0`` label.
# 2. ``gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`` for ``commit``.
# 3. List the release archive (``tar tzf``/``unzip -l``). Each license or notice
#    file in it is ``LicenseFile("<basename>")``. Each one only in the
#    repository is ``LicenseFile("<name>", url=_source_file(...), sha256=...)``
#    with the digest of the file downloaded from that URL.
# 4. Insert the entry in alphabetical position below. If the tool is not
#    installed by ``install-pinned-tool <tool>`` in the Dockerfile, add it to the
#    ``install-pinned-tool --licenses-only`` line there.
#
# For a Python tool installed with ``uv tool install``, set ``distribution`` to its
# PyPI name and ``version`` to its release tag, list the wheel's dist-info (``unzip
# -l``; PEP 639 wheels keep license files under ``licenses/``), and add the tool to
# the ``--licenses-only`` line that follows ``ash dependencies install``. A license
# file the wheel lacks is URL-pinned as in step 3. The entry's ``tool`` must be the
# scanner's name, because it is also the key ``--uv-tool-pins`` overrides.
#
# ``scripts/check_pinned_tool_versions.py`` reads new entries from these tables and
# needs no edit to start reporting the tool's upstream releases and what a bump of it
# changes, as long as ``TOOL_VERSIONS`` or ``RULES_BUNDLES`` pins its download or it
# has a ``distribution``. An entry none of those name is refused until the script is
# taught what kind of pin it is.
#
# Known limitations
# -----------------
# * The Go and Rust binaries here statically link their dependency modules, whose
#   own licenses are not reproduced. No upstream release ships them either; the
#   module list is embedded in each Go binary (``go version -m <binary>``).
# * For the Python tools only the tool's own distribution is covered, not the
#   dependency closure ``uv tool install`` resolves beside it in the tool's
#   environment. Each of those wheels keeps whatever license files it ships in its
#   own dist-info there, as installed.
# * The Jupyter converter's ``nbconvert`` (with ``jupyter``) is also installed with
#   ``uv tool`` and has no entry; its wheel carries its LICENSE in its dist-info.
# ---------------------------------------------------------------------------

THIRD_PARTY_DOC_DIR = "/usr/share/doc/ash/third-party"

# SPDX identifiers whose terms ask a redistributor to point at corresponding
# source. Matched per identifier inside an expression, so "MIT OR GPL-3.0-only"
# counts as copyleft: the conservative reading of a choice ASH has not made.
COPYLEFT_SPDX = frozenset(
    {
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "EPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
    }
)

# Identifiers an entry may use without being copyleft. A license outside both sets
# fails the unit tests, so a new one is classified on purpose rather than by
# omission.
PERMISSIVE_SPDX = frozenset(
    {
        "0BSD",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "MIT",
        "MIT-0",
        "OpenSSL",
        "Unlicense",
    }
)

# License exceptions an expression may name after WITH. An exception only adds
# permissions to the license it modifies, so it is not classified on its own: the
# license before WITH decides whether the entry is copyleft. Listed so an unknown
# token after WITH still fails the tests instead of passing as an exception.
SPDX_EXCEPTIONS = frozenset({"GCC-exception-2.0"})

_SPDX_OPERATORS = frozenset({"AND", "OR", "WITH"})


@dataclass(frozen=True)
class LicenseFile:
    """One license or notice file installed beside a bundled tool.

    ``name`` is the file's name in the image. With no ``url`` it is also the
    basename of the member read from the tool's release archive, matched by the
    same exactly-one rule as the executable; for an entry with a ``distribution``
    the archive is the wheel, and the file is read from its installed dist-info.
    With a ``url``, the bytes must hash to ``sha256``.
    """

    name: str
    url: "str | None" = None
    sha256: "str | None" = None

    @property
    def from_archive(self) -> bool:
        return self.url is None


@dataclass(frozen=True)
class ThirdPartyLicense:
    """What the image must carry for one bundled third-party tool.

    ``version`` is the upstream release tag, spelled exactly as TOOL_VERSIONS
    spells it. ``executables`` are the names the tool puts on PATH; empty means
    just ``tool``. The first must be present. Every copy of any of them on PATH
    that a Python package did not install must report ``version``: uv is also an
    ASH dependency from PyPI, at whatever version pyproject's range resolves to,
    and that copy carries its own license metadata in its dist-info.

    ``version_probe`` is for a component that is not an executable on PATH: a
    rules bundle another tool reads, or a native library inside a uv tool's
    environment. When set, the PATH and ``--version`` checks are replaced by
    running this argv, whose output must report ``version``. ``{uv_tool_dir}`` in
    an argument is replaced with what ``uv tool dir`` prints.

    ``distribution`` is set for a tool ``ash dependencies install`` installs with
    ``uv tool install``: the PyPI name of the distribution, whose installed
    dist-info the license files are read from. ``version`` is still the upstream
    release tag; without its leading ``v`` it is the version installed.
    """

    tool: str
    version: str
    license: str
    repository: str
    commit: str
    files: "tuple[LicenseFile, ...]"
    executables: "tuple[str, ...]" = ()
    version_probe: "tuple[str, ...]" = ()
    distribution: "str | None" = None
    # Appended to the "Corresponding source" section of a copyleft entry whose
    # binary also carries code from outside its own repository (a statically
    # linked binary's library dependencies), saying where that source is.
    source_note: "str | None" = None
    # The upstream tag when it is not spelled like ``version`` (OpenSSL's
    # "OpenSSL_1_1_1w"), or "" when the release has no tag (PCRE1).
    tag: "str | None" = None
    # Set for a library another wheel bundles: what bundles it, for SOURCE. Its version
    # is that wheel's choice, so the pin checker lists it without looking it up.
    bundled_in: "str | None" = None

    @property
    def executable_names(self) -> tuple[str, ...]:
        return self.executables or (self.tool,)

    @property
    def spdx_tokens(self) -> list[str]:
        """Every identifier in ``license``: licenses and exceptions alike."""
        tokens = self.license.replace("(", " ").replace(")", " ").split()
        return [t for t in tokens if t not in _SPDX_OPERATORS]

    @property
    def spdx_exceptions(self) -> list[str]:
        """The identifiers that follow WITH: exceptions, not licenses."""
        tokens = self.license.replace("(", " ").replace(")", " ").split()
        return [b for a, b in zip(tokens, tokens[1:]) if a == "WITH"]

    @property
    def spdx_identifiers(self) -> list[str]:
        """The license identifiers in ``license``, without operators or exceptions."""
        exceptions = self.spdx_exceptions
        return [t for t in self.spdx_tokens if t not in exceptions]

    @property
    def copyleft(self) -> bool:
        return any(t in COPYLEFT_SPDX for t in self.spdx_identifiers)

    @property
    def source_checkout(self) -> list[str]:
        """Commands that reproduce the source tree at ``commit``, submodules included."""
        directory = self.repository.rsplit("/", 1)[-1]
        return [
            f"git clone {self.repository}",
            f"git -C {directory} checkout {self.commit}",
            f"git -C {directory} submodule update --init --recursive",
        ]

    @property
    def _release_tag(self) -> str:
        if self.tag is None:
            return self.version
        return self.tag or "none (the repository has no tag for it; see Commit)"

    def source_notice(self, installed_from: "str | None" = None) -> str:
        """The text of the ``SOURCE`` file written beside the license files."""
        lines = [
            f"{self.tool} {self.version}",
            (
                f"License: {self.license}"
                f" (see {', '.join(f.name for f in self.files)} in this directory)"
            ),
            "",
            f"Upstream repository: {self.repository}",
            f"Release tag:         {self._release_tag}",
            f"Commit:              {self.commit}",
        ]
        if installed_from:
            lines.append(f"Installed from:      {installed_from}")
        if self.bundled_in:
            statement = (
                f"ASH ships this library as {self.bundled_in} bundles it, unmodified. "
                "The binary was built for that wheel, not published by the project "
                "above; the commit above is the upstream source of this release."
            )
        else:
            statement = (
                "ASH bundles this program unmodified, as published by its upstream "
                "project."
            )
        lines += ["", statement]
        if self.copyleft:
            lines += [
                "",
                "Corresponding source",
                "--------------------",
                (
                    f"{self.tool} is distributed under {self.license}. Its source is "
                    "the upstream repository at the commit this release was built "
                    "from, together with the git submodules that commit records:"
                ),
                "",
                f"  repository: {self.repository}",
                f"  tag:        {self.version}",
                f"  commit:     {self.commit}",
                "",
                "To check it out:",
                "",
                *(f"  {command}" for command in self.source_checkout),
            ]
            if self.source_note:
                lines += ["", self.source_note]
        return "\n".join(lines) + "\n"

    def index_record(self) -> "dict[str, object]":
        """This entry as it appears in the image's ``index.json``."""
        return {
            "tool": self.tool,
            "version": self.version,
            "license": self.license,
            "copyleft": self.copyleft,
            "repository": self.repository,
            "commit": self.commit,
            "executables": [] if self.version_probe else list(self.executable_names),
            "files": [f.name for f in self.files] + ["SOURCE"],
        }


def _source_file(repository: str, commit: str, path: str) -> str:
    """URL of ``path`` in ``repository`` at exactly ``commit``, never at a tag."""
    owner_repo = repository.removeprefix("https://github.com/")
    return f"https://raw.githubusercontent.com/{owner_repo}/{commit}/{path}"


# Every hex value the entries below use, and nothing else, in one block: the
# alpha config's ferret-scan suppression is pinned to exactly these lines, and
# tests/unit/utils/test_third_party_licenses.py keeps the two in step.
#
# "<tool> commit" is the commit the release tag points to, from
# `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`. "<tool>/<file>" is the
# SHA256 of that file downloaded from its URL in the entry. Archive-member files
# have no digest here: the archive digest in _DIGESTS covers them. For grype, syft
# and trivy the archive's LICENSE was also checked byte-identical to the
# repository's at the same commit. semgrep's two files are byte-identical to
# opengrep's, which forked it, so they share digests.
_THIRD_PARTY_HASHES: dict[str, str] = {
    "actionlint commit": "914e7df21a07ef503a81201c76d2b11c789d3fca",  # pragma: allowlist secret
    "aws-guard-rules-registry commit": "72352d1e5414e496ab75fae216119e65d8e61d53",  # pragma: allowlist secret
    "aws-guard-rules-registry/LICENSE": "09e8a9bcec8067104652c168685ab0931e7868f9c8284b66f5ae6edae5f1130b",  # pragma: allowlist secret
    "aws-guard-rules-registry/NOTICE": "d4290ed64c2edd0fce1d84e3f9dfb2881240fe534def76b8cd29ed6af683e287",  # pragma: allowlist secret
    "bandit commit": "92ae8b82fb422a639f0ed8d99e96cea769594e08",  # pragma: allowlist secret
    "betterleaks commit": "39d5bdcf34db54e944facac5cf6e8b03db5e2b99",  # pragma: allowlist secret
    "cfn-lint commit": "720c5cc3d59094baee65a6f5648c111524545061",  # pragma: allowlist secret
    "checkov commit": "2f107f8613830f773b23fa21104b7ac2885c2581",  # pragma: allowlist secret
    "cfn-guard commit": "db494a17fb6030b365d5a5144a397517c7746797",  # pragma: allowlist secret
    "cfn-guard/LICENSE": "28878a48de57252ed2c9119db71b2fc9766833a0c159d9f5df54cba4dea52dba",  # pragma: allowlist secret
    "cfn-guard/NOTICE": "ba249a48f79f76c72cffea8689eb7a5ce450a4a67ad6b1e44e8ff15a95b2b751",  # pragma: allowlist secret
    "crane commit": "8a72a424fdecb4caa14f2d525e5d2503331442b5",  # pragma: allowlist secret
    "gitleaks commit": "83d9cd684c87d95d656c1458ef04895a7f1cbd8e",  # pragma: allowlist secret
    "grype commit": "8f3ddeddc4a4ed6314248aaf0a7c510f98db8882",  # pragma: allowlist secret
    "guarddog commit": "3da172679cb58b1c9a780f9f5d640f855be016dc",  # pragma: allowlist secret
    "hadolint commit": "2eece55955ced00200be9729e9728cb7dacca505",  # pragma: allowlist secret
    "hadolint/LICENSE": "589ed823e9a84c56feb95ac58e7cf384626b9cbf4fda2a907bc36e103de1bad2",  # pragma: allowlist secret
    "hadolint/ThirdPartyNotices.txt": "424561d8aade37960e8db594ca5403f9a4a98f593ff1126a296298f11d3d1a27",  # pragma: allowlist secret
    "libgit2 commit": "0060d9cf5666f015b1067129bd874c6cc4c9c7ac",  # pragma: allowlist secret
    "libgit2/AUTHORS": "126ed06438e488d71f5232b39436b3a1dffccb9c2697e3a332fbe868975cd55f",  # pragma: allowlist secret
    "libgit2/COPYING": "e3712465634e97cfd850822a4eb5ac7d2f8a10f753189366d5a2060046f28288",  # pragma: allowlist secret
    "libssh2 commit": "a312b43325e3383c865a87bb1d26cb52e3292641",  # pragma: allowlist secret
    "libssh2/COPYING": "f7f9633cf9ff2f1333f3d7ce46973a8716a4d2a2815ad56f30d437d5fea7bafe",  # pragma: allowlist secret
    "opengrep commit": "526deafe6f0519c272bbee316fea8df26dd85dfa",  # pragma: allowlist secret
    "opengrep/COPYRIGHT": "0f90eaca8e598c6c67a6cda7beb4470518fb2dababc996b3898344d380769aca",  # pragma: allowlist secret
    "opengrep/LICENSE": "20c17d8b8c48a600800dfd14f95d5cb9ff47066a9641ddeab48dc54aec96e331",  # pragma: allowlist secret
    "openssl commit": "42768eafab40d3e2f0851caa84aa9801139c74ab",  # pragma: allowlist secret
    "openssl-1.1 commit": "e04bd3433fd84e1861bf258ea37928d9845e6a86",  # pragma: allowlist secret
    "openssl-1.1/LICENSE": "c32913b33252e71190af2066f08115c69bc9fddadf3bf29296e20c835389841c",  # pragma: allowlist secret
    "openssl/LICENSE.txt": "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a",  # pragma: allowlist secret
    "pcre commit": "c8dd39955982faaf63176bedc456746e5cf43e2f",  # pragma: allowlist secret
    "pcre/LICENCE": "f998c0f52eb704eff28f503580cfca3f2547280aa212994f6cf2d8e317587c1c",  # pragma: allowlist secret
    "pygit2 commit": "d88fa3dcbab21a7eb33ff354222c4ec8e5ff6ece",  # pragma: allowlist secret
    "pygit2/AUTHORS.md": "4ecad3164600b3c7a216cdd636288d1434afd6307737cfeba8fc1372dc04ba20",  # pragma: allowlist secret
    "pygit2/COPYING": "3f2a642de5f24ed216404873b875e9d1c5dd112a4e0ae27a42f7303583f69683",  # pragma: allowlist secret
    "semgrep commit": "a5844e7c2d9d04548f86048f525d467a00742656",  # pragma: allowlist secret
    "semgrep/COPYRIGHT": "0f90eaca8e598c6c67a6cda7beb4470518fb2dababc996b3898344d380769aca",  # pragma: allowlist secret
    "semgrep/LICENSE": "20c17d8b8c48a600800dfd14f95d5cb9ff47066a9641ddeab48dc54aec96e331",  # pragma: allowlist secret
    "syft commit": "1a72047fd46c72e0a12ee77e24b23d2316753d08",  # pragma: allowlist secret
    "trivy commit": "3f6334d223b52188324af3b9923b4249cd206652",  # pragma: allowlist secret
    "trivy/NOTICE": "aed9bc6dab87c6f6567d20bf0f5c0433a8ccd3ad7873322cf79b9244eb720a1f",  # pragma: allowlist secret
    "uv commit": "6b2d39dcc390293d51c9c0d2bbcd650f4bcbfdce",  # pragma: allowlist secret
    "uv/LICENSE-APACHE": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",  # pragma: allowlist secret
    "uv/LICENSE-MIT": "860e3d7a86b84e6a7012c7a635fc64df475cebc6cce34dfeb73a5982ec58176c",  # pragma: allowlist secret
    "zizmor commit": "0af0be985a4cae71ecfaa64ef574a94b35dc722a",  # pragma: allowlist secret
}


def _from_source(tool: str, repository: str, name: str) -> LicenseFile:
    """A license file fetched from ``repository`` at ``tool``'s pinned commit."""
    return LicenseFile(
        name,
        url=_source_file(repository, _THIRD_PARTY_HASHES[f"{tool} commit"], name),
        sha256=_THIRD_PARTY_HASHES[f"{tool}/{name}"],
    )


def _bundled_library_probe(
    module: str, libs_dir: str, parents: int, glob: str, pattern: bytes, prefix: str
) -> "tuple[str, ...]":
    """A version_probe for a shared library a wheel in GuardDog's environment bundles.

    auditwheel copies the shared libraries a wheel links against into
    ``site-packages/<project>.libs`` under hashed names, and none of them can be
    asked for its version, so the probe reads the version string each one embeds.
    ``module`` is imported with GuardDog's own interpreter to find
    site-packages, ``parents`` levels up from its ``__file__``. No matching file,
    or no match in it, raises, so the image build fails rather than vouching for a
    library that is not there.
    """
    code = (
        f"import pathlib, re, {module}; "
        f"d = pathlib.Path({module}.__file__).resolve(){'.parent' * parents} / {libs_dir!r}; "
        f"b = b''.join(p.read_bytes() for p in sorted(d.glob({glob!r}))); "
        f"m = re.search({pattern!r}, b); "
        f"print({prefix!r} + m.group(1).decode())"
    )
    return ("{uv_tool_dir}/guarddog/bin/python", "-c", code)


def _pygit2_bundled_library_probe(
    glob: str, pattern: bytes, prefix: str
) -> "tuple[str, ...]":
    """A probe for a library the pygit2 wheel bundles in ``pygit2.libs``."""
    return _bundled_library_probe("pygit2", "pygit2.libs", 2, glob, pattern, prefix)


# Alphabetical, one entry per tool.
THIRD_PARTY_LICENSES: dict[str, ThirdPartyLicense] = {
    "actionlint": ThirdPartyLicense(
        tool="actionlint",
        version="v1.7.12",
        license="MIT",
        repository="https://github.com/rhysd/actionlint",
        commit=_THIRD_PARTY_HASHES["actionlint commit"],
        files=(LicenseFile("LICENSE.txt"),),
    ),
    # The rule files cfn-guard evaluates, installed by
    # `install-pinned-tool aws-guard-rules-registry --rules-bundle` (RULES_BUNDLES).
    # Not an executable, so the build reads the version from the manifest that
    # install wrote. The release zip holds no license file.
    "aws-guard-rules-registry": ThirdPartyLicense(
        tool="aws-guard-rules-registry",
        version="1.0.2",
        license="Apache-2.0",
        repository="https://github.com/aws-cloudformation/aws-guard-rules-registry",
        commit=_THIRD_PARTY_HASHES["aws-guard-rules-registry commit"],
        files=(
            _from_source(
                "aws-guard-rules-registry",
                "https://github.com/aws-cloudformation/aws-guard-rules-registry",
                "LICENSE",
            ),
            _from_source(
                "aws-guard-rules-registry",
                "https://github.com/aws-cloudformation/aws-guard-rules-registry",
                "NOTICE",
            ),
        ),
        # The probe reads the manifest of the PINNED bundle directory only: a glob
        # over every aws-guard-rules-registry-* directory printed each installed
        # version, so the check passed as long as any of them was the pinned one,
        # and an unset ASH_CFN_GUARD_RULES_DIR raised KeyError, which read as a
        # version mismatch. With the variable unset or empty the probe now exits
        # after saying so on stderr: globbing with an empty base would search a
        # RELATIVE path, which could find a manifest from a lucky working
        # directory. The directory name carries the pinned release, so a bundle
        # bump moves the probe with it.
        version_probe=(
            "python3",
            "-c",
            (
                "import glob, json, os, sys; "
                "d = os.environ.get('ASH_CFN_GUARD_RULES_DIR'); "
                "d or print('ASH_CFN_GUARD_RULES_DIR is not set', file=sys.stderr); "
                "d or sys.exit(0); "
                "[print(json.load(open(m))['version']) for m in glob.glob(os.path.join("
                f"d, 'aws-guard-rules-registry-{_CFN_GUARD_RULES_RELEASE}', "
                "'.ash-rules-manifest.json'))]"
            ),
        ),
    ),
    # The wheel's dist-info carries licenses/LICENSE. The repository has no NOTICE.
    "bandit": ThirdPartyLicense(
        tool="bandit",
        version="1.9.4",
        license="Apache-2.0",
        repository="https://github.com/PyCQA/bandit",
        commit=_THIRD_PARTY_HASHES["bandit commit"],
        files=(LicenseFile("LICENSE"),),
        distribution="bandit",
    ),
    # The release archive holds the executable, a README and the MIT LICENSE, which
    # is byte-identical to the repository's at the release commit.
    "betterleaks": ThirdPartyLicense(
        tool="betterleaks",
        version="v1.10.1",
        license="MIT",
        repository="https://github.com/betterleaks/betterleaks",
        commit=_THIRD_PARTY_HASHES["betterleaks commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    # The release archive holds the executable and a README, no license file, so
    # both files come from the repository.
    "cfn-guard": ThirdPartyLicense(
        tool="cfn-guard",
        version="3.3.0",
        license="Apache-2.0",
        repository="https://github.com/aws-cloudformation/cloudformation-guard",
        commit=_THIRD_PARTY_HASHES["cfn-guard commit"],
        files=(
            _from_source(
                "cfn-guard",
                "https://github.com/aws-cloudformation/cloudformation-guard",
                "LICENSE",
            ),
            _from_source(
                "cfn-guard",
                "https://github.com/aws-cloudformation/cloudformation-guard",
                "NOTICE",
            ),
        ),
    ),
    # The cfn-lint scanner's uv tool. The wheel's dist-info carries
    # licenses/LICENSE and licenses/NOTICE.
    "cfn-lint": ThirdPartyLicense(
        tool="cfn-lint",
        version="v1.61.0",
        license="MIT-0",
        repository="https://github.com/aws-cloudformation/cfn-lint",
        commit=_THIRD_PARTY_HASHES["cfn-lint commit"],
        files=(
            LicenseFile("LICENSE"),
            LicenseFile("NOTICE"),
        ),
        distribution="cfn-lint",
    ),
    # The wheel's dist-info carries licenses/LICENSE. The repository has no NOTICE.
    "checkov": ThirdPartyLicense(
        tool="checkov",
        version="3.4.7",
        license="Apache-2.0",
        repository="https://github.com/bridgecrewio/checkov",
        commit=_THIRD_PARTY_HASHES["checkov commit"],
        files=(LicenseFile("LICENSE"),),
        distribution="checkov",
    ),
    "crane": ThirdPartyLicense(
        tool="crane",
        version="v0.22.1",
        license="Apache-2.0",
        repository="https://github.com/google/go-containerregistry",
        commit=_THIRD_PARTY_HASHES["crane commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    "gitleaks": ThirdPartyLicense(
        tool="gitleaks",
        version="v8.30.1",
        license="MIT",
        repository="https://github.com/gitleaks/gitleaks",
        commit=_THIRD_PARTY_HASHES["gitleaks commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    "grype": ThirdPartyLicense(
        tool="grype",
        version="v0.122.1",
        license="Apache-2.0",
        repository="https://github.com/anchore/grype",
        commit=_THIRD_PARTY_HASHES["grype commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    # The GuardDog alpha scanner's uv tool. The wheel's dist-info carries
    # licenses/LICENSE, licenses/NOTICE and licenses/LICENSE-3rdparty.csv.
    "guarddog": ThirdPartyLicense(
        tool="guarddog",
        version="v3.2.0",
        license="Apache-2.0",
        repository="https://github.com/DataDog/guarddog",
        commit=_THIRD_PARTY_HASHES["guarddog commit"],
        files=(
            LicenseFile("LICENSE"),
            LicenseFile("NOTICE"),
            LicenseFile("LICENSE-3rdparty.csv"),
        ),
        distribution="guarddog",
    ),
    # The asset is the executable itself, so both files come from the repository.
    # LICENSE: GPL version 3, with no "or later" grant in the repository.
    # ThirdPartyNotices.txt is upstream's report of the libraries linked into the
    # binary (ShellCheck, language-docker, HsYAML and others).
    "hadolint": ThirdPartyLicense(
        tool="hadolint",
        version="v2.15.1",
        license="GPL-3.0-only",
        repository="https://github.com/hadolint/hadolint",
        commit=_THIRD_PARTY_HASHES["hadolint commit"],
        files=(
            _from_source("hadolint", "https://github.com/hadolint/hadolint", "LICENSE"),
            _from_source(
                "hadolint",
                "https://github.com/hadolint/hadolint",
                "ThirdPartyNotices.txt",
            ),
        ),
        source_note=(
            "The release binary is statically linked with the Haskell libraries "
            "ThirdPartyNotices.txt in this directory lists, at the versions it "
            "lists. Their sources are on Hackage at "
            "https://hackage.haskell.org/package/<name>-<version>, the links that "
            "file gives."
        ),
    ),
    # Compiled into the pygit2 wheel GuardDog depends on (pygit2.libs/libgit2-*.so),
    # in GuardDog's uv tool environment. COPYING carries the linking exception and
    # the notices of the code libgit2 itself bundles. The version is whatever the
    # pinned pygit2 wheel bundles, read from pygit2 in that environment.
    "libgit2": ThirdPartyLicense(
        tool="libgit2",
        bundled_in="the pygit2 1.18.2 manylinux wheel",
        version="v1.9.1",
        license="GPL-2.0-only WITH GCC-exception-2.0",
        repository="https://github.com/libgit2/libgit2",
        commit=_THIRD_PARTY_HASHES["libgit2 commit"],
        files=(
            _from_source("libgit2", "https://github.com/libgit2/libgit2", "COPYING"),
            _from_source("libgit2", "https://github.com/libgit2/libgit2", "AUTHORS"),
        ),
        version_probe=(
            "{uv_tool_dir}/guarddog/bin/python",
            "-c",
            "import pygit2; print(pygit2.LIBGIT2_VERSION)",
        ),
    ),
    # Bundled in the pygit2 wheel (pygit2.libs/libssh2-*.so) for libgit2's SSH
    # transport; libgit2's COPYING does not cover it. 1.11.1 in both the x86_64
    # and the aarch64 manylinux wheels of pygit2 1.18.2.
    "libssh2": ThirdPartyLicense(
        tool="libssh2",
        bundled_in="the pygit2 1.18.2 manylinux wheel",
        version="libssh2-1.11.1",
        license="BSD-3-Clause",
        repository="https://github.com/libssh2/libssh2",
        commit=_THIRD_PARTY_HASHES["libssh2 commit"],
        files=(
            _from_source("libssh2", "https://github.com/libssh2/libssh2", "COPYING"),
        ),
        version_probe=_pygit2_bundled_library_probe(
            "libssh2-*", rb"SSH-2\.0-libssh2_([0-9.]+)", "libssh2-"
        ),
    ),
    # Installed by `ash dependencies install`, which publishes a bare executable
    # with no archive around it, so both files come from the repository.
    "opengrep": ThirdPartyLicense(
        tool="opengrep",
        version="v2.0.0",
        # COPYRIGHT: "GNU Lesser General Public License (LGPL) version 2.1", with
        # no "or later".
        license="LGPL-2.1-only",
        repository="https://github.com/opengrep/opengrep",
        commit=_THIRD_PARTY_HASHES["opengrep commit"],
        files=(
            _from_source("opengrep", "https://github.com/opengrep/opengrep", "LICENSE"),
            _from_source(
                "opengrep", "https://github.com/opengrep/opengrep", "COPYRIGHT"
            ),
        ),
    ),
    # Bundled in the pygit2 wheel (pygit2.libs/libcrypto-*.so.3 and libssl-*.so.3)
    # for libssh2 and libgit2's HTTPS transport. OpenSSL 3.3.3 in both manylinux
    # wheels of pygit2 1.18.2. Apache-2.0; the release has no NOTICE file. Only
    # libcrypto is probed: libssl embeds no "OpenSSL x.y.z" string, and the two are
    # one OpenSSL build (same release, grafted together by auditwheel).
    "openssl": ThirdPartyLicense(
        tool="openssl",
        bundled_in="the pygit2 1.18.2 manylinux wheel",
        version="openssl-3.3.3",
        license="Apache-2.0",
        repository="https://github.com/openssl/openssl",
        commit=_THIRD_PARTY_HASHES["openssl commit"],
        files=(
            _from_source(
                "openssl", "https://github.com/openssl/openssl", "LICENSE.txt"
            ),
        ),
        version_probe=_pygit2_bundled_library_probe(
            "libcrypto-*", rb"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+)", "openssl-"
        ),
    ),
    # Bundled in the yara-python wheel GuardDog depends on
    # (yara_python.libs/libcrypto-*.so.1.1), for libyara's hash and PE modules:
    # OpenSSL 1.1.1w, which auditwheel grafted in. A second OpenSSL beside the
    # pygit2 one above, and a different license: the 1.1 series is under the dual
    # OpenSSL and SSLeay license (SPDX "OpenSSL"), not 3.x's Apache-2.0. Upstream
    # ended support for 1.1.1 in September 2023.
    "openssl-1.1": ThirdPartyLicense(
        tool="openssl-1.1",
        bundled_in="the yara-python manylinux wheel GuardDog depends on",
        tag="OpenSSL_1_1_1w",
        version="1.1.1w",
        license="OpenSSL",
        repository="https://github.com/openssl/openssl",
        commit=_THIRD_PARTY_HASHES["openssl-1.1 commit"],
        files=(
            _from_source(
                "openssl-1.1", "https://github.com/openssl/openssl", "LICENSE"
            ),
        ),
        version_probe=_bundled_library_probe(
            "yara",
            "yara_python.libs",
            1,
            "libcrypto-*.so.1.1",
            rb"OpenSSL (1\.1\.1[a-z]?) ",
            "",
        ),
    ),
    # Bundled in the pygit2 wheel (pygit2.libs/libpcre-*.so) for libgit2's regex
    # support: the manylinux build image's system PCRE 8.42, which auditwheel
    # grafted in. PCRE1 has no release tags; the commit is "Final file tidies for
    # 8.42." in the project's archived PCRE1 repository.
    "pcre": ThirdPartyLicense(
        tool="pcre",
        bundled_in="the pygit2 1.18.2 manylinux wheel",
        tag="",
        version="8.42",
        license="BSD-3-Clause",
        repository="https://github.com/PCRE2Project/pcre1",
        commit=_THIRD_PARTY_HASHES["pcre commit"],
        files=(
            _from_source("pcre", "https://github.com/PCRE2Project/pcre1", "LICENCE"),
        ),
        version_probe=_pygit2_bundled_library_probe(
            "libpcre-*", rb"([0-9]+\.[0-9]+) [0-9]{4}-[0-9]{2}-[0-9]{2}", ""
        ),
    ),
    # A GuardDog dependency, in GuardDog's uv tool environment. Its version is held
    # to this one in the image by the uv constraint the Dockerfile writes
    # (PYGIT2_VERSION), so these files describe the copy that ships.
    "pygit2": ThirdPartyLicense(
        tool="pygit2",
        version="v1.18.2",
        license="GPL-2.0-only WITH GCC-exception-2.0",
        repository="https://github.com/libgit2/pygit2",
        commit=_THIRD_PARTY_HASHES["pygit2 commit"],
        files=(
            _from_source("pygit2", "https://github.com/libgit2/pygit2", "COPYING"),
            _from_source("pygit2", "https://github.com/libgit2/pygit2", "AUTHORS.md"),
        ),
        version_probe=(
            "{uv_tool_dir}/guarddog/bin/python",
            "-c",
            "import pygit2; print(pygit2.__version__)",
        ),
    ),
    # The wheel's dist-info holds no license file, only METADATA's
    # `License-Expression: LGPL-2.1-or-later`, so both files come from the
    # repository. COPYRIGHT grants "version 2.1" with no "or later", the narrower
    # of the two readings, and the one opengrep's entry takes from the same text.
    "semgrep": ThirdPartyLicense(
        tool="semgrep",
        version="v1.186.0",
        license="LGPL-2.1-only",
        repository="https://github.com/semgrep/semgrep",
        commit=_THIRD_PARTY_HASHES["semgrep commit"],
        files=(
            _from_source("semgrep", "https://github.com/semgrep/semgrep", "LICENSE"),
            _from_source("semgrep", "https://github.com/semgrep/semgrep", "COPYRIGHT"),
        ),
        distribution="semgrep",
    ),
    "syft": ThirdPartyLicense(
        tool="syft",
        version="v1.57.2",
        license="Apache-2.0",
        repository="https://github.com/anchore/syft",
        commit=_THIRD_PARTY_HASHES["syft commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    "trivy": ThirdPartyLicense(
        tool="trivy",
        version="v0.76.2",
        license="Apache-2.0",
        repository="https://github.com/aquasecurity/trivy",
        commit=_THIRD_PARTY_HASHES["trivy commit"],
        files=(
            LicenseFile("LICENSE"),
            # In the repository and not in the release archive. Apache-2.0 4(d)
            # requires it to travel with the binary all the same.
            _from_source("trivy", "https://github.com/aquasecurity/trivy", "NOTICE"),
        ),
    ),
    # The release archive holds uv and uvx and nothing else.
    "uv": ThirdPartyLicense(
        tool="uv",
        version="0.13.9",
        license="MIT OR Apache-2.0",
        repository="https://github.com/astral-sh/uv",
        commit=_THIRD_PARTY_HASHES["uv commit"],
        files=(
            _from_source("uv", "https://github.com/astral-sh/uv", "LICENSE-APACHE"),
            _from_source("uv", "https://github.com/astral-sh/uv", "LICENSE-MIT"),
        ),
        executables=("uv", "uvx"),
    ),
    # The zizmor scanner's uv tool, a compiled Rust binary in a wheel. The
    # wheel's dist-info carries licenses/LICENSE.
    "zizmor": ThirdPartyLicense(
        tool="zizmor",
        version="v1.33.1",
        license="MIT",
        repository="https://github.com/zizmorcore/zizmor",
        commit=_THIRD_PARTY_HASHES["zizmor commit"],
        files=(LicenseFile("LICENSE"),),
        distribution="zizmor",
    ),
}


@dataclass(frozen=True)
class HeldPin:
    """A pin that is deliberately kept below its upstream's newest release.

    ``scripts/check_pinned_tool_versions.py --fail-on-outdated`` treats the tool's
    outdated row as acknowledged, and passes, only while upstream's latest release is
    exactly ``acknowledged``. A newer release makes the row fail again, so a hold
    never absorbs a release nobody has looked at. The report lists every held row
    with its ``reason`` and ``until``.

    ``acknowledged`` is the newest upstream version the hold was written against,
    spelled as upstream spells it (the checker compares versions as numbers, so a
    leading ``v`` does not matter). ``reason`` says why the pin cannot move to it.
    ``until`` names the condition that ends the hold, so a reader knows what to watch
    for. Delete the entry when the pin is bumped past ``acknowledged``.
    """

    acknowledged: str
    reason: str
    until: str


# Pins held on purpose below upstream's latest release, by tool name (a key of
# TOOL_VERSIONS, RULES_BUNDLES, THIRD_PARTY_LICENSES, or a gem pin). Declared here,
# with the pins, so the decision to hold a tool is reviewed in the same diff as its
# pin and not in a CI argument. See HeldPin for what a hold does and does not excuse.
HELD_PINS: dict[str, HeldPin] = {
    "pygit2": HeldPin(
        acknowledged="1.21.0",
        reason=(
            "GuardDog 3.2.0 requires pygit2>=1.11,<1.19, so the image cannot install "
            "pygit2 1.21.0 while it ships that GuardDog."
        ),
        until="GuardDog releases a version that admits pygit2>=1.19.",
    ),
}


def get_third_party_license(tool: str) -> ThirdPartyLicense:
    """The license entry for ``tool``.

    Raises:
        ToolNotProvisionableError: if ``tool`` has none. The image build calls
            this before downloading anything, so a pinned tool added without its
            license entry fails the build instead of shipping without its license.
    """
    entry = THIRD_PARTY_LICENSES.get(tool)
    if entry is None:
        raise ToolNotProvisionableError(
            f"{tool} has no entry in THIRD_PARTY_LICENSES in tool_downloads.py, so "
            f"the image would ship it without its license and notice files. Add "
            f"one; the comment above that table says how."
        )
    return entry


def downloadable_tools() -> list[str]:
    """Tools this module can provision by verified release-asset download."""
    return sorted(_ASSET_TABLES)


def supported_platforms(tool: str) -> list[PlatformArch]:
    """The platform/arch pairs ``tool`` publishes an asset for.

    Raises:
        ToolNotProvisionableError: if ``tool`` has no download table at all.
    """
    if tool not in _ASSET_TABLES:
        raise ToolNotProvisionableError(
            f"{tool} has no release-asset download table. "
            f"Tools provisionable by download: {', '.join(downloadable_tools())}"
        )
    return sorted(_ASSET_TABLES[tool])


def get_tool_asset(tool: str, target_platform: str, arch: str) -> ToolAsset:
    """Resolve the pinned asset for ``tool`` on ``target_platform``/``arch``.

    Raises:
        ToolNotProvisionableError: if the tool is unknown here, or the tool
            publishes nothing for that platform/arch. Both are refused rather
            than approximated: installing a linux/amd64 binary on linux/arm64
            produces an executable that fails at exec time, which reads in a scan
            report as an execution failure rather than as a bad install.
    """
    table = _ASSET_TABLES.get(tool)
    if table is None:
        raise ToolNotProvisionableError(
            f"{tool} has no release-asset download table. "
            f"Tools provisionable by download: {', '.join(downloadable_tools())}"
        )
    # A tool in the asset table but not in the version or URL table is a
    # half-added entry; refused by name here, where a bare KeyError used to
    # escape the graceful handling every other refusal gets.
    missing = [
        name
        for name, entries in (
            ("TOOL_VERSIONS", TOOL_VERSIONS),
            ("_RELEASE_BASE_URLS", _RELEASE_BASE_URLS),
        )
        if tool not in entries
    ]
    if missing:
        raise ToolNotProvisionableError(
            f"{tool} has a release-asset download table but no entry in "
            f"{' or '.join(missing)} in tool_downloads.py; a tool added in one "
            "table and not the others cannot be downloaded."
        )

    filename = table.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(table))
        # The table lists the platforms ASH installs the tool on, which can be
        # fewer than the release publishes (uv's is linux-only by choice), so
        # the refusal names the table, not the vendor.
        raise ToolNotProvisionableError(
            f"ASH's download table for {tool} {TOOL_VERSIONS[tool]} has no asset for "
            f"{target_platform}/{arch}; it lists the platforms ASH installs the tool "
            f"on, not everything the release publishes. Available: {available}"
        )

    taken_at = _DIGESTS_TAKEN_AT.get(tool)
    if taken_at is not None and taken_at != TOOL_VERSIONS[tool]:
        raise ToolNotProvisionableError(
            f"{tool} is pinned to {TOOL_VERSIONS[tool]} but its digests in "
            f"tool_downloads.py were taken from {taken_at}. Its asset names carry no "
            f"version, so the old digests would be checked against the new release; "
            f"a version bump is half-applied."
        )

    digest = _DIGESTS.get(filename)
    if digest is None:
        # Reachable only if the asset table and the digest table disagree, which
        # is what happens when a version is bumped in one place and not the
        # other. Refused loudly here rather than downloading unverified.
        raise ToolNotProvisionableError(
            f"No pinned SHA256 for {filename}. The asset table and digest table "
            f"in tool_downloads.py disagree; a version bump is half-applied."
        )

    read = _LINKAGE_READS.get(filename)
    if read is not None and read.version != TOOL_VERSIONS[tool]:
        # A reading is of one release, and the pin has moved past it.
        read = None

    suffix = ".exe" if target_platform == "windows" else ""
    return ToolAsset(
        tool=tool,
        version=TOOL_VERSIONS[tool],
        url=f"{_RELEASE_BASE_URLS[tool]}/{TOOL_VERSIONS[tool]}/{filename}",
        sha256=digest,
        member_name=f"{tool}{suffix}",
        install_as=f"{tool}{suffix}",
        # A tool that otherwise publishes bare executables can still publish one
        # archive: opengrep's Windows asset is a zip from v2.0.0 on.
        archive=tool not in _BARE_EXECUTABLE_TOOLS or filename.endswith(".zip"),
        executable_sha256=_EXECUTABLE_DIGESTS.get(filename),
        companion_sha256=tuple(sorted(_COMPANION_DIGESTS.get(filename, {}).items())),
        linkage=read.linkage if read else Linkage.UNREAD,
        linkage_source=read.source if read else "",
        linkage_read_version=read.version if read else "",
    )
