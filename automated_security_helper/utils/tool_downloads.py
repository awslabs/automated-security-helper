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
  rather than guessing at a nearby architecture. The absences are real: grype and
  trivy publish no windows/arm64 asset, and trivy publishes no 32-bit macOS one.
* cfn-nag is not here. It is a Ruby gem with a dependency closure, not a single
  release binary, so it is provisioned through the committed
  ``assets/Gemfile.lock`` instead -- see ``cfn_nag_scanner``.
* npm-audit is not here either. It is a subcommand of npm, so its dependency is a
  Node.js runtime, which ASH does not install. See
  ``npm_audit_scanner.install_prerequisite_message``.
* Bumping a version means replacing every digest for that tool, in both tables:
  the archive digests and the executable digests (see ``_EXECUTABLE_DIGESTS``).
  A version bumped without its digests will fail every install with an integrity
  error, which is the intended direction to fail in. opengrep and uv name their assets without a
  version, so for those two a bump would not even change a filename; see
  ``_DIGESTS_TAKEN_AT`` for what catches it instead.
* opengrep is pinned for manylinux only. The scanner has always installed the
  manylinux build (``opengrep_scanner`` hardcodes it, with a TODO to detect musl),
  and pinning musllinux too would be two digests for a path nothing takes.
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
from typing import Optional

from automated_security_helper.core.exceptions import ToolNotProvisionableError

# Platform/architecture pair, in the vocabulary cli/dependencies.py already uses:
# platform is one of linux/darwin/windows, arch is one of amd64/arm64.
PlatformArch = tuple[str, str]


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
    opengrep publishes. There is nothing to extract, ``member_name`` is unused, and
    the pinned digest then covers the very bytes that will be executed -- which is
    what lets a cached copy be checked against the pin directly.
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

    @property
    def executable_digest(self) -> Optional[str]:
        """The pinned SHA256 of the executable this asset installs, or None.

        ``sha256`` covers the release asset as downloaded. For an archive that is
        not the file that runs, so it cannot tell whether a binary already on disk
        is the pinned one; ``executable_sha256`` can. An asset that is the
        executable itself, with no archive around it, needs no second digest: the
        asset digest already covers the bytes that run (opengrep, ``archive`` False).

        None means there is nothing to compare a binary on disk against. Callers
        then install as they always have; they never treat None as a match.
        """
        if self.executable_sha256:
            return self.executable_sha256
        if not self.archive:
            return self.sha256
        return None


# Versions are deliberately the same pins the container image already builds with
# (see the ARG lines in Dockerfile), so a scan run from a container, from nix and
# from a bare `ash dependencies install` all execute the same tool versions.
#
# opengrep is not in the Dockerfile's ARG lines: the image installs it through
# `ash dependencies install`, which resolves it from this table. Its version is the
# default of OpengrepScannerConfigOptions.version, which is also what nix/opengrep.nix
# pins -- NOT the v1.1.5 default in get_opengrep_url's signature, which no caller
# reaches because the scanner always passes its configured version.
TOOL_VERSIONS: dict[str, str] = {
    "grype": "v0.111.0",
    "opengrep": "v1.15.1",
    "syft": "v1.42.4",
    "trivy": "v0.69.3",
    # Tagged without a leading "v" upstream, so the release URL has none either.
    "uv": "0.12.23",
}

# The gem version cfn-nag installs at, kept beside the binary pins so there is one
# place to read ASH's external tool versions from. The authoritative pin for the
# whole gem closure is assets/Gemfile.lock; this must agree with assets/Gemfile.
CFN_NAG_GEM_VERSION = "0.8.10"


# ---------------------------------------------------------------------------
# Asset filenames, per tool, exactly as published upstream.
# ---------------------------------------------------------------------------

_GRYPE_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "grype_0.111.0_linux_amd64.tar.gz",
    ("linux", "arm64"): "grype_0.111.0_linux_arm64.tar.gz",
    ("darwin", "amd64"): "grype_0.111.0_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "grype_0.111.0_darwin_arm64.tar.gz",
    ("windows", "amd64"): "grype_0.111.0_windows_amd64.zip",
    # windows/arm64: upstream publishes no such asset for this release.
}

_SYFT_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "syft_1.42.4_linux_amd64.tar.gz",
    ("linux", "arm64"): "syft_1.42.4_linux_arm64.tar.gz",
    ("darwin", "amd64"): "syft_1.42.4_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "syft_1.42.4_darwin_arm64.tar.gz",
    ("windows", "amd64"): "syft_1.42.4_windows_amd64.zip",
    ("windows", "arm64"): "syft_1.42.4_windows_arm64.zip",
}

# Bare executables, not archives. The names carry no version; see _DIGESTS_TAKEN_AT.
_OPENGREP_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "opengrep_manylinux_x86",
    ("linux", "arm64"): "opengrep_manylinux_aarch64",
    ("darwin", "amd64"): "opengrep_osx_x86",
    ("darwin", "arm64"): "opengrep_osx_arm64",
    ("windows", "amd64"): "opengrep_windows_x86.exe",
    # windows/arm64: upstream publishes no such asset for this release.
}

# linux only: uv is pinned for the container image, which is built for linux alone.
_UV_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "uv-x86_64-unknown-linux-gnu.tar.gz",
    ("linux", "arm64"): "uv-aarch64-unknown-linux-gnu.tar.gz",
}

_TRIVY_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "trivy_0.69.3_Linux-64bit.tar.gz",
    ("linux", "arm64"): "trivy_0.69.3_Linux-ARM64.tar.gz",
    ("darwin", "amd64"): "trivy_0.69.3_macOS-64bit.tar.gz",
    ("darwin", "arm64"): "trivy_0.69.3_macOS-ARM64.tar.gz",
    ("windows", "amd64"): "trivy_0.69.3_windows-64bit.zip",
    # windows/arm64: upstream publishes no such asset for this release.
}


# ---------------------------------------------------------------------------
# SHA256 digests, keyed by asset filename.
#
# Transcribed verbatim from the checksums file published with each release, so a
# reviewer can diff this block against the upstream file line for line:
#   https://github.com/anchore/grype/releases/download/v0.111.0/grype_0.111.0_checksums.txt
#   https://github.com/anchore/syft/releases/download/v1.42.4/syft_1.42.4_checksums.txt
#   https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_checksums.txt
#
# opengrep publishes no checksums file. Its five digests were obtained three ways on
# 2026-10-06 and all three agreed byte for byte: the `digest` field GitHub reports for
# each asset of the v1.15.1 release (`gh api repos/opengrep/opengrep/releases/tags/
# v1.15.1`), sha256sum over each asset downloaded once, and -- for the four non-Windows
# assets -- the SRI hashes nix/opengrep.nix already pinned, decoded from base64. The
# third is an independent witness: nix verified those hashes on its own fetch, earlier,
# from a different machine. tests/unit/utils/test_pinned_tool_downloads.py keeps the
# nix copy and this one equal.
#
# uv publishes a `<asset>.sha256` beside each asset. Those two files were downloaded
# with the assets, and each agreed with sha256sum over its asset and with the `digest`
# field GitHub reports for it.
#
# Every line carries `# pragma: allowlist secret`, which is detect-secrets' own
# inline marker. It is needed and it is honest: a 64-character hex string is exactly
# what a high-entropy-string detector is built to find, and ASH scanning itself
# reported the first 16 as CRITICAL secrets -- correctly, by its own heuristic. A published
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
# container image installs these three tools into /usr/local/bin before ASH runs --
# and leave it alone, instead of writing a second copy of every binary into
# ASH_BIN_PATH. trivy alone is 162 MB uncompressed.
#
# Derived, not transcribed: no vendor publishes it. Each archive was downloaded,
# checked against its digest in _DIGESTS, and the member extracted and hashed, on
# 2026-10-07. Two extractors agreed on all 16: Python's tarfile/zipfile with the same
# exactly-one-basename rule the installer uses, and `tar -xzOf` / `unzip -p` piped to
# sha256sum. Every install re-checks it: the installer refuses an extracted
# executable that does not hash to this value, so a wrong entry fails the first real
# install of that asset in CI rather than sitting here unnoticed.
#
# The two tables are adjacent so that one line-pinned suppression covers both (see
# .ash/.ash_community_plugins.yaml); keep nothing but digests between them.
# ---------------------------------------------------------------------------

_DIGESTS: dict[str, str] = {
    # grype v0.111.0
    "grype_0.111.0_linux_amd64.tar.gz": "18ed2048d7a233566b681121d4632364f5f25d72cca86acc4c7ac57210d78a87",  # pragma: allowlist secret
    "grype_0.111.0_linux_arm64.tar.gz": "1a8b9bd691ce274e44056e7572cdf8c6970bdf9ec694001f7b4b17962b121b43",  # pragma: allowlist secret
    "grype_0.111.0_darwin_amd64.tar.gz": "8fefd00f6ddd6407275be31b228089820e91c7a8cd2d046e877601773ac5062f",  # pragma: allowlist secret
    "grype_0.111.0_darwin_arm64.tar.gz": "62d005a1e36ac7ec0b7be801ebc8eab0053fd831a227e1dc8ea9c356d38fa361",  # pragma: allowlist secret
    "grype_0.111.0_windows_amd64.zip": "17f3bfb758b3c18426a89060344d9569f4344b0a606d42b60bd89792f996e3bd",  # pragma: allowlist secret
    # syft v1.42.4
    "syft_1.42.4_linux_amd64.tar.gz": "590650c2743b83f327d1bf9bec64f6f83b7fec504187bb84f500c862bf8f2a0f",  # pragma: allowlist secret
    "syft_1.42.4_linux_arm64.tar.gz": "5029bad1ed372649527b1e443cbceef7f5d6ae1cfe52c16e721559f94267128b",  # pragma: allowlist secret
    "syft_1.42.4_darwin_amd64.tar.gz": "4a14affad1b90f0bfa38fdb784279f01598b6099df40686391d814620e9de226",  # pragma: allowlist secret
    "syft_1.42.4_darwin_arm64.tar.gz": "0797b64cf8841c904682e6007a695f9cd3e72103f064dd286723c0a56a2273e2",  # pragma: allowlist secret
    "syft_1.42.4_windows_amd64.zip": "a712f912e8fc83ce2bf6a7cea213c2d5185778d66ea2e07d42c767817f77e381",  # pragma: allowlist secret
    "syft_1.42.4_windows_arm64.zip": "6596227b24729d54e727917d5d59e3a6a49fc59cd505aae5a6d7eb630d871e82",  # pragma: allowlist secret
    # trivy v0.69.3
    "trivy_0.69.3_Linux-64bit.tar.gz": "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75",  # pragma: allowlist secret
    "trivy_0.69.3_Linux-ARM64.tar.gz": "7e3924a974e912e57b4a99f65ece7931f8079584dae12eb7845024f97087bdfd",  # pragma: allowlist secret
    "trivy_0.69.3_macOS-64bit.tar.gz": "fec4a9f7569b624dd9d044fca019e5da69e032700edbb1d7318972c448ec2f4e",  # pragma: allowlist secret
    "trivy_0.69.3_macOS-ARM64.tar.gz": "a2f2179afd4f8bb265ca3c7aefb56a666bc4a9a411663bc0f22c3549fbc643a5",  # pragma: allowlist secret
    "trivy_0.69.3_windows-64bit.zip": "74362dc711383255308230ecbeb587eb1e4e83a8d332be5b0259afac6e0c2224",  # pragma: allowlist secret
    # opengrep v1.15.1
    "opengrep_manylinux_x86": "c4f6aab1edc8130c7a46e8f5e5215763420740fb94198fc9301215135a372900",  # pragma: allowlist secret
    "opengrep_manylinux_aarch64": "08932db32f4cbfd6e3af6bda82adac41754275d18a91c0fe065181e6a5291be7",  # pragma: allowlist secret
    "opengrep_osx_x86": "afb2d508a501e3a7eb73d919af102f6764353955631ee5856efb214fee5e3432",  # pragma: allowlist secret
    "opengrep_osx_arm64": "a833323d87cfe87f292498d0ccdc037adfa07905f11f2eb2dca7fbcc8b803cc5",  # pragma: allowlist secret
    "opengrep_windows_x86.exe": "307ca6bd6852b38c8fa52d65f5066f780e61545c0e777ca5849a5cd517d688da",  # pragma: allowlist secret
    # uv 0.12.23
    "uv-x86_64-unknown-linux-gnu.tar.gz": "9167d72b3319674b6303c4cbe071854bba13ebdf3d76b1a7cbdc175471fb66d6",  # pragma: allowlist secret
    "uv-aarch64-unknown-linux-gnu.tar.gz": "6524bd338177ed50d035d39354e12545e993bbeba2ecbddf0480c5b3a81d313f",  # pragma: allowlist secret
}

# SHA256 of the executable inside each archive above; see the comment before _DIGESTS.
_EXECUTABLE_DIGESTS: dict[str, str] = {
    # grype v0.111.0
    "grype_0.111.0_linux_amd64.tar.gz": "e2ab3d4d7ffad9548d901f15f899cc5a2c4e124041d2b795f1758e8b1dd6a816",  # pragma: allowlist secret
    "grype_0.111.0_linux_arm64.tar.gz": "ef49e19156b5fea0623f3c0fb46fbbcce9cff65101e4a2d62d3afd68caa2adb5",  # pragma: allowlist secret
    "grype_0.111.0_darwin_amd64.tar.gz": "62a874ecfc906c25b83fb818ad196d9520725ba2c3a4a0980b3c4a3989ab6a49",  # pragma: allowlist secret
    "grype_0.111.0_darwin_arm64.tar.gz": "f52812683329db690e96531d889143f6fa684bf394532a49d57f8054f234d1cf",  # pragma: allowlist secret
    "grype_0.111.0_windows_amd64.zip": "47a39da8ec97407b78ede4afedb7ba31c286d0e649a7d89e566f0b5933df76aa",  # pragma: allowlist secret
    # syft v1.42.4
    "syft_1.42.4_linux_amd64.tar.gz": "04db0f882928929381ab5503bcb25ea0a062e487481483b8a8a60c9f6c4af353",  # pragma: allowlist secret
    "syft_1.42.4_linux_arm64.tar.gz": "8cedfeeb2554ba7901410508dfbe0edff240e808feb05a41aef344974c8f6d4c",  # pragma: allowlist secret
    "syft_1.42.4_darwin_amd64.tar.gz": "ad9f97b39122da2f4c350fed9c84d56d7153a4e47b9475c201bdb91bfe643184",  # pragma: allowlist secret
    "syft_1.42.4_darwin_arm64.tar.gz": "be3f91123ec317c579abaaa6025702b863807bb87e315c9101812267e7572040",  # pragma: allowlist secret
    "syft_1.42.4_windows_amd64.zip": "34ede462272b8ffc66077e790d83511e9b6041ae794fea41fc706f512397b0f3",  # pragma: allowlist secret
    "syft_1.42.4_windows_arm64.zip": "10e2b452eabade7571729f77a8e29a4c6202ebd6eb756df0cc75a4c7c8536b71",  # pragma: allowlist secret
    # trivy v0.69.3
    "trivy_0.69.3_Linux-64bit.tar.gz": "8266084a71d2e6a2333bc2c69b91c93c26dee9ef39ac2587ace2df54cc9b746b",  # pragma: allowlist secret
    "trivy_0.69.3_Linux-ARM64.tar.gz": "d860265c7ebd8128c349d063c91e8f32b26b730d14c2ce85e187fef8be70d72d",  # pragma: allowlist secret
    "trivy_0.69.3_macOS-64bit.tar.gz": "50368fbf0a1bce2b297049e0a0cf879f1f2ba24c302975380c6907910be69b30",  # pragma: allowlist secret
    "trivy_0.69.3_macOS-ARM64.tar.gz": "bef08bfe2644873257d75585dd62e1409eb5c53403075c4bc83d54279dffd812",  # pragma: allowlist secret
    "trivy_0.69.3_windows-64bit.zip": "8d0d0a4abe3f30485d9e89d88660a685ecc3769a37be8a6d25759ad1d80070ea",  # pragma: allowlist secret
    # uv 0.12.23
    "uv-x86_64-unknown-linux-gnu.tar.gz": "abdc39eab8b4ad341dca91f3823a23a343fae94bdb22ebdd9e91694415206f2f",  # pragma: allowlist secret
    "uv-aarch64-unknown-linux-gnu.tar.gz": "ed797a095bf9aea58135fa7081c290e51a14cfd3a7b1f24e55cb1d1a0c1007b0",  # pragma: allowlist secret
}

# The version each unversioned tool's digests above were taken from.
#
# grype, syft and trivy put the version in every asset name, so bumping
# TOOL_VERSIONS without the table changes every URL to a filename the digest table
# has no entry for, and get_tool_asset refuses it by name. opengrep and uv do not:
# `opengrep_manylinux_x86` is the name of that asset in every release. Bumping the
# version alone would therefore resolve the new URL to the OLD release's digest. That
# still fails closed -- the download would not match -- but as a SHA256 mismatch, the
# message that means "possible supply-chain substitution", for what is a half-applied
# edit. Recording the version here turns it into the same refusal by name instead.
_DIGESTS_TAKEN_AT: dict[str, str] = {
    "opengrep": "v1.15.1",
    "uv": "0.12.23",
}

# Tools whose release asset is the executable itself rather than an archive.
_BARE_EXECUTABLE_TOOLS = frozenset({"opengrep"})


_RELEASE_BASE_URLS: dict[str, str] = {
    "grype": "https://github.com/anchore/grype/releases/download",
    "opengrep": "https://github.com/opengrep/opengrep/releases/download",
    "syft": "https://github.com/anchore/syft/releases/download",
    "trivy": "https://github.com/aquasecurity/trivy/releases/download",
    "uv": "https://github.com/astral-sh/uv/releases/download",
}

_ASSET_TABLES: dict[str, dict[PlatformArch, str]] = {
    "grype": _GRYPE_ASSETS,
    "opengrep": _OPENGREP_ASSETS,
    "syft": _SYFT_ASSETS,
    "trivy": _TRIVY_ASSETS,
    "uv": _UV_ASSETS,
}


# ---------------------------------------------------------------------------
# License and notice files for the third-party executables the container image
# bundles.
#
# Why this exists
# ---------------
# The image redistributes upstream release binaries -- every tool in TOOL_VERSIONS,
# plus opengrep and uv -- and every one of those licenses makes redistribution
# conditional on shipping something with the binary: Apache-2.0 section 4(a) and
# (d) a copy of the license and the upstream NOTICE, MIT the copyright and
# permission notice, LGPL and GPL the license and a way to get the corresponding
# source. Until this table the image shipped the binaries alone. Not even trivy's
# NOTICE was there, because trivy keeps it in its repository and leaves it out of
# its release archive.
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
# Known limitations
# -----------------
# * The Go and Rust binaries here statically link their dependency modules, whose
#   own licenses are not reproduced. No upstream release ships them either; the
#   module list is embedded in each Go binary (``go version -m <binary>``).
# * Python tools installed with ``uv tool`` (bandit, checkov, semgrep) are not
#   here. Their wheels carry license metadata in their dist-info, which ASH does
#   not duplicate.
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
    {"0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "Unlicense"}
)

_SPDX_OPERATORS = frozenset({"AND", "OR", "WITH"})


@dataclass(frozen=True)
class LicenseFile:
    """One license or notice file installed beside a bundled tool.

    ``name`` is the file's name in the image. With no ``url`` it is also the
    basename of the member read from the tool's release archive, matched by the
    same exactly-one rule as the executable. With a ``url``, the bytes fetched
    must hash to ``sha256``.
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
    """

    tool: str
    version: str
    license: str
    repository: str
    commit: str
    files: "tuple[LicenseFile, ...]"
    executables: "tuple[str, ...]" = ()

    @property
    def executable_names(self) -> tuple[str, ...]:
        return self.executables or (self.tool,)

    @property
    def spdx_identifiers(self) -> list[str]:
        tokens = self.license.replace("(", " ").replace(")", " ").split()
        return [t for t in tokens if t not in _SPDX_OPERATORS]

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
            f"Release tag:         {self.version}",
            f"Commit:              {self.commit}",
        ]
        if installed_from:
            lines.append(f"Installed from:      {installed_from}")
        lines += [
            "",
            (
                "ASH bundles this program unmodified, as published by its upstream "
                "project."
            ),
        ]
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
            "executables": list(self.executable_names),
            "files": [f.name for f in self.files] + ["SOURCE"],
        }


def _source_file(repository: str, commit: str, path: str) -> str:
    """URL of ``path`` in ``repository`` at exactly ``commit``, never at a tag."""
    owner_repo = repository.removeprefix("https://github.com/")
    return f"https://raw.githubusercontent.com/{owner_repo}/{commit}/{path}"


# Every hex value the entries below use, and nothing else, in one block: the
# community config's ferret-scan suppression is pinned to exactly these lines, and
# tests/unit/utils/test_third_party_licenses.py keeps the two in step.
#
# "<tool> commit" is the commit the release tag points to, from
# `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`. "<tool>/<file>" is the
# SHA256 of that file downloaded from its URL in the entry. Archive-member files
# have no digest here: the archive digest in _DIGESTS covers them. For grype, syft
# and trivy the archive's LICENSE was also checked byte-identical to the
# repository's at the same commit.
_THIRD_PARTY_HASHES: dict[str, str] = {
    "grype commit": "1f19355a7ee2d7e2bd58da6255bdeb618eb0c0d1",  # pragma: allowlist secret
    "opengrep commit": "84c6da40995b0e15803401e44d16a745b3656df8",  # pragma: allowlist secret
    "opengrep/COPYRIGHT": "0f90eaca8e598c6c67a6cda7beb4470518fb2dababc996b3898344d380769aca",  # pragma: allowlist secret
    "opengrep/LICENSE": "20c17d8b8c48a600800dfd14f95d5cb9ff47066a9641ddeab48dc54aec96e331",  # pragma: allowlist secret
    "syft commit": "f6189175279981a79d8d8c15669c570f15a00568",  # pragma: allowlist secret
    "trivy commit": "6fb20c8edd70745d6b34bff0387b53b03c8a760a",  # pragma: allowlist secret
    "trivy/NOTICE": "aed9bc6dab87c6f6567d20bf0f5c0433a8ccd3ad7873322cf79b9244eb720a1f",  # pragma: allowlist secret
    "uv commit": "46b84fd0bfec23b72f29e8e2185ba68a65052f48",  # pragma: allowlist secret
    "uv/LICENSE-APACHE": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",  # pragma: allowlist secret
    "uv/LICENSE-MIT": "860e3d7a86b84e6a7012c7a635fc64df475cebc6cce34dfeb73a5982ec58176c",  # pragma: allowlist secret
}


def _from_source(tool: str, repository: str, name: str) -> LicenseFile:
    """A license file fetched from ``repository`` at ``tool``'s pinned commit."""
    return LicenseFile(
        name,
        url=_source_file(repository, _THIRD_PARTY_HASHES[f"{tool} commit"], name),
        sha256=_THIRD_PARTY_HASHES[f"{tool}/{name}"],
    )


# Alphabetical, one entry per tool.
THIRD_PARTY_LICENSES: dict[str, ThirdPartyLicense] = {
    "grype": ThirdPartyLicense(
        tool="grype",
        version="v0.111.0",
        license="Apache-2.0",
        repository="https://github.com/anchore/grype",
        commit=_THIRD_PARTY_HASHES["grype commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    # Installed by `ash dependencies install`, which publishes a bare executable
    # with no archive around it, so both files come from the repository.
    "opengrep": ThirdPartyLicense(
        tool="opengrep",
        version="v1.15.1",
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
    "syft": ThirdPartyLicense(
        tool="syft",
        version="v1.42.4",
        license="Apache-2.0",
        repository="https://github.com/anchore/syft",
        commit=_THIRD_PARTY_HASHES["syft commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    "trivy": ThirdPartyLicense(
        tool="trivy",
        version="v0.69.3",
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
        version="0.12.23",
        license="MIT OR Apache-2.0",
        repository="https://github.com/astral-sh/uv",
        commit=_THIRD_PARTY_HASHES["uv commit"],
        files=(
            _from_source("uv", "https://github.com/astral-sh/uv", "LICENSE-APACHE"),
            _from_source("uv", "https://github.com/astral-sh/uv", "LICENSE-MIT"),
        ),
        executables=("uv", "uvx"),
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

    filename = table.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(table))
        raise ToolNotProvisionableError(
            f"{tool} {TOOL_VERSIONS[tool]} publishes no release asset for "
            f"{target_platform}/{arch}. Available: {available}"
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

    suffix = ".exe" if target_platform == "windows" else ""
    return ToolAsset(
        tool=tool,
        version=TOOL_VERSIONS[tool],
        url=f"{_RELEASE_BASE_URLS[tool]}/{TOOL_VERSIONS[tool]}/{filename}",
        sha256=digest,
        member_name=f"{tool}{suffix}",
        install_as=f"{tool}{suffix}",
        archive=tool not in _BARE_EXECUTABLE_TOOLS,
        executable_sha256=_EXECUTABLE_DIGESTS.get(filename),
    )
