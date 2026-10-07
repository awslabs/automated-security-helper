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
