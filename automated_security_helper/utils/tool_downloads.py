# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pinned release assets for the scanner tools ASH provisions itself.

Why this module exists
----------------------
ASH ships ten scanners but, until this module, could only *install* three of them
(bandit, checkov and semgrep, via ``uv tool install``) plus opengrep by binary
download. grype, syft and trivy had no install path inside ASH at all, so a
machine without them scanned with those scanners absent. That state was invisible
from the outside: the scan reported them as not having run and still exited 0.

Every asset here is identified by an exact version and an exact SHA256. Both are
transcribed from the ``*_checksums.txt`` published alongside the upstream GitHub
release, which is the same file the vendors' own install scripts consult. The
digest is not decoration -- ``verified_download`` refuses to install an asset
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
* Bumping a version means replacing every digest for that tool. A version bumped
  without its digests will fail every install with an integrity error, which is
  the intended direction to fail in.
"""

from dataclasses import dataclass

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
    """

    tool: str
    version: str
    url: str
    sha256: str
    member_name: str
    install_as: str


# Versions are deliberately the same pins the container image already builds with
# (see the ARG lines in Dockerfile), so a scan run from a container, from nix and
# from a bare `ash dependencies install` all execute the same tool versions.
TOOL_VERSIONS: dict[str, str] = {
    "grype": "v0.111.0",
    "syft": "v1.42.4",
    "trivy": "v0.69.3",
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
# ---------------------------------------------------------------------------

_DIGESTS: dict[str, str] = {
    # grype v0.111.0
    "grype_0.111.0_linux_amd64.tar.gz": "18ed2048d7a233566b681121d4632364f5f25d72cca86acc4c7ac57210d78a87",
    "grype_0.111.0_linux_arm64.tar.gz": "1a8b9bd691ce274e44056e7572cdf8c6970bdf9ec694001f7b4b17962b121b43",
    "grype_0.111.0_darwin_amd64.tar.gz": "8fefd00f6ddd6407275be31b228089820e91c7a8cd2d046e877601773ac5062f",
    "grype_0.111.0_darwin_arm64.tar.gz": "62d005a1e36ac7ec0b7be801ebc8eab0053fd831a227e1dc8ea9c356d38fa361",
    "grype_0.111.0_windows_amd64.zip": "17f3bfb758b3c18426a89060344d9569f4344b0a606d42b60bd89792f996e3bd",
    # syft v1.42.4
    "syft_1.42.4_linux_amd64.tar.gz": "590650c2743b83f327d1bf9bec64f6f83b7fec504187bb84f500c862bf8f2a0f",
    "syft_1.42.4_linux_arm64.tar.gz": "5029bad1ed372649527b1e443cbceef7f5d6ae1cfe52c16e721559f94267128b",
    "syft_1.42.4_darwin_amd64.tar.gz": "4a14affad1b90f0bfa38fdb784279f01598b6099df40686391d814620e9de226",
    "syft_1.42.4_darwin_arm64.tar.gz": "0797b64cf8841c904682e6007a695f9cd3e72103f064dd286723c0a56a2273e2",
    "syft_1.42.4_windows_amd64.zip": "a712f912e8fc83ce2bf6a7cea213c2d5185778d66ea2e07d42c767817f77e381",
    "syft_1.42.4_windows_arm64.zip": "6596227b24729d54e727917d5d59e3a6a49fc59cd505aae5a6d7eb630d871e82",
    # trivy v0.69.3
    "trivy_0.69.3_Linux-64bit.tar.gz": "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75",
    "trivy_0.69.3_Linux-ARM64.tar.gz": "7e3924a974e912e57b4a99f65ece7931f8079584dae12eb7845024f97087bdfd",
    "trivy_0.69.3_macOS-64bit.tar.gz": "fec4a9f7569b624dd9d044fca019e5da69e032700edbb1d7318972c448ec2f4e",
    "trivy_0.69.3_macOS-ARM64.tar.gz": "a2f2179afd4f8bb265ca3c7aefb56a666bc4a9a411663bc0f22c3549fbc643a5",
    "trivy_0.69.3_windows-64bit.zip": "74362dc711383255308230ecbeb587eb1e4e83a8d332be5b0259afac6e0c2224",
}


_RELEASE_BASE_URLS: dict[str, str] = {
    "grype": "https://github.com/anchore/grype/releases/download",
    "syft": "https://github.com/anchore/syft/releases/download",
    "trivy": "https://github.com/aquasecurity/trivy/releases/download",
}

_ASSET_TABLES: dict[str, dict[PlatformArch, str]] = {
    "grype": _GRYPE_ASSETS,
    "syft": _SYFT_ASSETS,
    "trivy": _TRIVY_ASSETS,
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
    )
