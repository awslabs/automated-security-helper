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
    "cfn-guard": "3.2.1",
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

# cfn-guard's release assets carry no version in their names: every release
# publishes ``cfn-guard-v3-<arch>-<os>-latest.tar.gz``, and the version lives only
# in the release tag, which is the path segment of the URL. So for cfn-guard the
# digest is the whole pin, and a version bump that forgets the digests fails every
# install with an integrity error rather than being caught by the filename check
# the other tools get (see VERSIONLESS_ASSET_NAMES).
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
#
# Two entries have no upstream checksums file to transcribe from, so their digests
# were obtained differently and are stated here so a reviewer can redo it:
#
# * cfn-guard 3.2.1 publishes no checksums file. Its digests are the ``digest``
#   field GitHub's release API reports for each asset
#   (``gh release view 3.2.1 --repo aws-cloudformation/cloudformation-guard
#   --json assets``), and each was confirmed by downloading the asset from
#   https://github.com/aws-cloudformation/cloudformation-guard/releases/tag/3.2.1
#   and hashing it with sha256sum.
# * The AWS Guard Rules Registry 1.0.2 release predates GitHub's asset digests,
#   so its one digest is sha256sum of
#   https://github.com/aws-cloudformation/aws-guard-rules-registry/releases/download/1.0.2/ruleset-build-v1.0.2.zip
#   as downloaded on 2026-10-06.
#
# Every line carries `# pragma: allowlist secret`, which is detect-secrets' own
# inline marker. It is needed and it is honest: a 64-character hex string is exactly
# what a high-entropy-string detector is built to find, and ASH scanning itself
# reported all 16 as CRITICAL secrets -- correctly, by its own heuristic. A published
# release checksum is public by construction and is the opposite of a credential:
# it exists so that everyone can compare against it.
#
# Marked per line rather than by suppressing the file or the rule, so a real secret
# added to this file later is still found.
# ---------------------------------------------------------------------------

_DIGESTS: dict[str, str] = {
    # cfn-guard 3.2.1
    "cfn-guard-v3-x86_64-linux-latest.tar.gz": "8c66efb19c63e6c2bf26b9a41bbcf2f85baa8a937b01d350940194faaf64cf1d",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-linux-latest.tar.gz": "cd378026dad0f865926ab1d1c082e2faf825f7fd888a9fe6b5c142cdf175c129",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-macos-latest.tar.gz": "5089dfaa05a766cf118a020518e62f77eddbd43acf3a0b69d36b23175c6c6fda",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-macos-latest.tar.gz": "4c1eb10c061731159eaaf0e7dbd465db9fa4b767b82186a4ab489671cc00b7d0",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-windows-latest.tar.gz": "52af28c02081f1067c6710c08619d359899734ec59d51f17f68e1b4b396a1203",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-windows-latest.tar.gz": "faa9a14382314cd2c3ce6adc21388e0422280ab33ded3c8b1321877efd761300",  # pragma: allowlist secret
    # aws-guard-rules-registry 1.0.2 (a rules bundle, not a binary; see RULES_BUNDLES)
    "ruleset-build-v1.0.2.zip": "dc21aaad601c673843c299191d864cd9b9db32475b1937d930d6069ddde73296",  # pragma: allowlist secret
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
}


_RELEASE_BASE_URLS: dict[str, str] = {
    "cfn-guard": "https://github.com/aws-cloudformation/cloudformation-guard/releases/download",
    "grype": "https://github.com/anchore/grype/releases/download",
    "syft": "https://github.com/anchore/syft/releases/download",
    "trivy": "https://github.com/aquasecurity/trivy/releases/download",
}

_ASSET_TABLES: dict[str, dict[PlatformArch, str]] = {
    "cfn-guard": _CFN_GUARD_ASSETS,
    "grype": _GRYPE_ASSETS,
    "syft": _SYFT_ASSETS,
    "trivy": _TRIVY_ASSETS,
}


#: Tools whose upstream asset filenames do not carry the release version, so the
#: "pinned version appears in the filename" check cannot apply to them. For these
#: the version is asserted in the URL path instead, and the digest is the pin.
VERSIONLESS_ASSET_NAMES: frozenset[str] = frozenset({"cfn-guard"})


@dataclass(frozen=True)
class RulesBundle:
    """A pinned archive of rule files, installed as a directory rather than a binary.

    ``member_dir`` is the directory inside the archive that holds the rule files
    and ``member_suffix`` the extension they carry. Only regular files directly in
    that directory with that suffix are extracted, each to its basename, so the
    archive's own paths are never used as a destination. That also drops the
    ``__MACOSX/`` resource-fork entries the registry's zip carries.
    """

    name: str
    version: str
    url: str
    sha256: str
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
CFN_GUARD_RULES_VERSION = "1.0.2"

RULES_BUNDLES: dict[str, RulesBundle] = {
    "aws-guard-rules-registry": RulesBundle(
        name="aws-guard-rules-registry",
        version=CFN_GUARD_RULES_VERSION,
        url=(
            "https://github.com/aws-cloudformation/aws-guard-rules-registry/"
            f"releases/download/{CFN_GUARD_RULES_VERSION}/"
            f"ruleset-build-v{CFN_GUARD_RULES_VERSION}.zip"
        ),
        sha256=_DIGESTS[f"ruleset-build-v{CFN_GUARD_RULES_VERSION}.zip"],
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
