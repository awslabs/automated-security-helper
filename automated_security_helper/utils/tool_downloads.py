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
    opengrep and hadolint publish. There is nothing to extract, ``member_name`` is
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
    "actionlint": "v1.7.12",
    "cfn-guard": "3.2.1",
    "gitleaks": "v8.30.1",
    "grype": "v0.120.1",
    "hadolint": "v2.15.1",
    "opengrep": "v1.30.2",
    "syft": "v1.54.1",
    "trivy": "v0.75.0",
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

_ACTIONLINT_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "actionlint_1.7.12_linux_amd64.tar.gz",
    ("linux", "arm64"): "actionlint_1.7.12_linux_arm64.tar.gz",
    ("darwin", "amd64"): "actionlint_1.7.12_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "actionlint_1.7.12_darwin_arm64.tar.gz",
    ("windows", "amd64"): "actionlint_1.7.12_windows_amd64.zip",
    ("windows", "arm64"): "actionlint_1.7.12_windows_arm64.zip",
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

_GRYPE_ASSETS: dict[PlatformArch, str] = {
    ("linux", "amd64"): "grype_0.120.1_linux_amd64.tar.gz",
    ("linux", "arm64"): "grype_0.120.1_linux_arm64.tar.gz",
    ("darwin", "amd64"): "grype_0.120.1_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "grype_0.120.1_darwin_arm64.tar.gz",
    ("windows", "amd64"): "grype_0.120.1_windows_amd64.zip",
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
    ("linux", "amd64"): "syft_1.54.1_linux_amd64.tar.gz",
    ("linux", "arm64"): "syft_1.54.1_linux_arm64.tar.gz",
    ("darwin", "amd64"): "syft_1.54.1_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "syft_1.54.1_darwin_arm64.tar.gz",
    ("windows", "amd64"): "syft_1.54.1_windows_amd64.zip",
    ("windows", "arm64"): "syft_1.54.1_windows_arm64.zip",
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
    ("linux", "amd64"): "trivy_0.75.0_Linux-64bit.tar.gz",
    ("linux", "arm64"): "trivy_0.75.0_Linux-ARM64.tar.gz",
    ("darwin", "amd64"): "trivy_0.75.0_macOS-64bit.tar.gz",
    ("darwin", "arm64"): "trivy_0.75.0_macOS-ARM64.tar.gz",
    ("windows", "amd64"): "trivy_0.75.0_windows-64bit.zip",
    # windows/arm64: upstream publishes no such asset for this release.
}


# ---------------------------------------------------------------------------
# SHA256 digests, keyed by asset filename.
#
# Transcribed verbatim from the checksums file published with each release, so a
# reviewer can diff this block against the upstream file line for line:
#   https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_checksums.txt
#   https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt
#   https://github.com/anchore/grype/releases/download/v0.120.1/grype_0.120.1_checksums.txt
#   https://github.com/hadolint/hadolint/releases/download/v2.15.1/checksums.sha256
#   https://github.com/anchore/syft/releases/download/v1.54.1/syft_1.54.1_checksums.txt
#   https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_checksums.txt
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
# opengrep publishes no checksums file. Its five digests were obtained two ways on
# 2026-10-07 and both agreed byte for byte: the `digest` field GitHub reports for
# each asset of the v1.30.2 release (`gh api repos/opengrep/opengrep/releases/tags/
# v1.30.2`) and sha256sum over each asset downloaded once. Each asset's `.sig` was
# also checked against the public key in its `.cert`, whose identity is opengrep's
# rolling-release.yml workflow at release-v1.30.2; that check is not repeated at
# install time (see the module docstring). tests/unit/utils/test_pinned_tool_downloads.py
# keeps nix/opengrep.nix's SRI copy of the four non-Windows digests equal to this one.
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
# hadolint has no entry: its asset is the executable itself, so the asset digest
# already covers the bytes that run (ToolAsset.executable_digest; the same holds for opengrep).
#
# The two tables are adjacent so that one line-pinned suppression covers both (see
# .ash/.ash_community_plugins.yaml); keep nothing but digests between them.
# ---------------------------------------------------------------------------

_DIGESTS: dict[str, str] = {
    # actionlint v1.7.12
    "actionlint_1.7.12_linux_amd64.tar.gz": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",  # pragma: allowlist secret
    "actionlint_1.7.12_linux_arm64.tar.gz": "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6",  # pragma: allowlist secret
    "actionlint_1.7.12_darwin_amd64.tar.gz": "5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644",  # pragma: allowlist secret
    "actionlint_1.7.12_darwin_arm64.tar.gz": "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f",  # pragma: allowlist secret
    "actionlint_1.7.12_windows_amd64.zip": "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9",  # pragma: allowlist secret
    "actionlint_1.7.12_windows_arm64.zip": "cadcf7ea4efe3a68728893813643cebe1185e5b1d4be5b96245f65c9a4d5ea41",  # pragma: allowlist secret
    # cfn-guard 3.2.1
    "cfn-guard-v3-x86_64-linux-latest.tar.gz": "8c66efb19c63e6c2bf26b9a41bbcf2f85baa8a937b01d350940194faaf64cf1d",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-linux-latest.tar.gz": "cd378026dad0f865926ab1d1c082e2faf825f7fd888a9fe6b5c142cdf175c129",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-macos-latest.tar.gz": "5089dfaa05a766cf118a020518e62f77eddbd43acf3a0b69d36b23175c6c6fda",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-macos-latest.tar.gz": "4c1eb10c061731159eaaf0e7dbd465db9fa4b767b82186a4ab489671cc00b7d0",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-windows-latest.tar.gz": "52af28c02081f1067c6710c08619d359899734ec59d51f17f68e1b4b396a1203",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-windows-latest.tar.gz": "faa9a14382314cd2c3ce6adc21388e0422280ab33ded3c8b1321877efd761300",  # pragma: allowlist secret
    # aws-guard-rules-registry 1.0.2 (a rules bundle, not a binary; see RULES_BUNDLES)
    "ruleset-build-v1.0.2.zip": "dc21aaad601c673843c299191d864cd9b9db32475b1937d930d6069ddde73296",  # pragma: allowlist secret
    # gitleaks v8.30.1
    "gitleaks_8.30.1_linux_x64.tar.gz": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",  # pragma: allowlist secret
    "gitleaks_8.30.1_linux_arm64.tar.gz": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",  # pragma: allowlist secret
    "gitleaks_8.30.1_darwin_x64.tar.gz": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",  # pragma: allowlist secret
    "gitleaks_8.30.1_darwin_arm64.tar.gz": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",  # pragma: allowlist secret
    "gitleaks_8.30.1_windows_x64.zip": "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",  # pragma: allowlist secret
    "gitleaks_8.30.1_windows_arm64.zip": "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f",  # pragma: allowlist secret
    # grype v0.120.1
    "grype_0.120.1_linux_amd64.tar.gz": "0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d",  # pragma: allowlist secret
    "grype_0.120.1_linux_arm64.tar.gz": "29f47391dc283aa79fcc38e65224cd61f64dec0ecfd0db7074128ebf8ff23514",  # pragma: allowlist secret
    "grype_0.120.1_darwin_amd64.tar.gz": "5313004ccbc524c8757521dc3913f1edf4309f56bef06a2fb2d0c0eeade7cc62",  # pragma: allowlist secret
    "grype_0.120.1_darwin_arm64.tar.gz": "cf97957fa467d25575ec2cc3228289f391ea51cf88b9cffc5f83dc03d4cbc732",  # pragma: allowlist secret
    "grype_0.120.1_windows_amd64.zip": "32e3c811f31822d17592908bafdc6288aaaca3d52583c479167a8dc8399ed65d",  # pragma: allowlist secret
    # hadolint v2.15.1
    "hadolint-linux-x86_64": "c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507",  # pragma: allowlist secret
    "hadolint-linux-arm64": "f6198ef8090f404dbb771abfee086eb8c48ac177f30da7fd3510aca35b344b5d",  # pragma: allowlist secret
    "hadolint-macos-x86_64": "ffe9bb18b23d5ed1eae50237aecdbb523d016e96da0bd4e7aa432040acfc3fde",  # pragma: allowlist secret
    "hadolint-macos-arm64": "5c09f3213f8e40406abe048233d985eebef336d4a6a20021be47fadb6cf480a2",  # pragma: allowlist secret
    "hadolint-windows-x86_64.exe": "01d927294962b5387f9ead4f18679158452be4f17c765ad0bdffe5264b9c7b0a",  # pragma: allowlist secret
    # syft v1.54.1
    "syft_1.54.1_linux_amd64.tar.gz": "c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47",  # pragma: allowlist secret
    "syft_1.54.1_linux_arm64.tar.gz": "dfdf0537610113edbefe1f1fc6548bc957b2d77439636ec824fcf0e10d46d054",  # pragma: allowlist secret
    "syft_1.54.1_darwin_amd64.tar.gz": "2956322838b2f64e470eea474495f0cd96be4f222b1ac037258cdc47d965064e",  # pragma: allowlist secret
    "syft_1.54.1_darwin_arm64.tar.gz": "b4319c3abaa87a0170ab76ee83ea2260ca34b53aecfa3ab0dd5428d2319d744f",  # pragma: allowlist secret
    "syft_1.54.1_windows_amd64.zip": "8b56e8285e295e0bbed26eeea9b16ed51c493be97ccdf42dae6326c84fe8e19f",  # pragma: allowlist secret
    "syft_1.54.1_windows_arm64.zip": "440019acac7c5b3b44edb8d224aa226b52aadca66a1c3a0a8d58a9525f675e36",  # pragma: allowlist secret
    # trivy v0.75.0
    "trivy_0.75.0_Linux-64bit.tar.gz": "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",  # pragma: allowlist secret
    "trivy_0.75.0_Linux-ARM64.tar.gz": "a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3",  # pragma: allowlist secret
    "trivy_0.75.0_macOS-64bit.tar.gz": "291edaa9778acbe4693d067b5ad60ee11570e5ac68296e85595417528ca641e4",  # pragma: allowlist secret
    "trivy_0.75.0_macOS-ARM64.tar.gz": "4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568",  # pragma: allowlist secret
    "trivy_0.75.0_windows-64bit.zip": "4e43bd71a30f51aee39525f60f2b47043af77eb8df8fe082aae4372b69c6660f",  # pragma: allowlist secret
    # opengrep v1.30.2
    "opengrep_manylinux_x86": "a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7",  # pragma: allowlist secret
    "opengrep_manylinux_aarch64": "90acea5df4b733083f388d4feeb250ca802f671b33d1f222653d1e571dd2b0d8",  # pragma: allowlist secret
    "opengrep_osx_x86": "fcf47da30d5c3a11119f2ec4e0d1ee55e3c3822e8f90d909bf9f33dfce99044a",  # pragma: allowlist secret
    "opengrep_osx_arm64": "f1aaa30b88959cb82522c4e1475816278a1f161f994509a518453c0455f9d24b",  # pragma: allowlist secret
    "opengrep_windows_x86.exe": "523b1074a81006436fec457e2daccf7cf7cacc04000d4482f1072a1b19bc6372",  # pragma: allowlist secret
    # uv 0.12.23
    "uv-x86_64-unknown-linux-gnu.tar.gz": "9167d72b3319674b6303c4cbe071854bba13ebdf3d76b1a7cbdc175471fb66d6",  # pragma: allowlist secret
    "uv-aarch64-unknown-linux-gnu.tar.gz": "6524bd338177ed50d035d39354e12545e993bbeba2ecbddf0480c5b3a81d313f",  # pragma: allowlist secret
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
    # cfn-guard 3.2.1
    "cfn-guard-v3-x86_64-linux-latest.tar.gz": "75109d136e80060bee5572a23d0c1110949c02a8cebb2a56284866ab906b3978",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-linux-latest.tar.gz": "9f8d9a7bc483b39468595b91e99369e8bdbfb12160182a2e2c64ba758892bb79",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-macos-latest.tar.gz": "d4e79468a54262b4bf4e963da661bb0e610db9ffb97f378c3588e8d57c2a5e7d",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-macos-latest.tar.gz": "09601e53649b8ca352800d0578e1c810a322a38d8c75fa7b8cbdbfb0c7e32be3",  # pragma: allowlist secret
    "cfn-guard-v3-x86_64-windows-latest.tar.gz": "a8d57b739b6ac02dbf9ab20e3e91d6761abff706eb5ea01674ff430c2aa179f9",  # pragma: allowlist secret
    "cfn-guard-v3-aarch64-windows-latest.tar.gz": "c163f76f71af20c9437daec7af0ef9705bb2adadeef29bdeacf45938331d5722",  # pragma: allowlist secret
    # gitleaks v8.30.1
    "gitleaks_8.30.1_linux_x64.tar.gz": "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",  # pragma: allowlist secret
    "gitleaks_8.30.1_linux_arm64.tar.gz": "00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b",  # pragma: allowlist secret
    "gitleaks_8.30.1_darwin_x64.tar.gz": "cee01fea7173f1b779dff188e1c26ecbcb4027d394acc573b23aaf0be260e291",  # pragma: allowlist secret
    "gitleaks_8.30.1_darwin_arm64.tar.gz": "ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f",  # pragma: allowlist secret
    "gitleaks_8.30.1_windows_x64.zip": "17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c",  # pragma: allowlist secret
    "gitleaks_8.30.1_windows_arm64.zip": "200df852fdecbedb19a33960657333cba5e231740bc8968972b507b50f93b194",  # pragma: allowlist secret
    # grype v0.120.1
    "grype_0.120.1_linux_amd64.tar.gz": "d6e3248b0e788b4da7450a9e03d1e72811771cf97de3640a18e6517bf6507eb7",  # pragma: allowlist secret
    "grype_0.120.1_linux_arm64.tar.gz": "94afbea0a9b65a3a83b820e622e8ac337e26608c860315208d58dad9a80b25db",  # pragma: allowlist secret
    "grype_0.120.1_darwin_amd64.tar.gz": "4042c050aa6581f6c852d611c51ec62577dff24059547307063a317b975cb075",  # pragma: allowlist secret
    "grype_0.120.1_darwin_arm64.tar.gz": "1de9d74fff477a652408406b45786ed5694e3030c89dc75805ffe9424c802d36",  # pragma: allowlist secret
    "grype_0.120.1_windows_amd64.zip": "96373670a07b8b6cbcfff4331c8b3d8ffb70d570f072450f8548d04bbe2db537",  # pragma: allowlist secret
    # syft v1.54.1
    "syft_1.54.1_linux_amd64.tar.gz": "dbf75864e7a7ff9e1fbf00552c31483f693188632a9f68f343cd7653dac513d6",  # pragma: allowlist secret
    "syft_1.54.1_linux_arm64.tar.gz": "7d3cc523a2652d26568b9b2b94b5419dbf05f34ce896cf29904a0073d84eecf2",  # pragma: allowlist secret
    "syft_1.54.1_darwin_amd64.tar.gz": "9de0c19c5e6bf06884c4699c11449fcf97cfe68b7d0451730dfc38894c6b3bda",  # pragma: allowlist secret
    "syft_1.54.1_darwin_arm64.tar.gz": "bc08d98ac3ca9cf475952b8eab22dfda70f3ab475ceb4e0113b9f77b24b75e26",  # pragma: allowlist secret
    "syft_1.54.1_windows_amd64.zip": "b7e78564e72dc550301ff221c9e034d9ece77d16f8e5cc0f7782caa302addbc6",  # pragma: allowlist secret
    "syft_1.54.1_windows_arm64.zip": "a6dc42b0802fcad9582b178bc6117e4c3fe7cd94912d14054bb489717f34e223",  # pragma: allowlist secret
    # trivy v0.75.0
    "trivy_0.75.0_Linux-64bit.tar.gz": "93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e",  # pragma: allowlist secret
    "trivy_0.75.0_Linux-ARM64.tar.gz": "869e310e208f0f2e3e90e4f842cc6adaa2b2c046fecbaade481e6b23fcc8f2a9",  # pragma: allowlist secret
    "trivy_0.75.0_macOS-64bit.tar.gz": "484287e06ab2e4038c42ba396da8637aaaca0967e3e65840563706a0284169b4",  # pragma: allowlist secret
    "trivy_0.75.0_macOS-ARM64.tar.gz": "32b84c068e11e5381fc85d3fe2e8ac238659ab22524ce1b2b9dfcbd0b1f7331a",  # pragma: allowlist secret
    "trivy_0.75.0_windows-64bit.zip": "3b4fcf6fec53c4c73c325cfd518c7264100695b19e6c59c6a777e4a67dc9f0e6",  # pragma: allowlist secret
    # uv 0.12.23
    "uv-x86_64-unknown-linux-gnu.tar.gz": "abdc39eab8b4ad341dca91f3823a23a343fae94bdb22ebdd9e91694415206f2f",  # pragma: allowlist secret
    "uv-aarch64-unknown-linux-gnu.tar.gz": "ed797a095bf9aea58135fa7081c290e51a14cfd3a7b1f24e55cb1d1a0c1007b0",  # pragma: allowlist secret
}

# The version each unversioned tool's digests above were taken from.
#
# The other tools put the version in every asset name, so bumping
# TOOL_VERSIONS without the table changes every URL to a filename the digest table
# has no entry for, and get_tool_asset refuses it by name. opengrep and uv do not:
# `opengrep_manylinux_x86` is the name of that asset in every release. Bumping the
# version alone would therefore resolve the new URL to the OLD release's digest. That
# still fails closed -- the download would not match -- but as a SHA256 mismatch, the
# message that means "possible supply-chain substitution", for what is a half-applied
# edit. Recording the version here turns it into the same refusal by name instead.
_DIGESTS_TAKEN_AT: dict[str, str] = {
    "cfn-guard": "3.2.1",
    "hadolint": "v2.15.1",
    "opengrep": "v1.30.2",
    "uv": "0.12.23",
}

# Tools whose release asset is the executable itself rather than an archive.
_BARE_EXECUTABLE_TOOLS = frozenset({"hadolint", "opengrep"})


_RELEASE_BASE_URLS: dict[str, str] = {
    "actionlint": "https://github.com/rhysd/actionlint/releases/download",
    "cfn-guard": "https://github.com/aws-cloudformation/cloudformation-guard/releases/download",
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
    "cfn-guard": _CFN_GUARD_ASSETS,
    "gitleaks": _GITLEAKS_ASSETS,
    "grype": _GRYPE_ASSETS,
    "hadolint": _HADOLINT_ASSETS,
    "opengrep": _OPENGREP_ASSETS,
    "syft": _SYFT_ASSETS,
    "trivy": _TRIVY_ASSETS,
    "uv": _UV_ASSETS,
}


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
# needs no edit to start reporting the tool's upstream releases.
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
# community config's ferret-scan suppression is pinned to exactly these lines, and
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
    "cfn-lint commit": "be66fb3e224b41c85065cb3002ad0b24e31db535",  # pragma: allowlist secret
    "checkov commit": "e5f995a6e2dd033e99354b6c477d056eb5eaf2d0",  # pragma: allowlist secret
    "cfn-guard commit": "e531ef56092abb662e08fc6062c92db6d53f99c9",  # pragma: allowlist secret
    "cfn-guard/LICENSE": "28878a48de57252ed2c9119db71b2fc9766833a0c159d9f5df54cba4dea52dba",  # pragma: allowlist secret
    "cfn-guard/NOTICE": "ba249a48f79f76c72cffea8689eb7a5ce450a4a67ad6b1e44e8ff15a95b2b751",  # pragma: allowlist secret
    "gitleaks commit": "83d9cd684c87d95d656c1458ef04895a7f1cbd8e",  # pragma: allowlist secret
    "grype commit": "6f8d854af29d3a3086b11a84afa51554a2a245fe",  # pragma: allowlist secret
    "guarddog commit": "3da172679cb58b1c9a780f9f5d640f855be016dc",  # pragma: allowlist secret
    "hadolint commit": "2eece55955ced00200be9729e9728cb7dacca505",  # pragma: allowlist secret
    "hadolint/LICENSE": "589ed823e9a84c56feb95ac58e7cf384626b9cbf4fda2a907bc36e103de1bad2",  # pragma: allowlist secret
    "hadolint/ThirdPartyNotices.txt": "424561d8aade37960e8db594ca5403f9a4a98f593ff1126a296298f11d3d1a27",  # pragma: allowlist secret
    "libgit2 commit": "0060d9cf5666f015b1067129bd874c6cc4c9c7ac",  # pragma: allowlist secret
    "libgit2/AUTHORS": "126ed06438e488d71f5232b39436b3a1dffccb9c2697e3a332fbe868975cd55f",  # pragma: allowlist secret
    "libgit2/COPYING": "e3712465634e97cfd850822a4eb5ac7d2f8a10f753189366d5a2060046f28288",  # pragma: allowlist secret
    "libssh2 commit": "a312b43325e3383c865a87bb1d26cb52e3292641",  # pragma: allowlist secret
    "libssh2/COPYING": "f7f9633cf9ff2f1333f3d7ce46973a8716a4d2a2815ad56f30d437d5fea7bafe",  # pragma: allowlist secret
    "opengrep commit": "062fc871dbe9951887d0b985ea30977d3c36d315",  # pragma: allowlist secret
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
    "semgrep commit": "a35fe8306115b3e55274969098cc46f8451d6b4d",  # pragma: allowlist secret
    "semgrep/COPYRIGHT": "0f90eaca8e598c6c67a6cda7beb4470518fb2dababc996b3898344d380769aca",  # pragma: allowlist secret
    "semgrep/LICENSE": "20c17d8b8c48a600800dfd14f95d5cb9ff47066a9641ddeab48dc54aec96e331",  # pragma: allowlist secret
    "syft commit": "b254e6d92f28c3868a755f62fb3ca8f26e9fee76",  # pragma: allowlist secret
    "trivy commit": "591e9799316a602e703f0b484f6c6d7b234ec8f3",  # pragma: allowlist secret
    "trivy/NOTICE": "aed9bc6dab87c6f6567d20bf0f5c0433a8ccd3ad7873322cf79b9244eb720a1f",  # pragma: allowlist secret
    "uv commit": "46b84fd0bfec23b72f29e8e2185ba68a65052f48",  # pragma: allowlist secret
    "uv/LICENSE-APACHE": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",  # pragma: allowlist secret
    "uv/LICENSE-MIT": "860e3d7a86b84e6a7012c7a635fc64df475cebc6cce34dfeb73a5982ec58176c",  # pragma: allowlist secret
    "zizmor commit": "99a054ed9283c90abdd2d5b9fb5101d27dde9783",  # pragma: allowlist secret
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
        version_probe=(
            "python3",
            "-c",
            (
                "import glob, json, os; "
                "[print(json.load(open(m))['version']) for m in glob.glob(os.path.join("
                "os.environ['ASH_CFN_GUARD_RULES_DIR'], 'aws-guard-rules-registry-*', "
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
    # The release archive holds the executable and a README, no license file, so
    # both files come from the repository.
    "cfn-guard": ThirdPartyLicense(
        tool="cfn-guard",
        version="3.2.1",
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
        version="v1.57.2",
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
        version="3.3.26",
        license="Apache-2.0",
        repository="https://github.com/bridgecrewio/checkov",
        commit=_THIRD_PARTY_HASHES["checkov commit"],
        files=(LicenseFile("LICENSE"),),
        distribution="checkov",
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
        version="v0.120.1",
        license="Apache-2.0",
        repository="https://github.com/anchore/grype",
        commit=_THIRD_PARTY_HASHES["grype commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    # The GuardDog community scanner's uv tool. The wheel's dist-info carries
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
        version="v1.30.2",
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
        version="v1.180.0",
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
        version="v1.54.1",
        license="Apache-2.0",
        repository="https://github.com/anchore/syft",
        commit=_THIRD_PARTY_HASHES["syft commit"],
        files=(LicenseFile("LICENSE"),),
    ),
    "trivy": ThirdPartyLicense(
        tool="trivy",
        version="v0.75.0",
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
    # The zizmor scanner's uv tool, a compiled Rust binary in a wheel. The
    # wheel's dist-info carries licenses/LICENSE.
    "zizmor": ThirdPartyLicense(
        tool="zizmor",
        version="v1.30.1",
        license="MIT",
        repository="https://github.com/zizmorcore/zizmor",
        commit=_THIRD_PARTY_HASHES["zizmor commit"],
        files=(LicenseFile("LICENSE"),),
        distribution="zizmor",
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
