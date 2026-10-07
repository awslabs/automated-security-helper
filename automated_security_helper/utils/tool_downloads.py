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
    "grype": "https://github.com/anchore/grype/releases/download",
    "syft": "https://github.com/anchore/syft/releases/download",
    "trivy": "https://github.com/aquasecurity/trivy/releases/download",
}

_ASSET_TABLES: dict[str, dict[PlatformArch, str]] = {
    "grype": _GRYPE_ASSETS,
    "syft": _SYFT_ASSETS,
    "trivy": _TRIVY_ASSETS,
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

    def index_record(self) -> dict:
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
